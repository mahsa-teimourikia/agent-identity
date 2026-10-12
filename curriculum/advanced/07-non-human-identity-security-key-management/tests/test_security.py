from __future__ import annotations

import json
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import jwt
import pytest
from cryptography import x509

COURSE = Path(__file__).parents[1]
sys.path.insert(0, str(COURSE))

from lab import (
    ACTION,
    AUDIENCE,
    NOW,
    RESOURCE_URI,
    SPIFFE_ID,
    KeyInventory,
    ReplayCache,
    SecurityError,
    authorize_request,
    bearer_baseline,
    cases,
    evaluate,
    hardened,
    issue_access_token,
    issue_dpop,
    public_jwk,
    redact,
    scenario,
    validate_svid,
)


def test_evaluation_release_gate_and_baseline_gap():
    secure, rows = evaluate()
    baseline, _ = evaluate(True)
    assert len(rows) == 24 and secure.correct == 24
    assert secure.invalid_allows == secure.valid_blocks == 0
    assert baseline.invalid_allows == 21


def test_fixture_corpus_matches_executable_cases():
    fixture = json.loads((COURSE / "data/adversarial_cases.json").read_text())
    executable = cases()
    assert [item["case_id"] for item in fixture] == [
        case.case_id for case in executable
    ]
    assert [item["expected_allowed"] for item in fixture] == [
        case.expected for case in executable
    ]


@pytest.mark.parametrize("case", cases(), ids=lambda c: c.case_id)
def test_every_labelled_case(case):
    assert case.run() is case.expected


def test_svid_is_real_x509_with_exact_spiffe_uri():
    value = scenario("svid")
    assert isinstance(value.svid, x509.Certificate)
    assert validate_svid(value.svid, value.ca_cert) == SPIFFE_ID
    sans = value.svid.extensions.get_extension_for_class(
        x509.SubjectAlternativeName
    ).value
    assert sans.get_values_for_type(x509.UniformResourceIdentifier) == [SPIFFE_ID]


def test_access_token_is_signed_short_lived_and_sender_bound():
    value = scenario("token")
    header = jwt.get_unverified_header(value.token)
    claims = jwt.decode(value.token, options={"verify_signature": False})
    assert header == {"alg": "EdDSA", "kid": "sts:v1", "typ": "at+jwt"}
    assert claims["sub"] == SPIFFE_ID and claims["aud"] == AUDIENCE
    assert claims["exp"] - claims["iat"] == 300
    assert set(claims["cnf"]) == {"jkt"}


def test_dpop_proof_binds_method_uri_token_nonce_and_key():
    value = scenario("dpop")
    header = jwt.get_unverified_header(value.proof)
    claims = jwt.decode(value.proof, options={"verify_signature": False})
    assert header["typ"] == "dpop+jwt" and set(header["jwk"]) == {"kty", "crv", "x"}
    assert claims["htm"] == "GET" and claims["htu"] == RESOURCE_URI
    assert claims["nonce"] == "resource-nonce" and claims["ath"]


def test_complete_valid_request_returns_auditable_fields():
    value = scenario("decision")
    result = authorize_request(
        value.token, value.proof, value.issuer_key.public_key(), replay=value.replay
    )
    assert result == {
        "allowed": True,
        "subject": SPIFFE_ID,
        "action": ACTION,
        "resource": RESOURCE_URI,
        "token_id": "access:decision",
    }


def test_replay_cache_is_atomic():
    cache = ReplayCache()

    def consume(_: int) -> bool:
        try:
            cache.consume("same")
            return True
        except SecurityError:
            return False

    with ThreadPoolExecutor(max_workers=8) as executor:
        assert sum(executor.map(consume, range(32))) == 1


def test_key_inventory_enforces_purpose_rotation_overlap_and_revocation():
    inventory = KeyInventory()
    first = inventory.create("token-signing", 1)
    second = inventory.rotate(first.key_id, overlap=120)
    assert second.version == 2 and inventory.key_for(first.key_id, "token-signing", NOW)
    with pytest.raises(SecurityError):
        inventory.key_for(first.key_id, "encryption", NOW)
    with pytest.raises(SecurityError):
        inventory.key_for(first.key_id, "token-signing", NOW + 120)
    inventory.revoke(second.key_id)
    with pytest.raises(SecurityError):
        inventory.key_for(second.key_id, "token-signing")


@pytest.mark.parametrize("overlap", [-1, 301])
def test_rotation_rejects_unsafe_overlap(overlap):
    inventory = KeyInventory()
    record = inventory.create("signing", 1)
    with pytest.raises(SecurityError, match="rotation_invalid"):
        inventory.rotate(record.key_id, overlap=overlap)


@pytest.mark.parametrize(
    "text",
    [
        "Authorization: Bearer abc.def.ghi",
        "Authorization: DPoP abc.def.ghi",
        "key=AKIAABCDEFGHIJKLMNOP",
        "-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----",
    ],
)
def test_redaction_removes_common_secret_shapes(text):
    assert "[REDACTED]" in redact(text)


def test_redaction_does_not_destroy_safe_identity_metadata():
    assert (
        redact(f"subject={SPIFFE_ID} action={ACTION}")
        == f"subject={SPIFFE_ID} action={ACTION}"
    )


def test_forged_token_is_not_confused_with_valid_dpop():
    value = scenario("forged")
    attacker = scenario("attacker").workload_key
    value.token = issue_access_token(
        attacker, confirmation_jwk=public_jwk(value.dpop_key)
    )
    value.proof = issue_dpop(value.dpop_key, value.token)
    assert not hardened(value)
    assert bearer_baseline(value)


def test_policy_examples_cover_current_identity_and_sender_constraint():
    opa = (COURSE / "policies/opa/non_human_identity.rego").read_text().lower()
    cedar = (COURSE / "policies/cedar/non_human_identity.cedar").read_text().lower()
    for text in (opa, cedar):
        for required in ("active", "audience", "scope", "revoked"):
            assert required in text


def test_course_uses_no_network(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("network attempted")

    monkeypatch.setattr("socket.create_connection", forbidden)
    assert hardened(scenario("offline"))
