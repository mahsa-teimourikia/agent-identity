"""Course 03 invariant tests for credential and token verification."""

import importlib.util
import hashlib
from pathlib import Path
import sys


LAB_PATH = Path(__file__).parents[1] / "lab.py"
SPEC = importlib.util.spec_from_file_location("course03_lab", LAB_PATH)
lab = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = lab
SPEC.loader.exec_module(lab)


def controlled_rows():
    return lab.evaluate(lab.build_cases(), lab.hardened_verifier)[1]


def test_fixture_tokens_are_reproducible():
    first = {case.case_id: case.token for case in lab.build_cases()}
    second = {case.case_id: case.token for case in lab.build_cases()}

    assert first == second


def test_public_jwk_contains_no_private_key_material():
    _, key_set = lab.build_key_material()
    jwk = lab.public_jwk(key_set.keys["sig-2026-09"])

    assert jwk == {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": jwk["x"],
        "kid": "sig-2026-09",
        "alg": "EdDSA",
        "use": "sig",
    }
    assert "d" not in jwk


def test_all_labelled_attempts_match_acceptance_and_reason():
    rows = controlled_rows()

    for _, _, expected_accept, reason_matches, decision in rows:
        assert decision.accepted is expected_accept
        assert reason_matches


def test_unknown_and_revoked_keys_fail_before_claim_promotion():
    rows = {case_id: decision for case_id, _, _, _, decision in controlled_rows()}

    assert rows["unknown_key"].reason_code == "unknown_key"
    assert rows["revoked_key"].reason_code == "key_revoked"
    assert rows["unknown_key"].subject is None
    assert rows["revoked_key"].subject is None


def test_key_set_is_bound_to_the_configured_issuer():
    case = lab.build_cases()[0]
    _, key_set = lab.build_key_material()
    wrong_issuer_key_set = lab.TrustedKeySet("https://other.example", key_set.keys)

    decision = lab.hardened_verifier(
        case.token,
        wrong_issuer_key_set,
        lab.build_profile(),
        lab.ReplayCache(),
        1,
    )

    assert not decision.accepted
    assert decision.reason_code == "keyset_issuer_mismatch"


def test_issuer_audience_and_type_are_independent_profile_checks():
    rows = {case_id: decision for case_id, _, _, _, decision in controlled_rows()}

    assert rows["wrong_issuer"].reason_code == "issuer_mismatch"
    assert rows["wrong_audience"].reason_code == "audience_mismatch"
    assert rows["missing_type"].reason_code == "token_type_mismatch"
    assert rows["id_token_confusion"].reason_code == "token_type_mismatch"


def test_expiry_future_use_and_max_lifetime_fail_closed():
    rows = {case_id: decision for case_id, _, _, _, decision in controlled_rows()}

    assert rows["expired"].reason_code == "token_expired"
    assert rows["future_not_before"].reason_code == "token_not_yet_valid"
    assert rows["excessive_lifetime"].reason_code == "token_lifetime_invalid"


def test_tampering_fails_signature_verification():
    rows = {case_id: decision for case_id, _, _, _, decision in controlled_rows()}

    assert not rows["tampered_payload"].accepted
    assert rows["tampered_payload"].reason_code == "signature_invalid"


def test_single_use_action_token_is_consumed_once():
    replay_rows = [
        decision
        for case_id, _, _, _, decision in controlled_rows()
        if case_id == "replayed_action_token"
    ]

    assert [decision.accepted for decision in replay_rows] == [True, False]
    assert [decision.reason_code for decision in replay_rows] == [
        "token_profile_valid",
        "replay_detected",
    ]


def test_decisions_record_digest_not_raw_token():
    cases = lab.build_cases()
    token_by_digest = {
        f"sha256:{hashlib.sha256(case.token.encode()).hexdigest()}": case.token
        for case in cases
    }

    for _, _, _, _, decision in controlled_rows():
        assert decision.token_digest in token_by_digest
        assert token_by_digest[decision.token_digest] not in repr(decision)
        assert decision.evidence_complete


def test_baseline_and_hardened_metrics_use_explicit_populations():
    cases = lab.build_cases()
    baseline, _ = lab.evaluate(cases, lab.signature_only_baseline)
    controlled, _ = lab.evaluate(cases, lab.hardened_verifier)

    assert baseline.attempts == controlled.attempts == 17
    assert baseline.expected_valid_attempts == controlled.expected_valid_attempts == 3
    assert baseline.expected_invalid_attempts == controlled.expected_invalid_attempts == 14
    assert baseline.valid_attempt_success_rate == 1.0
    assert baseline.invalid_acceptance_rate == 12 / 14
    assert baseline.replay_block_rate == 0.0
    assert controlled.valid_attempt_success_rate == 1.0
    assert controlled.invalid_acceptance_rate == 0.0
    assert controlled.invalid_block_rate == 1.0
    assert controlled.replay_block_rate == 1.0
