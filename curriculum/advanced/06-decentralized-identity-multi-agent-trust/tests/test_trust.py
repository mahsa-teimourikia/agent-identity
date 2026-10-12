from __future__ import annotations

import copy
import json
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import cedarpy
import jwt
import networkx as nx
import pytest

COURSE = Path(__file__).parents[1]
sys.path.insert(0, str(COURSE))

from lab import (
    AUDIENCE,
    DOMAIN,
    GOVERNANCE,
    NOW,
    OWNER,
    PARTNER,
    WORKER,
    TrustError,
    authorize,
    b58decode,
    build_cases,
    build_scenario,
    did_key_document,
    did_key_from_public,
    did_web_url,
    digest,
    evaluate,
    parse_did,
    public_bytes,
    release_gate,
    resolve_quorum,
    service_endpoint_safe,
    trust_graph,
    unverified,
    validate_did_document,
    verify_did_auth,
)


def test_labelled_corpus_is_complete_and_release_ready():
    cases = build_cases()
    metrics, rows = evaluate(cases)
    assert len(cases) == 42
    assert {case.category for case in cases} == {
        "valid",
        "authentication",
        "resolution",
        "credential",
        "delegation",
        "policy",
        "request",
    }
    assert metrics.correct == 42
    assert metrics.invalid_allows == metrics.valid_blocks == 0
    assert all(row["match"] for row in rows)
    assert release_gate(metrics)


def test_authentication_only_baseline_exposes_authorization_failures():
    metrics, _ = evaluate(build_cases(), baseline=True)
    assert metrics.invalid_allows == 25
    assert metrics.valid_blocks == 0


@pytest.mark.parametrize("case", build_cases(), ids=lambda case: case.case_id)
def test_every_labelled_case(case):
    assert case.run().allowed is case.expected_allowed


def test_valid_decision_carries_auditable_evidence():
    decision = authorize(build_scenario("evidence"))
    assert decision.allowed
    assert decision.evidence["did"] == WORKER
    assert len(decision.evidence["capabilities"]) == 2
    assert len(decision.evidence["requestDigest"]) == 64


@pytest.mark.parametrize(
    ("did", "method", "identifier"),
    [
        (WORKER, "web", "agents.partner.example:investigator"),
        ("did:example:abc%2Fdef", "example", "abc%2Fdef"),
    ],
)
def test_strict_did_parser(did, method, identifier):
    assert parse_did(did, frozenset({"web", "example"})) == (method, identifier)


@pytest.mark.parametrize(
    "did",
    [
        "not-a-did",
        "DID:web:example.com",
        "did:web:",
        "did:Web:example.com",
        "did:web:bad%ZZ",
    ],
)
def test_parser_rejects_malformed_dids(did):
    with pytest.raises(TrustError):
        parse_did(did)


def test_did_key_is_ed25519_multicodec_and_resolves_offline():
    scenario = build_scenario("did-key")
    did = did_key_from_public(scenario.keys[WORKER])
    decoded = b58decode(did.removeprefix("did:key:z"))
    assert decoded[:2] == b"\xed\x01"
    assert decoded[2:] == public_bytes(scenario.keys[WORKER])
    document = did_key_document(did)
    assert document["id"] == did
    assert document["authentication"] == document["capabilityInvocation"]


@pytest.mark.parametrize(
    ("did", "url"),
    [
        ("did:web:partner.example", "https://partner.example/.well-known/did.json"),
        (WORKER, "https://agents.partner.example/investigator/did.json"),
    ],
)
def test_did_web_mapping_is_deterministic(did, url):
    assert did_web_url(did) == url


@pytest.mark.parametrize(
    "did",
    [
        "did:web:localhost",
        "did:web:127.0.0.1",
        "did:web:169.254.169.254",
        "did:web:evil.example",
        "did:web:user%40agents.partner.example",
        "did:web:agents.partner.example:..:secret",
        "did:web:agents.partner.example:path%2Fescape",
        "did:web:agents.partner.example%3A8443",
    ],
)
def test_did_web_policy_blocks_ssrf_and_path_confusion(did):
    with pytest.raises(TrustError):
        did_web_url(did)


@pytest.mark.parametrize(
    ("endpoint", "safe"),
    [
        ("https://agents.partner.example/card", True),
        ("http://agents.partner.example/card", False),
        ("https://evil.example/card", False),
        ("https://user@agents.partner.example/card", False),
        ("https://127.0.0.1/card", False),
    ],
)
def test_service_endpoints_are_hints_subject_to_egress_policy(endpoint, safe):
    assert service_endpoint_safe(endpoint) is safe


def test_document_validation_rejects_private_key_material():
    scenario = build_scenario("private-jwk")
    document = scenario.resolver.documents[WORKER]
    document["verificationMethod"][0]["publicKeyJwk"]["d"] = "must-not-appear"
    with pytest.raises(TrustError, match="jwk_invalid"):
        validate_did_document(WORKER, document, {"versionId": "1"})


def test_document_validation_rejects_dangling_relationship_reference():
    scenario = build_scenario("dangling")
    document = scenario.resolver.documents[WORKER]
    document["authentication"] = [f"{WORKER}#missing"]
    with pytest.raises(TrustError, match="verification_relationship_invalid"):
        validate_did_document(WORKER, document, {"versionId": "1"})


def test_resolver_returns_both_metadata_layers():
    result = build_scenario("metadata").resolver.resolve(WORKER)
    assert result.document_metadata["versionId"] == "1"
    assert result.resolution_metadata["contentType"] == "application/did+json"
    assert result.resolution_metadata["source"].startswith("https://")


def test_cache_requires_refresh_after_rotation():
    scenario = build_scenario("rotation")
    first = scenario.resolver.resolve(WORKER)
    rotated = copy.deepcopy(first.document)
    old_id = rotated["verificationMethod"][0]["id"]
    new_id = f"{WORKER}#controller-2"
    rotated["verificationMethod"][0]["id"] = new_id
    for relationship in ("authentication", "assertionMethod", "capabilityInvocation"):
        rotated[relationship] = [
            new_id if item == old_id else item for item in rotated[relationship]
        ]
    scenario.resolver.documents[WORKER] = rotated
    scenario.resolver.metadata[WORKER]["versionId"] = "2"
    assert scenario.resolver.resolve(WORKER).document_metadata["versionId"] == "1"
    assert (
        scenario.resolver.resolve(WORKER, refresh=True).document_metadata["versionId"]
        == "2"
    )


def test_high_assurance_resolution_requires_digest_and_version_agreement():
    scenario = build_scenario("quorum")
    assert (
        resolve_quorum(
            scenario.resolver, scenario.secondary_resolver, WORKER, NOW
        ).document["id"]
        == WORKER
    )
    scenario.secondary_resolver.invalidate(WORKER)
    scenario.secondary_resolver.documents[WORKER]["alsoKnownAs"] = [
        "did:web:other.example"
    ]
    with pytest.raises(TrustError, match="resolver_disagreement"):
        resolve_quorum(scenario.resolver, scenario.secondary_resolver, WORKER, NOW)


def test_did_auth_envelope_binds_verifier_challenge():
    scenario = build_scenario("inspect-proof")
    header, claims = unverified(scenario.proof)
    assert header == {
        "alg": "EdDSA",
        "kid": f"{WORKER}#controller-1",
        "typ": "did-auth+jwt",
    }
    assert claims["iss"] == claims["sub"] == WORKER
    assert claims["aud"] == AUDIENCE and claims["domain"] == DOMAIN
    assert claims["nonce"] == scenario.request.nonce


def test_replay_store_is_atomic_under_concurrency():
    scenario = build_scenario("atomic")

    def verify(_: int) -> bool:
        try:
            verify_did_auth(
                scenario.proof,
                did=WORKER,
                audience=AUDIENCE,
                domain=DOMAIN,
                nonce=scenario.request.nonce,
                resolver=scenario.resolver,
                secondary_resolver=None,
                high_assurance=False,
                replay_store=scenario.replay_store,
                now=NOW,
            )
            return True
        except TrustError:
            return False

    with ThreadPoolExecutor(max_workers=8) as executor:
        assert sum(executor.map(verify, range(24))) == 1


def test_registration_is_a_signed_bounded_training_profile():
    scenario = build_scenario("registration")
    header, claims = unverified(scenario.registration)
    subject = claims["vc"]["credentialSubject"]
    assert header["typ"] == "vc+jwt" and claims["iss"] == GOVERNANCE
    assert subject["id"] == WORKER
    assert set(subject) == {"id", "organization", "agentClass", "status"}


def test_capability_chain_is_parent_bound_and_attenuated():
    scenario = build_scenario("capability")
    root = jwt.decode(scenario.capabilities[0], options={"verify_signature": False})
    child = jwt.decode(scenario.capabilities[1], options={"verify_signature": False})
    assert root["iss"] == OWNER and root["sub"] == PARTNER
    assert child["iss"] == PARTNER and child["sub"] == WORKER
    assert child["capability"]["parent"] == digest(scenario.capabilities[0])
    assert set(child["capability"]["actions"]) < set(root["capability"]["actions"])
    assert set(child["capability"]["resources"]) < set(root["capability"]["resources"])


def test_verification_relationships_are_purpose_bound():
    scenario = build_scenario("relationships")
    scenario.high_assurance = False
    scenario.resolver.documents[PARTNER]["capabilityInvocation"] = []
    assert authorize(scenario).reason == "key_relationship_invalid"


def test_trust_graph_is_directed_not_implicitly_transitive():
    graph = trust_graph()
    assert graph.is_directed() and nx.has_path(graph, GOVERNANCE, WORKER)
    assert not graph.has_edge(GOVERNANCE, WORKER)
    assert not graph.has_edge(WORKER, GOVERNANCE)


def test_data_corpus_matches_executable_cases():
    data = json.loads((COURSE / "data" / "adversarial_cases.json").read_text())
    cases = build_cases()
    assert [item["case_id"] for item in data] == [case.case_id for case in cases]
    assert [item["expected_allowed"] for item in data] == [
        case.expected_allowed for case in cases
    ]


def test_trust_registry_uses_exact_local_anchors():
    registry = json.loads((COURSE / "data" / "trust_registry.json").read_text())
    assert registry["registrationIssuer"] == GOVERNANCE
    assert registry["capabilityRoot"] == OWNER
    assert registry["allowedDidMethods"] == ["web", "key"]
    assert registry["maxDelegationDepth"] == 3


@pytest.mark.parametrize(
    "policy", ["opa/decentralized_agent.rego", "cedar/decentralized_agent.cedar"]
)
def test_policy_examples_encode_fail_closed_constraints(policy):
    text = (COURSE / "policies" / policy).read_text().lower()
    for required in ("tenant", "purpose", "audience", "active"):
        assert required in text


def test_cedar_policy_parses_as_two_policies():
    policies = cedarpy.PolicySet.from_str(
        (COURSE / "policies/cedar/decentralized_agent.cedar").read_text()
    )
    assert len(policies) == 2


def test_fixture_lab_runs_without_network(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("network access attempted")

    monkeypatch.setattr("socket.create_connection", forbidden)
    assert authorize(build_scenario("offline")).allowed
