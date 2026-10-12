from __future__ import annotations

import json
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError
from pathlib import Path

import jwt
import networkx as nx
import pytest
from hypothesis import given
from hypothesis import strategies as st

COURSE = Path(__file__).parents[1]
sys.path.insert(0, str(COURSE))

from advanced_evidence_runtime import (
    ACTION,
    AGENT,
    CONFIG,
    EVALUATION,
    GOVERNANCE,
    HOLDER,
    REGISTRATION,
    RELEASE,
    RESOURCE,
    TENANT,
    TOOL_MANIFEST,
    AccessRequest,
    EvidenceGateway,
    ReplayCache,
    build_cases,
    build_dcql_query,
    build_evidence_graph,
    create_presentation,
    disclosure_state,
    dsse_pae,
    evaluate_baseline,
    evaluate_cases,
    release_gate,
    scenario,
    verify_credential,
    verify_eat,
    verify_presentation,
    verify_provenance,
)


def gateway(value):
    return EvidenceGateway(
        value["keys"],
        value["policies"],
        value["schemas"],
        value["builder_keys"],
    )


def test_labelled_corpus_has_broad_slices_and_exact_results():
    cases = build_cases()
    metrics, rows = evaluate_cases(cases)
    assert len(cases) == 42
    assert {case.category for case in cases} >= {
        "presentation",
        "credential",
        "status",
        "binding",
        "negative-evidence",
        "workload",
        "supply-chain",
        "lifecycle",
    }
    assert all(row["match"] for row in rows)
    assert metrics.invalid_allows == metrics.valid_blocked == 0
    assert release_gate(metrics)


def test_signature_only_baseline_exposes_assurance_laundering():
    metrics, _ = evaluate_baseline(build_cases())
    assert metrics.invalid_allows == 40
    assert metrics.valid_blocked == 0


@pytest.mark.parametrize("case", build_cases(), ids=lambda case: case.case_id)
def test_every_labelled_case(case):
    assert case.run() is case.expected_allowed


def test_complete_evidence_produces_explainable_profile():
    value = scenario()
    decision = gateway(value).authorize(value["context"])
    assert decision.allowed
    assert decision.profile is not None
    assert decision.profile.identity == "verified"
    assert decision.profile.workload == "verified"
    assert decision.profile.supply_chain == "verified"
    assert decision.profile.evaluation == "verified"
    assert decision.profile.governance == "verified"
    assert len(decision.profile.evidence_ids) == 3


def test_presentation_verifies_holder_nonce_audience_and_three_credentials():
    value = scenario()
    context = value["context"]
    result = verify_presentation(
        context.presentation,
        value["keys"],
        value["policies"],
        value["schemas"],
        context.status_lists,
        ReplayCache(),
        expected_holder=HOLDER,
        expected_subject=AGENT,
        expected_audience=context.request.verifier,
        expected_nonce=context.request.nonce,
    )
    assert result.valid
    assert {item.credential_type for item in result.credentials} == {
        REGISTRATION,
        EVALUATION,
        GOVERNANCE,
    }
    assert all(item.subject == AGENT for item in result.credentials)


def test_presentation_rejects_duplicate_required_credential():
    value = scenario()
    context = value["context"]
    duplicated = create_presentation(
        (*value["credentials"], value["credentials"][0]),
        value["private_keys"][HOLDER],
        kid=value["kids"][HOLDER],
        nonce=context.request.nonce,
        presentation_id="vp:duplicate-credential",
    )
    result = verify_presentation(
        duplicated,
        value["keys"],
        value["policies"],
        value["schemas"],
        context.status_lists,
        ReplayCache(),
        expected_holder=HOLDER,
        expected_subject=AGENT,
        expected_audience=context.request.verifier,
        expected_nonce=context.request.nonce,
    )
    assert not result.valid
    assert result.reason_code == "required_credential_set_incomplete"


def test_presentation_rejects_unrecognized_vp_profile():
    value = scenario()
    context = value["context"]
    claims = jwt.decode(context.presentation, options={"verify_signature": False})
    claims["vp"]["type"] = ["UnexpectedPresentation"]
    malformed = jwt.encode(
        claims,
        value["private_keys"][HOLDER],
        algorithm="EdDSA",
        headers=jwt.get_unverified_header(context.presentation),
    )
    result = verify_presentation(
        malformed,
        value["keys"],
        value["policies"],
        value["schemas"],
        context.status_lists,
        ReplayCache(),
        expected_holder=HOLDER,
        expected_subject=AGENT,
        expected_audience=context.request.verifier,
        expected_nonce=context.request.nonce,
    )
    assert not result.valid
    assert result.reason_code == "presentation_profile_invalid"


def test_credential_rejects_non_string_type_without_crashing():
    value = scenario()
    original = value["credentials"][0]
    claims = jwt.decode(original, options={"verify_signature": False})
    claims["vc"]["type"] = ["VerifiableCredential", {"unexpected": "object"}]
    issuer = claims["iss"]
    malformed = jwt.encode(
        claims,
        value["private_keys"][issuer],
        algorithm="EdDSA",
        headers=jwt.get_unverified_header(original),
    )
    result, reason = verify_credential(
        malformed,
        value["keys"],
        value["policies"],
        value["schemas"],
        value["context"].status_lists,
        expected_audience=value["context"].request.verifier,
    )
    assert result is None
    assert reason == "credential_type_invalid"


def test_credential_documents_use_vc2_context_and_exact_schema_profiles():
    value = scenario()
    for token in value["credentials"]:
        claims = jwt.decode(token, options={"verify_signature": False})
        vc = claims["vc"]
        assert vc["@context"] == ["https://www.w3.org/ns/credentials/v2"]
        credential_type = (set(vc["type"]) - {"VerifiableCredential"}).pop()
        assert value["schemas"][credential_type]["$schema"].endswith("2020-12/schema")
        assert vc["issuer"] == claims["iss"]
        assert vc["credentialSubject"]["id"] == claims["sub"]
        assert vc["credentialStatus"]["statusPurpose"] == "revocation"


def test_replay_cache_consumption_is_atomic():
    cache = ReplayCache()
    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(cache.consume, ["vp:one"] * 32))
    assert results.count(True) == 1
    assert results.count(False) == 31


def test_eat_binds_fresh_runtime_measurements_to_challenge():
    value = scenario()
    result = verify_eat(
        value["context"].workload_attestation,
        value["keys"],
        value["context"].request,
    )
    assert result.valid
    assert result.claims["nonce"] == value["context"].request.nonce
    assert result.claims["measurements"] == {
        "releaseDigest": RELEASE,
        "configDigest": CONFIG,
        "toolManifestDigest": TOOL_MANIFEST,
    }


def test_dsse_pae_is_length_bound_and_provenance_is_exact():
    assert dsse_pae("a", b"bc") != dsse_pae("ab", b"c")
    value = scenario()
    result = verify_provenance(
        value["context"].provenance,
        value["builder_keys"],
        value["context"].request,
    )
    assert result.valid
    assert result.statement["subject"][0]["digest"]["sha256"] == RELEASE.removeprefix(
        "sha256:"
    )
    assert result.statement["predicateType"] == "https://slsa.dev/provenance/v1"


def test_minimal_dcql_query_requests_only_policy_inputs():
    query = build_dcql_query()
    assert [item["id"] for item in query["credentials"]] == [
        "registration",
        "evaluation",
        "governance",
    ]
    paths = {
        tuple(claim["path"])
        for item in query["credentials"]
        for claim in item["claims"]
    }
    assert ("credentialSubject", "releaseDigest") in paths
    assert ("credentialSubject", "owner") not in paths


@given(st.booleans())
def test_undisclosed_is_not_collapsed_into_verified_false(value):
    assert disclosure_state({}, "approved") == ("unknown", None)
    assert disclosure_state({"approved": value}, "approved") == ("verified", value)


def test_evidence_graph_preserves_issuers_subjects_and_release_edges():
    value = scenario()
    context = value["context"]
    result = verify_presentation(
        context.presentation,
        value["keys"],
        value["policies"],
        value["schemas"],
        context.status_lists,
        ReplayCache(),
        expected_holder=HOLDER,
        expected_subject=AGENT,
        expected_audience=context.request.verifier,
        expected_nonce=context.request.nonce,
    )
    graph = build_evidence_graph(context.request, result.credentials)
    assert isinstance(graph, nx.DiGraph)
    assert graph.has_edge(AGENT, RELEASE)
    assert graph.has_edge(HOLDER, RELEASE)
    assert all(graph.has_edge(item.issuer, AGENT) for item in result.credentials)


def test_gateway_evidence_is_reconstructable_without_credentials_or_subject():
    value = scenario()
    gate = gateway(value)
    assert gate.authorize(value["context"]).allowed
    serialized = json.dumps(gate.evidence)
    assert value["context"].presentation not in serialized
    assert value["context"].workload_attestation not in serialized
    assert AGENT not in serialized
    assert gate.evidence[0]["evidence_ids"]
    assert gate.evidence[0]["reason_code"] == "authorized"


def test_configured_issuer_profiles_and_adversarial_catalog_match_runtime():
    registry = json.loads((COURSE / "data/trusted_issuers.json").read_text())
    adversarial = json.loads((COURSE / "data/adversarial_cases.json").read_text())
    assert set(registry) >= {
        "https://registry.corp.example",
        "https://evaluation.corp.example",
        "https://governance.corp.example",
    }
    assert {item["case_id"] for item in adversarial} == {
        case.case_id for case in build_cases()
    }
    assert sum(item["expected"] == "allow" for item in adversarial) == 1


def test_readme_uses_primary_sources_and_separates_final_from_draft_work():
    readme = (COURSE / "README.md").read_text()
    for source in (
        "w3.org/TR/vc-data-model-2.0",
        "rfc-editor.org/rfc/rfc9901",
        "openid.net/specs/openid-4-verifiable-presentations-1_0-final",
        "rfc-editor.org/rfc/rfc9711",
        "slsa.dev/spec/v1.2",
    ):
        assert source in readme
    assert "SD-JWT VC remains an Internet-Draft" in readme


def test_request_contract_is_immutable_and_exactly_bound():
    request = scenario()["context"].request
    assert isinstance(request, AccessRequest)
    assert request.agent_id == AGENT
    assert request.holder_id == HOLDER
    assert request.tenant_id == TENANT
    assert request.action == ACTION
    assert request.resource == RESOURCE
    with pytest.raises(FrozenInstanceError):
        request.agent_id = "urn:agent:evil"
