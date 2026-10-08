from __future__ import annotations

import copy
import sys
from dataclasses import replace
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

COURSE = Path(__file__).parents[1]
sys.path.insert(0, str(COURSE))

from advanced_delegation_runtime import (
    ACCESS_TOKEN,
    CLAIM,
    CLAIMS_AGENT,
    KNOWLEDGE_API,
    NOW,
    RESEARCH_AGENT,
    ROOT_ISSUER,
    TASK,
    TENANT,
    CallBudgetStore,
    CapabilityGateway,
    DPoP_NONCE,
    ReplayStore,
    attenuate_macaroon,
    attenuation_violations,
    build_cases,
    create_dpop_proof,
    create_macaroon,
    deterministic_private_key,
    digest,
    evaluate_cases,
    evaluate_cedar_context,
    evidence_hash,
    jwk_thumbprint,
    public_jwk,
    release_gate,
    scenario,
    sign_capability,
    sign_evidence,
    valid_cedar_context,
    verify_chain,
    verify_dpop_proof,
    verify_evidence_chain,
    verify_macaroon,
)


def test_labelled_corpus_has_required_slices_and_exact_results():
    cases = build_cases()
    metrics, rows = evaluate_cases(cases)
    assert len(cases) == 27
    assert {case.category for case in cases} >= {
        "identity",
        "isolation",
        "attenuation",
        "crypto",
        "revocation",
        "dpop",
        "policy",
    }
    assert all(row["match"] for row in rows)
    assert release_gate(metrics)


@pytest.mark.parametrize("case", build_cases(), ids=lambda case: case.case_id)
def test_every_labelled_case(case):
    assert case.run() is case.expected_allowed


def test_valid_chain_verifies_both_signatures_and_parent_binding():
    value = scenario()
    result = verify_chain(value["chain"], value["keys"])
    assert result.valid
    assert result.leaf.subject == RESEARCH_AGENT
    assert result.reason_codes == ("chain_valid",)


def test_unknown_issuer_cannot_create_authority():
    value = scenario()
    keys = dict(value["keys"])
    keys.pop(CLAIMS_AGENT)
    result = verify_chain(value["chain"], keys)
    assert not result.valid
    assert "signature_invalid:1" in result.reason_codes


def test_resigning_widened_child_still_fails_attenuation():
    value = scenario()
    root, child = value["chain"]
    widened = replace(
        child.claims, actions=frozenset({"knowledge.search", "claim.delete"})
    )
    resigned = sign_capability(widened, value["private_keys"][CLAIMS_AGENT])
    result = verify_chain((root, resigned), value["keys"])
    assert not result.valid
    assert "action_widened" in result.reason_codes


@pytest.mark.parametrize(
    "field,value,reason",
    [
        ("issuer", "agent:other", "issuer_not_parent_subject"),
        ("tenant_id", "tenant:other", "tenant_widened"),
        ("task_id", "task:other", "task_widened"),
        ("audiences", frozenset({KNOWLEDGE_API, "https://evil"}), "audience_widened"),
        ("actions", frozenset({"knowledge.search", "claim.delete"}), "action_widened"),
        ("resources", frozenset({CLAIM, "claim:999"}), "resource_widened"),
        ("tools", frozenset({"tool:knowledge", "tool:wire"}), "tool_widened"),
        ("purposes", frozenset({"fraud-research", "marketing"}), "purpose_widened"),
        ("expires_at", NOW + 601, "expiry_widened"),
        ("max_calls", 6, "call_budget_widened"),
        ("max_amount_cents", 50_001, "amount_widened"),
        ("depth", 2, "depth_invalid"),
        ("parent_jti", "wrong", "parent_jti_mismatch"),
        ("parent_digest", "wrong", "parent_digest_mismatch"),
        ("policy_version", "other", "policy_version_changed"),
    ],
)
def test_each_delegation_dimension_is_monotonic(field, value, reason):
    root, child = scenario()["chain"]
    changed = replace(child.claims, **{field: value})
    assert reason in attenuation_violations(root.claims, changed)


@given(st.sets(st.sampled_from(["knowledge.search"])))
def test_action_subsets_never_widen(actions):
    root, child = scenario()["chain"]
    changed = replace(child.claims, actions=frozenset(actions))
    assert "action_widened" not in attenuation_violations(root.claims, changed)


def test_dpop_proof_is_bound_to_key_method_uri_token_nonce_and_time():
    value = scenario()
    request = value["request"]
    store = ReplayStore()
    ok, reason = verify_dpop_proof(
        value["proof"],
        expected_jkt=value["chain"][-1].claims.confirmation_jkt,
        method=request.method,
        uri=request.uri,
        access_token=ACCESS_TOKEN,
        nonce=DPoP_NONCE,
        replay_store=store,
    )
    assert (ok, reason) == (True, "dpop_valid")
    replay = verify_dpop_proof(
        value["proof"],
        expected_jkt=value["chain"][-1].claims.confirmation_jkt,
        method=request.method,
        uri=request.uri,
        access_token=ACCESS_TOKEN,
        nonce=DPoP_NONCE,
        replay_store=store,
    )
    assert replay == (False, "dpop_replayed")


def test_dpop_query_and_fragment_are_excluded_from_htu():
    value = scenario()
    request = value["request"]
    proof = create_dpop_proof(
        value["dpop_key"],
        method="POST",
        uri=request.uri + "?secret=1#fragment",
        access_token=ACCESS_TOKEN,
        jti="dpop:normalized",
        nonce=DPoP_NONCE,
    )
    ok, _ = verify_dpop_proof(
        proof,
        expected_jkt=value["chain"][-1].claims.confirmation_jkt,
        method="POST",
        uri=request.uri,
        access_token=ACCESS_TOKEN,
        nonce=DPoP_NONCE,
        replay_store=ReplayStore(),
    )
    assert ok


def test_wrong_dpop_key_is_rejected_before_request_policy():
    value = scenario()
    other = deterministic_private_key("other-dpop")
    proof = create_dpop_proof(
        other,
        method=value["request"].method,
        uri=value["request"].uri,
        access_token=ACCESS_TOKEN,
        jti="dpop:wrong-key",
        nonce=DPoP_NONCE,
    )
    decision = CapabilityGateway(value["keys"]).authorize(
        value["chain"], value["request"], value["policy"], proof=proof
    )
    assert (decision.allowed, decision.reason_code) == (
        False,
        "dpop_key_binding_invalid",
    )


def test_gateway_evidence_uses_hashes_not_credentials():
    value = scenario()
    gateway = CapabilityGateway(value["keys"])
    assert gateway.authorize(
        value["chain"], value["request"], value["policy"], proof=value["proof"]
    ).allowed
    serialized = str(gateway.evidence)
    assert ACCESS_TOKEN not in serialized
    assert value["proof"] not in serialized
    assert "capability_jti_hash" in gateway.evidence[0]


def test_call_budget_is_atomic_bounded_and_operation_ids_are_bound():
    value = scenario()
    store = CallBudgetStore()
    gateway = CapabilityGateway(value["keys"], call_budgets=store)

    def proof(jti):
        return create_dpop_proof(
            value["dpop_key"],
            method=value["request"].method,
            uri=value["request"].uri,
            access_token=ACCESS_TOKEN,
            jti=jti,
            nonce=DPoP_NONCE,
        )

    first = gateway.authorize(
        value["chain"], value["request"], value["policy"], proof=proof("dpop:1")
    )
    second_request = replace(value["request"], operation_id="operation:search:484")
    second = gateway.authorize(
        value["chain"], second_request, value["policy"], proof=proof("dpop:2")
    )
    third_request = replace(value["request"], operation_id="operation:search:485")
    exhausted = gateway.authorize(
        value["chain"], third_request, value["policy"], proof=proof("dpop:3")
    )
    conflicting_request = replace(value["request"], resource="claim:999")
    conflict = store.reserve(
        value["chain"][-1].claims.jti,
        2,
        value["request"].operation_id,
        digest(conflicting_request),
    )
    assert (first.allowed, second.allowed) == (True, True)
    assert (exhausted.allowed, exhausted.reason_code) == (
        False,
        "call_budget_exhausted",
    )
    assert conflict == (False, "operation_id_conflict")


def test_real_macaroon_verifies_only_when_every_caveat_is_satisfied():
    root = create_macaroon()
    child = attenuate_macaroon(root, "expires_before = 1800000300", "max_results = 5")
    satisfied = [
        f"tenant = {TENANT}",
        f"task = {TASK}",
        "action = knowledge.search",
        f"resource = {CLAIM}",
        "expires_before = 1800000300",
        "max_results = 5",
    ]
    assert verify_macaroon(child, satisfied)
    assert not verify_macaroon(child, satisfied[:-1])
    assert len(child.caveats) == len(root.caveats) + 2


def evidence_fixture():
    authority = deterministic_private_key("evidence:authority")
    agent = deterministic_private_key("evidence:agent")
    first = sign_evidence(
        event_id="event:1",
        producer=ROOT_ISSUER,
        event_type="capability_issued",
        subject_id=CLAIMS_AGENT,
        object_digest=digest("cap:root:483"),
        previous_hash="",
        private_key=authority,
    )
    second = sign_evidence(
        event_id="event:2",
        producer=CLAIMS_AGENT,
        event_type="capability_attenuated",
        subject_id=RESEARCH_AGENT,
        object_digest=digest("cap:research:483"),
        previous_hash=evidence_hash(first),
        private_key=agent,
    )
    keys = {ROOT_ISSUER: authority.public_key(), CLAIMS_AGENT: agent.public_key()}
    return first, second, keys


def test_signed_provenance_chain_verifies():
    first, second, keys = evidence_fixture()
    assert verify_evidence_chain((first, second), keys) == (True, "evidence_valid")


@pytest.mark.parametrize(
    "mutate,reason",
    [
        (
            lambda a, b: (replace(a, object_digest="changed"), b),
            "evidence_signature_invalid",
        ),
        (lambda a, b: (a, replace(b, previous_hash="wrong")), "evidence_link_invalid"),
        (lambda a, b: (b, a), "evidence_link_invalid"),
        (lambda a, b: (a, a), "evidence_duplicate"),
        (lambda a, b: (a, replace(b, producer="unknown")), "evidence_producer_unknown"),
    ],
)
def test_provenance_tampering_reordering_and_unknown_producers_fail(mutate, reason):
    first, second, keys = evidence_fixture()
    assert verify_evidence_chain(mutate(first, second), keys) == (False, reason)


def test_jwk_thumbprint_is_stable_and_private_material_is_absent():
    key = deterministic_private_key("thumbprint")
    jwk = public_jwk(key.public_key())
    assert set(jwk) == {"kty", "crv", "x"}
    assert jwk_thumbprint(jwk) == jwk_thumbprint(copy.deepcopy(jwk))


def test_cedar_policy_executes_and_forbid_overrides_permit():
    context = valid_cedar_context()
    assert evaluate_cedar_context(context)
    context["riskScore"] = 80
    assert not evaluate_cedar_context(context)


@pytest.mark.parametrize(
    "fact",
    [
        "proofValid",
        "attenuationValid",
        "dpopValid",
        "replayConsumed",
        "capabilityCurrent",
        "policyVersionCurrent",
        "subjectBound",
        "tenantBound",
        "taskBound",
        "audienceBound",
        "actionBound",
        "resourceBound",
        "toolBound",
        "purposeBound",
        "workloadApproved",
        "relationshipValid",
    ],
)
def test_cedar_denies_when_a_required_gateway_fact_is_false(fact):
    context = valid_cedar_context()
    context[fact] = False
    assert not evaluate_cedar_context(context)


def test_policy_artifacts_and_current_primary_sources_are_linked():
    readme = (COURSE / "README.md").read_text()
    assert "import rego.v1" in (COURSE / "policies/opa/capability.rego").read_text()
    assert "forbid" in (COURSE / "policies/cedar/capability.cedar").read_text()
    for source in (
        "rfc-editor.org",
        "biscuitsec.org",
        "modelcontextprotocol.io",
        "nist.gov",
    ):
        assert source in readme
