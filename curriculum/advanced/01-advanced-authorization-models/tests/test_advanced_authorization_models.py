from __future__ import annotations

import sys
from dataclasses import replace
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

COURSE = Path(__file__).parents[1]
sys.path.insert(0, str(COURSE))

from advanced_authz_runtime import (
    AGENT,
    ATTRIBUTE_VERSION,
    CLAIM,
    NOW,
    OTHER_TENANT,
    POLICY_VERSION,
    RELATION_VERSION,
    SUBAGENT,
    TENANT,
    TOOL,
    ApprovalStore,
    CachedPDP,
    DecisionCache,
    DelegationGrant,
    EnforcementError,
    HybridPDP,
    Obligation,
    PolicyEnforcementPoint,
    build_cases,
    cache_key,
    delegation_violations,
    digest,
    environment,
    evaluate_cases,
    evaluate_cedar,
    opa_input,
    openfga_check,
    release_gate,
)


def test_labelled_corpus_has_coverage_and_exact_reference_outcomes():
    cases = build_cases()
    metrics, rows = evaluate_cases(cases, hardened=True)
    assert len(cases) == 38
    assert {case.category for case in cases} >= {
        "identity",
        "isolation",
        "relationship",
        "freshness",
        "dependency",
        "approval",
        "risk",
        "constraint",
    }
    assert metrics.exact_matches == metrics.total
    assert all(row["match"] for row in rows)
    assert release_gate(metrics)


def test_role_only_baseline_measurably_overauthorizes():
    metrics, _ = evaluate_cases(build_cases(), hardened=False)
    assert metrics.invalid_allows == 34
    assert metrics.outcome_accuracy < 0.2
    assert not release_gate(metrics)


@pytest.mark.parametrize("case", build_cases(), ids=lambda case: case.case_id)
def test_each_labelled_case(case):
    assert HybridPDP().evaluate(case.prepare()).outcome == case.expected_outcome


@pytest.mark.parametrize(
    "field,value,reason",
    [
        ("authenticated", False, "identity_not_authenticated"),
        ("workload_attested", False, "workload_not_attested"),
        ("workload_id", "spiffe://evil/agent", "workload_not_attested"),
        ("tenant_id", OTHER_TENANT, "tenant_mismatch"),
        ("subject_id", "user:eve", "subject_task_mismatch"),
        ("agent_id", "agent:rogue", "agent_task_mismatch"),
        ("roles", frozenset(), "role_ineligible"),
    ],
)
def test_trusted_identity_dimensions_are_enforced(field, value, reason):
    authz = environment()
    changed = replace(authz, identity=replace(authz.identity, **{field: value}))
    assert reason in HybridPDP().evaluate(changed).reason_codes


@pytest.mark.parametrize(
    "field,reason",
    [
        ("user_operates_agent", "operator_relationship_missing"),
        ("agent_assigned_to_task", "task_assignment_missing"),
        ("task_contains_resource", "resource_relationship_missing"),
        ("task_permits_tool", "tool_relationship_missing"),
    ],
)
def test_every_relationship_intersection_is_required(field, reason):
    authz = environment()
    changed = replace(
        authz, relationships=replace(authz.relationships, **{field: False})
    )
    decision = HybridPDP().evaluate(changed)
    assert decision.outcome == "deny"
    assert reason in decision.reason_codes


@given(risk=st.integers(min_value=0, max_value=100))
def test_cross_tenant_never_allows_for_any_risk(risk):
    authz = environment()
    changed = replace(
        authz,
        resource=replace(authz.resource, tenant_id=OTHER_TENANT),
        attributes=replace(authz.attributes, risk_score=risk),
    )
    assert HybridPDP().evaluate(changed).outcome == "deny"


@given(
    low=st.integers(min_value=0, max_value=99),
    high=st.integers(min_value=1, max_value=100),
)
def test_increasing_risk_never_improves_the_outcome(low, high):
    if low > high:
        low, high = high, low
    authz = environment()
    rank = {"deny": 0, "retryable_error": 0, "step_up": 1, "allow": 2}
    low_result = (
        HybridPDP()
        .evaluate(replace(authz, attributes=replace(authz.attributes, risk_score=low)))
        .outcome
    )
    high_result = (
        HybridPDP()
        .evaluate(replace(authz, attributes=replace(authz.attributes, risk_score=high)))
        .outcome
    )
    assert rank[high_result] <= rank[low_result]


def test_dependency_outage_is_distinct_from_policy_denial():
    authz = environment()
    outage = replace(authz, relationships=replace(authz.relationships, available=False))
    decision = HybridPDP().evaluate(outage)
    assert decision.outcome == "retryable_error"
    assert "relationship_dependency_unavailable" in decision.reason_codes


def test_non_allow_decision_records_privacy_safe_evidence():
    authz = environment()
    denied = replace(authz, resource=replace(authz.resource, tenant_id=OTHER_TENANT))
    pep = PolicyEnforcementPoint(HybridPDP())
    with pytest.raises(EnforcementError, match="tenant_mismatch"):
        pep.execute(denied)
    assert pep.evidence[0]["decision_outcome"] == "deny"
    assert pep.evidence[0]["outcome"] == "not_executed"
    assert "ssn" not in str(pep.evidence)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda x: replace(x, expected_policy_version="old"),
        lambda x: replace(
            x, relationships=replace(x.relationships, version="relations:old")
        ),
        lambda x: replace(x, attributes=replace(x.attributes, version="attrs:old")),
        lambda x: replace(x, resource=replace(x.resource, version=10)),
        lambda x: replace(x, proposal=replace(x.proposal, purpose="different")),
        lambda x: replace(x, proposal=replace(x.proposal, tool_id="tool:other")),
    ],
)
def test_cache_key_binds_every_mutated_state(mutate):
    authz = environment()
    assert cache_key(mutate(authz)) != cache_key(authz)


def test_cache_hit_avoids_second_evaluation_but_expiry_does_not():
    engine = HybridPDP()
    cached = CachedPDP(engine, DecisionCache(ttl_seconds=5))
    first = cached.evaluate(environment(), NOW)
    second = cached.evaluate(environment(), NOW + 1)
    third = cached.evaluate(environment(), NOW + 5)
    assert not first.cache_hit and second.cache_hit and not third.cache_hit
    assert engine.evaluations == 2


def test_cache_does_not_reuse_allow_after_relationship_version_change():
    engine = HybridPDP()
    cached = CachedPDP(engine, DecisionCache())
    assert cached.evaluate(environment()).outcome == "allow"
    authz = environment()
    stale = replace(
        authz, relationships=replace(authz.relationships, version="relations:41")
    )
    assert cached.evaluate(stale).outcome == "deny"
    assert engine.evaluations == 2


def parent_grant() -> DelegationGrant:
    return DelegationGrant(
        "grant:parent",
        TENANT,
        AGENT,
        frozenset({"claim.read", "claim.update"}),
        frozenset({CLAIM}),
        frozenset({TOOL}),
        frozenset({"claims-processing"}),
        NOW + 600,
        4,
        0,
    )


def child_grant(parent: DelegationGrant, **changes) -> DelegationGrant:
    values = {
        "grant_id": "grant:child",
        "tenant_id": parent.tenant_id,
        "delegate_id": SUBAGENT,
        "actions": frozenset({"claim.read"}),
        "resources": parent.resources,
        "tools": parent.tools,
        "purposes": parent.purposes,
        "expires_at": parent.expires_at - 60,
        "max_calls": 2,
        "depth": 1,
        "parent_digest": digest(parent),
    }
    values.update(changes)
    return DelegationGrant(**values)


def test_narrow_child_delegation_is_valid():
    parent = parent_grant()
    assert delegation_violations(parent, child_grant(parent)) == ()


@pytest.mark.parametrize(
    "changes,reason",
    [
        ({"tenant_id": OTHER_TENANT}, "tenant_widened"),
        ({"actions": frozenset({"claim.read", "claim.delete"})}, "action_widened"),
        ({"resources": frozenset({CLAIM, "claim:999"})}, "resource_widened"),
        ({"tools": frozenset({TOOL, "tool:wire"})}, "tool_widened"),
        (
            {"purposes": frozenset({"claims-processing", "marketing"})},
            "purpose_widened",
        ),
        ({"expires_at": NOW + 601}, "expiry_widened"),
        ({"max_calls": 5}, "budget_widened"),
        ({"depth": 3}, "depth_invalid"),
        ({"parent_digest": "wrong"}, "parent_binding_invalid"),
    ],
)
def test_delegation_cannot_widen(changes, reason):
    parent = parent_grant()
    assert reason in delegation_violations(parent, child_grant(parent, **changes))


@given(st.sets(st.sampled_from(["claim.read", "claim.update"])))
def test_any_action_subset_is_monotonic(actions):
    parent = parent_grant()
    child = child_grant(parent, actions=frozenset(actions))
    assert "action_widened" not in delegation_violations(parent, child)


def test_pep_executes_allow_and_records_privacy_safe_evidence():
    pep = PolicyEnforcementPoint(HybridPDP())
    receipt = pep.execute(environment())
    assert receipt.effect_id.startswith("effect:")
    assert set(receipt.obligation_ids) == {"audit", "redact"}
    assert pep.evidence[0]["outcome"] == "executed"
    assert "ssn" not in str(pep.evidence)


def test_pep_reauthorizes_at_commit_and_rejects_revocation():
    authz = environment("claim.update")
    revoked = replace(authz, task=replace(authz.task, active=False))
    with pytest.raises(EnforcementError, match="commit_task_inactive"):
        PolicyEnforcementPoint(HybridPDP()).execute(authz, refresh=lambda: revoked)


def test_pep_detects_resource_version_change_at_commit():
    authz = environment("claim.update")
    changed = replace(authz, resource=replace(authz.resource, version=10))
    with pytest.raises(EnforcementError, match="commit_resource_version_changed"):
        PolicyEnforcementPoint(HybridPDP()).execute(authz, refresh=lambda: changed)


def test_field_constraints_are_enforced_by_pdp_and_pep():
    authz = environment("claim.update")
    attack = replace(authz, proposal=replace(authz.proposal, fields=("bank_account",)))
    with pytest.raises(EnforcementError, match="field_constraint_violated"):
        PolicyEnforcementPoint(HybridPDP()).execute(attack)


class UnknownObligationPDP(HybridPDP):
    def evaluate(self, authz, now=NOW):
        decision = super().evaluate(authz, now)
        return replace(decision, obligations=(Obligation("unknown_side_effect"),))


def test_unknown_obligation_fails_closed():
    with pytest.raises(EnforcementError, match="obligation_unsupported"):
        PolicyEnforcementPoint(UnknownObligationPDP()).execute(environment())


def test_exact_approval_is_single_use_but_effect_retry_is_idempotent():
    authz = environment("claim.settle")
    store = ApprovalStore()
    first_pep = PolicyEnforcementPoint(HybridPDP(), approvals=store)
    first = first_pep.execute(authz)
    assert first_pep.execute(authz) == first
    with pytest.raises(EnforcementError, match="approval_replayed"):
        PolicyEnforcementPoint(HybridPDP(), approvals=store).execute(authz)


def test_operation_id_cannot_be_reused_for_changed_proposal():
    pep = PolicyEnforcementPoint(HybridPDP())
    authz = environment()
    pep.execute(authz)
    changed = replace(
        authz,
        proposal=replace(authz.proposal, purpose="different-purpose"),
    )
    with pytest.raises(EnforcementError, match="operation_id_conflict"):
        pep.execute(changed)


@pytest.mark.parametrize("action", ["claim.read", "claim.update", "claim.settle"])
def test_cedar_executes_valid_core_paths(action):
    assert evaluate_cedar(environment(action))


@pytest.mark.parametrize(
    "mutate",
    [
        lambda x: replace(x, resource=replace(x.resource, tenant_id=OTHER_TENANT)),
        lambda x: replace(
            x, relationships=replace(x.relationships, task_contains_resource=False)
        ),
        lambda x: replace(x, attributes=replace(x.attributes, risk_score=80)),
        lambda x: replace(x, task=replace(x.task, active=False)),
    ],
)
def test_cedar_denies_core_invariant_failures(mutate):
    assert not evaluate_cedar(mutate(environment()))


def test_opa_mapping_contains_versions_and_only_trusted_identity():
    document = opa_input(environment())
    assert document["policy_version"] == POLICY_VERSION
    assert document["relationships"]["version"] == RELATION_VERSION
    assert document["attributes"]["version"] == ATTRIBUTE_VERSION
    assert "password" not in str(document).lower()


def test_openfga_sdk_request_is_constructed_without_network():
    request = openfga_check(environment("claim.update"))
    assert request.user == AGENT
    assert request.relation == "can_update"
    assert request.object == CLAIM
    assert len(request.contextual_tuples) == 4


def test_policy_artifacts_and_primary_sources_are_present():
    readme = (COURSE / "README.md").read_text()
    opa = (COURSE / "policies/opa/agent_authz.rego").read_text()
    assert "import rego.v1" in opa
    assert "forbid" in (COURSE / "policies/cedar/agent_authz.cedar").read_text()
    assert "can_settle" in (COURSE / "policies/openfga/model.fga").read_text()
    for source in (
        "openpolicyagent.org",
        "docs.cedarpolicy.com",
        "openfga.dev",
        "nist.gov",
    ):
        assert source in readme
