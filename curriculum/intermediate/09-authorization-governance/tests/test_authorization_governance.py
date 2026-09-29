"""Executable invariants for Intermediate 09 authorization governance."""

import importlib.util
import json
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import cedarpy
import pytest
from jsonschema import Draft202012Validator

LAB_PATH = Path(__file__).parents[1] / "lab.py"
SPEC = importlib.util.spec_from_file_location("intermediate09_lab", LAB_PATH)
lab = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = lab
SPEC.loader.exec_module(lab)


@pytest.mark.parametrize("case", lab.build_cases(), ids=lambda case: case.case_id)
def test_authorization_scenario_matrix(case):
    assert lab.run_case(case) is case.expected


def test_scenario_matrix_has_no_invalid_allow_or_valid_block():
    report, _ = lab.evaluate()
    assert report == {
        "invalid_allows": 0,
        "matches": 18,
        "total": 18,
        "valid_work_blocked": 0,
    }


def test_effective_permissions_combine_direct_and_valid_delegated_authority():
    engine = lab.GovernanceEngine()
    assert ("claim.update", lab.CLAIM) in engine.direct_permissions(lab.CLAIMS_AGENT)
    assert engine.direct_permissions(lab.RESEARCH_AGENT) == set()
    assert engine.effective_permissions(lab.RESEARCH_AGENT) == {
        ("claim.read", lab.CLAIM)
    }


@pytest.mark.parametrize(
    "mutation,code",
    [
        (
            lambda engine: engine.delegations.__setitem__(
                "del:claims-research",
                lab.replace(
                    engine.delegations["del:claims-research"],
                    permissions=frozenset({("claim.delete", lab.CLAIM)}),
                ),
            ),
            "DELEGATION_WIDENED",
        ),
        (
            lambda engine: engine.delegations.__setitem__(
                "del:alice-claims",
                lab.replace(engine.delegations["del:alice-claims"], redelegable=False),
            ),
            "REDELEGATION_NOT_ALLOWED",
        ),
        (
            lambda engine: engine.delegations.__setitem__(
                "del:claims-research",
                lab.replace(engine.delegations["del:claims-research"], depth=3),
            ),
            "DELEGATION_DEPTH_EXCEEDED",
        ),
        (
            lambda engine: engine.delegations.__setitem__(
                "del:claims-research",
                lab.replace(
                    engine.delegations["del:claims-research"],
                    tenant_id="tenant:evil",
                ),
            ),
            "DELEGATION_BINDING_INVALID",
        ),
    ],
)
def test_invalid_delegation_is_detected_and_never_effective(mutation, code):
    engine = lab.GovernanceEngine()
    mutation(engine)
    assert code in {finding.code for finding in engine.validate_delegations()}
    assert engine.effective_permissions(lab.RESEARCH_AGENT) == set()


def test_delegation_cycle_is_detected_and_fails_closed():
    engine = lab.GovernanceEngine()
    engine.delegations["del:alice-claims"] = lab.replace(
        engine.delegations["del:alice-claims"], parent_id="del:claims-research"
    )
    findings = engine.validate_delegations()
    assert "DELEGATION_CYCLE" in {finding.code for finding in findings}
    assert (
        engine.authorize(lab.RESEARCH_AGENT, "claim.read", lab.CLAIM).outcome
        is lab.Outcome.DENY
    )


def test_expired_delegation_is_reported_and_excluded():
    engine = lab.GovernanceEngine()
    findings = engine.validate_delegations(lab.NOW + 2_000)
    assert "DELEGATION_EXPIRED" in {finding.code for finding in findings}
    assert engine.effective_permissions(lab.RESEARCH_AGENT, lab.NOW + 2_000) == set()


def test_inventory_findings_cover_lifecycle_usage_wildcards_and_sod():
    engine = lab.GovernanceEngine()
    codes = {finding.code for finding in engine.findings({"ent:claim-update": 4})}
    assert {
        "ORPHANED_AGENT",
        "STALE_AGENT",
        "HIGH_RISK_WILDCARD",
        "UNUSED_HIGH_RISK_PERMISSION",
        "TOXIC_COMBINATION",
    } <= codes


def test_usage_is_review_evidence_and_does_not_automatically_revoke():
    engine = lab.GovernanceEngine()
    engine.findings({"ent:legacy-export": 0})
    assert "ent:legacy-export" in engine.entitlements


@pytest.mark.parametrize(
    "updates,reason",
    [
        ({"tenant_id": "tenant:evil"}, "exception_lifetime_invalid"),
        ({"expires_at": lab.NOW}, "exception_lifetime_invalid"),
        ({"expires_at": lab.NOW + 86_401}, "exception_lifetime_invalid"),
        ({"approver_ids": ("security:bob",)}, "exception_approval_invalid"),
        (
            {"approver_ids": (lab.CLAIMS_AGENT, "security:bob")},
            "exception_approval_invalid",
        ),
        ({"controls": ()}, "exception_binding_invalid"),
        ({"ticket_id": ""}, "exception_binding_invalid"),
        ({"reason": ""}, "exception_binding_invalid"),
        ({"policy_version": "policy:old"}, "exception_binding_invalid"),
    ],
)
def test_exception_workflow_rejects_unbounded_or_weak_grants(updates, reason):
    engine = lab.GovernanceEngine()
    with pytest.raises(lab.GovernanceError, match=reason):
        engine.create_exception(lab.valid_exception(**updates))


def test_valid_exception_is_exact_time_bounded_and_idempotent():
    engine = lab.GovernanceEngine()
    grant = lab.valid_exception()
    engine.create_exception(grant)
    engine.create_exception(grant)
    assert (
        engine.authorize(lab.CLAIMS_AGENT, "claim.export", lab.CLAIM).outcome
        is lab.Outcome.ALLOW
    )
    assert (
        engine.authorize(
            lab.CLAIMS_AGENT, "claim.export", lab.CLAIM, now=grant.expires_at
        ).outcome
        is lab.Outcome.DENY
    )


def test_exception_identifier_cannot_be_reused_for_different_authority():
    engine = lab.GovernanceEngine()
    engine.create_exception(lab.valid_exception())
    with pytest.raises(lab.GovernanceError, match="exception_id_conflict"):
        engine.create_exception(
            lab.valid_exception(permission=("claim.delete", lab.CLAIM))
        )


def make_review(engine, outcome="renew", **changes):
    packet = engine.review_packet("ent:claim-update", 4)
    values = {
        "review_id": packet.review_id,
        "reviewer_id": "security:bob",
        "outcome": outcome,
        "snapshot_digest": packet.snapshot_digest,
        "reason": "quarterly recertification",
        "decided_at": lab.NOW + 30,
    }
    values.update(changes)
    return packet, lab.ReviewDecision(**values)


@pytest.mark.parametrize("outcome", ["renew", "reduce", "revoke", "escalate"])
def test_review_workflow_accepts_each_documented_disposition(outcome):
    engine = lab.GovernanceEngine()
    packet, decision = make_review(engine, outcome)
    result = engine.apply_review(decision, packet.inventory_version)
    assert result["outcome"] == outcome
    assert decision.used is True
    if outcome == "revoke":
        assert packet.entitlement_id not in engine.entitlements
    elif outcome == "reduce":
        assert engine.entitlements[packet.entitlement_id].resource == lab.CLAIM
    elif outcome == "renew":
        assert (
            engine.entitlements[packet.entitlement_id].expires_at
            == lab.NOW + 90 * 86_400
        )


@pytest.mark.parametrize(
    "changes,version,reason",
    [
        (
            {"reviewer_id": lab.CLAIMS_AGENT},
            lab.INVENTORY_VERSION,
            "review_binding_invalid",
        ),
        (
            {"reviewer_id": "team:claims"},
            lab.INVENTORY_VERSION,
            "review_binding_invalid",
        ),
        (
            {"snapshot_digest": "0" * 64},
            lab.INVENTORY_VERSION,
            "review_binding_invalid",
        ),
        ({"reason": ""}, lab.INVENTORY_VERSION, "review_binding_invalid"),
        ({"decided_at": lab.NOW + 901}, lab.INVENTORY_VERSION, "review_packet_invalid"),
        ({}, lab.INVENTORY_VERSION - 1, "inventory_version_conflict"),
    ],
)
def test_review_rejects_self_review_stale_evidence_or_version_conflict(
    changes, version, reason
):
    engine = lab.GovernanceEngine()
    _, decision = make_review(engine, **changes)
    with pytest.raises(lab.GovernanceError, match=reason):
        engine.apply_review(decision, version)


def test_review_recomputes_snapshot_to_close_time_of_check_time_of_use_gap():
    engine = lab.GovernanceEngine()
    packet, decision = make_review(engine)
    engine.entitlements[packet.entitlement_id] = lab.replace(
        engine.entitlements[packet.entitlement_id], resource="claim:attacker"
    )
    with pytest.raises(lab.GovernanceError, match="review_binding_invalid"):
        engine.apply_review(decision, packet.inventory_version)


def test_exact_review_retry_reconciles_but_changed_retry_conflicts():
    engine = lab.GovernanceEngine()
    packet, decision = make_review(engine)
    engine.apply_review(decision, packet.inventory_version)
    retry = lab.replace(decision, used=False)
    assert (
        engine.apply_review(retry, packet.inventory_version)["outcome"] == "reconciled"
    )
    with pytest.raises(lab.GovernanceError, match="review_replay_conflict"):
        engine.apply_review(
            lab.replace(retry, reason="changed"), packet.inventory_version
        )


def test_concurrent_review_retries_create_one_inventory_mutation():
    engine = lab.GovernanceEngine()
    packet, decision = make_review(engine)
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(
            pool.map(
                lambda _: engine.apply_review(
                    lab.replace(decision, used=False), packet.inventory_version
                ),
                range(8),
            )
        )
    assert engine.inventory_version == lab.INVENTORY_VERSION + 1
    assert sum(result["outcome"] == "reconciled" for result in results) == 7


def test_policy_impact_reports_expansion_regression_and_high_risk_action():
    old = lab.PolicyCandidate(
        "old", {lab.CLAIMS_AGENT: frozenset({("claim.read", lab.CLAIM)})}
    )
    new = lab.PolicyCandidate(
        "new", {lab.CLAIMS_AGENT: frozenset({("claim.export", lab.CLAIM)})}
    )
    impact = lab.GovernanceEngine().policy_impact(
        old,
        new,
        [
            ("valid-read", lab.CLAIMS_AGENT, f"claim.read|{lab.CLAIM}", True),
            ("forbidden-export", lab.CLAIMS_AGENT, f"claim.export|{lab.CLAIM}", False),
        ],
    )
    assert impact.newly_allowed == ("forbidden-export",)
    assert impact.newly_denied == ("valid-read",)
    assert impact.high_risk_expansions == ("forbidden-export",)
    assert impact.valid_work_blocked == 1
    assert impact.forbidden_allows == 1


def test_governance_evidence_is_versioned_deterministic_and_privacy_minimized():
    engine = lab.GovernanceEngine()
    first = engine.evidence_bundle({"ent:claim-read": 91})
    second = engine.evidence_bundle({"ent:claim-read": 91})
    assert first == second
    assert first["inventory_version"] == lab.INVENTORY_VERSION
    assert first["policy_version"] == lab.POLICY_VERSION
    assert first["model_version"] == lab.MODEL_VERSION
    assert len(first["inventory_digest"]) == 64
    serialized = lab.canonical(first)
    assert "spiffe://" not in serialized
    assert "user:alice" not in serialized
    assert "regulatory response" not in serialized


def test_offboarding_revokes_every_modeled_authority_surface_atomically():
    engine = lab.GovernanceEngine()
    engine.create_exception(lab.valid_exception())
    receipt = engine.offboard(lab.CLAIMS_AGENT, "offboard:1042")
    assert engine.agents[lab.CLAIMS_AGENT].status == "retired"
    assert not any(
        e.principal_id == lab.CLAIMS_AGENT for e in engine.entitlements.values()
    )
    assert all(
        not d.active
        for d in engine.delegations.values()
        if d.delegator == lab.CLAIMS_AGENT or d.delegatee == lab.CLAIMS_AGENT
    )
    assert engine.exceptions["exc:bulk-export"].revoked
    assert "mcp_registration" in receipt["surfaces"]


def test_offboarding_retry_reconciles_and_operation_id_is_bound_to_agent():
    engine = lab.GovernanceEngine()
    engine.offboard(lab.CLAIMS_AGENT, "offboard:1042")
    assert engine.offboard(lab.CLAIMS_AGENT, "offboard:1042")["reconciled"] is True
    with pytest.raises(lab.GovernanceError, match="operation_id_conflict"):
        engine.offboard(lab.RESEARCH_AGENT, "offboard:1042")


def test_unknown_agent_cannot_be_offboarded():
    with pytest.raises(lab.GovernanceError, match="agent_unknown"):
        lab.GovernanceEngine().offboard("agent:unknown", "offboard:unknown")


def test_sample_inventory_conforms_to_draft_2020_12_schema():
    schema = json.loads(
        (LAB_PATH.parent / "schemas" / "governance_schema.json").read_text()
    )
    instance = json.loads((LAB_PATH.parent / "data" / "sample_data.json").read_text())
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(instance)


def test_cedar_runtime_policy_parses_and_validates_against_schema():
    policy_dir = LAB_PATH.parent / "policies" / "cedar"
    policies = (policy_dir / "governance.cedar").read_text()
    schema = json.loads((policy_dir / "schema.json").read_text())
    assert len(cedarpy.PolicySet.from_str(policies)) == 3
    result = cedarpy.validate_policies(policies, schema)
    assert result.validation_passed, result.errors
