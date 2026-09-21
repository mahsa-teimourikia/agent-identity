"""Course 04 invariant tests for agent authorization."""

from dataclasses import replace
from datetime import timedelta
import importlib.util
from pathlib import Path
import sys

import pytest


LAB_PATH = Path(__file__).parents[1] / "lab.py"
SPEC = importlib.util.spec_from_file_location("course04_lab", LAB_PATH)
lab = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = lab
SPEC.loader.exec_module(lab)


def controlled_rows():
    return lab.evaluate(lab.build_cases(), lab.hardened_factory)[1]


def row_map():
    rows = {}
    for case_id, expected, result in controlled_rows():
        rows.setdefault(case_id, []).append((expected, result))
    return rows


def test_all_labelled_outcomes_match_and_only_allow_executes():
    for _, expected, result in controlled_rows():
        assert result.decision.outcome is expected
        assert (result.execution is not None) is (expected is lab.Outcome.ALLOW)


def test_model_proposal_contains_no_identity_or_authority_fields():
    proposal_fields = set(lab.RefundProposal.__dataclass_fields__)

    assert not proposal_fields.intersection(
        {"requester_id", "actor_id", "workload_id", "tenant_id", "roles"}
    )


def test_workload_actor_and_tenant_are_independently_bound():
    rows = row_map()

    assert rows["wrong_workload"][0][1].decision.reason_code == "workload_not_bound"
    assert rows["wrong_actor"][0][1].decision.reason_code == "workload_not_bound"
    assert (
        rows["presented_tenant_substitution"][0][1].decision.reason_code
        == "workload_not_bound"
    )


def test_resource_tenant_and_lifecycle_come_from_authoritative_records():
    rows = row_map()

    assert rows["cross_tenant_resource"][0][1].decision.reason_code == "tenant_mismatch"
    assert rows["closed_order"][0][1].decision.reason_code == "resource_not_refundable"


def test_task_grant_enforces_expiry_resource_action_and_amount():
    rows = row_map()

    assert rows["expired_delegation"][0][1].decision.reason_code == "delegation_expired"
    assert rows["missing_delegation"][0][1].decision.reason_code == "delegation_missing"
    assert rows["unauthorized_action"][0][1].decision.reason_code == "invalid_request"
    assert rows["amount_escalation"][0][1].decision.reason_code == "amount_exceeds_authority"


def test_high_value_refund_returns_an_obligation_not_a_boolean_allow():
    result = row_map()["approval_required"][0][1]

    assert result.decision.outcome is lab.Outcome.REQUIRE_APPROVAL
    assert result.decision.obligations == ("obtain_bound_manager_approval",)
    assert result.execution is None


def test_approval_is_bound_to_exact_proposal_and_is_single_use():
    rows = row_map()

    assert rows["altered_after_approval"][0][1].decision.reason_code == "approval_invalid"
    replay = [result for _, result in rows["replayed_approval"]]
    assert [result.decision.outcome for result in replay] == [
        lab.Outcome.ALLOW,
        lab.Outcome.DENY,
    ]
    assert replay[1].decision.reason_code == "approval_replayed"


def test_separation_of_duties_and_expiry_are_enforced_for_approval():
    case = next(c for c in lab.build_cases() if c.case_id == "valid_approved_refund")
    same_party = lab.issue_approval(
        case.proposal,
        approval_id="approval:same-party",
        approver_id="user:alice",
        approver_role="refund_manager",
    )
    expired = lab.issue_approval(
        case.proposal,
        approval_id="approval:expired",
        expires_at=lab.NOW - timedelta(seconds=1),
    )

    for receipt in (same_party, expired):
        result = lab.RefundGateway(lab.RefundPDP()).submit(
            case.context, case.proposal, approval=receipt
        )
        assert result.decision.reason_code == "approval_invalid"
        assert result.execution is None


def test_pdp_outage_fails_closed_at_the_gateway():
    result = row_map()["pdp_outage"][0][1]

    assert result.decision.outcome is lab.Outcome.DENY
    assert result.decision.reason_code == "pdp_unavailable"
    assert result.execution is None


def test_delegation_attenuation_rejects_every_widening_dimension():
    parent = replace(
        lab.build_policy_data()[3]["task:refund-928"],
        redelegation_allowed=True,
    )
    valid = lab.attenuate(
        parent,
        grant_id="grant:child",
        delegate_actor_id="agent:refund-child",
        workload_id="spiffe://corp.example/ns/research/sa/research-prod",
        actions=frozenset({"order:read"}),
        resources=frozenset({"order:north:123"}),
        max_amount_cents=10_000,
        expires_at=parent.expires_at - timedelta(minutes=1),
    )
    assert valid.actions < parent.actions
    assert valid.max_amount_cents < parent.max_amount_cents
    assert not valid.redelegation_allowed

    variants = [
        {"actions": frozenset({"order:delete"})},
        {"resources": frozenset({"order:south:999"})},
        {"max_amount_cents": parent.max_amount_cents + 1},
        {"expires_at": parent.expires_at + timedelta(seconds=1)},
    ]
    base = {
        "grant_id": "grant:bad-child",
        "delegate_actor_id": "agent:refund-child",
        "workload_id": "spiffe://corp.example/ns/research/sa/research-prod",
        "actions": frozenset({"order:read"}),
        "resources": frozenset({"order:north:123"}),
        "max_amount_cents": 10_000,
        "expires_at": parent.expires_at - timedelta(minutes=1),
    }
    for changes in variants:
        with pytest.raises(ValueError):
            lab.attenuate(parent, **(base | changes))


def test_authorization_happens_before_retrieval_and_filters_exact_resources():
    case = lab.build_cases()[0]
    documents = lab.authorized_order_context(
        case.context,
        case.proposal.task_id,
        ["order:north:123", "order:south:999"],
    )

    assert [order.order_id for order in documents] == ["order:north:123"]
    assert lab.authorized_order_context(
        replace(case.context, tenant_id="tenant:south"),
        case.proposal.task_id,
        ["order:north:123"],
    ) == []


def test_common_policy_engine_mappings_preserve_the_same_trusted_tuple():
    case = lab.build_cases()[0]
    mappings = lab.policy_engine_inputs(case.context, case.proposal)

    assert mappings["opa"]["input"]["principal"] == case.context.actor_id
    assert mappings["cedar"]["resource"] == case.proposal.resource_id
    assert mappings["openfga"]["checks"][0]["user"] == case.proposal.task_id


def test_baseline_and_hardened_metrics_have_explicit_populations():
    cases = lab.build_cases()
    baseline, _ = lab.evaluate(cases, lab.baseline_factory)
    hardened, _ = lab.evaluate(cases, lab.hardened_factory)

    assert baseline.attempts == hardened.attempts == 17
    assert baseline.expected_executable_attempts == 3
    assert baseline.expected_blocked_attempts == 14
    assert baseline.valid_execution_rate == 1.0
    assert baseline.invalid_execution_rate == 12 / 14
    assert hardened.valid_execution_rate == 1.0
    assert hardened.invalid_execution_rate == 0.0
    assert hardened.invalid_block_rate == 1.0
    assert hardened.evidence_completeness_rate == 1.0
    assert lab.release_gate(hardened)


def test_decision_evidence_contains_digests_and_no_approval_object():
    for _, _, result in controlled_rows():
        assert result.decision.evidence_complete
        assert result.decision.proposal_digest.startswith("sha256:")
        assert "ApprovalReceipt(" not in repr(result.decision)
