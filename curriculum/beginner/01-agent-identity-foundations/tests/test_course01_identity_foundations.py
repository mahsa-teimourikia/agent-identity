"""Course 01 invariant tests for the evidence-bound procurement boundary."""
from __future__ import annotations

import runpy
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace


LAB_PATH = Path(__file__).resolve().parents[1] / "lab.py"
lab = SimpleNamespace(**runpy.run_path(str(LAB_PATH), run_name="course01_tests"))


def test_valid_purchase_preserves_distinct_identities() -> None:
    case = lab.build_cases()[0]
    decision = lab.evidence_bound_gate(case, lab.build_registry())

    assert decision.allowed
    assert decision.authenticated_workload == "spiffe://example.com/prod/procurement"
    assert decision.validated_actor == "agent:procurement"
    assert decision.validated_requester == "user:alice"
    assert "logical_agent_bound_to_workload" in decision.checks


def test_declared_agent_name_cannot_override_workload_binding() -> None:
    case = lab.build_cases()[1]

    baseline = lab.declared_agent_baseline(case, lab.build_registry(), lab.NOW)
    secure = lab.evidence_bound_gate(case, lab.build_registry())

    assert baseline.allowed
    assert not secure.allowed
    assert secure.reason_code == "agent_workload_binding_mismatch"
    assert secure.authenticated_workload == "spiffe://example.com/prod/research"
    assert secure.validated_requester is None


def test_every_labelled_boundary_matches_expected_result() -> None:
    for case in lab.build_cases():
        decision = lab.evidence_bound_gate(case, lab.build_registry())
        assert decision.allowed is case.expected_allow, case.case_id
        assert decision.reason_code == case.expected_reason, case.case_id


def test_resource_tenant_is_not_selected_by_the_model() -> None:
    case = next(case for case in lab.build_cases() if case.case_id == "cross_tenant_resource")
    assert case.resource.tenant == "tenant:partner"

    decision = lab.evidence_bound_gate(case, lab.build_registry())

    assert not decision.allowed
    assert decision.reason_code == "tenant_mismatch"


def test_delegation_cannot_widen_amount_or_lifetime() -> None:
    cases = {case.case_id: case for case in lab.build_cases()}

    amount = lab.evidence_bound_gate(cases["amount_escalation"], lab.build_registry())
    expired = lab.evidence_bound_gate(cases["expired_grant"], lab.build_registry())

    assert (amount.allowed, amount.reason_code) == (False, "amount_exceeds_grant")
    assert (expired.allowed, expired.reason_code) == (False, "grant_not_current")


def test_unknown_requester_is_not_promoted_to_validated_identity() -> None:
    case = next(case for case in lab.build_cases() if case.case_id == "unknown_requester")
    decision = lab.evidence_bound_gate(case, lab.build_registry())

    assert not decision.allowed
    assert decision.reason_code == "invalid_requester"
    assert decision.validated_requester is None


def test_unregistered_workload_fails_closed() -> None:
    valid = lab.build_cases()[0]
    unknown = replace(
        valid,
        context=replace(valid.context, workload_id="spiffe://example.com/prod/unknown"),
        evidence=replace(valid.evidence, workload_id="spiffe://example.com/prod/unknown"),
        expected_allow=False,
        expected_reason="unregistered_workload",
    )

    decision = lab.evidence_bound_gate(unknown, lab.build_registry())

    assert not decision.allowed
    assert decision.reason_code == "unregistered_workload"


def test_control_reduces_unauthorized_success_without_blocking_valid_work() -> None:
    registry = lab.build_registry()
    cases = lab.build_cases()
    baseline, _ = lab.evaluate(cases, lab.declared_agent_baseline, registry)
    secure, _ = lab.evaluate(cases, lab.evidence_bound_gate, registry)

    assert baseline.valid_task_success_rate == 1.0
    assert baseline.unauthorized_success_rate == 1.0
    assert baseline.evidence_completeness_rate == 0.0
    assert secure.valid_task_success_rate == 1.0
    assert secure.unauthorized_success_rate == 0.0
    assert secure.invalid_block_rate == 1.0
    assert secure.evidence_completeness_rate == 1.0
