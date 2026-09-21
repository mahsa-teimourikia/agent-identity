"""Course 02 invariant tests for multi-hop identity provenance."""

from dataclasses import replace
import importlib.util
from pathlib import Path
import sys


LAB_PATH = Path(__file__).parents[1] / "lab.py"
SPEC = importlib.util.spec_from_file_location("course02_lab", LAB_PATH)
lab = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = lab
SPEC.loader.exec_module(lab)


def test_valid_multihop_path_preserves_each_identity_class():
    case = lab.build_cases()[0]
    decision = lab.provenance_bound_gate(case, lab.build_registry())

    assert decision.allowed
    assert decision.validated_requester == "user:alice"
    assert decision.validated_application == "client:travel-portal"
    assert decision.validated_actor == "agent:booking-specialist"
    assert decision.validated_workload == "spiffe://corp.example/prod/booking-specialist"
    assert decision.validated_service == "service:booking-api"
    assert decision.validated_resource == "trip:483"
    assert decision.validated_actor_chain == (
        "agent:travel-planner",
        "agent:booking-specialist",
    )
    assert len(decision.delegation_ids) == 2


def test_all_labelled_cases_match_expected_results_and_reasons():
    cases = lab.build_cases()
    expected_reasons = {
        "valid_multihop_booking": "identity_provenance_valid",
        "spoofed_logical_agent": "deployment_binding_mismatch",
        "development_runtime": "nonproduction_workload",
        "application_identity_collision": "deployment_binding_mismatch",
        "unknown_requester": "invalid_requester",
        "cross_tenant_context": "tenant_mismatch",
        "missing_parent_actor": "parent_actor_mismatch",
        "cyclic_actor_chain": "actor_chain_invalid",
        "task_substitution": "delegation_path_invalid",
        "disabled_workload": "invalid_workload",
    }

    for case in cases:
        decision = lab.provenance_bound_gate(case, lab.build_registry())
        assert decision.allowed is case.expected_allow
        assert decision.reason_code == expected_reasons[case.case_id]


def test_logical_agent_label_cannot_override_authenticated_workload():
    spoofed = next(case for case in lab.build_cases() if case.case_id == "spoofed_logical_agent")

    baseline = lab.collapsed_platform_baseline(spoofed, lab.build_registry())
    controlled = lab.provenance_bound_gate(spoofed, lab.build_registry())

    assert baseline.allowed
    assert not controlled.allowed
    assert controlled.reason_code == "deployment_binding_mismatch"


def test_application_identity_is_part_of_the_deployment_binding():
    case = lab.build_cases()[0]
    collision = replace(
        case,
        envelope=replace(case.envelope, application_id="client:shared-agent-platform"),
        expected_allow=False,
    )

    decision = lab.provenance_bound_gate(collision, lab.build_registry())

    assert not decision.allowed
    assert decision.reason_code == "deployment_binding_mismatch"


def test_delegation_path_is_task_bound_and_cannot_skip_parent():
    valid = lab.build_cases()[0]
    wrong_task = replace(valid, envelope=replace(valid.envelope, task_id="trip:999"), expected_allow=False)
    missing_parent = replace(valid, envelope=replace(valid.envelope, parent_actor_id=None), expected_allow=False)

    assert lab.provenance_bound_gate(wrong_task, lab.build_registry()).reason_code == "delegation_path_invalid"
    assert lab.provenance_bound_gate(missing_parent, lab.build_registry()).reason_code == "parent_actor_mismatch"


def test_disabled_or_nonproduction_workload_fails_closed():
    cases = {case.case_id: case for case in lab.build_cases()}

    disabled = lab.provenance_bound_gate(cases["disabled_workload"], lab.build_registry())
    development = lab.provenance_bound_gate(cases["development_runtime"], lab.build_registry())

    assert (disabled.allowed, disabled.reason_code) == (False, "invalid_workload")
    assert (development.allowed, development.reason_code) == (False, "nonproduction_workload")


def test_denial_does_not_promote_presented_names_to_validated_identity():
    spoofed = next(case for case in lab.build_cases() if case.case_id == "spoofed_logical_agent")
    decision = lab.provenance_bound_gate(spoofed, lab.build_registry())

    assert decision.presented_actor == "agent:booking-specialist"
    assert decision.validated_actor is None
    assert decision.validated_requester is None
    assert decision.validated_workload is None


def test_baseline_and_control_metrics_use_disjoint_populations():
    registry = lab.build_registry()
    cases = lab.build_cases()
    baseline, _ = lab.evaluate(cases, lab.collapsed_platform_baseline, registry)
    controlled, _ = lab.evaluate(cases, lab.provenance_bound_gate, registry)

    assert baseline.valid_cases == 1
    assert baseline.invalid_cases == 9
    assert baseline.valid_task_success_rate == 1.0
    assert baseline.unauthorized_success_rate == 1.0
    assert baseline.invalid_identity_collision_rate == 1.0
    assert controlled.valid_task_success_rate == 1.0
    assert controlled.unauthorized_success_rate == 0.0
    assert controlled.invalid_block_rate == 1.0
    assert controlled.valid_provenance_completeness_rate == 1.0
    assert controlled.invalid_identity_collision_rate == 0.0
