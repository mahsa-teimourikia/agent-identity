"""Invariant tests for Intermediate 04 fine-grained authorization."""

from dataclasses import replace
import importlib.util
from pathlib import Path
import sys
from threading import Thread

import pytest


LAB_PATH = Path(__file__).parents[1] / "lab.py"
SPEC = importlib.util.spec_from_file_location("intermediate04_lab", LAB_PATH)
lab = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = lab
SPEC.loader.exec_module(lab)


def test_hardened_matrix_matches_all_labels_and_release_gate():
    metrics, rows = lab.evaluate(lab.build_cases())
    assert len(rows) == 33
    assert metrics.expected_allowed == 4
    assert metrics.expected_blocked == 29
    assert metrics.invalid_acceptances == 0
    assert metrics.valid_work_blocked == 0
    assert metrics.outcome_matches == 33
    assert lab.release_gate(metrics)


def test_scope_only_baseline_exposes_invalid_acceptances():
    metrics, _ = lab.evaluate(lab.build_cases(), hardened=False)
    assert metrics.invalid_acceptances == 28
    assert metrics.valid_work_blocked == 0
    assert not lab.release_gate(metrics)


@pytest.mark.parametrize("case", lab.build_cases(), ids=lambda case: case.case_id)
def test_every_case_matches_its_label(case):
    actual, _ = lab.run_case(case)
    assert actual is case.expected_allowed


def test_agent_proposal_cannot_supply_identity_or_authority():
    assert set(lab.ActionProposal.__dataclass_fields__).isdisjoint(
        {"subject_id", "agent_id", "workload_id", "tenant_id", "scopes", "approval_valid"}
    )


def test_authzen_request_is_sarc_shaped_and_derived_from_trusted_state():
    request = lab.authzen_request(lab.environment("claim.update"))
    assert set(request) == {"subject", "action", "resource", "context"}
    assert request["subject"]["id"] == lab.AGENT
    assert request["resource"]["id"] == lab.CLAIM
    assert request["action"]["name"] == "claim.update"


def test_cedar_policy_validates_and_matches_reference_cases():
    rows = lab.parity_rows(lab.build_cases())
    assert len(rows) == 30
    assert all(row["parity"] for row in rows)


def test_openfga_sdk_request_contains_task_intersection_tuples():
    request = lab.openfga_check(lab.environment())
    assert request.user == lab.AGENT
    assert request.relation == "can_read"
    assert request.object == lab.CLAIM
    tuples = {(item.user, item.relation, item.object) for item in request.contextual_tuples}
    assert (lab.AGENT, "assignee", lab.TASK) in tuples
    assert (lab.AGENT, "delegated_agent", lab.TASK) in tuples
    assert (lab.TASK, "assigned_task", lab.CLAIM) in tuples


def test_opa_input_has_trusted_facts_but_no_raw_credentials():
    document = lab.opa_input(lab.environment("payment.create"))
    serialized = str(document)
    assert document["approval_valid"] is True
    assert document["proposal"]["resource_id"] == lab.CLAIM
    assert "token" not in serialized.lower()
    assert "password" not in serialized.lower()


def test_exact_retry_reconciles_and_changed_request_conflicts():
    authz = lab.environment("claim.update")
    pep = lab.PolicyEnforcementPoint(lab.ReferencePDP())
    first = pep.execute(authz)
    assert pep.execute(authz) == first
    changed = replace(authz, proposal=replace(authz.proposal, resource_id=lab.OTHER_CLAIM))
    with pytest.raises(lab.AuthorizationError, match="operation_id_conflict"):
        pep.execute(changed)


def test_approval_is_atomically_single_use_across_operations():
    authz = lab.environment("payment.create")
    store = lab.ApprovalStore()
    outcomes = []

    def consume():
        try:
            store.consume(authz.approval)
            outcomes.append("ok")
        except lab.AuthorizationError as exc:
            outcomes.append(exc.reason_code)

    threads = [Thread(target=consume), Thread(target=consume)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sorted(outcomes) == ["approval_replayed", "ok"]


def test_changed_proposal_invalidates_approval():
    authz = lab.environment("payment.create")
    changed = replace(authz, proposal=replace(authz.proposal, amount_cents=30_000))
    decision = lab.ReferencePDP().evaluate(changed)
    assert not decision.allowed
    assert "approval_proposal_digest_mismatch" in decision.reason_codes


def test_unsupported_obligation_fails_closed_before_execution():
    authz = lab.environment("claim.read")
    pep = lab.PolicyEnforcementPoint(lab._UnknownObligationPDP())
    with pytest.raises(lab.AuthorizationError, match="obligation_unsupported"):
        pep.execute(authz)
    assert pep.evidence[-1]["outcome"] == "not_executed"
    assert pep.evidence[-1]["reason_codes"] == ["obligation_unsupported"]


def test_pdp_dependency_failure_is_recorded_without_execution():
    pep = lab.PolicyEnforcementPoint(lab._UnavailablePDP())
    with pytest.raises(lab.AuthorizationError, match="pdp_unavailable"):
        pep.execute(lab.environment("claim.read"))
    assert pep.evidence[-1]["allowed"] is False
    assert pep.evidence[-1]["outcome"] == "not_executed"


def test_decision_evidence_is_digest_based_and_excludes_approval_contents():
    authz = lab.environment("payment.create")
    pep = lab.PolicyEnforcementPoint(lab.ReferencePDP())
    pep.execute(authz)
    evidence = pep.evidence[-1]
    assert evidence["outcome"] == "executed"
    assert len(evidence["input_digest"]) == 64
    serialized = str(evidence)
    assert authz.approval.approver_id not in serialized
    assert authz.approval.receipt_id not in serialized


def test_pdp_decides_but_does_not_consume_approval():
    authz = lab.environment("payment.create")
    pdp = lab.ReferencePDP()
    assert pdp.evaluate(authz).allowed
    assert pdp.evaluate(authz).allowed


def test_opa_client_adapter_constructs_without_network_call():
    assert type(lab.opa_client()).__name__ == "OpaClient"
