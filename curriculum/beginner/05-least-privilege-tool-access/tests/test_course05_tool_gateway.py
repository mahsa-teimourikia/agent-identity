"""Course 05 invariant tests for least-privilege tool access."""

from dataclasses import replace
import importlib.util
from pathlib import Path
import sys


LAB_PATH = Path(__file__).parents[1] / "lab.py"
SPEC = importlib.util.spec_from_file_location("course05_lab", LAB_PATH)
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


def test_all_labelled_outcomes_match():
    for _, expected, result in controlled_rows():
        assert result.decision.outcome is expected


def test_model_request_contains_no_identity_role_or_credential_fields():
    fields = set(lab.ToolRequest.__dataclass_fields__)

    assert not fields.intersection(
        {
            "requester_id",
            "actor_id",
            "workload_id",
            "tenant_id",
            "roles",
            "credential",
            "credential_profile",
        }
    )


def test_discovery_minimizes_tools_but_execution_rechecks():
    case = lab.build_cases()[0]
    grant = lab.build_policy_data()[3][case.request.task_id]

    assert lab.visible_tools(case.context, grant) == [
        "book_flight",
        "search_flights",
        "send_itinerary",
    ]
    rows = row_map()
    assert rows["direct_cancel_call"][0][1].decision.reason_code == "tool_not_permitted"
    assert rows["shell_call"][0][1].decision.reason_code == "tool_not_permitted"


def test_strict_schema_rejects_model_supplied_egress_field():
    result = row_map()["argument_injection"][0][1]

    assert result.decision.reason_code == "arguments_invalid"
    assert not result.effect_committed


def test_workload_and_resource_authority_come_from_trusted_records():
    rows = row_map()

    assert rows["wrong_workload"][0][1].decision.reason_code == "task_grant_subject_mismatch"
    assert rows["cross_tenant_resource"][0][1].decision.reason_code == "resource_not_authorized"


def test_argument_policy_enforces_price_airline_and_recipient_domain():
    rows = row_map()

    assert rows["price_escalation"][0][1].decision.reason_code == "price_exceeds_authority"
    assert rows["unapproved_airline"][0][1].decision.reason_code == "airline_not_authorized"
    assert rows["external_recipient"][0][1].decision.reason_code == "recipient_not_authorized"


def test_high_risk_tool_requires_exact_bound_approval():
    rows = row_map()

    challenge = rows["approval_required"][0][1]
    altered = rows["altered_after_approval"][0][1]
    assert challenge.decision.outcome is lab.Outcome.APPROVAL_REQUIRED
    assert challenge.decision.obligations == ("obtain_bound_travel_approval",)
    assert altered.decision.reason_code == "approval_invalid"


def test_approval_is_consumed_once_while_exact_retry_reconciles():
    case = next(c for c in lab.build_cases() if c.case_id == "valid_booking")
    service = lab.TravelServiceSimulator()
    gateway = lab.ToolGateway(service=service)

    first = gateway.invoke(case.context, case.request, approval=case.approval)
    retry = gateway.invoke(case.context, case.request, approval=case.approval, attempt=2)

    assert first.decision.reason_code == "tool_execution_verified"
    assert retry.decision.reason_code == "operation_reconciled"
    assert first.execution == retry.execution
    assert first.effect_committed
    assert not retry.effect_committed
    assert service.effect_count == 1
    assert gateway.approvals.was_consumed(case.approval.approval_id)


def test_unknown_outcome_is_reconciled_before_retrying_effect():
    case = next(
        c for c in lab.build_cases() if c.case_id == "unknown_outcome_reconciled"
    )
    service = lab.TravelServiceSimulator(lab.ServiceMode.UNKNOWN_ONCE)
    gateway = lab.ToolGateway(service=service)

    first = gateway.invoke(case.context, case.request, approval=case.approval)
    second = gateway.invoke(case.context, case.request, approval=case.approval, attempt=2)

    assert first.decision.outcome is lab.Outcome.UNKNOWN
    assert first.effect_committed
    assert second.decision.outcome is lab.Outcome.EXECUTED
    assert second.decision.reason_code == "operation_reconciled"
    assert not second.effect_committed
    assert service.effect_count == 1


def test_changed_request_cannot_reuse_operation_id():
    results = [result for _, result in row_map()["idempotency_conflict"]]

    assert results[0].decision.outcome is lab.Outcome.EXECUTED
    assert results[1].decision.reason_code == "idempotency_conflict"
    assert not results[1].effect_committed


def test_budget_counts_only_authorized_dispatches_and_fails_closed():
    case = lab.build_cases()[0]
    gateway = lab.ToolGateway()
    invalid = replace(
        case.request,
        operation_id="operation:invalid-before-budget",
        arguments={**case.request.arguments, "callback_url": "https://attacker.example"},
    )
    assert gateway.invoke(case.context, invalid).decision.reason_code == "arguments_invalid"
    assert gateway.budgets.used(case.request.task_id, case.request.tool_name) == 0

    outcomes = []
    for number in range(3):
        request = replace(case.request, operation_id=f"operation:budget-test-{number}")
        outcomes.append(gateway.invoke(case.context, request).decision.outcome)
    assert outcomes == [lab.Outcome.EXECUTED, lab.Outcome.EXECUTED, lab.Outcome.DENIED]


def test_exhausted_budget_does_not_consume_approval():
    case = next(c for c in lab.build_cases() if c.case_id == "valid_booking")
    gateway = lab.ToolGateway()
    limit = lab.build_policy_data()[3][case.request.task_id].call_limits["book_flight"]
    assert gateway.budgets.consume(case.request.task_id, "book_flight", limit)

    result = gateway.invoke(case.context, case.request, approval=case.approval)

    assert result.decision.reason_code == "call_budget_exhausted"
    assert not gateway.approvals.was_consumed(case.approval.approval_id)
    assert not result.effect_committed


def test_credential_broker_exposes_metadata_not_a_secret():
    spec = lab.build_catalog()["book_flight"]
    lease = lab.CredentialBroker().issue(spec, "operation:lease")

    assert lease is not None
    assert lease.profile == "travel-book-limited"
    assert lease.audience == "https://booking.api.corp.example"
    assert lease.scopes == frozenset({"bookings:create"})
    assert "token" not in set(lab.CredentialLease.__dataclass_fields__)
    assert "secret" not in set(lab.CredentialLease.__dataclass_fields__)


def test_fixed_egress_is_independent_of_model_arguments():
    case = next(c for c in lab.build_cases() if c.case_id == "valid_booking")
    grant = lab.build_policy_data()[3][case.request.task_id]
    restricted = replace(
        grant,
        allowed_egress_hosts=grant.allowed_egress_hosts
        - {"booking.api.corp.example"},
    )
    result = lab.ToolGateway().invoke(
        case.context, case.request, approval=case.approval, grant=restricted
    )

    assert result.decision.reason_code == "egress_not_permitted"
    assert not result.effect_committed


def test_mcp_mapping_exposes_only_authorized_typed_tools():
    case = lab.build_cases()[0]
    grant = lab.build_policy_data()[3][case.request.task_id]
    definitions = lab.mcp_tool_definitions(case.context, grant)

    assert [item["name"] for item in definitions] == [
        "book_flight",
        "search_flights",
        "send_itinerary",
    ]
    booking = next(item for item in definitions if item["name"] == "book_flight")
    assert booking["inputSchema"]["additionalProperties"] is False
    assert booking["annotations"]["openWorldHint"] is True
    assert booking["annotations"]["readOnlyHint"] is False


def test_untrusted_tool_result_is_validated_before_promotion():
    rows = row_map()
    result = rows["malformed_tool_result"][0][1]
    mismatch = rows["mismatched_tool_result"][0][1]

    assert result.decision.reason_code == "tool_result_invalid"
    assert result.output is None
    assert not result.effect_committed
    assert mismatch.decision.reason_code == "tool_result_mismatch"
    assert mismatch.output is None
    assert not mismatch.effect_committed


def test_policy_outage_and_task_lifecycle_fail_closed():
    rows = row_map()

    assert rows["policy_outage"][0][1].decision.reason_code == "policy_unavailable"
    assert rows["expired_task"][0][1].decision.reason_code == "task_grant_inactive"
    assert rows["cancelled_task"][0][1].decision.reason_code == "task_grant_inactive"


def test_baseline_and_hardened_metrics_use_explicit_populations():
    cases = lab.build_cases()
    baseline, _ = lab.evaluate(cases, lab.baseline_factory)
    hardened, _ = lab.evaluate(cases, lab.hardened_factory)

    assert baseline.attempts == hardened.attempts == 24
    assert hardened.expected_terminal_successes == 6
    assert hardened.expected_blocked_or_challenged == 17
    assert hardened.expected_unknown_outcomes == 1
    assert baseline.terminal_success_rate == 1.0
    assert baseline.invalid_dispatch_rate == 1.0
    assert baseline.forbidden_effect_rate == 8 / 17
    assert hardened.outcome_match_rate == 1.0
    assert hardened.terminal_success_rate == 1.0
    assert hardened.invalid_dispatch_rate == 0.0
    assert hardened.forbidden_effect_rate == 0.0
    assert hardened.duplicate_effect_rate == 0.0
    assert hardened.evidence_completeness_rate == 1.0
    assert lab.release_gate(hardened)


def test_decision_evidence_contains_digests_not_arguments_or_leases():
    for _, _, result in controlled_rows():
        assert result.decision.evidence_complete
        assert result.decision.request_digest.startswith("sha256:")
        rendered = repr(result.decision)
        assert "CredentialLease(" not in rendered
        assert "callback_url" not in rendered
        assert "attacker.example" not in rendered
