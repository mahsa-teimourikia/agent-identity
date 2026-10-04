"""Executable invariants for Intermediate 10 authorization observability."""

import importlib.util
import json
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

LAB_PATH = Path(__file__).parents[1] / "lab.py"
SPEC = importlib.util.spec_from_file_location("intermediate10_lab", LAB_PATH)
lab = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = lab
SPEC.loader.exec_module(lab)


def ingest(pipeline, event):
    return pipeline.ingest_decision(event, pipeline.authority.sign(event))


def record(pipeline, receipt):
    return pipeline.record_execution(receipt, pipeline.authority.sign(receipt))


def test_course_fixture_meets_every_release_gate_with_explicit_denominators():
    pipeline, operations, _, _ = lab.course_fixture()
    metrics = pipeline.metrics(operations)
    assert metrics.protected_operations == 8
    assert metrics.operations_with_decision == 8
    assert metrics.decision_coverage == 1.0
    assert metrics.expected_executions == 4
    assert metrics.compliant_executions == 4
    assert metrics.valid_work_execution_rate == 1.0
    assert metrics.actual_forbidden_executions == 0
    assert lab.release_gate(metrics)


def test_baseline_findings_separate_operational_signals_from_actual_violations():
    pipeline, _, _, _ = lab.course_fixture()
    findings = pipeline.findings()
    assert {finding.code for finding in findings} == {
        "HIGH_RISK_ALLOW",
        "POLICY_EVALUATION_ERROR",
    }
    assert not any(finding.actual_violation for finding in findings)


def test_pseudonyms_are_stable_scoped_and_do_not_expose_raw_identity():
    first = lab.pseudonym("user:alice")
    assert first == lab.pseudonym("user:alice")
    assert first != lab.pseudonym("user:bob")
    assert "alice" not in first
    assert len(first) == 28


def test_request_digest_binds_every_consequential_input():
    base = lab.request_digest(
        "op:1", lab.TENANT, "agent:claims", "claim.update", "claim:483", {"note": "a"}
    )
    variants = [
        lab.request_digest(
            "op:2",
            lab.TENANT,
            "agent:claims",
            "claim.update",
            "claim:483",
            {"note": "a"},
        ),
        lab.request_digest(
            "op:1",
            "tenant:evil",
            "agent:claims",
            "claim.update",
            "claim:483",
            {"note": "a"},
        ),
        lab.request_digest(
            "op:1", lab.TENANT, "agent:evil", "claim.update", "claim:483", {"note": "a"}
        ),
        lab.request_digest(
            "op:1",
            lab.TENANT,
            "agent:claims",
            "claim.delete",
            "claim:483",
            {"note": "a"},
        ),
        lab.request_digest(
            "op:1",
            lab.TENANT,
            "agent:claims",
            "claim.update",
            "claim:999",
            {"note": "a"},
        ),
        lab.request_digest(
            "op:1",
            lab.TENANT,
            "agent:claims",
            "claim.update",
            "claim:483",
            {"note": "b"},
        ),
    ]
    assert all(value != base for value in variants)


@pytest.mark.parametrize(
    "change,reason",
    [
        ({"schema_version": "0.9"}, "event_contract_invalid"),
        ({"event_type": "agent.message"}, "event_contract_invalid"),
        ({"emitted_by": "service:untrusted"}, "event_contract_invalid"),
        ({"trace_id": "0" * 32}, "trace_context_invalid"),
        ({"span_id": "ABC"}, "trace_context_invalid"),
        ({"producer_sequence": 0}, "event_freshness_invalid"),
        ({"attempt": 0}, "event_freshness_invalid"),
        ({"observed_at": lab.NOW - 1}, "event_freshness_invalid"),
        ({"observed_at": lab.NOW + 301}, "event_freshness_invalid"),
        ({"valid_until": lab.NOW + 301}, "event_freshness_invalid"),
        ({"latency_ms": -1}, "event_freshness_invalid"),
        ({"decision_id": ""}, "event_field_invalid"),
        ({"action": "secret-token"}, "sensitive_data_present"),
    ],
)
def test_event_admission_rejects_invalid_untrusted_or_sensitive_data(change, reason):
    pipeline = lab.AuditPipeline()
    event = replace(lab.make_event(), **change)
    with pytest.raises(lab.AuditError, match=reason):
        ingest(pipeline, event)


def test_event_admission_rejects_cross_tenant_evidence():
    pipeline = lab.AuditPipeline()
    event = lab.make_event(tenant_id="tenant:evil")
    with pytest.raises(lab.AuditError, match="event_tenant_invalid"):
        ingest(pipeline, event)


def test_allow_requires_determining_policy_provenance():
    pipeline = lab.AuditPipeline()
    event = lab.make_event(determining_policy_ids=())
    with pytest.raises(lab.AuditError, match="allow_provenance_missing"):
        ingest(pipeline, event)


@pytest.mark.parametrize(
    "outcome,reason",
    [
        (lab.Decision.ALLOW, "ALLOW_ERROR"),
        (lab.Decision.DENY, "DENY_TASK_SCOPE"),
    ],
)
def test_policy_evaluation_errors_have_fail_closed_reason_semantics(outcome, reason):
    pipeline = lab.AuditPipeline()
    event = lab.make_event(
        outcome=outcome,
        reason_code=reason,
        evaluation_error_codes=("policy:error",),
    )
    with pytest.raises(lab.AuditError, match="evaluation_error_semantics_invalid"):
        ingest(pipeline, event)


def test_producer_signature_authenticates_exact_event():
    pipeline = lab.AuditPipeline()
    event = lab.make_event()
    signature = pipeline.authority.sign(event)
    pipeline.ingest_decision(event, signature)
    changed = replace(event, action="claim.delete")
    with pytest.raises(lab.AuditError, match="producer_signature_invalid"):
        pipeline.ingest_decision(changed, signature)


def test_malformed_signature_fails_closed():
    with pytest.raises(lab.AuditError, match="producer_signature_invalid"):
        lab.AuditPipeline().ingest_decision(lab.make_event(), "not-hex")


def test_exact_decision_redelivery_reconciles_without_new_ledger_entry():
    pipeline = lab.AuditPipeline()
    event = lab.make_event()
    signature = pipeline.authority.sign(event)
    assert pipeline.ingest_decision(event, signature) == "accepted"
    assert pipeline.ingest_decision(event, signature) == "reconciled"
    assert len(pipeline.ledger) == 1
    assert pipeline.reconciled_duplicates == 1


def test_changed_decision_retry_cannot_reuse_decision_id():
    pipeline = lab.AuditPipeline()
    event = lab.make_event()
    ingest(pipeline, event)
    changed = replace(event, latency_ms=99)
    with pytest.raises(lab.AuditError, match="decision_id_conflict"):
        ingest(pipeline, changed)


def test_one_producer_sequence_cannot_name_different_events():
    pipeline = lab.AuditPipeline()
    ingest(pipeline, lab.make_event(sequence=1))
    changed = lab.make_event(
        sequence=1, decision_id="decision:other", action="claim.update"
    )
    with pytest.raises(lab.AuditError, match="producer_sequence_conflict"):
        ingest(pipeline, changed)


def test_out_of_order_delivery_is_accepted_but_sequence_gap_is_visible():
    pipeline = lab.AuditPipeline()
    ingest(pipeline, lab.make_event(sequence=3))
    ingest(pipeline, lab.make_event(sequence=1))
    assert pipeline.missing_sequences() == (2,)
    assert "SOURCE_SEQUENCE_GAP" in {finding.code for finding in pipeline.findings()}


def test_concurrent_exact_decision_redelivery_appends_once():
    pipeline = lab.AuditPipeline()
    event = lab.make_event()
    signature = pipeline.authority.sign(event)
    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(
            pool.map(lambda _: pipeline.ingest_decision(event, signature), range(8))
        )
    assert outcomes.count("accepted") == 1
    assert outcomes.count("reconciled") == 7
    assert len(pipeline.ledger) == 1


@pytest.mark.parametrize(
    "change,reason",
    [
        ({"schema_version": "0.9"}, "receipt_contract_invalid"),
        ({"event_type": "tool.result"}, "receipt_contract_invalid"),
        ({"emitted_by": "service:untrusted"}, "receipt_contract_invalid"),
        ({"tenant_id": "tenant:evil"}, "receipt_contract_invalid"),
        ({"trace_id": "0" * 32}, "trace_context_invalid"),
        ({"timestamp": lab.NOW + 601}, "receipt_binding_invalid"),
        ({"request_digest": "short"}, "receipt_binding_invalid"),
    ],
)
def test_enforcement_receipt_admission_rejects_invalid_evidence(change, reason):
    pipeline = lab.AuditPipeline()
    event = lab.make_event()
    ingest(pipeline, event)
    receipt = replace(lab.make_receipt(event), **change)
    with pytest.raises(lab.AuditError, match=reason):
        record(pipeline, receipt)


def test_pep_bypass_is_an_actual_violation_not_just_a_blocked_attempt():
    pipeline = lab.AuditPipeline()
    event = lab.make_event()
    receipt = replace(lab.make_receipt(event), decision_id="decision:missing")
    record(pipeline, receipt)
    finding = pipeline.findings()[0]
    assert finding.code == "PEP_BYPASS"
    assert finding.actual_violation is True


def test_executing_a_denied_decision_is_an_actual_violation():
    pipeline = lab.AuditPipeline()
    event = lab.make_event(
        outcome=lab.Decision.DENY,
        reason_code="DENY_TASK_SCOPE",
        determining_policy_ids=(),
    )
    ingest(pipeline, event)
    record(pipeline, lab.make_receipt(event))
    assert "DENIED_OPERATION_EXECUTED" in {item.code for item in pipeline.findings()}


@pytest.mark.parametrize(
    "change,code",
    [
        ({"request_digest_override": "0" * 64}, "DECISION_ACTION_MISMATCH"),
        ({"operation_id": "op:changed"}, "DECISION_ACTION_MISMATCH"),
        ({"timestamp": lab.NOW + 61}, "STALE_DECISION_EXECUTED"),
    ],
)
def test_decision_to_action_reconciliation_detects_changed_or_stale_execution(
    change, code
):
    pipeline = lab.AuditPipeline()
    event = lab.make_event()
    ingest(pipeline, event)
    record(pipeline, lab.make_receipt(event, **change))
    assert code in {item.code for item in pipeline.findings()}


def test_duplicate_effect_is_counted_separately_from_duplicate_delivery():
    pipeline = lab.AuditPipeline()
    event = lab.make_event()
    ingest(pipeline, event)
    record(pipeline, lab.make_receipt(event, execution_id="execution:1"))
    record(pipeline, lab.make_receipt(event, execution_id="execution:2"))
    finding = next(
        item for item in pipeline.findings() if item.code == "DUPLICATE_EFFECT"
    )
    assert finding.actual_violation is True
    assert pipeline.reconciled_duplicates == 0


def test_exact_receipt_redelivery_is_idempotent_but_changed_retry_conflicts():
    pipeline = lab.AuditPipeline()
    event = lab.make_event()
    ingest(pipeline, event)
    receipt = lab.make_receipt(event)
    signature = pipeline.authority.sign(receipt)
    assert pipeline.record_execution(receipt, signature) == "accepted"
    assert pipeline.record_execution(receipt, signature) == "reconciled"
    with pytest.raises(lab.AuditError, match="execution_id_conflict"):
        record(pipeline, replace(receipt, outcome=lab.ReceiptOutcome.ERROR))


def test_hash_chain_detects_entry_tampering_reordering_and_deletion():
    pipeline, _, _, _ = lab.course_fixture()
    assert pipeline.verify_chain()
    changed = list(pipeline.ledger)
    changed[1] = replace(changed[1], record_digest="0" * 64)
    assert not pipeline.verify_chain(changed)
    reordered = list(pipeline.ledger)
    reordered[0], reordered[1] = reordered[1], reordered[0]
    assert not pipeline.verify_chain(reordered)
    assert not pipeline.verify_chain(pipeline.ledger[1:])


def test_signed_checkpoint_binds_chain_root_count_window_and_versions():
    pipeline, _, _, _ = lab.course_fixture()
    checkpoint = pipeline.checkpoint()
    assert pipeline.verify_checkpoint(checkpoint)
    assert checkpoint.entry_count == len(pipeline.ledger)
    assert checkpoint.policy_versions == (lab.POLICY_VERSION,)
    assert len(checkpoint.signature) == 128
    assert len(pipeline.authority.public_key_hex()) == 64
    assert not pipeline.verify_checkpoint(replace(checkpoint, entry_count=999))


def test_empty_ledger_cannot_claim_a_checkpoint():
    with pytest.raises(lab.AuditError, match="checkpoint_empty"):
        lab.AuditPipeline().checkpoint()


def test_privacy_scanner_covers_exported_evidence_not_raw_source_requests():
    pipeline, _, _, _ = lab.course_fixture()
    assert pipeline.privacy_leaks() == 0
    first_id = next(iter(pipeline.decisions))
    pipeline.decisions[first_id] = replace(
        pipeline.decisions[first_id], action="secret-token"
    )
    assert pipeline.privacy_leaks() == 1


def test_metrics_fail_when_a_protected_operation_has_no_decision():
    pipeline, operations, _, _ = lab.course_fixture()
    del pipeline.decisions["decision:delete"]
    metrics = pipeline.metrics(operations)
    assert metrics.operations_with_decision == 7
    assert metrics.decision_coverage == 7 / 8
    assert not lab.release_gate(metrics)


def test_metrics_count_actual_forbidden_outcomes_not_blocked_attempts():
    pipeline = lab.AuditPipeline()
    event = lab.make_event(
        outcome=lab.Decision.DENY,
        reason_code="DENY_TASK_SCOPE",
        determining_policy_ids=(),
    )
    ingest(pipeline, event)
    operations = [lab.ProtectedOperation(event.operation_id, lab.Decision.DENY, False)]
    clean = pipeline.metrics(operations)
    assert clean.actual_forbidden_executions == 0
    record(pipeline, lab.make_receipt(event))
    violated = pipeline.metrics(operations)
    assert violated.actual_forbidden_executions == 1


def test_p95_latency_uses_nearest_rank_over_actual_decisions():
    pipeline, operations, events, _ = lab.course_fixture()
    metrics = pipeline.metrics(operations)
    ordered = sorted(event.latency_ms for event in events)
    assert metrics.p95_decision_latency_ms == ordered[-1]


def test_otel_span_uses_validated_trace_context_and_minimized_attributes():
    event = lab.make_event()
    span = lab.emit_in_memory_span(event)
    assert f"{span.context.trace_id:032x}" == event.trace_id
    assert span.attributes["authz.decision.id"] == event.decision_id
    exported = lab.canonical(dict(span.attributes))
    assert "user:alice" not in exported
    assert "claim:483" not in exported
    assert "secret-token" not in exported


def test_span_attributes_do_not_place_high_cardinality_ids_in_metric_dimensions():
    attributes = lab.otel_span_attributes(lab.make_event())
    assert "authz.decision.id" in attributes
    assert "principal.id" not in attributes
    assert "resource.id" not in attributes
    assert "tool.arguments" not in attributes


def test_decision_event_and_fixture_validate_against_draft_2020_12_schema():
    schema = json.loads(
        (LAB_PATH.parent / "schemas" / "authorization_log_schema.json").read_text()
    )
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(
        schema, format_checker=Draft202012Validator.FORMAT_CHECKER
    )
    validator.validate(json.loads(lab.canonical(lab.make_event())))
    fixtures = json.loads((LAB_PATH.parent / "data" / "sample_events.json").read_text())
    assert fixtures
    for event in fixtures:
        validator.validate(event)


def test_schema_rejects_unknown_fields_and_raw_tokens():
    schema = json.loads(
        (LAB_PATH.parent / "schemas" / "authorization_log_schema.json").read_text()
    )
    instance = json.loads(lab.canonical(lab.make_event()))
    instance["token"] = "secret-token"
    errors = list(Draft202012Validator(schema).iter_errors(instance))
    assert errors


def test_dashboard_uses_pipeline_metric_semantics():
    dashboard_path = LAB_PATH.parent / "dashboard" / "authorization_dashboard.py"
    spec = importlib.util.spec_from_file_location("course10_dashboard", dashboard_path)
    dashboard = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[spec.name] = dashboard
    spec.loader.exec_module(dashboard)
    pipeline, operations, _, _ = lab.course_fixture()
    kpis = dashboard.authorization_kpis(pipeline, operations)
    assert kpis["decision_coverage"] == 1.0
    assert kpis["actual_forbidden_executions"] == 0
    assert kpis["valid_work_execution_rate"] == 1.0
