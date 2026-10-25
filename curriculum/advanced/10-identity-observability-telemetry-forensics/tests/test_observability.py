from __future__ import annotations

import json
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path

import pytest
import yaml
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

COURSE = Path(__file__).parents[1]
sys.path.insert(0, str(COURSE))

from lab import (
    NOW,
    PSEUDONYM_KEY,
    Case,
    Checkpoint,
    DetectionEngine,
    EvidenceLedger,
    ForensicsError,
    IdentityEvent,
    TelemetryAuthority,
    TrustedCollector,
    build_case_bundle,
    cases,
    complete_trace,
    completeness,
    correlate,
    decode,
    deterministic_key,
    digest,
    evaluate,
    fingerprint,
    load_rules,
    make_event,
    otel_trace_demo,
    run_case,
    sanitize,
)


def collect(events, observed_at=NOW + 10):
    authority = TelemetryAuthority()
    collector = TrustedCollector(authority)
    return [
        collector.ingest(authority.issue(event), observed_at=observed_at)
        for event in events
    ]


def test_release_gate_and_raw_log_baseline_gap():
    hardened, rows = evaluate()
    baseline, _ = evaluate(True)
    assert len(rows) == hardened.total == 20
    assert hardened.exact == 20
    assert hardened.false_positives == hardened.false_negatives == 0
    assert hardened.precision == hardened.recall == 1.0
    assert baseline.exact == 5
    assert baseline.false_negatives == 14
    assert baseline.false_positives == 1
    assert baseline.precision == baseline.recall == 0.0


@pytest.mark.parametrize("case", cases(), ids=lambda case: case.case_id)
def test_every_labelled_trace_has_exact_expected_findings(case: Case):
    assert run_case(case) == case.expected_rules


def test_adversarial_fixture_matches_executable_cases():
    fixture = json.loads((COURSE / "data/adversarial_cases.json").read_text())
    assert [item["case_id"] for item in fixture] == [case.case_id for case in cases()]
    assert [tuple(item["expected_rules"]) for item in fixture] == [
        case.expected_rules for case in cases()
    ]


def test_signed_event_is_verified_then_sanitized():
    event = make_event(
        "privacy",
        "tool.execute",
        attributes={
            "authorization": "Bearer top-secret-token",
            "owner": "alice@example.test",
            "nested": {"note": "Bearer another-secret-token"},
        },
    )
    authority = TelemetryAuthority()
    item = TrustedCollector(authority).ingest(authority.issue(event), observed_at=NOW)
    assert item.redaction_count == 3
    assert item.event.attributes["authorization"] == "[REDACTED]"
    assert item.event.attributes["owner"].startswith("hmac:")
    assert item.event.attributes["nested"]["note"] == "[REDACTED]"
    assert item.signed_event_digest == digest(event.record())
    assert item.verification_id


def test_modified_signed_payload_is_rejected():
    authority = TelemetryAuthority()
    envelope = json.loads(authority.issue(make_event("signed", "api.access")))
    envelope["event"]["resource"] = "claim:other"
    with pytest.raises(ForensicsError, match="envelope_invalid"):
        TrustedCollector(authority).ingest(json.dumps(envelope), observed_at=NOW + 10)


def test_unknown_producer_is_rejected():
    authority = TelemetryAuthority()
    envelope = json.loads(authority.issue(make_event("unknown", "api.access")))
    envelope["producer"] = "unknown"
    with pytest.raises(ForensicsError, match="envelope_invalid"):
        TrustedCollector(authority).ingest(json.dumps(envelope), observed_at=NOW + 10)


def test_valid_signature_does_not_grant_wrong_event_authority():
    event = make_event(
        "wrong-authority",
        "authorization.decision",
        producer="claims-api",
    )
    authority = TelemetryAuthority()
    with pytest.raises(ForensicsError, match="producer_authority_invalid"):
        TrustedCollector(authority).ingest(authority.issue(event), observed_at=NOW + 10)


@pytest.mark.parametrize(
    ("event", "observed_at", "reason"),
    [
        (
            make_event("wrong-tenant", "api.access", tenant_id="tenant:other"),
            NOW + 10,
            "tenant_invalid",
        ),
        (
            make_event("future", "api.access", occurred_at=NOW + 100),
            NOW,
            "event_time_invalid",
        ),
        (
            make_event("stale", "api.access", occurred_at=NOW - 4_000),
            NOW,
            "event_time_invalid",
        ),
    ],
)
def test_collection_fails_closed_on_context_errors(event, observed_at, reason):
    authority = TelemetryAuthority()
    with pytest.raises(ForensicsError, match=reason):
        TrustedCollector(authority).ingest(
            authority.issue(event), observed_at=observed_at
        )


def test_envelope_and_event_replay_are_rejected():
    authority = TelemetryAuthority()
    event = make_event("replay", "api.access")
    collector = TrustedCollector(authority)
    token = authority.issue(event)
    collector.ingest(token, observed_at=NOW + 10)
    with pytest.raises(ForensicsError, match="envelope_replayed"):
        collector.ingest(token, observed_at=NOW + 10)
    with pytest.raises(ForensicsError, match="event_replayed"):
        collector.ingest(
            authority.issue(event, envelope_id="env:second"), observed_at=NOW + 10
        )


def test_concurrent_duplicate_delivery_has_one_winner():
    authority = TelemetryAuthority()
    collector = TrustedCollector(authority)
    token = authority.issue(make_event("concurrent", "api.access"))

    def attempt(_: int) -> bool:
        try:
            collector.ingest(token, observed_at=NOW + 10)
            return True
        except ForensicsError:
            return False

    with ThreadPoolExecutor(max_workers=8) as executor:
        assert sum(executor.map(attempt, range(32))) == 1


def test_sequence_gap_and_late_arrival_are_visible_not_silently_reordered():
    authority = TelemetryAuthority()
    collector = TrustedCollector(authority)
    third = make_event("third", "api.access", sequence=3)
    first = make_event("first", "api.access", sequence=1)
    gap = collector.ingest(authority.issue(third), observed_at=NOW + 10)
    late = collector.ingest(authority.issue(first), observed_at=NOW + 11)
    assert gap.collection_anomalies == ("sequence_gap",)
    assert late.collection_anomalies == ("late_out_of_order",)


def test_event_schema_is_strict_and_enforces_conditional_fields():
    record = make_event("strict", "api.access").record()
    with pytest.raises(ValidationError):
        IdentityEvent.model_validate({**record, "agent_says_safe": True})
    decision = make_event("decision", "authorization.decision").record()
    decision.pop("authorization_request_id")
    with pytest.raises(ValidationError):
        IdentityEvent.model_validate(decision)
    with pytest.raises(ValidationError, match="raw email identity"):
        IdentityEvent.model_validate({**record, "actor_id": "alice@example.test"})


def test_fingerprint_requires_key_and_is_stable_without_exposing_input():
    first = fingerprint("alice@example.test", PSEUDONYM_KEY)
    assert first == fingerprint("alice@example.test", PSEUDONYM_KEY)
    assert "alice" not in first
    with pytest.raises(ForensicsError, match="pseudonym_key_too_short"):
        fingerprint("alice@example.test", b"short")


def test_sanitize_preserves_structure_and_does_not_mutate_input():
    original = {"safe": [1, {"api_key": "secret"}], "name": "service"}
    cleaned, count = sanitize(original)
    assert cleaned == {"safe": [1, {"api_key": "[REDACTED]"}], "name": "service"}
    assert original["safe"][1]["api_key"] == "secret"
    assert count == 1


def test_real_opentelemetry_sdk_emits_parented_privacy_safe_spans():
    spans = otel_trace_demo()
    assert {span["name"] for span in spans} == {
        "invoke_agent claims",
        "execute_tool policy-search",
    }
    assert len({span["trace_id"] for span in spans}) == 1
    child = next(span for span in spans if span["parent_span_id"])
    assert child["attributes"]["gen_ai.operation.name"] == "execute_tool"
    serialized = json.dumps(spans).lower()
    assert "prompt" not in serialized and "bearer" not in serialized


def test_correlation_builds_causal_graph_and_rejects_mixed_traces():
    items = collect(complete_trace())
    view = correlate(items)
    assert len(view.graph) == 8
    assert nx_path(view, "00f067aa0ba902b7", "a4f0d1c2b3e4f506")
    other = replace(
        items[0], event=items[0].event.model_copy(update={"trace_id": "f" * 32})
    )
    with pytest.raises(ForensicsError, match="trace_mixed"):
        correlate([other, *items[1:]])
    with pytest.raises(ForensicsError, match="trace_empty"):
        correlate([])


def nx_path(view, source, target):
    import networkx as nx

    return nx.has_path(view.graph, source, target)


def test_rule_loader_rejects_executable_expression(tmp_path):
    path = tmp_path / "rules.yaml"
    path.write_text(
        """rules:\n  - id: X\n    name: unsafe\n    severity: critical\n    detector: __import__('os').system('false')\n    evidence_requirement: none\n"""
    )
    with pytest.raises(ForensicsError, match="rule_invalid"):
        load_rules(path)


def test_completeness_uses_documented_denominators():
    complete = completeness(correlate(collect(complete_trace())))
    assert complete.expected_phases == complete.observed_phases == 8
    assert complete.phase_coverage == 1.0
    assert complete.attribution_coverage == 1.0
    assert complete.enforcement_coverage == 1.0
    incomplete_events = [
        event
        for event in complete_trace()
        if event.event_type != "authorization.enforced"
    ]
    incomplete = completeness(correlate(collect(incomplete_events)))
    assert incomplete.observed_phases == 7
    assert incomplete.phase_coverage == 0.875
    assert incomplete.permit_decisions == 1
    assert incomplete.matched_enforcements == 0
    assert incomplete.enforcement_coverage == 0.0


def test_evidence_chain_and_signed_checkpoint_detect_tampering():
    items = collect(complete_trace())
    ledger = EvidenceLedger()
    for item in items:
        ledger.append(item)
    key = deterministic_key("audit-anchor")
    checkpoint = ledger.checkpoint(key)
    assert ledger.verify(checkpoint, key.public_key())
    ledger.entries[0]["record"]["event"]["resource"] = "claim:tampered"
    assert not ledger.verify(checkpoint, key.public_key())


def test_checkpoint_detects_truncation_and_wrong_signer():
    ledger = EvidenceLedger()
    for item in collect(complete_trace()):
        ledger.append(item)
    key = deterministic_key("audit-anchor")
    checkpoint = ledger.checkpoint(key)
    ledger.entries.pop()
    assert not ledger.verify(checkpoint, key.public_key())
    assert not ledger.verify(checkpoint, deterministic_key("attacker").public_key())


def test_checkpoint_signature_cannot_be_forged_by_editing_root():
    ledger = EvidenceLedger()
    ledger.append(collect([complete_trace()[0]])[0])
    key = deterministic_key("audit-anchor")
    checkpoint = ledger.checkpoint(key)
    forged = Checkpoint(
        checkpoint.count,
        "0" * 64,
        checkpoint.signer,
        checkpoint.signature,
    )
    assert not ledger.verify(forged, key.public_key())
    assert decode(checkpoint.signature)


def test_case_bundle_separates_observed_timeline_from_evidence_gaps():
    events = [
        event
        for event in complete_trace()
        if event.event_type != "authorization.enforced"
    ]
    items = collect(events)
    view = correlate(items)
    findings = DetectionEngine().detect(view)
    ledger = EvidenceLedger()
    for item in items:
        ledger.append(item)
    key = deterministic_key("anchor")
    bundle = build_case_bundle(view, findings, ledger.checkpoint(key))
    assert all(item["claim_status"] == "observed" for item in bundle["timeline"])
    assert bundle["findings"][0]["status"] == "evidence_gap"
    assert bundle["manifest_digest"] == digest(
        {key: value for key, value in bundle.items() if key != "manifest_digest"}
    )


def test_schema_and_collector_config_match_course_contract():
    schema = json.loads((COURSE / "schemas/identity_event.schema.json").read_text())
    required = set(schema["required"])
    assert {"event_id", "producer", "sequence", "trace_id", "span_id"} <= required
    config = yaml.safe_load((COURSE / "configs/otel/collector.yaml").read_text())
    processors = config["service"]["pipelines"]["logs"]["processors"]
    assert processors[0] == "memory_limiter"
    assert "redaction/security" in processors
    assert config["processors"]["redaction/security"]["allow_all_keys"] is False


def test_lab_does_not_require_network(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("network attempted")

    monkeypatch.setattr("socket.create_connection", forbidden)
    result, _ = evaluate()
    assert result.exact == result.total


def test_private_key_type_used_only_by_trusted_authority():
    assert isinstance(deterministic_key("type-check"), Ed25519PrivateKey)
