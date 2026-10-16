from __future__ import annotations

import json
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path

import jwt
import pytest
from pydantic import ValidationError

COURSE = Path(__file__).parents[1]
sys.path.insert(0, str(COURSE))

from lab import (
    AUDIENCE,
    NOW,
    Case,
    ControlState,
    DetectionEngine,
    Finding,
    IdentityEvent,
    ResponseOrchestrator,
    TelemetryAuthority,
    TelemetryIngestor,
    ThreatDefenseError,
    cases,
    deterministic_key,
    evaluate,
    load_rules,
    make_event,
    northstar_graph,
    posture_score,
    recovery_ready,
    run_case,
)


def verified(event: IdentityEvent):
    authority = TelemetryAuthority()
    return TelemetryIngestor(authority).ingest(authority.issue(event))


def finding_for(case_id: str, rule_id: str) -> Finding:
    case = next(item for item in cases() if item.case_id == case_id)
    return next(
        item
        for item in DetectionEngine().detect(verified(case.event))
        if item.rule_id == rule_id
    )


def test_release_gate_and_opaque_risk_baseline_gap():
    hardened, rows = evaluate()
    baseline, _ = evaluate(True)
    assert len(rows) == 30
    assert hardened.exact == hardened.total == 30
    assert hardened.false_positives == hardened.false_negatives == 0
    assert hardened.precision == hardened.recall == 1.0
    assert baseline.exact == 12
    assert baseline.false_negatives == 17
    assert baseline.false_positives == 1


def test_fixture_corpus_matches_executable_cases():
    fixture = json.loads((COURSE / "data/adversarial_cases.json").read_text())
    executable = cases()
    assert [item["case_id"] for item in fixture] == [
        item.case_id for item in executable
    ]
    assert [tuple(item["expected_rules"]) for item in fixture] == [
        item.expected_rules for item in executable
    ]


@pytest.mark.parametrize("case", cases(), ids=lambda case: case.case_id)
def test_every_labelled_case_has_exact_expected_rules(case: Case):
    assert run_case(case) == tuple(sorted(case.expected_rules))


def test_signed_envelope_has_set_profile_and_bound_event():
    event = make_event("profile")
    authority = TelemetryAuthority()
    token = authority.issue(event)
    header = jwt.get_unverified_header(token)
    claims = jwt.decode(token, options={"verify_signature": False})
    assert header == {"alg": "EdDSA", "kid": "gateway", "typ": "secevent+jwt"}
    assert claims["aud"] == AUDIENCE
    assert claims["events"]["urn:northstar:identity-event"]["event_id"] == "evt:profile"


def test_forged_envelope_is_rejected():
    event = make_event("forged")
    claims = {
        "iss": "gateway",
        "aud": AUDIENCE,
        "iat": NOW,
        "nbf": NOW,
        "exp": NOW + 300,
        "jti": "set:forged",
        "events": {"urn:northstar:identity-event": event.record()},
    }
    token = jwt.encode(
        claims,
        deterministic_key("attacker"),
        algorithm="EdDSA",
        headers={"kid": "gateway", "typ": "secevent+jwt"},
    )
    with pytest.raises(ThreatDefenseError, match="telemetry_invalid"):
        TelemetryIngestor(TelemetryAuthority()).ingest(token)


def test_source_is_not_authoritative_for_unregistered_event_type():
    event = make_event("wrong-source", "telemetry", "gateway")
    authority = TelemetryAuthority()
    with pytest.raises(ThreatDefenseError, match="source_authority_invalid"):
        TelemetryIngestor(authority).ingest(authority.issue(event))


@pytest.mark.parametrize(
    ("event", "issue_kwargs", "reason"),
    [
        (make_event("wrong-tenant", tenant_id="tenant:other"), {}, "tenant_invalid"),
        (make_event("stale", occurred_at=NOW - 1_000), {}, "event_stale"),
        (make_event("sequence-gap", sequence=2), {}, "sequence_gap"),
        (
            make_event("expired"),
            {"now": NOW - 1_000, "lifetime": 10},
            "telemetry_time_invalid",
        ),
    ],
)
def test_ingestion_fails_closed_on_context_errors(event, issue_kwargs, reason):
    authority = TelemetryAuthority()
    token = authority.issue(event, **issue_kwargs)
    with pytest.raises(ThreatDefenseError, match=reason):
        TelemetryIngestor(authority).ingest(token, now=NOW)


def test_envelope_replay_is_rejected():
    authority, event = TelemetryAuthority(), make_event("replay-envelope")
    ingestor = TelemetryIngestor(authority)
    token = authority.issue(event)
    ingestor.ingest(token)
    with pytest.raises(ThreatDefenseError, match="envelope_replayed"):
        ingestor.ingest(token)


def test_concurrent_duplicate_delivery_has_one_winner():
    authority, event = TelemetryAuthority(), make_event("concurrent")
    ingestor = TelemetryIngestor(authority)
    token = authority.issue(event)

    def attempt(_: int) -> bool:
        try:
            ingestor.ingest(token)
            return True
        except ThreatDefenseError:
            return False

    with ThreadPoolExecutor(max_workers=8) as executor:
        assert sum(executor.map(attempt, range(32))) == 1


def test_event_schema_rejects_unknown_fields():
    with pytest.raises(ValidationError):
        IdentityEvent(**{**make_event("extra").record(), "agent_says_safe": True})


def test_detector_requires_verified_event():
    with pytest.raises(ThreatDefenseError, match="event_not_verified"):
        DetectionEngine().detect(
            replace(verified(make_event("unverified")), verification_id="")
        )


def test_rule_loader_rejects_unknown_detector_and_does_not_eval_expressions(tmp_path):
    path = tmp_path / "rules.yaml"
    path.write_text(
        """rules:\n  - id: X\n    name: unsafe\n    severity: critical\n    kind: confirmed_control_violation\n    detector: __import__('os').system('false')\n    response: []\n    attack_mapping: []\n"""
    )
    with pytest.raises(ThreatDefenseError, match="rule_invalid"):
        load_rules(path)


def test_graph_enumerates_transitive_paths_and_blast_radius():
    graph = northstar_graph()
    paths = graph.attack_paths("external:vendor")
    assert len(paths) == 4
    assert {path[-1] for path in paths} == {"api:claims", "kms:claims"}
    assert graph.blast_radius("external:vendor") == {
        "agent:research",
        "agent:data",
        "tool:vector",
        "store:research",
        "api:claims",
        "kms:claims",
    }


def test_graph_prioritization_is_transparent_and_not_probability():
    graph = northstar_graph()
    result = graph.path_priority(graph.attack_paths("external:vendor")[-1])
    assert result == {
        "score": 64,
        "edge_count": 4,
        "target_impact": 1.0,
        "label": "prioritization_index_not_probability",
    }


def test_choke_points_are_based_on_counted_attack_paths():
    assert northstar_graph().choke_points(["external:vendor"])[0] == (
        "agent:research",
        4,
    )


def test_remediation_simulation_reports_security_and_business_effects():
    graph = northstar_graph()
    safe = graph.simulate_edge_removal("tool:vector", "api:claims", "external:vendor")
    disruptive = graph.simulate_edge_removal(
        "agent:research", "tool:vector", "external:vendor"
    )
    assert safe == {
        "before_paths": 4,
        "after_paths": 2,
        "paths_removed": 2,
        "breaks_required_business_path": False,
    }
    assert disruptive["breaks_required_business_path"] is True


def test_confirmed_violation_applies_scoped_containment():
    finding = finding_for("audience-mismatch", "IDT-006")
    orchestrator = ResponseOrchestrator(ControlState())
    result = orchestrator.respond(finding, operation_id="contain:audience")
    assert result.status == "contained"
    assert orchestrator.state.quarantined_principals == {"agent:research"}
    assert orchestrator.state.revoked_credentials == {"cred:research:v2"}


def test_behavioral_anomaly_routes_to_review_without_automatic_side_effect():
    finding = finding_for("kms-spike", "IDT-011")
    orchestrator = ResponseOrchestrator()
    result = orchestrator.respond(finding, operation_id="review:kms")
    assert result.status == "review_required"
    assert result.actions == ("human_review",)
    assert not orchestrator.state.quarantined_principals
    assert finding.finding_id in orchestrator.state.review_queue


def test_response_is_idempotent_and_changed_request_conflicts():
    first = finding_for("revoked", "IDT-001")
    second = finding_for("audience-mismatch", "IDT-006")
    orchestrator = ResponseOrchestrator()
    result = orchestrator.respond(first, operation_id="contain:1")
    assert orchestrator.respond(first, operation_id="contain:1") == result
    assert len(orchestrator.evidence) == 1
    with pytest.raises(ThreatDefenseError, match="idempotency_conflict"):
        orchestrator.respond(second, operation_id="contain:1")


def test_response_evidence_chain_detects_tampering():
    orchestrator = ResponseOrchestrator()
    orchestrator.respond(finding_for("revoked", "IDT-001"), operation_id="one")
    orchestrator.respond(
        finding_for("audience-mismatch", "IDT-006"), operation_id="two"
    )
    assert orchestrator.verify_evidence()
    orchestrator.evidence[0]["status"] = "ignored"
    assert not orchestrator.verify_evidence()


def test_recovery_requires_complete_positive_evidence():
    checks = {
        "persistence_removed": True,
        "credentials_rotated": True,
        "workload_reattested": True,
        "delegations_reviewed": True,
        "telemetry_healthy": True,
        "policy_validated": True,
        "incident_closed": True,
    }
    assert recovery_ready(checks)
    assert not recovery_ready({**checks, "telemetry_healthy": False})
    with pytest.raises(ThreatDefenseError, match="recovery_evidence_incomplete"):
        recovery_ready(
            {key: value for key, value in checks.items() if key != "incident_closed"}
        )


def test_posture_score_exposes_dimensions_and_critical_override():
    dimensions = {
        "inventory": 0.9,
        "least_privilege": 0.6,
        "credential_hygiene": 0.7,
        "delegation": 0.6,
        "detection": 0.8,
        "runtime_binding": 0.9,
        "external_trust": 0.7,
        "response": 0.7,
    }
    ordinary = posture_score(dimensions)
    critical = posture_score(dimensions, ["leaked_active_credential"])
    assert ordinary.score == 72
    assert critical.score == 25
    assert critical.critical_findings == ("leaked_active_credential",)
    assert critical.label == "prioritization_index_not_breach_probability"


@pytest.mark.parametrize(
    "dimensions",
    [
        {"inventory": 1.0},
        {
            "inventory": 2.0,
            "least_privilege": 1.0,
            "credential_hygiene": 1.0,
            "delegation": 1.0,
            "detection": 1.0,
            "runtime_binding": 1.0,
            "external_trust": 1.0,
            "response": 1.0,
        },
    ],
)
def test_posture_rejects_missing_or_out_of_range_dimensions(dimensions):
    with pytest.raises(ThreatDefenseError, match="posture_dimensions_invalid"):
        posture_score(dimensions)


def test_policy_examples_cover_current_state_and_fail_closed_signals():
    opa = (COURSE / "policies/opa/identity_threat.rego").read_text().lower()
    cedar = (COURSE / "policies/cedar/identity_threat.cedar").read_text().lower()
    for text in (opa, cedar):
        for required in ("active", "audience", "delegation", "telemetry", "revoked"):
            assert required in text


def test_lab_uses_no_network(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("network attempted")

    monkeypatch.setattr("socket.create_connection", forbidden)
    hardened, _ = evaluate()
    assert hardened.exact == hardened.total
