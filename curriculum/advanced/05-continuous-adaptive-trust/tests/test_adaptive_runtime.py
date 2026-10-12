from __future__ import annotations

import json
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError, replace
from pathlib import Path

import cedarpy
import jwt
import pytest

COURSE = Path(__file__).parents[1]
sys.path.insert(0, str(COURSE))

from advanced_adaptive_runtime import (
    AGENT,
    AGENT_BEHAVIOR_CHANGE,
    AUDIENCE,
    NOW,
    POLICY_VERSION,
    QUARANTINE_CHANGE,
    SESSION_REVOKED,
    SUBJECT,
    TASK_CHANGE,
    TENANT,
    AdaptiveController,
    DecisionCache,
    EvidenceLog,
    SetTransmitter,
    build_cases,
    default_request,
    digest,
    emit,
    evaluate,
    release_gate,
    scenario,
)


def test_labelled_corpus_has_exact_outcomes_and_broad_slices():
    cases = build_cases()
    metrics, rows = evaluate(cases)
    assert len(cases) == 40
    assert {case.category for case in cases} >= {
        "valid",
        "lifecycle",
        "risk",
        "binding",
        "governance",
        "resilience",
        "ordering",
        "recovery",
    }
    assert all(row["match"] for row in rows)
    assert metrics.invalid_allows == metrics.valid_blocked == 0
    assert release_gate(metrics)


def test_point_in_time_baseline_exposes_unsafe_allows():
    metrics, _ = evaluate(build_cases(), baseline=True)
    assert metrics.invalid_allows == 35
    assert metrics.valid_blocked == 0
    assert metrics.accuracy == 0.125


@pytest.mark.parametrize("case", build_cases(), ids=lambda case: case.case_id)
def test_every_labelled_case(case):
    assert case.run() is case.expected_allowed


def test_set_uses_signed_security_event_profile_and_complex_subject():
    value = scenario()
    transmitter = value["transmitters"]["identity"]
    token = transmitter.issue(SESSION_REVOKED, {}, jti="set:inspect")
    header = jwt.get_unverified_header(token)
    claims = jwt.decode(token, options={"verify_signature": False})
    assert header == {"alg": "EdDSA", "kid": "id-2026", "typ": "secevent+jwt"}
    assert claims["aud"] == AUDIENCE
    assert claims["sub_id"] == SUBJECT.as_sub_id()
    assert list(claims["events"]) == [SESSION_REVOKED]


def test_receiver_persists_before_202_and_projector_marks_applied():
    value = scenario()
    transmitter = value["transmitters"]["identity"]
    token = transmitter.issue(SESSION_REVOKED, {}, jti="set:persist")
    result = value["receiver"].receive(token)
    assert result.http_status == 202
    assert result.outcome == "persisted"
    assert value["receiver"].pending_count == 1
    assert value["state"].session_active
    assert value["projector"].project(value["receiver"]) == 1
    assert value["receiver"].pending_count == 0
    assert not value["state"].session_active


def test_duplicate_delivery_is_atomic_and_idempotent():
    value = scenario()
    token = value["transmitters"]["security"].issue(
        AGENT_BEHAVIOR_CHANGE,
        {"current_level": "low"},
        jti="set:atomic-duplicate",
    )
    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(value["receiver"].receive, [token] * 24))
    assert sum(result.outcome == "persisted" for result in results) == 1
    assert sum(result.outcome == "duplicate" for result in results) == 23
    assert all(result.http_status == 202 for result in results)


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        ({"typ": "JWT"}, "set_profile_invalid"),
        ({"kid": "unknown"}, "set_key_untrusted"),
    ],
)
def test_receiver_rejects_wrong_header_profile(change, reason):
    value = scenario()
    transmitter = value["transmitters"]["identity"]
    token = transmitter.issue(
        SESSION_REVOKED,
        {},
        jti=f"set:{reason}",
        typ=change.get("typ", "secevent+jwt"),
        kid=change.get("kid"),
    )
    result = value["receiver"].receive(token)
    assert result.http_status == 400
    assert result.outcome == reason


def test_receiver_rejects_forged_signature_untrusted_issuer_and_audience():
    value = scenario()
    identity = value["transmitters"]["identity"]
    attacker = SetTransmitter("https://attacker.example", "attacker")
    forged = identity.issue(
        SESSION_REVOKED,
        {},
        jti="set:forged",
        private_key=attacker.private_key,
    )
    unknown = attacker.issue(SESSION_REVOKED, {}, jti="set:unknown")
    wrong_audience = identity.issue(
        SESSION_REVOKED,
        {},
        audience="https://other.example/ssf",
        jti="set:audience",
    )
    assert value["receiver"].receive(forged).outcome == "set_signature_or_claims_invalid"
    assert value["receiver"].receive(unknown).outcome == "transmitter_untrusted"
    assert value["receiver"].receive(wrong_audience).outcome == "set_audience_mismatch"


def test_receiver_rejects_old_future_and_malformed_time():
    value = scenario()
    transmitter = value["transmitters"]["identity"]
    old = transmitter.issue(SESSION_REVOKED, {}, issued_at=NOW - 301, jti="set:old")
    future = transmitter.issue(
        SESSION_REVOKED, {}, issued_at=NOW + 31, jti="set:future"
    )
    malformed = transmitter.issue(
        SESSION_REVOKED,
        {},
        jti="set:bad-time",
        extra_claims={"iat": "not-an-integer"},
    )
    old_event = transmitter.issue(
        SESSION_REVOKED,
        {},
        event_timestamp=NOW - 3601,
        jti="set:old-event",
    )
    assert value["receiver"].receive(old).outcome == "set_too_old"
    assert value["receiver"].receive(future).outcome == "set_from_future"
    assert value["receiver"].receive(malformed).outcome == "set_time_invalid"
    assert value["receiver"].receive(old_event).outcome == "event_too_old"


def test_subject_correlation_is_exact_and_tenant_scoped():
    value = scenario()
    transmitter = value["transmitters"]["identity"]
    other = replace(SUBJECT, tenant_id="tenant:other")
    token = transmitter.issue(SESSION_REVOKED, {}, subject=other, jti="set:other-tenant")
    result = value["receiver"].receive(token)
    assert result.outcome == "subject_tenant_mismatch"

    claims = jwt.decode(
        transmitter.issue(SESSION_REVOKED, {}, jti="set:bad-subject"),
        options={"verify_signature": False},
    )
    claims["sub_id"] = {"format": "opaque", "id": AGENT, "extra": True}
    malformed = jwt.encode(
        claims,
        transmitter.private_key,
        algorithm="EdDSA",
        headers={"typ": "secevent+jwt", "kid": transmitter.kid},
    )
    assert value["receiver"].receive(malformed).outcome == "subject_identifier_invalid"


def test_receiver_enforces_one_authorized_well_formed_event():
    value = scenario()
    identity = value["transmitters"]["identity"]
    multiple = identity.issue(
        SESSION_REVOKED,
        {},
        jti="set:multiple",
        extra_events={TASK_CHANGE: {"active": False, "task_version": 5}},
    )
    unauthorized = identity.issue(
        TASK_CHANGE,
        {"active": False, "task_version": 5},
        jti="set:unauthorized",
    )
    malformed = value["transmitters"]["governance"].issue(
        TASK_CHANGE,
        {"active": "false", "task_version": 5},
        jti="set:malformed",
    )
    assert value["receiver"].receive(multiple).outcome == "set_event_count_invalid"
    assert value["receiver"].receive(unauthorized).outcome == "event_type_not_authorized"
    assert value["receiver"].receive(malformed).outcome == "event_payload_invalid"


def test_receiver_applies_backpressure_before_unbounded_queue_growth():
    value = scenario()
    value["receiver"].capacity = 1
    first = value["transmitters"]["identity"].issue(
        SESSION_REVOKED, {}, jti="set:first"
    )
    second = value["transmitters"]["identity"].issue(
        SESSION_REVOKED, {}, jti="set:second"
    )
    assert value["receiver"].receive(first).http_status == 202
    result = value["receiver"].receive(second)
    assert result.http_status == 429
    assert result.outcome == "receiver_backpressure"


def test_stale_relaxation_loses_but_late_restriction_wins():
    cases = {case.case_id: case for case in build_cases()}
    assert not cases["stale_relaxation"].run()
    assert not cases["late_restriction"].run()


def test_negative_state_has_precedence_over_low_risk_score():
    value = scenario()
    value["state"].quarantined = True
    value["state"].risk = {name: 0 for name in value["state"].risk}
    decision = value["controller"].decide(
        value["state"], value["request"], value["receiver"]
    )
    assert not decision.allowed
    assert decision.mode == "QUARANTINE"
    assert decision.reason_code == "agent_quarantined"


def test_moderate_risk_observes_reads_but_reduces_writes():
    read_value = scenario()
    emit(
        read_value,
        "security",
        AGENT_BEHAVIOR_CHANGE,
        {"current_level": "medium"},
        jti="set:read-medium",
    )
    read = read_value["controller"].decide(
        read_value["state"],
        replace(read_value["request"], action="claim.read"),
        read_value["receiver"],
    )
    write = AdaptiveController().decide(
        read_value["state"], read_value["request"], read_value["receiver"]
    )
    assert read.allowed and read.mode == "OBSERVE"
    assert not write.allowed and write.mode == "REDUCE"


def test_recovery_requires_governance_evidence_and_cooldown():
    value = scenario()
    emit(
        value,
        "security",
        QUARANTINE_CHANGE,
        {"action": "quarantine"},
        jti="set:recovery-quarantine",
    )
    first = value["controller"].decide(
        value["state"], value["request"], value["receiver"], now=NOW
    )
    assert first.mode == "QUARANTINE"
    emit(
        value,
        "governance",
        QUARANTINE_CHANGE,
        {
            "action": "release",
            "human_approved": True,
            "incident_cleared": True,
            "fresh_attestation": True,
        },
        jti="set:recovery-release",
        timestamp=NOW + 1,
    )
    early = value["controller"].decide(
        value["state"], value["request"], value["receiver"], now=NOW + 2
    )
    recovered = value["controller"].decide(
        value["state"], value["request"], value["receiver"], now=NOW + 301
    )
    assert not early.allowed and early.reason_code == "recovery_cooldown"
    assert recovered.allowed and recovered.mode == "ALLOW"


def test_decision_cache_binds_request_state_stream_and_expiry():
    value = scenario()
    decision = value["controller"].decide(
        value["state"], value["request"], value["receiver"]
    )
    cache = DecisionCache()
    cache.put(value["request"], value["state"], value["receiver"], decision)
    assert cache.get(value["request"], value["state"], value["receiver"]) == decision
    value["state"].state_version += 1
    assert cache.get(value["request"], value["state"], value["receiver"]) is None
    value["state"].state_version -= 1
    value["receiver"].set_stream_available(False)
    assert cache.get(value["request"], value["state"], value["receiver"]) is None
    value["receiver"].set_stream_available(True)
    assert cache.get(
        value["request"], value["state"], value["receiver"], now=NOW + 30
    ) is None


def test_commit_gate_reauthorizes_after_midflight_revocation():
    value = scenario()

    def revoke():
        emit(
            value,
            "identity",
            SESSION_REVOKED,
            {},
            jti="set:midflight-revoke",
        )

    decision = value["gate"].execute(
        value["request"],
        value["state"],
        value["receiver"],
        before_commit=revoke,
    )
    assert not decision.allowed
    assert decision.reason_code == "session_revoked"
    assert value["gate"].effects == []


def test_commit_gate_is_idempotent_and_rejects_changed_retry():
    value = scenario()
    first = value["gate"].execute(
        value["request"], value["state"], value["receiver"]
    )
    retry = value["gate"].execute(
        value["request"], value["state"], value["receiver"]
    )
    changed = value["gate"].execute(
        replace(value["request"], action="claim.read"),
        value["state"],
        value["receiver"],
    )
    assert first.allowed and retry == first
    assert value["gate"].effects == [value["request"].operation_id]
    assert not changed.allowed and changed.reason_code == "operation_conflict"


def test_evidence_is_reconstructable_without_raw_events_or_plain_subject():
    value = scenario()
    decision = value["controller"].decide(
        value["state"], value["request"], value["receiver"]
    )
    evidence = EvidenceLog()
    evidence.append(value["request"], decision)
    serialized = json.dumps(evidence.records)
    assert AGENT not in serialized
    assert "secevent+jwt" not in serialized
    assert evidence.records[0]["subject_hash"] == digest(
        {"tenant": TENANT, "agent": AGENT, "workload": value["request"].workload_id}
    )
    assert evidence.records[0]["policy_version"] == POLICY_VERSION


def test_request_contract_is_immutable():
    request = default_request()
    with pytest.raises(FrozenInstanceError):
        request.agent_id = "agent:evil"


def test_static_config_and_adversarial_catalog_match_runtime():
    config = json.loads((COURSE / "configs/shared-signals/receiver.json").read_text())
    catalog = json.loads((COURSE / "data/adversarial_cases.json").read_text())
    assert config["audience"] == AUDIENCE
    assert config["delivery_method"] == "urn:ietf:rfc:8935"
    assert config["durable_before_ack"] is True
    assert {item["case_id"] for item in catalog} == {
        case.case_id for case in build_cases()
    }
    assert sum(item["expected"] == "allow" for item in catalog) == 3


def test_cedar_policy_is_parseable_and_has_permit_and_forbid():
    policies = (COURSE / "policies/cedar/adaptive_authz.cedar").read_text()
    assert len(cedarpy.PolicySet.from_str(policies)) == 2
    assert "permit" in policies and "forbid" in policies


def test_readme_uses_primary_sources_and_current_final_status():
    readme = (COURSE / "README.md").read_text()
    for source in (
        "openid-sharedsignals-framework-1_0-final",
        "openid-caep-1_0-final",
        "rfc/rfc8417",
        "rfc/rfc8935",
        "rfc/rfc8936",
        "rfc/rfc9493",
        "csrc.nist.gov/pubs/sp/800/207/final",
    ):
        assert source in readme
    assert "Final Specifications" in readme
    assert "29 August 2025" in readme
