"""Executable invariants for Intermediate 05 dynamic authorization."""

from dataclasses import replace
import importlib.util
from pathlib import Path
import sys

import jwt
import pytest


LAB_PATH = Path(__file__).parents[1] / "lab.py"
SPEC = importlib.util.spec_from_file_location("intermediate05_lab", LAB_PATH)
lab = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = lab
SPEC.loader.exec_module(lab)


def test_hardened_matrix_matches_labels_and_release_gate():
    metrics, rows = lab.evaluate(lab.build_cases())
    assert len(rows) == 32
    assert metrics.expected_allowed == 5
    assert metrics.expected_blocked == 27
    assert metrics.invalid_acceptances == 0
    assert metrics.valid_work_blocked == 0
    assert metrics.outcome_matches == 32
    assert lab.release_gate(metrics)


def test_one_time_baseline_exposes_invalid_acceptances():
    metrics, _ = lab.evaluate(lab.build_cases(), hardened=False)
    assert metrics.invalid_acceptances >= 20
    assert not lab.release_gate(metrics)


@pytest.mark.parametrize("case", lab.build_cases(), ids=lambda case: case.case_id)
def test_every_scenario_matches_its_label(case):
    assert lab.run_case(case) is case.expected_allowed


def test_valid_set_is_persisted_before_202_ack_and_then_projected():
    tx, inbox, projection = lab.stream_fixture()
    result = inbox.receive(tx.issue(lab.CAEP_RISK_LEVEL_CHANGE, {"sequence": 1, "risk_level": "high"}))
    assert result.http_status == 202
    assert result.outcome == "persisted"
    assert len(inbox.pending()) == 1
    evidence = projection.apply_pending(inbox)
    assert projection.get().risk_level == "high"
    assert evidence[0]["received_ms"] < evidence[0]["validated_ms"] < evidence[0]["persisted_ms"] < evidence[0]["projected_ms"]


def test_duplicate_set_is_idempotent_and_returns_same_protocol_status():
    tx, inbox, projection = lab.stream_fixture()
    token = tx.issue(lab.CAEP_SESSION_REVOKED, {"sequence": 1})
    assert inbox.receive(token).outcome == "persisted"
    assert inbox.receive(token).outcome == "duplicate"
    assert len(inbox.pending()) == 1
    projection.apply_pending(inbox)
    assert not projection.get().session_active


@pytest.mark.parametrize(
    "token_builder,reason",
    [
        (lambda tx: tx.issue(lab.CAEP_SESSION_REVOKED, {"sequence": 1}, typ="JWT"), "set_typ_invalid"),
        (lambda tx: tx.issue(lab.CAEP_SESSION_REVOKED, {"sequence": 1}, audience="https://wrong.example"), "set_audience_invalid"),
        (lambda tx: tx.issue(lab.CAEP_SESSION_REVOKED, {"sequence": 1}, issuer="https://evil.example"), "set_issuer_invalid"),
        (lambda tx: tx.issue(lab.CAEP_SESSION_REVOKED, {"sequence": 1}, extra_claims={"sub": lab.SUBJECT}), "set_profile_invalid"),
        (lambda tx: tx.issue(lab.CAEP_SESSION_REVOKED, {"sequence": 1}, extra_claims={"exp": lab.NOW + 60}), "set_profile_invalid"),
        (lambda tx: tx.issue("https://evil.example/event", {"sequence": 1}), "event_type_not_allowed"),
        (lambda tx: tx.issue(lab.CAEP_SESSION_REVOKED, {"sequence": 0}), "event_sequence_invalid"),
    ],
)
def test_receiver_rejects_invalid_profiles(token_builder, reason):
    tx, inbox, _ = lab.stream_fixture()
    with pytest.raises(lab.LabError, match=reason):
        inbox.receive(token_builder(tx))


def test_receiver_rejects_wrong_signature():
    tx, inbox, _ = lab.stream_fixture()
    attacker = lab.SetTransmitter(issuer=tx.issuer, kid=tx.kid)
    with pytest.raises(lab.LabError, match="set_signature_invalid"):
        inbox.receive(attacker.issue(lab.CAEP_SESSION_REVOKED, {"sequence": 1}))


def test_receiver_rejects_two_events_in_one_set():
    tx, inbox, _ = lab.stream_fixture()
    token = tx.issue(
        lab.CAEP_SESSION_REVOKED,
        {"sequence": 1},
        extra_claims={"events": {lab.CAEP_SESSION_REVOKED: {"sequence": 1}, lab.CAEP_RISK_LEVEL_CHANGE: {"sequence": 1}}},
    )
    with pytest.raises(lab.LabError, match="set_event_count_invalid"):
        inbox.receive(token)


def test_subject_scoping_prevents_cross_subject_revocation():
    tx, inbox, projection = lab.stream_fixture()
    lab.apply_event(tx, inbox, projection, lab.CAEP_SESSION_REVOKED, {"sequence": 1}, subject=lab.OTHER_SUBJECT)
    assert projection.get(lab.SUBJECT).session_active
    assert not projection.get(lab.OTHER_SUBJECT).session_active


def test_unknown_subject_receives_fail_closed_projection_and_cannot_authorize():
    projection = lab.ProjectionStore()
    unknown = projection.get(lab.OTHER_SUBJECT)
    assert not unknown.session_active
    decision = lab.ReferencePDP().evaluate(
        replace(lab.VerifiedCaller(), subject_id=lab.OTHER_SUBJECT),
        lab.proposal("claim.read"),
        unknown,
    )
    assert not decision.allowed
    assert "subject_not_authorized_for_resource" in decision.reason_codes


def test_newer_risk_event_does_not_suppress_older_session_revocation():
    tx, inbox, projection = lab.stream_fixture()
    lab.apply_event(tx, inbox, projection, lab.CAEP_RISK_LEVEL_CHANGE, {"sequence": 9, "risk_level": "low"}, jti="risk-9")
    lab.apply_event(tx, inbox, projection, lab.CAEP_SESSION_REVOKED, {"sequence": 1}, jti="session-1")
    assert not projection.get().session_active
    assert projection.get().cursors == {"risk": 9, "session": 1}


def test_stale_relaxation_is_ignored_but_late_restriction_is_applied():
    tx, inbox, projection = lab.stream_fixture()
    lab.apply_event(tx, inbox, projection, lab.CAEP_RISK_LEVEL_CHANGE, {"sequence": 2, "risk_level": "high"}, jti="risk-2")
    evidence = lab.apply_event(tx, inbox, projection, lab.CAEP_RISK_LEVEL_CHANGE, {"sequence": 1, "risk_level": "low"}, jti="risk-1")
    assert projection.get().risk_level == "high"
    assert evidence[-1]["outcome"] == "stale_relaxation_ignored"
    lab.apply_event(tx, inbox, projection, lab.CAEP_SESSION_REVOKED, {"sequence": 2}, jti="session-2")
    evidence = lab.apply_event(tx, inbox, projection, lab.CAEP_SESSION_REVOKED, {"sequence": 1}, jti="session-1")
    assert not projection.get().session_active
    assert evidence[-1]["outcome"] == "restriction_applied"


def test_gap_marks_stream_stale_and_blocks_write_but_not_defined_read():
    tx, inbox, projection = lab.stream_fixture()
    evidence = lab.apply_event(tx, inbox, projection, lab.CAEP_RISK_LEVEL_CHANGE, {"sequence": 3, "risk_level": "low"})
    assert evidence[-1]["outcome"].startswith("gap_detected")
    assert not projection.get().stream_fresh
    pdp = lab.ReferencePDP()
    assert not pdp.evaluate(lab.VerifiedCaller(), lab.proposal("claim.update"), projection.get()).allowed
    assert pdp.evaluate(lab.VerifiedCaller(), lab.proposal("claim.read"), projection.get()).allowed


def test_restart_reopens_durable_unprocessed_event(tmp_path):
    database = tmp_path / "inbox.db"
    tx, inbox, _ = lab.stream_fixture(database)
    inbox.receive(tx.issue(lab.CAEP_SESSION_REVOKED, {"sequence": 1}))
    reopened = lab.SecurityEventInbox(inbox.config, database)
    projection = lab.ProjectionStore()
    projection.apply_pending(reopened)
    assert not projection.get().session_active


def test_cache_key_binds_amount_purpose_tenant_and_projection():
    caller = lab.VerifiedCaller()
    p = lab.proposal("payment.create")
    state = lab.AuthorizationProjection()
    variants = [
        replace(p, amount_cents=p.amount_cents + 1),
        replace(p, purpose="other"),
        replace(p, tenant_id="tenant:other"),
    ]
    approval = lab.make_approval(p, state)
    original = lab.DecisionCache.key(caller, p, state, approval)
    assert all(lab.DecisionCache.key(caller, item, state, approval) != original for item in variants)
    assert lab.DecisionCache.key(caller, p, replace(state, risk_level="high"), approval) != original
    assert lab.DecisionCache.key(caller, p, state, None) != original
    assert lab.vulnerable_cache_key(p) == lab.vulnerable_cache_key(variants[0])


def test_pep_reauthorizes_at_commit_and_blocks_midflight_revocation():
    tx, inbox, projection = lab.stream_fixture()
    pep = lab.PolicyEnforcementPoint(projection)
    p = lab.proposal("claim.update")

    def revoke():
        lab.apply_event(tx, inbox, projection, lab.CAEP_SESSION_REVOKED, {"sequence": 1})

    with pytest.raises(lab.LabError, match="session_revoked"):
        pep.execute(lab.VerifiedCaller(), p, before_commit=revoke)
    assert not pep.effects
    assert pep.evidence[-1]["outcome"] == "not_executed"


def test_resume_after_wait_uses_current_state_not_old_lease():
    tx, inbox, projection = lab.stream_fixture()
    pep = lab.PolicyEnforcementPoint(projection)
    p = lab.proposal("claim.update")
    assert pep.authorize(lab.VerifiedCaller(), p).allowed
    lab.apply_event(tx, inbox, projection, lab.INTERNAL_TASK_CHANGE, {"sequence": 1, "task_active": False})
    with pytest.raises(lab.LabError, match="task_inactive_or_expired"):
        pep.execute(lab.VerifiedCaller(), p)


def test_changed_payment_cannot_reuse_exact_approval():
    state = lab.AuthorizationProjection()
    original = lab.proposal("payment.create")
    approval = lab.make_approval(original, state)
    changed = replace(original, amount_cents=30_000)
    decision = lab.ReferencePDP().evaluate(lab.VerifiedCaller(), changed, state, approval)
    assert not decision.allowed
    assert "approval_proposal_digest_mismatch" in decision.reason_codes


def test_payment_approval_is_single_use():
    projection = lab.ProjectionStore()
    pep = lab.PolicyEnforcementPoint(projection)
    first = lab.proposal("payment.create", "op-1")
    approval = lab.make_approval(first)
    pep.execute(lab.VerifiedCaller(), first, approval)
    second = replace(first, operation_id="op-2")
    # A changed operation changes the proposal digest, so the old receipt fails even before consumption.
    with pytest.raises(lab.LabError, match="approval_proposal_digest_mismatch"):
        pep.execute(lab.VerifiedCaller(), second, approval)


def test_approval_store_rejects_direct_replay():
    approval = lab.make_approval(lab.proposal("payment.create"))
    store = lab.ApprovalStore()
    store.consume(approval)
    with pytest.raises(lab.LabError, match="approval_replayed"):
        store.consume(approval)


def test_exact_retry_reconciles_and_changed_operation_conflicts():
    pep = lab.PolicyEnforcementPoint(lab.ProjectionStore())
    p = lab.proposal("claim.update")
    result = pep.execute(lab.VerifiedCaller(), p)
    assert pep.execute(lab.VerifiedCaller(), p) == result
    with pytest.raises(lab.LabError, match="operation_id_conflict"):
        pep.execute(lab.VerifiedCaller(), replace(p, purpose="changed"))


def test_pdp_outage_fails_closed():
    class Unavailable:
        def evaluate(self, *args, **kwargs):
            raise ConnectionError("down")

    pep = lab.PolicyEnforcementPoint(lab.ProjectionStore(), Unavailable())
    with pytest.raises(lab.LabError, match="pdp_unavailable"):
        pep.authorize(lab.VerifiedCaller(), lab.proposal("claim.update"))


def test_commit_time_pdp_outage_records_denial_and_no_effect():
    class FailsSecondDecision:
        def __init__(self):
            self.calls = 0

        def evaluate(self, *args, **kwargs):
            self.calls += 1
            if self.calls == 2:
                raise ConnectionError("down")
            return lab.ReferencePDP().evaluate(*args, **kwargs)

    pep = lab.PolicyEnforcementPoint(lab.ProjectionStore(), FailsSecondDecision())
    with pytest.raises(lab.LabError, match="pdp_unavailable"):
        pep.execute(lab.VerifiedCaller(), lab.proposal("claim.update"))
    assert not pep.effects
    assert pep.evidence[-1]["reason_codes"] == ["pdp_unavailable"]


def test_evidence_uses_digests_not_sensitive_approval_contents():
    pep = lab.PolicyEnforcementPoint(lab.ProjectionStore())
    p = lab.proposal("payment.create")
    approval = lab.make_approval(p)
    pep.execute(lab.VerifiedCaller(), p, approval)
    evidence = str(pep.evidence[-1])
    assert approval.receipt_id not in evidence
    assert len(pep.evidence[-1]["proposal_digest"]) == 64


def test_openfga_sdk_request_models_task_intersection():
    request = lab.openfga_check()
    assert request.user == lab.AGENT
    assert request.relation == "can_update"
    assert request.object == lab.CLAIM
    tuples = {(item.user, item.relation, item.object) for item in request.contextual_tuples}
    assert (lab.AGENT, "assignee", lab.TASK) in tuples
    assert (lab.AGENT, "delegated_agent", lab.TASK) in tuples
    assert (lab.TASK, "assigned_task", lab.CLAIM) in tuples


def test_opa_input_contains_no_raw_token_or_private_key():
    document = lab.opa_input(lab.VerifiedCaller(), lab.proposal(), lab.AuthorizationProjection())
    serialized = str(document).lower()
    assert "compact_set" not in serialized
    assert "bearer" not in serialized
    assert "private_key" not in serialized
    assert document["projection"]["policy_version"] == lab.POLICY_VERSION
    assert document["proposal"]["digest"] == lab.proposal_digest(lab.proposal())


def test_propagation_metrics_use_stage_timestamps_not_sleep():
    tx, inbox, projection = lab.stream_fixture()
    evidence = lab.apply_event(tx, inbox, projection, lab.CAEP_SESSION_REVOKED, {"sequence": 1})
    metrics = lab.propagation_metrics(evidence, inbox.clock.tick())
    assert metrics == {
        "receive_to_persist_ms": 2,
        "persist_to_project_ms": 1,
        "project_to_enforce_ms": 1,
        "receive_to_enforce_ms": 4,
    }


def test_set_payload_uses_sub_id_and_omits_sub_and_exp():
    tx, _, _ = lab.stream_fixture()
    token = tx.issue(lab.CAEP_SESSION_REVOKED, {"sequence": 1})
    claims = jwt.decode(token, options={"verify_signature": False})
    assert claims["sub_id"]["format"] == "iss_sub"
    assert "sub" not in claims
    assert "exp" not in claims
