"""Executable invariants for Intermediate 07 risk and step-up authorization."""

from concurrent.futures import ThreadPoolExecutor
import importlib.util
import json
from pathlib import Path
import sys
from urllib.parse import parse_qs, urlparse

import pytest
import cedarpy


LAB_PATH = Path(__file__).parents[1] / "lab.py"
SPEC = importlib.util.spec_from_file_location("intermediate07_lab", LAB_PATH)
lab = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = lab
SPEC.loader.exec_module(lab)


def approval_args(**updates):
    value = lab.payment_args(**updates)
    value.pop("approval_id")
    return value


def test_hardened_matrix_matches_every_label_and_release_gate():
    metrics, rows = lab.evaluate(lab.build_cases())
    assert len(rows) == 55
    assert metrics.matches == 55
    assert metrics.invalid_allows == 0
    assert metrics.valid_work_blocked == 0
    assert metrics.by_outcome == {
        "allow": 4,
        "constrain": 1,
        "user_step_up": 4,
        "workload_step_up": 3,
        "approval_required": 2,
        "scope_required": 1,
        "deny": 40,
        "reconciled": 0,
    }
    assert lab.release_gate(metrics)


def test_authenticated_only_baseline_has_many_invalid_allows():
    metrics, _ = lab.evaluate(lab.build_cases(), hardened=False)
    assert metrics.invalid_allows == 40
    assert metrics.matches == 4
    assert not lab.release_gate(metrics)


@pytest.mark.parametrize("case", lab.build_cases(), ids=lambda case: case.case_id)
def test_each_scenario_matches_its_label(case):
    assert lab.run_case(case) is case.expected


def test_acr_registry_keeps_assurance_properties_separate():
    assert lab.ACR_REGISTRY[lab.ACR_AAL2].aal == 2
    assert not lab.ACR_REGISTRY[lab.ACR_AAL2].phishing_resistant
    assert lab.ACR_REGISTRY[lab.ACR_AAL2_PHISHING].phishing_resistant
    assert lab.ACR_REGISTRY[lab.ACR_AAL3].non_exportable_key


def test_session_verifier_derives_assurance_from_trusted_acr_mapping():
    issuer, engine, token = lab.fixture(acr=lab.ACR_AAL3)
    session = engine.verifier.verify(token)
    assert session.aal == 3
    assert session.phishing_resistant
    assert session.non_exportable_key


def test_unknown_acr_is_denied_not_treated_as_a_higher_number():
    issuer, engine, _ = lab.fixture()
    decision = engine.authorize(
        issuer.issue(acr="urn:caller:aal999"), "claim.read", {"claim_id": lab.CLAIM}
    )
    assert decision.outcome is lab.Outcome.DENY
    assert decision.reason_codes == ("acr_untrusted",)


def test_rfc9470_challenge_is_a_real_www_authenticate_header():
    challenge = lab.StepUpChallenge((lab.ACR_AAL2_PHISHING, lab.ACR_AAL3), 300)
    assert challenge.status == 401
    assert 'error="insufficient_user_authentication"' in challenge.www_authenticate
    assert (
        f'acr_values="{lab.ACR_AAL2_PHISHING} {lab.ACR_AAL3}"'
        in challenge.www_authenticate
    )
    assert 'max_age="300"' in challenge.www_authenticate
    assert challenge.authorization_parameters() == {
        "acr_values": f"{lab.ACR_AAL2_PHISHING} {lab.ACR_AAL3}",
        "max_age": "300",
    }


def test_payment_returns_step_up_for_valid_but_stale_user_authentication():
    issuer, engine, token = lab.fixture(auth_time=lab.NOW - 301)
    decision = engine.authorize(token, "payment.create", lab.payment_args())
    assert decision.outcome is lab.Outcome.USER_STEP_UP
    assert decision.challenge.status == 401
    assert "user_authentication_stale" in decision.reason_codes


def test_step_up_cannot_repair_an_ineligible_resource():
    issuer, engine, token = lab.fixture(acr=lab.ACR_AAL1, auth_time=lab.NOW - 10_000)
    decision = engine.authorize(token, "claim.read", {"claim_id": "claim:clm-999"})
    assert decision.outcome is lab.Outcome.DENY
    assert "resource_unknown" in decision.reason_codes
    assert decision.challenge is None


def test_missing_scope_is_not_misrepresented_as_user_authentication_step_up():
    issuer, engine, token = lab.fixture(scopes=("claims:read",))
    decision = engine.authorize(token, "payment.create", lab.payment_args())
    assert decision.outcome is lab.Outcome.SCOPE_REQUIRED
    assert decision.challenge is None
    assert decision.obligations == ("request_scope:payments:create",)


def test_stale_workload_requests_reattest_but_wrong_image_is_denied():
    _, stale, token = lab.fixture()
    stale.workload.observed_at = lab.NOW - 1_000
    decision = stale.authorize(token, "payment.create", lab.payment_args())
    assert decision.outcome is lab.Outcome.WORKLOAD_STEP_UP
    assert decision.obligations == ("refresh_workload_attestation",)
    _, wrong, token = lab.fixture()
    wrong.workload.image_digest = "sha256:attacker"
    decision = wrong.authorize(token, "payment.create", lab.payment_args())
    assert decision.outcome is lab.Outcome.DENY
    assert decision.reason_codes == ("workload_image_unapproved",)


def test_risk_assessment_is_explainable_and_versioned():
    _, engine, token = lab.fixture()
    engine.signals.device_state = "unknown"
    decision = engine.authorize(token, "claim.read", {"claim_id": lab.CLAIM})
    assert decision.risk.model_version == lab.RISK_MODEL_VERSION
    assert decision.risk.signal_version == lab.SIGNAL_VERSION
    assert "device_unknown:+15" in decision.risk.reason_codes
    assert "base_risk:20" in decision.risk.reason_codes


def test_prompt_injection_signal_removes_write_authority_in_trusted_code():
    _, engine, token = lab.fixture()
    engine.signals.prompt_injection_score = 0.99
    decision = engine.authorize(
        token,
        "claim.update",
        {
            "claim_id": lab.CLAIM,
            "expected_version": 4,
            "note": "looks safe",
            "operation_id": "op-update",
        },
    )
    assert decision.outcome is lab.Outcome.DENY
    assert "prompt_injection_blocks_side_effect" in decision.reason_codes


def test_begin_step_up_binds_state_to_request_identity_and_requirement():
    issuer, engine, token = lab.fixture(acr=lab.ACR_AAL1)
    transaction, url = engine.begin_user_step_up(
        token, "payment.create", lab.payment_args()
    )
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    assert parsed.scheme == "https"
    assert parsed.netloc == "id.northstar.example"
    assert params["state"] == [transaction.handle]
    assert params["max_age"] == ["300"]
    assert params["acr_values"] == [f"{lab.ACR_AAL2_PHISHING} {lab.ACR_AAL3}"]
    assert transaction.request_digest


def test_complete_step_up_accepts_fresh_matching_session_once():
    issuer, engine, token = lab.fixture(acr=lab.ACR_AAL1)
    transaction, _ = engine.begin_user_step_up(
        token, "payment.create", lab.payment_args()
    )
    stepped = issuer.issue(
        acr=lab.ACR_AAL2_PHISHING, auth_time=lab.NOW, jti="session-stepup"
    )
    session = engine.complete_user_step_up(transaction.handle, stepped)
    assert session.aal == 2
    with pytest.raises(lab.LabError, match="step_up_transaction_consumed"):
        engine.complete_user_step_up(transaction.handle, stepped)


@pytest.mark.parametrize(
    "token_kwargs,reason",
    [
        (
            {"subject_id": "user:mallory", "acr": lab.ACR_AAL2_PHISHING},
            "step_up_identity_binding_invalid",
        ),
        (
            {"tenant_id": "tenant:evil", "acr": lab.ACR_AAL2_PHISHING},
            "step_up_identity_binding_invalid",
        ),
        (
            {"agent_id": "agent:evil", "acr": lab.ACR_AAL2_PHISHING},
            "step_up_identity_binding_invalid",
        ),
        (
            {"client_id": "client:evil", "acr": lab.ACR_AAL2_PHISHING},
            "step_up_identity_binding_invalid",
        ),
        (
            {"task_id": "task:evil", "acr": lab.ACR_AAL2_PHISHING},
            "step_up_identity_binding_invalid",
        ),
        ({"acr": lab.ACR_AAL1}, "step_up_acr_unsatisfied"),
        (
            {"acr": lab.ACR_AAL2_PHISHING, "auth_time": lab.NOW - 301},
            "step_up_freshness_unsatisfied",
        ),
    ],
)
def test_step_up_completion_rejects_identity_downgrade_or_staleness(
    token_kwargs, reason
):
    issuer, engine, token = lab.fixture(acr=lab.ACR_AAL1)
    transaction, _ = engine.begin_user_step_up(
        token, "payment.create", lab.payment_args()
    )
    with pytest.raises(lab.LabError, match=reason):
        engine.complete_user_step_up(transaction.handle, issuer.issue(**token_kwargs))


def test_payment_approval_binds_exact_proposal_risk_and_versions():
    _, engine, token = lab.fixture()
    approval = engine.record_approval(token, approval_args())
    assert approval.risk_score > 0
    assert approval.policy_version == lab.POLICY_VERSION
    assert approval.risk_model_version == lab.RISK_MODEL_VERSION
    assert approval.signal_version == lab.SIGNAL_VERSION
    assert approval.resource_version == lab.RESOURCE_VERSION
    decision = engine.authorize(token, "payment.create", lab.payment_args())
    assert decision.outcome is lab.Outcome.ALLOW


@pytest.mark.parametrize(
    "change,reason",
    [
        (
            lambda engine, args: args.update(amount_cents=30_001),
            "approval_binding_invalid",
        ),
        (
            lambda engine, args: args.update(beneficiary_id="vendor:attacker"),
            "approval_binding_invalid",
        ),
        (
            lambda engine, args: setattr(
                engine.signals, "version", lab.SIGNAL_VERSION + 1
            ),
            "approval_binding_invalid",
        ),
        (
            lambda engine, args: setattr(
                engine.resource, "version", lab.RESOURCE_VERSION + 1
            ),
            "approval_binding_invalid",
        ),
        (
            lambda engine, args: setattr(
                engine.approvals["approval-001"], "used", True
            ),
            "approval_consumed",
        ),
    ],
)
def test_approval_mutation_replay_and_version_changes_fail(change, reason):
    _, engine, token = lab.fixture(acr=lab.ACR_AAL3)
    args = lab.payment_args()
    engine.record_approval(
        token, approval_args(), approver_ids=("manager:bob", "controller:carol")
    )
    change(engine, args)
    decision = engine.authorize(token, "payment.create", args)
    assert decision.outcome is lab.Outcome.DENY
    assert reason in decision.reason_codes


def test_high_value_payment_requires_two_distinct_independent_approvers():
    _, engine, token = lab.fixture(acr=lab.ACR_AAL3)
    args = lab.payment_args(amount_cents=1_500_000)
    engine.record_approval(
        token, approval_args(amount_cents=1_500_000), approver_ids=("manager:bob",)
    )
    decision = engine.authorize(token, "payment.create", args)
    assert decision.reason_codes == ("approval_count_insufficient",)
    engine.record_approval(
        token,
        approval_args(amount_cents=1_500_000),
        approver_ids=("manager:bob", "controller:carol"),
    )
    assert engine.authorize(token, "payment.create", args).outcome is lab.Outcome.ALLOW


def test_requester_or_agent_cannot_approve_own_payment():
    _, engine, token = lab.fixture()
    engine.record_approval(token, approval_args(), approver_ids=(lab.SUBJECT,))
    decision = engine.authorize(token, "payment.create", lab.payment_args())
    assert decision.outcome is lab.Outcome.DENY
    assert decision.reason_codes == ("separation_of_duties_violated",)


def test_absolute_deny_ceiling_survives_aal3_and_fake_approval():
    _, engine, token = lab.fixture(acr=lab.ACR_AAL3, scopes=("admin:audit",))
    decision = engine.authorize(
        token,
        "audit.disable",
        {"control": "authorization-audit", "operation_id": "op-audit"},
    )
    assert decision.outcome is lab.Outcome.DENY
    assert "agent_action_prohibited" in decision.reason_codes


def test_commit_time_reassessment_closes_signal_change_race():
    _, engine, token = lab.fixture()
    args = {
        "claim_id": lab.CLAIM,
        "expected_version": 4,
        "note": "reviewed",
        "operation_id": "op-update",
    }
    with pytest.raises(lab.LabError, match="device_compromised"):
        engine.execute(
            token,
            "claim.update",
            args,
            before_commit=lambda value: setattr(
                value.signals, "device_state", "compromised"
            ),
        )
    assert engine.effect_count == 0
    assert engine.resource.version == 4


def test_lost_response_reconciles_exact_retry_without_duplicate_effect():
    _, engine, token = lab.fixture()
    args = {
        "claim_id": lab.CLAIM,
        "expected_version": 4,
        "note": "reviewed",
        "operation_id": "op-update",
    }
    with pytest.raises(lab.UnknownOutcome):
        engine.execute(token, "claim.update", args, lose_response_after_commit=True)
    result = engine.execute(token, "claim.update", args)
    assert result["reconciled"] is True
    assert engine.effect_count == 1


def test_concurrent_exact_retries_create_one_effect():
    _, engine, token = lab.fixture()
    args = {
        "claim_id": lab.CLAIM,
        "expected_version": 4,
        "note": "reviewed",
        "operation_id": "op-race",
    }
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(
            pool.map(lambda _: engine.execute(token, "claim.update", args), range(8))
        )
    assert engine.effect_count == 1
    assert sum(result.get("reconciled", False) for result in results) == 7


def test_audit_evidence_is_versioned_and_does_not_store_raw_token():
    _, engine, token = lab.fixture()
    engine.authorize(token, "claim.read", {"claim_id": lab.CLAIM})
    event = engine.audit[-1]
    assert event["policy_version"] == lab.POLICY_VERSION
    assert event["risk_model_version"] == lab.RISK_MODEL_VERSION
    assert event["signal_version"] == lab.SIGNAL_VERSION
    assert len(event["token_fingerprint"]) == 16
    assert token not in lab.canonical(event)


def test_cedar_policy_parses_and_validates_against_its_schema():
    policy_dir = LAB_PATH.parent / "policies" / "cedar"
    policies = (policy_dir / "risk_stepup.cedar").read_text()
    schema = json.loads((policy_dir / "schema.json").read_text())
    assert len(cedarpy.PolicySet.from_str(policies)) == 4
    result = cedarpy.validate_policies(policies, schema)
    assert result.validation_passed, result.errors
