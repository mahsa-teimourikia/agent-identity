"""Course 06 invariant tests for governed agent-identity lifecycle."""

from dataclasses import replace
import importlib.util
from pathlib import Path
import sys
from threading import Thread


LAB_PATH = Path(__file__).parents[1] / "lab.py"
SPEC = importlib.util.spec_from_file_location("course06_lab", LAB_PATH)
lab = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = lab
SPEC.loader.exec_module(lab)


def controlled_rows():
    return lab.evaluate(lab.build_cases(), lab.hardened_factory)[1]


def row_map():
    return {case_id: (expected, result) for case_id, expected, result in controlled_rows()}


def seeded(state, **kwargs):
    manager = lab.LifecycleController()
    manager.seed(lab.build_record(state, **kwargs))
    return manager


def test_all_labelled_outcomes_match_and_release_gate_passes():
    metrics, rows = lab.evaluate(lab.build_cases(), lab.hardened_factory)

    assert all(result.decision.outcome is expected for _, expected, result in rows)
    assert metrics.attempts == 20
    assert metrics.expected_applied == 7
    assert metrics.expected_blocked == 12
    assert metrics.expected_partial == 1
    assert lab.release_gate(metrics)


def test_lifecycle_request_cannot_supply_actor_roles_tenant_or_approval():
    fields = set(lab.LifecycleRequest.__dataclass_fields__)

    assert not fields.intersection(
        {"actor_id", "roles", "tenant_id", "sponsor_id", "approval", "credential"}
    )


def test_payload_schema_rejects_extra_authority_fields():
    manager = seeded(lab.LifecycleState.DRAFT)
    request = lab.make_request(
        manager,
        lab.Action.REGISTER,
        {"roles": ["iam_admin"]},
        operation_id="operation:payload-authority-injection",
    )
    result = manager.execute(lab.context("user:owner", lab.Role.OWNER), request)

    assert result.decision.reason_code == "payload_invalid"
    assert manager.get().state is lab.LifecycleState.DRAFT
    assert not result.effect_committed


def test_registration_requires_active_owner_sponsor_and_blueprint():
    rows = row_map()

    assert rows["valid_registration"][1].decision.reason_code == "agent_registered"
    assert rows["inactive_sponsor"][1].decision.reason_code == "sponsor_invalid"
    assert rows["cross_tenant_admin"][1].decision.reason_code == "tenant_mismatch"


def test_approval_is_exact_independent_and_single_use():
    manager = seeded(lab.LifecycleState.UNDER_REVIEW)
    request = lab.make_request(
        manager,
        lab.Action.APPROVE,
        {"manifest_digest": manager.get().manifest_digest},
        operation_id="operation:approval-single-use",
    )
    approval = lab.make_approval(request)
    admin = lab.context("user:iam", lab.Role.IAM_ADMIN)

    first = manager.execute(admin, request, approval=approval)
    exact_retry = manager.execute(admin, request, approval=approval)

    assert first.decision.outcome is lab.Outcome.APPLIED
    assert manager.approvals.was_consumed(approval.approval_id)
    assert exact_retry.decision.reason_code == "operation_reconciled"
    assert exact_retry.decision.reconciled
    assert not exact_retry.effect_committed

    rows = row_map()
    assert rows["self_approval"][1].decision.reason_code == "separation_of_duties_violation"
    assert rows["altered_approval"][1].decision.reason_code == "approval_not_bound"


def test_approval_role_is_rechecked_against_authoritative_directory():
    manager = seeded(lab.LifecycleState.UNDER_REVIEW)
    request = lab.make_request(
        manager,
        lab.Action.APPROVE,
        {"manifest_digest": manager.get().manifest_digest},
        operation_id="operation:forged-approver-role",
    )
    forged = lab.make_approval(request, approver_id="user:iam")
    result = manager.execute(
        lab.context("user:risk", lab.Role.IAM_ADMIN), request, approval=forged
    )

    assert result.decision.reason_code == "approver_not_authorized"
    assert not result.effect_committed


def test_provisioning_binds_exact_manifest_to_attested_workload():
    rows = row_map()

    assert rows["overbroad_provisioning"][1].decision.reason_code == "capability_manifest_mismatch"
    assert rows["wrong_workload_binding"][1].decision.reason_code == "workload_not_attested"
    assert rows["valid_provisioning"][1].decision.reason_code == "assets_provisioned"


def test_activation_requires_current_review_and_complete_assets():
    rows = row_map()

    assert rows["overdue_activation"][1].decision.reason_code == "review_overdue"
    assert rows["valid_activation"][1].decision.reason_code == "agent_activated"

    manager = seeded(lab.LifecycleState.PROVISIONED)
    manager.records[lab.AGENT_ID] = replace(manager.get(), credential_profiles=())
    request = lab.make_request(
        manager, lab.Action.ACTIVATE, operation_id="operation:missing-credential"
    )
    result = manager.execute(
        lab.context("workload:platform", lab.Role.PLATFORM), request
    )
    assert result.decision.reason_code == "credential_profile_missing"


def test_optimistic_version_allows_only_one_concurrent_review():
    manager = seeded(lab.LifecycleState.ACTIVE)
    version = manager.get().version
    sponsor = lab.context("user:alice", lab.Role.SPONSOR)
    payload = {
        "verdict": lab.ReviewVerdict.CONTINUE,
        "justification": "The bounded travel access is still required.",
    }
    requests = [
        lab.make_request(
            manager,
            lab.Action.RECERTIFY,
            payload,
            operation_id=f"operation:concurrent-review-{index}",
            expected_version=version,
        )
        for index in range(2)
    ]
    results = []

    threads = [Thread(target=lambda req=req: results.append(manager.execute(sponsor, req))) for req in requests]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert sorted(result.decision.outcome.value for result in results) == ["applied", "denied"]
    assert {result.decision.reason_code for result in results} == {
        "access_recertified",
        "stale_record_version",
    }


def test_recertification_requires_the_current_sponsor():
    rows = row_map()

    assert rows["wrong_reviewer"][1].decision.reason_code == "reviewer_not_sponsor"
    assert rows["valid_recertification"][1].decision.reason_code == "access_recertified"


def test_verified_sponsor_succession_updates_manifest_digest():
    manager = seeded(lab.LifecycleState.ACTIVE)
    original = manager.get()
    manager.directory["user:alice"] = replace(
        manager.directory["user:alice"], active=False
    )
    request = lab.make_request(
        manager,
        lab.Action.TRANSFER_SPONSOR,
        {
            "expected_old_sponsor_id": "user:alice",
            "new_sponsor_id": "user:director-travel",
        },
        operation_id="operation:sponsor-succession",
    )
    result = manager.execute(lab.context("user:iam", lab.Role.IAM_ADMIN), request)

    assert result.decision.outcome is lab.Outcome.APPLIED
    assert manager.get().manifest.sponsor_id == "user:director-travel"
    assert manager.get().manifest_digest != original.manifest_digest


def test_material_change_invalidates_runtime_and_requires_review():
    scenario = next(case for case in lab.build_cases() if case.case_id == "material_change")
    manager = seeded(lab.LifecycleState.ACTIVE)
    request = lab.make_request(
        manager,
        scenario.action,
        scenario.payload_factory(manager.get()),
        operation_id="operation:material-change-test",
    )
    result = manager.execute(lab.context("user:owner", lab.Role.OWNER), request)
    record = manager.get()

    assert result.decision.reason_code == "material_change_requires_review"
    assert record.state is lab.LifecycleState.UNDER_REVIEW
    assert record.next_review_at is None
    assert all(item.status == "suspended" for item in record.access_grants)
    assert all(item.status == "suspended" for item in record.credential_profiles)
    assert all(item.status == "revoked" for item in record.sessions)


def test_reactivation_requires_bound_approval_and_rotated_credentials():
    manager = seeded(lab.LifecycleState.SUSPENDED)
    request = lab.make_request(
        manager,
        lab.Action.REACTIVATE,
        {"incident_id": "incident:travel-2026-09", "credential_generation": 1},
        operation_id="operation:reactivate-without-rotation",
    )
    approval = lab.make_approval(request)
    result = manager.execute(
        lab.context("service:soc", lab.Role.SECURITY), request, approval=approval
    )

    assert result.decision.reason_code == "credentials_not_rotated"
    assert manager.get().state is lab.LifecycleState.SUSPENDED
    assert row_map()["reactivation_needs_approval"][1].decision.outcome is lab.Outcome.APPROVAL_REQUIRED


def test_emergency_revocation_propagates_to_every_runtime_artifact():
    manager = seeded(lab.LifecycleState.ACTIVE)
    request = lab.make_request(
        manager,
        lab.Action.REVOKE,
        {"reason": "Confirmed credential theft from the production runtime."},
        operation_id="operation:emergency-revoke",
    )
    result = manager.execute(lab.context("service:soc", lab.Role.SECURITY), request)
    record = manager.get()

    assert result.decision.reason_code == "revocation_propagated"
    assert record.state is lab.LifecycleState.REVOKED
    assert all(item.status == "revoked" for item in record.workload_bindings)
    assert all(item.status == "revoked" for item in record.access_grants)
    assert all(item.status == "revoked" for item in record.credential_profiles)
    assert all(item.status == "revoked" for item in record.sessions)


def test_retirement_reports_partial_cleanup_then_resumes_idempotently():
    manager = seeded(lab.LifecycleState.REVOKED)
    request = lab.make_request(
        manager,
        lab.Action.RETIRE,
        {"reason": "The replacement agent completed its production cutover."},
        operation_id="operation:retirement-resume",
    )
    adapter = lab.CleanupAdapter(fail_once_on="cleanup:credentials")
    sponsor = lab.context("user:alice", lab.Role.SPONSOR)

    first = manager.execute(sponsor, request, cleanup=adapter)
    second = manager.execute(sponsor, request, cleanup=adapter)
    third = manager.execute(sponsor, request, cleanup=adapter)

    assert first.decision.outcome is lab.Outcome.PARTIAL
    assert manager.get().state is lab.LifecycleState.RETIRED
    assert second.cleanup_verified
    assert adapter.effect_count == 4
    assert third.decision.reason_code == "operation_reconciled"
    assert not third.effect_committed


def test_operation_id_cannot_be_reused_for_changed_request():
    manager = seeded(lab.LifecycleState.ACTIVE)
    security = lab.context("service:soc", lab.Role.SECURITY)
    first = lab.make_request(
        manager,
        lab.Action.SUSPEND,
        {"reason": "Investigate anomalous booking behavior immediately."},
        operation_id="operation:stable-id",
    )
    changed = replace(
        first,
        payload={"reason": "Different incident and therefore a different command."},
    )

    assert manager.execute(security, first).decision.outcome is lab.Outcome.APPLIED
    conflict = manager.execute(security, changed)

    assert conflict.decision.reason_code == "idempotency_conflict"
    assert not conflict.effect_committed


def test_audit_chain_is_complete_and_tamper_evident():
    manager = seeded(lab.LifecycleState.DRAFT)
    request = lab.make_request(
        manager, lab.Action.REGISTER, operation_id="operation:audit-chain"
    )
    result = manager.execute(lab.context("user:owner", lab.Role.OWNER), request)

    assert result.decision.evidence_complete
    assert manager.audit.verify()
    original = manager.audit.events[0]
    manager.audit._events = (replace(original, reason_code="tampered"),)
    assert not manager.audit.verify()


def test_state_transition_evidence_preserves_before_and_after():
    manager = seeded(lab.LifecycleState.DRAFT)
    request = lab.make_request(
        manager, lab.Action.REGISTER, operation_id="operation:evidence-state"
    )
    result = manager.execute(lab.context("user:owner", lab.Role.OWNER), request)

    assert result.decision.state_before is lab.LifecycleState.DRAFT
    assert result.decision.state_after is lab.LifecycleState.REGISTERED


def test_credential_profiles_contain_metadata_not_secrets():
    fields = set(lab.CredentialProfile.__dataclass_fields__)

    assert not fields.intersection({"token", "secret", "private_key", "password"})
    assert {"profile_id", "audience", "generation", "status"}.issubset(fields)


def test_baseline_performs_every_forbidden_effect_and_misses_partial_failure():
    baseline, _ = lab.evaluate(lab.build_cases(), lab.baseline_factory)
    hardened, _ = lab.evaluate(lab.build_cases(), lab.hardened_factory)

    assert baseline.outcome_match_rate == 7 / 20
    assert baseline.valid_apply_rate == 1.0
    assert baseline.forbidden_effect_rate == 1.0
    assert baseline.partial_detection_rate == 0.0
    assert hardened.outcome_match_rate == 1.0
    assert hardened.forbidden_effect_rate == 0.0
    assert hardened.partial_detection_rate == 1.0
    assert hardened.evidence_completeness_rate == 1.0


def test_json_schemas_are_strict_and_cover_every_action():
    schemas = lab.lifecycle_json_schemas()

    assert set(schemas) == {action.value for action in lab.Action}
    assert schemas[lab.Action.PROVISION.value]["additionalProperties"] is False
    assert set(schemas[lab.Action.PROVISION.value]["required"]) == {
        "workload_id",
        "capabilities",
        "credential_profiles",
    }
