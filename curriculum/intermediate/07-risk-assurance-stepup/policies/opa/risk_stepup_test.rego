package agent.risk_stepup_test

import rego.v1
import data.agent.risk_stepup

base := {
  "now": 1800000000,
  "policy_version": 14,
  "action": "payment.create",
  "required_scope": "payments:create",
  "caller": {"subject_id": "user:alice", "tenant_id": "tenant:northstar", "agent_id": "agent:claims-adjuster", "client_id": "client:claims-copilot", "task_id": "task:clm-100-review", "scopes": ["payments:create"], "aal": 2, "phishing_resistant": true, "non_exportable_key": false, "auth_time": 1799999940},
  "task": {"subject_id": "user:alice", "tenant_id": "tenant:northstar", "agent_id": "agent:claims-adjuster", "client_id": "client:claims-copilot", "task_id": "task:clm-100-review", "workload_id": "spiffe://northstar.example/prod/claims/adjuster", "actions": ["payment.create"], "resources": ["claim:clm-100"], "active": true},
  "resource": {"resource_id": "claim:clm-100", "tenant_id": "tenant:northstar", "owner_id": "user:alice", "version": 4},
  "workload": {"workload_id": "spiffe://northstar.example/prod/claims/adjuster", "image_digest": "sha256:approved-claims-build", "environment": "prod", "attested": true, "observed_at": 1799999970, "expires_at": 1800000270},
  "signals": {"version": 11},
  "risk": {"score": 65, "model_version": 8, "signal_version": 11, "hard_denials": []},
  "requirements": {"min_aal": 2, "phishing_resistant": true, "non_exportable_key": false, "max_auth_age": 300, "max_workload_age": 300, "approval_count": 1},
  "proposal": {"resource_id": "claim:clm-100", "digest": "sha256:payment"},
  "approval": {"id": "approval-001", "proposal_digest": "sha256:payment", "approver_ids": ["manager:bob"], "subject_id": "user:alice", "tenant_id": "tenant:northstar", "agent_id": "agent:claims-adjuster", "task_id": "task:clm-100-review", "risk_score": 65, "policy_version": 14, "risk_model_version": 8, "signal_version": 11, "resource_version": 4, "expires_at": 1800000180, "used": false},
}

test_exact_payment_allowed if { risk_stepup.decision.outcome == "allow" with input as base }

test_stale_user_authentication_steps_up if {
  request := object.union(base, {"caller": object.union(base.caller, {"auth_time": 1799999000})})
  risk_stepup.decision.outcome == "user_step_up" with input as request
}

test_stale_workload_requests_reattest if {
  request := object.union(base, {"workload": object.union(base.workload, {"observed_at": 1799999000})})
  risk_stepup.decision.outcome == "workload_step_up" with input as request
}

test_missing_scope_is_distinct_from_user_stepup if {
  request := object.union(base, {"caller": object.union(base.caller, {"scopes": []})})
  risk_stepup.decision.outcome == "scope_required" with input as request
}

test_missing_approval_requests_approval if {
  request := object.union(base, {"approval": object.union(base.approval, {"id": ""})})
  risk_stepup.decision.outcome == "approval_required" with input as request
}

test_changed_proposal_denied if {
  request := object.union(base, {"proposal": object.union(base.proposal, {"digest": "sha256:changed"})})
  risk_stepup.decision.outcome == "deny" with input as request
}

test_self_approval_denied if {
  request := object.union(base, {"approval": object.union(base.approval, {"approver_ids": ["user:alice"]})})
  risk_stepup.decision.outcome == "deny" with input as request
}

test_risk_model_drift_denied if {
  request := object.union(base, {"risk": object.union(base.risk, {"model_version": 7})})
  risk_stepup.decision.outcome == "deny" with input as request
}

test_wrong_resource_denied_before_stepup if {
  request := object.union(base, {"proposal": object.union(base.proposal, {"resource_id": "claim:clm-999"}), "caller": object.union(base.caller, {"aal": 1})})
  risk_stepup.decision.outcome == "deny" with input as request
}

test_absolute_ceiling_survives_aal3 if {
  request := object.union(base, {"action": "audit.disable", "caller": object.union(base.caller, {"aal": 3, "non_exportable_key": true})})
  risk_stepup.decision.outcome == "deny" with input as request
}

test_evidence_carries_all_policy_versions if {
  result := risk_stepup.evidence with input as base
  result.outcome == "allow"
  result.policy_version == 14
  result.risk_model_version == 8
  result.signal_version == 11
  result.resource_version == 4
}
