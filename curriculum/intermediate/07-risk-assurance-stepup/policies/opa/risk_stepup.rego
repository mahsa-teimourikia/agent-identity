package agent.risk_stepup

import rego.v1

deny_reasons contains "policy_version_invalid" if { input.policy_version != 14 }
deny_reasons contains "risk_model_untrusted" if { input.risk.model_version != 8 }
deny_reasons contains "signal_version_invalid" if { input.risk.signal_version != input.signals.version }
deny_reasons contains "agent_action_prohibited" if { input.action == "audit.disable" }
deny_reasons contains "risk_ceiling_exceeded" if { input.risk.score >= 95 }
deny_reasons contains reason if { some reason in input.risk.hard_denials }
deny_reasons contains "task_inactive" if { not input.task.active }
deny_reasons contains "identity_task_binding_invalid" if { input.caller.subject_id != input.task.subject_id }
deny_reasons contains "identity_task_binding_invalid" if { input.caller.tenant_id != input.task.tenant_id }
deny_reasons contains "identity_task_binding_invalid" if { input.caller.agent_id != input.task.agent_id }
deny_reasons contains "identity_task_binding_invalid" if { input.caller.client_id != input.task.client_id }
deny_reasons contains "identity_task_binding_invalid" if { input.caller.task_id != input.task.task_id }
action_delegated if { input.action in input.task.actions }
deny_reasons contains "action_not_delegated" if { not action_delegated }
deny_reasons contains "resource_not_authorized" if { input.proposal.resource_id != input.resource.resource_id }
resource_delegated if { input.resource.resource_id in input.task.resources }
deny_reasons contains "resource_not_authorized" if { not resource_delegated }
deny_reasons contains "resource_not_authorized" if { input.resource.tenant_id != input.caller.tenant_id }
deny_reasons contains "resource_not_authorized" if { input.resource.owner_id != input.caller.subject_id }
deny_reasons contains "workload_binding_invalid" if { input.workload.workload_id != input.task.workload_id }
deny_reasons contains "workload_image_unapproved" if { input.workload.image_digest != "sha256:approved-claims-build" }
deny_reasons contains "workload_environment_invalid" if { input.workload.environment != "prod" }

approval_present if { input.approval.id != "" }
subject_is_approver if { input.caller.subject_id in input.approval.approver_ids }
agent_is_approver if { input.caller.agent_id in input.approval.approver_ids }

approval_exact if {
  approval_present
  not input.approval.used
  input.approval.expires_at > input.now
  input.approval.proposal_digest == input.proposal.digest
  input.approval.subject_id == input.caller.subject_id
  input.approval.tenant_id == input.caller.tenant_id
  input.approval.agent_id == input.caller.agent_id
  input.approval.task_id == input.caller.task_id
  input.approval.risk_score == input.risk.score
  input.approval.policy_version == input.policy_version
  input.approval.risk_model_version == input.risk.model_version
  input.approval.signal_version == input.signals.version
  input.approval.resource_version == input.resource.version
  count({approver | some approver in input.approval.approver_ids}) >= input.requirements.approval_count
  not subject_is_approver
  not agent_is_approver
}

deny_reasons contains "approval_binding_invalid" if {
  input.requirements.approval_count > 0
  approval_present
  not approval_exact
}

scope_sufficient if { input.required_scope == "" }
scope_sufficient if { input.required_scope in input.caller.scopes }

workload_current if {
  input.workload.attested
  input.workload.expires_at > input.now
  input.now - input.workload.observed_at <= input.requirements.max_workload_age
}

user_assurance_sufficient if {
  input.caller.aal >= input.requirements.min_aal
  not input.requirements.phishing_resistant
  input.now - input.caller.auth_time <= input.requirements.max_auth_age
}
user_assurance_sufficient if {
  input.caller.aal >= input.requirements.min_aal
  input.requirements.phishing_resistant
  input.caller.phishing_resistant
  not input.requirements.non_exportable_key
  input.now - input.caller.auth_time <= input.requirements.max_auth_age
}
user_assurance_sufficient if {
  input.caller.aal >= input.requirements.min_aal
  input.requirements.phishing_resistant
  input.caller.phishing_resistant
  input.requirements.non_exportable_key
  input.caller.non_exportable_key
  input.now - input.caller.auth_time <= input.requirements.max_auth_age
}

decision := {"outcome": "deny", "reason_codes": sort([reason | some reason in deny_reasons])} if {
  count(deny_reasons) > 0
} else := {"outcome": "scope_required", "reason_codes": ["scope_insufficient"]} if {
  not scope_sufficient
} else := {"outcome": "workload_step_up", "reason_codes": ["fresh_workload_attestation_required"]} if {
  not workload_current
} else := {"outcome": "user_step_up", "reason_codes": ["user_assurance_insufficient"]} if {
  not user_assurance_sufficient
} else := {"outcome": "approval_required", "reason_codes": ["approval_missing"]} if {
  input.requirements.approval_count > 0
  not approval_present
} else := {"outcome": "allow", "reason_codes": ["requirements_satisfied"]} if {
  input.requirements.approval_count == 0
} else := {"outcome": "allow", "reason_codes": ["requirements_satisfied"]} if {
  approval_exact
}

evidence := {
  "outcome": decision.outcome,
  "reason_codes": decision.reason_codes,
  "proposal_digest": input.proposal.digest,
  "risk_score": input.risk.score,
  "policy_version": input.policy_version,
  "risk_model_version": input.risk.model_version,
  "signal_version": input.signals.version,
  "resource_version": input.resource.version,
}
