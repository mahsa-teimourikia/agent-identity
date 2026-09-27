package northstar.dynamic

import rego.v1

# One default decision and one allow rule avoid conflicting complete rules.
default allow := false

supported_action if input.proposal.action in {"claim.read", "claim.update", "payment.create"}

scope_ok if {
  input.proposal.action == "claim.read"
  "claims:read" in input.caller.scopes
}
scope_ok if {
  input.proposal.action == "claim.update"
  "claims:update" in input.caller.scopes
}
scope_ok if {
  input.proposal.action == "payment.create"
  "payments:create" in input.caller.scopes
}

fresh_enough if input.proposal.action == "claim.read"
fresh_enough if input.projection.stream_fresh

approval_ok if input.proposal.action != "payment.create"
approval_ok if {
  input.proposal.action == "payment.create"
  input.approval != null
  input.projection.approval_active
  input.approval.proposal_digest == input.proposal.digest
  input.approval.subject_id == input.caller.subject_id
  input.approval.agent_id == input.caller.agent_id
  input.approval.tenant_id == input.proposal.tenant_id
  input.approval.action == input.proposal.action
  input.approval.resource_id == input.proposal.resource_id
  input.approval.approver_role == "claims-supervisor"
  input.approval.policy_version == input.projection.policy_version
  input.approval.approval_version == input.projection.approval_version
  input.approval.issued_at <= input.now
  input.approval.expires_at > input.now
  input.proposal.amount_cents > 0
  input.proposal.amount_cents <= 50000
}

allow if {
  supported_action
  scope_ok
  input.caller.subject_id == input.projection.subject_id
  input.caller.agent_id == "agent:claims-adjuster"
  input.caller.workload_id == "spiffe://northstar.example/claims/adjuster"
  input.caller.tenant_id == "tenant:northstar"
  input.proposal.tenant_id == "tenant:northstar"
  input.proposal.resource_id == "claim:clm-100"
  input.caller.token_expires_at > input.now
  input.projection.session_active
  input.projection.claims_active
  input.projection.device_compliant
  input.projection.task_active
  input.projection.task_expires_at > input.now
  input.projection.relationship_active
  input.projection.delegation_active
  not input.projection.workload_quarantined
  input.projection.risk_level == "low"
  fresh_enough
  approval_ok
}

decision := {
  "allowed": allow,
  "policy_version": input.projection.policy_version,
  "resource_version": input.projection.resource_version,
  "relationship_version": input.projection.relationship_version,
  "stream_fresh": input.projection.stream_fresh,
}
