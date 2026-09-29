package mcp.authz

import rego.v1

default allow := false

trusted_identity if {
  input.policy_version == 12
  input.toolset_version == 7
  input.token.valid
  input.token.issuer == "https://id.northstar.example"
  input.token.audience == "https://claims-mcp.northstar.example"
  input.caller.subject_id == input.task.subject_id
  input.caller.tenant_id == input.task.tenant_id
  input.caller.agent_id == input.task.agent_id
  input.caller.client_id == "client:claims-copilot"
  input.caller.workload_id == "spiffe://northstar.example/claims/adjuster"
  input.caller.task_id == input.task.task_id
  input.task.active
  input.proposal.tool in input.task.allowed_tools
}

target_authorized if {
  input.proposal.resource_id == input.resource.resource_id
  input.resource.resource_id in input.task.resources
  input.resource.tenant_id == input.caller.tenant_id
  input.resource.owner_id == input.caller.subject_id
}

allow if {
  trusted_identity
  input.proposal.tool == "claim.search"
  "claims:search" in input.caller.scopes
  input.proposal.limit >= 1
  input.proposal.limit <= 10
}

allow if {
  trusted_identity
  target_authorized
  input.proposal.tool == "claim.read"
  "claims:read" in input.caller.scopes
}

allow if {
  trusted_identity
  target_authorized
  input.proposal.tool == "claim.update"
  "claims:update" in input.caller.scopes
  input.proposal.expected_version == input.resource.version
}

exact_approval if {
  input.approval.id == input.proposal.approval_id
  input.approval.proposal_digest == input.proposal.digest
  input.approval.subject_id == input.caller.subject_id
  input.approval.tenant_id == input.caller.tenant_id
  input.approval.agent_id == input.caller.agent_id
  input.approval.task_id == input.task.task_id
  input.approval.policy_version == input.policy_version
  input.approval.resource_version == input.resource.version
  input.approval.expires_at > input.now
  not input.approval.used
}

allow if {
  trusted_identity
  target_authorized
  input.proposal.tool == "payment.create"
  "payments:create" in input.caller.scopes
  input.risk.level != "high"
  input.proposal.amount_cents > 0
  input.proposal.amount_cents <= 100000
  input.proposal.currency == "CAD"
  exact_approval
}

decision := {
  "allowed": allow,
  "policy_version": input.policy_version,
  "toolset_version": input.toolset_version,
  "proposal_digest": input.proposal.digest,
}
