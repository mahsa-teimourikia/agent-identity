package claims.authz

import rego.v1

default allow := false

common if {
  input.policy_version == "claims-authz-2026-09-27"
  input.caller.authenticated
  input.caller.workload_attested
  input.caller.workload_id == "spiffe://northstar.example/claims/adjuster"
  input.caller.subject_id == input.task.requester_id
  input.caller.agent_id == input.task.assignee_id
  input.task.active
  input.task.expires_at > input.now
  input.proposal.resource_id == input.resource.resource_id
  input.task.resource_id == input.resource.resource_id
  input.resource.owner_id == input.caller.subject_id
  input.caller.tenant_id == input.task.tenant_id
  input.task.tenant_id == input.resource.tenant_id
  input.resource.tenant_id == input.risk.tenant_id
  input.risk.resource_id == input.resource.resource_id
  input.risk.observed_at >= input.now - 300
  input.risk.source == "fraud-service:v4"
  input.risk.score >= 0
  input.risk.score <= 100
  input.proposal.action in input.task.allowed_actions
}

allow if {
  common
  input.proposal.action == "claim.read"
  "claims:read" in input.caller.scopes
}

allow if {
  common
  input.proposal.action == "claim.update"
  "claims:update" in input.caller.scopes
  input.resource.status == "open"
  input.risk.score < 50
}

allow if {
  common
  input.proposal.action == "payment.create"
  "payments:create" in input.caller.scopes
  input.resource.status == "settlement-approved"
  input.proposal.amount_cents > 0
  input.proposal.amount_cents <= 50000
  input.proposal.purpose == concat("", ["settle:", input.resource.resource_id])
  input.approval_valid
}

obligations := [{"id": "audit"}, {"id": "redact_pii", "arguments": {"fields": ["ssn"]}}] if {
  allow
  input.proposal.action == "claim.read"
}

obligations := [{"id": "audit"}] if {
  allow
  input.proposal.action == "claim.update"
}

obligations := [{"id": "audit"}, {"id": "idempotency", "arguments": {"operation_id": input.proposal.operation_id}}] if {
  allow
  input.proposal.action == "payment.create"
}

decision := {
  "decision": allow,
  "policy_version": input.policy_version,
  "obligations": obligations,
}
