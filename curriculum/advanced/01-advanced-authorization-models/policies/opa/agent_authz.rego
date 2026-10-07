package agent.authz

import rego.v1

default allow := false

policy_version := "advanced-authz-2026-10-07"

trusted_identity if {
  input.identity.authenticated
  input.identity.workload_attested
  input.identity.workload_id == "spiffe://northstar.example/claims/agent"
  "claims-operator" in input.identity.roles
}

current_versioned_state if {
  input.policy_version == policy_version
  input.relationships.version == "relations:42"
  input.attributes.version == "attributes:17"
  input.relationships.observed_at >= input.now - 60
  input.attributes.observed_at >= input.now - 60
  input.relationships.available
  input.attributes.available
  input.attributes.source == "risk-engine:v5"
  input.attributes.risk_score >= 0
  input.attributes.risk_score <= 100
}

low_risk if {
  current_versioned_state
  input.attributes.risk_score < 50
}

relationship_binding if {
  input.relationships.user_operates_agent
  input.relationships.agent_assigned_to_task
  input.relationships.task_contains_resource
  input.relationships.task_permits_tool
}

task_binding if {
  input.task.active
  input.task.expires_at > input.now
  input.task.remaining_calls > 0
  input.identity.subject_id == input.task.subject_id
  input.identity.agent_id == input.task.agent_id
  input.proposal.action in input.task.actions
  input.proposal.purpose in input.task.purposes
  input.proposal.resource_id == input.task.resource_id
  input.proposal.tool_id == input.task.tool_id
}

tenant_resource_binding if {
  input.identity.tenant_id == input.task.tenant_id
  input.task.tenant_id == input.resource.tenant_id
  input.proposal.resource_id == input.resource.resource_id
  input.resource.owner_id == input.identity.subject_id
}

common if {
  trusted_identity
  low_risk
  relationship_binding
  task_binding
  tenant_resource_binding
}

allow if {
  common
  input.proposal.action == "claim.read"
}

allow if {
  common
  input.proposal.action == "claim.update"
  input.resource.status == "open"
  input.attributes.device_managed
  input.attributes.network_zone == "corporate"
  every field in input.proposal.fields {
    field in {"status", "notes"}
  }
}

allow if {
  common
  input.proposal.action == "claim.settle"
  input.resource.status == "settlement-approved"
  input.proposal.amount_cents > 0
  input.proposal.amount_cents <= 50000
  input.approval_valid
}

step_up if {
  trusted_identity
  current_versioned_state
  relationship_binding
  task_binding
  tenant_resource_binding
  input.attributes.risk_score >= 50
  input.attributes.risk_score < 80
}

obligations := [
  {"id": "audit"},
  {"id": "redact", "arguments": {"fields": ["ssn", "bank_account"]}},
] if {
  allow
  input.proposal.action == "claim.read"
}

obligations := [
  {"id": "audit"},
  {"id": "optimistic_lock"},
] if {
  allow
  input.proposal.action == "claim.update"
}

obligations := [
  {"id": "audit"},
  {"id": "idempotency"},
  {"id": "consume_approval"},
  {"id": "optimistic_lock"},
] if {
  allow
  input.proposal.action == "claim.settle"
}

decision := {
  "outcome": "allow",
  "policy_version": policy_version,
  "obligations": obligations,
} if { allow }

decision := {
  "outcome": "step_up",
  "policy_version": policy_version,
  "obligations": [],
} if {
  not allow
  step_up
}

decision := {
  "outcome": "deny",
  "policy_version": policy_version,
  "obligations": [],
} if {
  not allow
  not step_up
}
