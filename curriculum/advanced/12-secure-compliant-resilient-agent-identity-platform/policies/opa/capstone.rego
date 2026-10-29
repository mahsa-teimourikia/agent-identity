package capstone.agent
default allow := false
default approval_required := false

identity_ready if {
  input.agent.state == "active"
  input.agent.tenant_id == input.context.tenant_id
  input.workload.tenant_id == input.context.tenant_id
  input.workload.agent_id == input.agent.id
  input.workload.spiffe_id in input.agent.approved_workloads
  input.workload.attestation_fresh
}

authority_ready if {
  input.context.tenant_id == input.resource.tenant_id
  input.relationship.assigned
  not input.delegation.revoked
  input.delegation.current
  input.action in input.delegation.actions
  input.resource.id in input.delegation.resources
  input.intent.purpose in input.delegation.purposes
  input.intent.tool == input.expected_tool
}

allow if {
  identity_ready
  authority_ready
  input.risk.level == "low"
  input.decision.request_digest == input.intent.digest
  input.decision.policy_version == data.capstone.policy_version
}

approval_required if {
  identity_ready
  authority_ready
  input.action == "payment.create"
  input.risk.level != "critical"
}

deny_reason contains "agent_not_active" if input.agent.state != "active"
deny_reason contains "tenant_mismatch" if input.context.tenant_id != input.resource.tenant_id
deny_reason contains "attestation_stale" if not input.workload.attestation_fresh
deny_reason contains "delegation_revoked" if input.delegation.revoked
deny_reason contains "relationship_missing" if not input.relationship.assigned
deny_reason contains "critical_risk" if input.risk.level == "critical"
