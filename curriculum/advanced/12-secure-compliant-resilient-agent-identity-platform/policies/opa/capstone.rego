package capstone.agent
default allow := false

allow if {
  input.agent.registered
  input.workload.approved
  input.workload.agent_id == input.agent.id
  input.principal.tenant == input.resource.tenant
  input.delegation.active
  input.action in input.delegation.actions
  input.resource.id in input.delegation.resources
  input.risk.level == "low"
}

step_up if {
  input.agent.registered
  input.workload.approved
  input.principal.tenant == input.resource.tenant
  input.risk.level == "high"
}

deny_reason contains "quarantined" if input.agent.quarantined
deny_reason contains "revoked" if input.agent.revoked
