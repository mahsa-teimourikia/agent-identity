package agent.authz
default allow := false

tenant_match if {
  input.principal.tenant == input.resource.tenant
}

trusted_runtime if {
  input.agent.registered
  input.workload.approved
  input.workload.agent_id == input.agent.id
}

task_valid if {
  input.task.active
  input.task.agent_id == input.agent.id
  input.action in input.task.actions
  input.resource.id in input.task.resources
}

allow if {
  tenant_match
  trusted_runtime
  task_valid
  input.risk.level == "low"
}

step_up if {
  tenant_match
  trusted_runtime
  task_valid
  input.risk.level == "high"
}
