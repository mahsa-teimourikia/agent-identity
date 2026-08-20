package capstone.authz
default allow := false
allow if {
 input.principal.authenticated
 input.principal.tenant == input.resource.tenant
 input.agent.registered
 input.workload.approved
 input.workload.agent_id == input.agent.id
 input.delegation.active
 input.delegation.delegatee == input.agent.id
 input.action in input.delegation.actions
 input.resource.id in input.delegation.resources
}
requires_approval if { input.risk in {"high", "critical"} }
