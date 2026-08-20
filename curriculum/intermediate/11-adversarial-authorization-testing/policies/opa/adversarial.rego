package agent.authz

default allow := false

allow if {
    input.principal.authenticated == true
    input.principal.tenant == input.resource.tenant
    input.workload.approved == true
    input.delegation.active == true
    input.delegation.delegatee == input.agent.id
    input.action in input.delegation.actions
    input.resource.id in input.delegation.resources
}
