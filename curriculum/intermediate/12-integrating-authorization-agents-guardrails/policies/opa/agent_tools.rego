package agent.tools

default allow := false

allow if {
    input.principal.authenticated
    input.principal.tenant == input.resource.tenant
    input.workload.approved
    input.delegation.active
    input.delegation.delegatee == input.agent.id
    input.action in input.delegation.actions
    input.resource.id in input.delegation.resources
}

requires_approval if {
    input.risk.level == "high"
}

requires_approval if {
    input.action == "payment.create"
    input.parameters.amount > 500
}
