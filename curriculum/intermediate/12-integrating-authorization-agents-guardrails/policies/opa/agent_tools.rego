package agent.tools

import rego.v1

default allow := false
default requires_approval := false

allow if {
    input.principal.authenticated
    input.principal.tenant == input.resource.tenant
    input.principal.id == input.delegation.principal
    input.agent.id == input.delegation.delegatee
    input.workload.id == input.delegation.workload
    input.workload.approved
    input.delegation.active
    input.delegation.tenant == input.principal.tenant
    input.task.id == input.delegation.task
    input.action in input.delegation.actions
    input.resource.id in input.delegation.resources
    input.tool.name == input.request.tool
    input.tool.action == input.action
    input.tool.server == input.request.server
    input.tool.schema_hash == input.request.schema_hash
    input.policy.version == data.agent_tools.policy_version
}

requires_approval if {
    input.action == "payment.create"
    input.parameters.amount_cents > 50000
}

decision := {"allow": true, "requires_approval": true, "policy_version": version} if {
    allow
    requires_approval
    version := data.agent_tools.policy_version
}

decision := {"allow": true, "requires_approval": false, "policy_version": version} if {
    allow
    not requires_approval
    version := data.agent_tools.policy_version
}

decision := {"allow": false, "requires_approval": false, "policy_version": version} if {
    not allow
    version := data.agent_tools.policy_version
}
