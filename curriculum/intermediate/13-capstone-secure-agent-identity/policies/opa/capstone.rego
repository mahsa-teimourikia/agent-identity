package capstone.authz

import rego.v1

default allow := false
default requires_approval := false

allow if {
    input.principal.authenticated
    input.principal.active
    input.principal.tenant == input.resource.tenant
    input.principal.id == input.delegation.principal
    input.token.issuer == data.capstone.trusted_issuer
    input.token.audience == data.capstone.gateway_audience
    input.token.sender_bound
    input.agent.registered
    input.agent.active
    input.agent.review_current
    input.workload.approved
    input.workload.id == input.delegation.workload
    input.workload.agent_id == input.agent.id
    input.workload.artifact_approved
    input.delegation.active
    input.delegation.delegatee == input.agent.id
    input.delegation.tenant == input.principal.tenant
    input.task.id == input.delegation.task
    input.action in input.delegation.actions
    input.resource.id in input.delegation.resources
    input.relationship.authorized
    input.tool.name == input.request.tool
    input.tool.action == input.action
    input.tool.server == input.request.server
    input.tool.audience == input.request.audience
    input.tool.scope in input.token.scopes
    not input.request.token_passthrough
    input.policy.version == data.capstone.policy_version
}

requires_approval if {
    input.risk in {"high", "critical"}
}

decision := {"allow": true, "requires_approval": true, "policy_version": version} if {
    allow
    requires_approval
    version := data.capstone.policy_version
}

decision := {"allow": true, "requires_approval": false, "policy_version": version} if {
    allow
    not requires_approval
    version := data.capstone.policy_version
}

decision := {"allow": false, "requires_approval": false, "policy_version": version} if {
    not allow
    version := data.capstone.policy_version
}
