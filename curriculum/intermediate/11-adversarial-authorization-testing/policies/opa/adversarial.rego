package agent.authz

import rego.v1

default allow := false

# The gateway verifies the JWT signature/issuer/audience before constructing
# this typed policy input. OPA still binds those trusted claims to the request.
allow if {
    input.token.verified
    input.token.issuer == "https://identity.northstar.example"
    input.token.audience == "https://claims-api.northstar.example"
    input.token.subject == input.principal.id
    input.token.actor == input.agent.id
    input.token.workload_id == input.workload.id
    input.token.tenant_id == input.principal.tenant
    input.token.task_id == input.task.id
    input.principal.authenticated
    input.principal.tenant == input.resource.tenant
    input.workload.approved
    input.delegation.active
    not input.delegation.revoked
    input.delegation.not_before <= input.now
    input.now < input.delegation.expires_at
    input.delegation.delegatee == input.agent.id
    input.delegation.tenant_id == input.principal.tenant
    input.delegation.task_id == input.task.id
    input.delegation.depth <= input.delegation.max_depth
    input.action in input.delegation.actions
    input.resource.id in input.delegation.resources
    input.tool.approved
    input.tool.binding_valid
    input.request.binding_valid
    input.policy_data_fresh
}
