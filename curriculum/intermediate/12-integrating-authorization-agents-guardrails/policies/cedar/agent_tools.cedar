// Cedar demonstrates default deny plus an explicit forbid override.

permit (
    principal is Agent,
    action == Action::"ReadClaim",
    resource is Claim
)
when {
    principal.tenant == resource.tenant &&
    principal.workload == context.expectedWorkload &&
    principal.task == context.taskId &&
    context.toolName == "claims.get" &&
    context.toolServer == "mcp://claims-prod" &&
    context.policyVersion == "agent-tools/2026-10-04" &&
    context.workloadApproved &&
    context.delegationActive
};

permit (
    principal is Agent,
    action == Action::"UpdateClaim",
    resource is Claim
)
when {
    principal.tenant == resource.tenant &&
    principal.workload == context.expectedWorkload &&
    principal.task == context.taskId &&
    context.toolName == "claims.update" &&
    context.toolServer == "mcp://claims-prod" &&
    context.policyVersion == "agent-tools/2026-10-04" &&
    context.workloadApproved &&
    context.delegationActive &&
    context.taskResource == resource.id
};

forbid (
    principal is Agent,
    action,
    resource
)
when {
    !context.workloadApproved ||
    !context.delegationActive ||
    context.requestTenant != principal.tenant
};
