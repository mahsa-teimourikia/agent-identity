// Illustrative Cedar policy for agent tool/resource authorization.

permit (
    principal is Agent,
    action == Action::"ReadClaim",
    resource is Claim
)
when {
    principal.tenant == resource.tenant &&
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
    !context.delegationActive
};
