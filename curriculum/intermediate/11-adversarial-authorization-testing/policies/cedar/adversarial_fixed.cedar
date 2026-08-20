// Hardened Cedar example used after mutation/red-team exercises.

permit (
    principal is Agent,
    action == Action::"ReadClaim",
    resource is Claim
)
when {
    principal.tenant == resource.tenant &&
    context.workloadApproved &&
    context.delegationActive &&
    context.delegatee == principal.id &&
    context.resourceBound &&
    context.authzFresh
};

forbid (
    principal is Agent,
    action,
    resource
)
when {
    !context.workloadApproved ||
    !context.delegationActive ||
    !context.authzFresh
};

forbid (
    principal is Agent,
    action,
    resource is Claim
)
when {
    principal.tenant != resource.tenant
};
