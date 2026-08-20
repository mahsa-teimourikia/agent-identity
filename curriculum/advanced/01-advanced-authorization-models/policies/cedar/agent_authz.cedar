permit (
    principal is Agent,
    action == Action::"ReadClaim",
    resource is Claim
)
when {
    principal.tenant == resource.tenant &&
    context.workloadApproved &&
    context.taskActive &&
    context.risk == "low"
};

permit (
    principal is Agent,
    action == Action::"UpdateClaim",
    resource is Claim
)
when {
    principal.tenant == resource.tenant &&
    context.workloadApproved &&
    context.taskActive &&
    context.risk == "low"
};

forbid (principal, action, resource)
when {
    !context.workloadApproved ||
    !context.taskActive ||
    context.risk == "critical"
};
