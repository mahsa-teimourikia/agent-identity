// Illustrative Cedar policies for adversarial testing.
// Cedar semantics: default deny; any matching forbid overrides permits.

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

forbid (
    principal is Agent,
    action,
    resource is Claim
)
when {
    principal.tenant != resource.tenant
};

forbid (
    principal is Agent,
    action,
    resource
)
when {
    !context.workloadApproved
};
