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
forbid (principal, action, resource)
when { !context.workloadApproved || !context.delegationActive };
