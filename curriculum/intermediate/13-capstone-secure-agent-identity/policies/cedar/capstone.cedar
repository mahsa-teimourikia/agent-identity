permit (
 principal is Agent,
 action == Action::"ReadClaim",
 resource is Claim
)
when {
 principal.tenant == resource.tenant &&
 context.requestTenant == principal.tenant &&
 principal.workload == context.expectedWorkload &&
 principal.task == context.taskId &&
 context.toolName == "claims.get" &&
 context.toolServer == "mcp://claims-prod" &&
 context.policyVersion == "capstone/2026-10-04" &&
 context.workloadApproved &&
 context.delegationActive
};
forbid (principal, action, resource)
when {
 !context.workloadApproved ||
 !context.delegationActive ||
 context.requestTenant != principal.tenant
};
