permit (
    principal is Agent,
    action == Action::"ReadClaim",
    resource is Claim
)
when {
    context.tokenValid &&
    context.audience == "https://claims-mcp.northstar.example" &&
    principal.tenantId == resource.tenantId &&
    principal.subjectId == resource.ownerId &&
    principal.taskId == context.taskId &&
    principal.workloadId == "spiffe://northstar.example/claims/adjuster" &&
    context.taskActive &&
    context.toolDelegated &&
    context.scope == "claims:read"
};

permit (
    principal is Agent,
    action == Action::"UpdateClaim",
    resource is Claim
)
when {
    context.tokenValid &&
    context.audience == "https://claims-mcp.northstar.example" &&
    principal.tenantId == resource.tenantId &&
    principal.subjectId == resource.ownerId &&
    principal.taskId == context.taskId &&
    principal.workloadId == "spiffe://northstar.example/claims/adjuster" &&
    context.taskActive &&
    context.toolDelegated &&
    context.scope == "claims:update" &&
    context.expectedResourceVersion == resource.version
};

permit (
    principal is Agent,
    action == Action::"CreatePayment",
    resource is Claim
)
when {
    context.tokenValid &&
    context.audience == "https://claims-mcp.northstar.example" &&
    principal.tenantId == resource.tenantId &&
    principal.subjectId == resource.ownerId &&
    principal.taskId == context.taskId &&
    principal.workloadId == "spiffe://northstar.example/claims/adjuster" &&
    context.taskActive &&
    context.toolDelegated &&
    context.scope == "payments:create" &&
    context.riskLevel != "high" &&
    context.amountCents > 0 &&
    context.amountCents <= 100000 &&
    context.currency == "CAD" &&
    !context.approvalUsed &&
    context.approvalExpiresAt > context.now &&
    context.approvalProposalDigest == context.proposalDigest &&
    context.approvalSubjectId == principal.subjectId &&
    context.approvalTenantId == principal.tenantId &&
    context.approvalTaskId == principal.taskId &&
    context.approvalAgentId == principal.agentId &&
    context.approvalPolicyVersion == context.policyVersion &&
    context.approvalResourceVersion == resource.version
};

forbid (principal, action, resource)
when {
    !context.tokenValid ||
    !context.taskActive ||
    !context.toolDelegated
};
