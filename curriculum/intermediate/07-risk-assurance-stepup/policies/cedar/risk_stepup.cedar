permit (
  principal is Agent,
  action == Action::"ReadClaim",
  resource is Claim
)
when {
  context.tokenValid &&
  principal.tenantId == resource.tenantId &&
  principal.subjectId == resource.ownerId &&
  principal.taskId == context.taskId &&
  principal.workloadId == context.workloadId &&
  context.taskActive &&
  context.workloadAttested &&
  context.workloadCurrent &&
  context.scope == "claims:read" &&
  context.humanAAL >= 1 &&
  context.authAgeSeconds <= 28800 &&
  context.riskScore < 95
};

permit (
  principal is Agent,
  action == Action::"CreatePayment",
  resource is Claim
)
when {
  context.tokenValid &&
  principal.tenantId == resource.tenantId &&
  principal.subjectId == resource.ownerId &&
  principal.taskId == context.taskId &&
  principal.workloadId == context.workloadId &&
  context.taskActive &&
  context.workloadAttested &&
  context.workloadCurrent &&
  context.scope == "payments:create" &&
  context.humanAAL >= context.requiredAAL &&
  context.phishingResistant &&
  (!context.requireNonExportableKey || context.nonExportableKey) &&
  context.authAgeSeconds <= context.maxAuthAgeSeconds &&
  context.riskScore < 95 &&
  !context.approvalUsed &&
  context.approvalExpiresAt > context.now &&
  context.approvalCount >= context.requiredApprovalCount &&
  context.approvalProposalDigest == context.proposalDigest &&
  context.approvalSubjectId == principal.subjectId &&
  context.approvalTenantId == principal.tenantId &&
  context.approvalTaskId == principal.taskId &&
  context.approvalAgentId == principal.agentId &&
  context.approvalPolicyVersion == context.policyVersion &&
  context.approvalRiskModelVersion == context.riskModelVersion &&
  context.approvalSignalVersion == context.signalVersion &&
  context.approvalResourceVersion == resource.version &&
  context.separationOfDutiesSatisfied
};

forbid (
  principal,
  action == Action::"DisableAudit",
  resource
);

forbid (principal, action, resource)
when {
  !context.tokenValid ||
  !context.taskActive ||
  context.riskScore >= 95
};
