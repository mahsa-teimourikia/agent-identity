// Negative current state has precedence over positive portable evidence.
forbid (principal, action, resource)
when {
  context.quarantined ||
  !context.relationshipActive ||
  !context.taskActive ||
  context.riskScore >= 50 ||
  context.credentialRevoked ||
  context.releaseWithdrawn
};

permit (
  principal is Agent,
  action == Action::"claim.update",
  resource == Claim::"claim:483"
)
when {
  context.tenantId == "tenant:northstar" &&
  context.identity == "verified" &&
  context.workload == "verified" &&
  context.supplyChain == "verified" &&
  context.evaluation == "verified" &&
  context.governance == "verified" &&
  context.policyVersion == "evidence-policy-2026-10-12"
};
