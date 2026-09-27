permit (
  principal is Agent,
  action == Action::"ReadClaim",
  resource is Claim
) when {
  context.authenticated &&
  context.workloadAttested &&
  context.tenantMatch &&
  context.taskBinding &&
  context.riskCurrent
};

permit (
  principal is Agent,
  action == Action::"UpdateClaim",
  resource is Claim
) when {
  context.authenticated &&
  context.workloadAttested &&
  context.tenantMatch &&
  context.taskBinding &&
  context.riskCurrent &&
  context.claimOpen &&
  context.riskScore < 50
};

permit (
  principal is Agent,
  action == Action::"CreatePayment",
  resource is Claim
) when {
  context.authenticated &&
  context.workloadAttested &&
  context.tenantMatch &&
  context.taskBinding &&
  context.riskCurrent &&
  context.settlementApproved &&
  context.amountValid &&
  context.purposeMatches &&
  context.approvalValid
};

forbid (principal, action, resource) when {
  !context.authenticated ||
  !context.workloadAttested ||
  !context.tenantMatch ||
  !context.taskBinding ||
  !context.riskCurrent
};
