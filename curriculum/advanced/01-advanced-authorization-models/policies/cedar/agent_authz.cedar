permit (
  principal is Agent,
  action == Action::"ReadClaim",
  resource is Claim
) when {
  context.authenticated &&
  context.workloadTrusted &&
  context.roleEligible &&
  context.policyVersionCurrent &&
  context.tenantMatch &&
  context.relationshipBinding &&
  context.taskValid &&
  context.stateCurrent &&
  context.riskScore < 50
};

permit (
  principal is Agent,
  action == Action::"UpdateClaim",
  resource is Claim
) when {
  context.authenticated &&
  context.workloadTrusted &&
  context.roleEligible &&
  context.policyVersionCurrent &&
  context.tenantMatch &&
  context.relationshipBinding &&
  context.taskValid &&
  context.stateCurrent &&
  context.riskScore < 50 &&
  context.updateContextTrusted &&
  context.claimOpen
};

permit (
  principal is Agent,
  action == Action::"SettleClaim",
  resource is Claim
) when {
  context.authenticated &&
  context.workloadTrusted &&
  context.roleEligible &&
  context.policyVersionCurrent &&
  context.tenantMatch &&
  context.relationshipBinding &&
  context.taskValid &&
  context.stateCurrent &&
  context.riskScore < 50 &&
  context.settlementApproved &&
  context.amountValid &&
  context.approvalValid
};

forbid (principal, action, resource) when {
  !context.authenticated ||
  !context.workloadTrusted ||
  !context.roleEligible ||
  !context.policyVersionCurrent ||
  !context.tenantMatch ||
  !context.relationshipBinding ||
  !context.taskValid ||
  !context.stateCurrent ||
  context.riskScore >= 80
};
