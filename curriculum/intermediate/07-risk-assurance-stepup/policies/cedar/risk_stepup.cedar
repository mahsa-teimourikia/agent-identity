permit (
  principal is Agent,
  action == Action::"ReadClaim",
  resource is Claim
)
when {
  context.workloadAttested &&
  context.riskScore < 60
};

permit (
  principal is Agent,
  action == Action::"CreatePayment",
  resource is Claim
)
when {
  context.workloadAttested &&
  context.humanAAL >= 2 &&
  context.authAgeSeconds <= 300 &&
  context.approved &&
  context.amount <= context.approvedAmount &&
  context.riskScore < 80
};

forbid (
  principal,
  action == Action::"DisableAudit",
  resource
);
