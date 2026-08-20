permit (
  principal is Agent,
  action,
  resource
)
when {
  context.riskScore < 45 &&
  !context.quarantined &&
  !context.revoked
};

forbid (principal, action, resource)
when {
  context.quarantined ||
  context.revoked ||
  context.riskScore >= 90
};
