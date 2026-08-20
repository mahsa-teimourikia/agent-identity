permit (
  principal is Agent,
  action,
  resource
)
when {
  principal.registered &&
  context.workloadApproved &&
  context.tenantMatch &&
  context.delegationValid &&
  context.risk == "low"
};

forbid (principal, action, resource)
when {
  principal.quarantined ||
  principal.revoked ||
  context.credentialRevoked ||
  context.crossTenant
};
