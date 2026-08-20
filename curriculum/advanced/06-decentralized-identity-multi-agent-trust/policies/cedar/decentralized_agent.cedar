permit (
  principal is ExternalAgent,
  action,
  resource
)
when {
  principal.authenticated &&
  principal.organizationVerified &&
  principal.agentRegistered &&
  context.delegationValid
};

forbid (principal, action, resource)
when {
  context.identityDeactivated ||
  context.credentialRevoked ||
  context.delegationRevoked ||
  context.quarantined
};
