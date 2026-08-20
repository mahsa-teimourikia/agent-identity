permit (principal is AgentWorkload, action, resource)
when {
  principal.active &&
  context.credentialShortLived &&
  context.audienceMatches &&
  context.scopeMatches
};
forbid (principal, action, resource)
when {
  context.credentialRevoked || context.identityQuarantined || context.breakGlassExpired
};
