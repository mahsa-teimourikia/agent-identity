permit (principal is AgentWorkload, action, resource)
when {
  principal.active &&
  context.credentialShortLived &&
  context.audienceMatches &&
  context.scopeMatches &&
  context.senderConstrained &&
  context.confirmationThumbprint == context.proofThumbprint &&
  context.requestMethod == context.proofMethod &&
  context.requestUri == context.proofUri &&
  context.tokenHash == context.proofTokenHash &&
  context.nonce == context.proofNonce &&
  !context.proofReplayed
};
forbid (principal, action, resource)
when {
  context.credentialRevoked || context.identityQuarantined || context.breakGlassExpired
};
