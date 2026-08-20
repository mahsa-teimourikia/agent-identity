permit (
  principal is Agent,
  action,
  resource
)
when {
  context.capabilitySignatureValid &&
  context.capabilityChainValid &&
  context.capabilityAudienceValid &&
  context.capabilityScopeValid &&
  context.capabilityFresh &&
  context.workloadApproved
};

forbid (principal, action, resource)
when {
  context.capabilityRevoked ||
  !context.workloadApproved
};
