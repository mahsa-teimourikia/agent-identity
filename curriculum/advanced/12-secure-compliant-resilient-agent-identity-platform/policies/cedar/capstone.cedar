permit (
  principal is Agent,
  action,
  resource
)
when {
  principal.state == "active" &&
  principal.tenantId == resource.tenantId &&
  context.workload.agentId == principal.agentId &&
  context.workload.approved &&
  context.workload.attestationFresh &&
  context.delegation.current &&
  context.delegation.tenantId == principal.tenantId &&
  context.relationshipAssigned &&
  context.expectedTool == context.requestedTool &&
  context.risk == "low" &&
  context.requestDigest == context.decisionRequestDigest &&
  context.policyVersion == context.decisionPolicyVersion
};

forbid (principal, action, resource)
when {
  principal.state == "quarantined" ||
  principal.state == "revoked" ||
  context.credentialRevoked ||
  context.crossTenant ||
  !context.workload.attestationFresh ||
  !context.delegation.current ||
  context.risk == "critical"
};
