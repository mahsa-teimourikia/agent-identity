// Illustrative Cedar enforcement policy; production deployments need a schema.
permit (principal is Agent, action, resource)
when {
  principal.status == "active" &&
  context.telemetryHealthy &&
  context.audience == resource.audience &&
  context.workloadId == principal.expectedWorkloadId &&
  context.environment == resource.environment &&
  context.credentialVersion == context.currentCredentialVersion &&
  context.delegationAttenuated
};

forbid (principal, action, resource)
when {
  principal.status == "revoked" ||
  principal.status == "suspended" ||
  context.credentialLeaked ||
  context.telemetrySuppressed ||
  context.audience != resource.audience ||
  !context.delegationAttenuated
};
