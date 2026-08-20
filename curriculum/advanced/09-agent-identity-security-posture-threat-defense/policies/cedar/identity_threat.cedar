permit (principal is Agent, action, resource)
when {
  principal.active &&
  context.telemetryHealthy &&
  context.audienceMatches &&
  context.delegationAttenuated
};
forbid (principal, action, resource)
when {
  principal.revoked || context.credentialLeaked || context.telemetrySuppressed
};
