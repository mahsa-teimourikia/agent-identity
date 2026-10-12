// Current negative state has precedence over a positive authorization rule.
forbid (principal, action, resource)
when {
  context.quarantined ||
  !context.sessionActive ||
  !context.credentialActive ||
  !context.workloadTrusted ||
  !context.taskActive ||
  !context.relationshipActive ||
  !context.claimsCurrent ||
  !context.signalStreamAvailable ||
  context.pendingSignals > 0 ||
  !context.signalsFresh ||
  context.maxRisk >= 45
};

permit (
  principal is Agent,
  action == Action::"claim.update",
  resource == Claim::"claim:483"
)
when {
  context.tenantId == "tenant:northstar" &&
  context.workloadId == "spiffe://northstar.example/claims/adjuster" &&
  context.sessionId == "session:claims:483" &&
  context.policyVersion == "adaptive-policy-2026-10-12"
};
