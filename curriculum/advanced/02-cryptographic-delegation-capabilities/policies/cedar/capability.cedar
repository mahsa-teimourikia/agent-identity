permit (
  principal is Agent,
  action == Action::"SearchKnowledge",
  resource is Claim
) when {
  context.proofValid && context.attenuationValid && context.dpopValid &&
  context.replayConsumed && context.capabilityCurrent &&
  context.policyVersionCurrent && context.subjectBound &&
  context.tenantBound && context.taskBound && context.audienceBound &&
  context.actionBound && context.resourceBound && context.toolBound &&
  context.purposeBound && context.workloadApproved &&
  context.relationshipValid && context.riskScore < 50
};

// A forbid overrides every permit. These are trusted gateway facts, not fields
// copied directly from an unverified token or caller-controlled request.
forbid (principal, action, resource) when {
  !context.proofValid || !context.attenuationValid || !context.dpopValid ||
  !context.replayConsumed || !context.capabilityCurrent ||
  !context.policyVersionCurrent || !context.workloadApproved ||
  !context.relationshipValid || context.riskScore >= 80
};
