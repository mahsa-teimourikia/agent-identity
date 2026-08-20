permit (
  principal is Agent,
  action,
  resource
)
when {
  context.agentRegistered &&
  context.workloadAttested &&
  context.provenanceVerified &&
  context.evaluationPassed &&
  context.governanceApproved &&
  context.risk == "low"
};

forbid (principal, action, resource)
when {
  context.agentQuarantined ||
  context.credentialRevoked ||
  context.releaseWithdrawn
};
