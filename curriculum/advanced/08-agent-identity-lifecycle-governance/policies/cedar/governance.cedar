permit (
  principal is DeploymentPipeline,
  action == Action::"deployAgent",
  resource is Agent
)
when {
  resource.approved &&
  resource.ownerAssigned &&
  resource.runtimeIdentityBound &&
  resource.monitoringEnabled &&
  !resource.staticCredential
};

forbid (principal, action, resource)
when {
  resource.revoked || resource.exceptionExpired
};
