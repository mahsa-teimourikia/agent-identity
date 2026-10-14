// Illustrative Cedar policy. A production schema should strongly type every attribute.
permit (
  principal is Agent,
  action,
  resource is Claim
)
when {
  principal.state == "active" &&
  principal.credentialActive &&
  principal.tenant == resource.tenant &&
  principal.workload == context.workload &&
  principal.approvedActions.contains(action) &&
  context.now < principal.reviewDue &&
  context.policyVersion == principal.policyVersion
};

forbid (principal is Agent, action, resource)
when {
  principal.state == "retired" ||
  principal.state == "quarantined" ||
  principal.state == "suspended" ||
  context.now >= principal.reviewDue ||
  principal.tenant != resource.tenant ||
  principal.workload != context.workload
};
