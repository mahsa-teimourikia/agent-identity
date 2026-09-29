// Runtime enforcement complements—not replaces—the governance control plane.
permit (
  principal is Agent,
  action == Action::"ReadClaim",
  resource is Claim
)
when {
  principal.status == "active" &&
  principal.ownerId != "" &&
  principal.tenantId == resource.tenantId &&
  context.inventoryCurrent &&
  context.policyVersion == "policy:v20" &&
  context.modelVersion == "authz-model:01K9GOVERNANCE" &&
  principal.activeEntitlements.contains("claim.read|claim:483")
};

permit (
  principal is Agent,
  action == Action::"ExportClaim",
  resource is Claim
)
when {
  principal.status == "active" &&
  principal.ownerId != "" &&
  principal.tenantId == resource.tenantId &&
  context.inventoryCurrent &&
  context.exceptionValid &&
  context.exceptionApprovalCount >= 2 &&
  context.policyVersion == "policy:v20" &&
  context.modelVersion == "authz-model:01K9GOVERNANCE" &&
  principal.activeEntitlements.contains("claim.export|claim:483")
};

forbid (principal, action, resource)
when {
  principal.status != "active" ||
  principal.ownerId == "" ||
  principal.tenantId != resource.tenantId ||
  !context.inventoryCurrent ||
  context.toxicCombination
};
