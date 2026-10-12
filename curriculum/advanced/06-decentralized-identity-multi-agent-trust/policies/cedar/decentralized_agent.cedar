// Context is populated only after signature, DID-resolution, credential, and
// capability verification. A DID or reputation score alone never grants access.
permit (
  principal is ExternalAgent,
  action,
  resource
)
when {
  context.didControlValid &&
  context.resolverAgreement &&
  context.registrationValid &&
  context.delegationValid &&
  principal.status == "active" &&
  principal.organizationStatus == "active" &&
  principal.relationshipStatus == "active" &&
  context.tenant == context.delegatedTenant &&
  context.purpose == context.delegatedPurpose &&
  context.audience == context.delegatedAudience &&
  context.actionDelegated &&
  context.resourceDelegated
};

forbid (principal, action, resource)
when {
  context.identityDeactivated ||
  context.credentialRevoked ||
  context.capabilityRevoked ||
  context.quarantined
};
