forbid (principal is Agent, action, resource)
when {
  principal.environment == "prod" &&
  (!principal.registered || !principal.hasOwner)
};
forbid (principal is Agent, action, resource)
when {
  principal.environment == "prod" &&
  context.credentialLongLived
};
