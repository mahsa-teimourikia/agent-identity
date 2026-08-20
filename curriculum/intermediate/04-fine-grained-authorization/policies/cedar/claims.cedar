permit (
  principal is Agent,
  action == Action::"ReadClaim",
  resource is Claim
)
when {
  principal.id == "claims-agent" &&
  resource.id == context.taskClaimId &&
  context.onBehalfOf == "alice" &&
  context.taskActive
};

permit (
  principal is Agent,
  action == Action::"CreatePayment",
  resource is Claim
)
when {
  principal.id == "claims-agent" &&
  resource.id == context.taskClaimId &&
  context.onBehalfOf == "alice" &&
  context.taskActive &&
  context.approved &&
  context.amount <= 500
};

forbid (
  principal,
  action == Action::"CreatePayment",
  resource
)
when {
  context.amount > 500
};
