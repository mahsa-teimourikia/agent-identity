// Illustrative runtime policies whose lifecycle is governed by this course.

permit (
  principal is Agent,
  action == Action::"ReadClaim",
  resource is Claim
)
when {
  principal.status == "active" &&
  principal.owner != "" &&
  resource.tenant == principal.tenant
};

forbid (
  principal is Agent,
  action in [Action::"CreatePayment", Action::"ApprovePayment"],
  resource
)
when {
  principal.hasToxicFinanceCombination
};
