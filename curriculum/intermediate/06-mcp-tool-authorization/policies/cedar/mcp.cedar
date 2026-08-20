permit (
    principal is Agent,
    action == Action::"CallClaimRead",
    resource is Claim
)
when {
    principal.id == "claims-agent" &&
    context.onBehalfOf == resource.owner &&
    context.taskActive &&
    context.taskResource == resource.id
};

permit (
    principal is Agent,
    action == Action::"CallPaymentCreate",
    resource is Claim
)
when {
    principal.id == "claims-agent" &&
    context.onBehalfOf == resource.owner &&
    context.taskActive &&
    context.taskResource == resource.id &&
    context.approved &&
    context.amount <= context.approvedAmount
};

forbid (
    principal,
    action == Action::"CallPaymentCreate",
    resource
)
when {
    context.amount > context.approvedAmount
};
