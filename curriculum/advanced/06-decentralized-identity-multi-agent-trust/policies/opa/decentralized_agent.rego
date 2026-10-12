package agent.decentralized

# Input contains facts produced only after cryptographic and resolver validation.
# OPA is the final policy decision point; it does not parse or verify JWTs.
default allow := false

allow if {
    input.assurance.did_control_valid
    input.assurance.resolver_agreement
    input.assurance.registration_valid
    input.assurance.delegation_valid

    input.principal.status == "active"
    input.principal.organization_status == "active"
    input.principal.relationship_status == "active"
    input.principal.did_method in data.trust.allowed_did_methods

    input.request.tenant == input.delegation.tenant
    input.request.purpose == input.delegation.purpose
    input.request.audience == input.delegation.audience
    input.request.action in input.delegation.actions
    input.request.resource in input.delegation.resources

    not input.state.identity_deactivated
    not input.state.credential_revoked
    not input.state.capability_revoked
    not input.state.quarantined
}
