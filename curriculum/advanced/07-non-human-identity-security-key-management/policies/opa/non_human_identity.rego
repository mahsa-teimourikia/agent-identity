package agent.nhi
default allow := false
allow if {
  input.identity.active
  input.identity.owner != ""
  input.identity.spiffe_id == input.credential.subject
  input.identity.trust_domain == "northstar.example"
  input.credential.short_lived
  input.credential.audience == input.resource.audience
  input.credential.sender_constrained
  input.credential.confirmation_thumbprint == input.request.proof_thumbprint
  input.request.method == input.proof.method
  input.request.uri == input.proof.uri
  input.request.token_hash == input.proof.token_hash
  input.request.nonce == input.proof.nonce
  input.action in input.credential.scopes
  not input.credential.revoked
  not input.proof.replayed
  not input.identity.quarantined
}
