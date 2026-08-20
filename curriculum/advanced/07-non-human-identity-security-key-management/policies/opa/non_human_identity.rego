package agent.nhi
default allow := false
allow if {
  input.identity.active
  input.identity.owner != ""
  input.credential.short_lived
  input.credential.audience == input.resource.audience
  input.action in input.credential.scopes
  not input.credential.revoked
  not input.identity.quarantined
}
