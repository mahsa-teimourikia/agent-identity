package agent.decentralized
default allow := false

allow if {
  input.principal.authenticated
  input.principal.did_method in {"web", "key"}
  input.credentials.organization_verified
  input.credentials.agent_registered
  input.delegation.valid
  input.action in input.delegation.actions
  not input.state.revoked
  not input.state.quarantined
}
