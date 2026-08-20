package agent.capability
default allow := false

allow if {
  input.crypto.signature_valid
  input.crypto.chain_valid
  input.capability.audience == input.request.audience
  input.request.action in input.capability.actions
  input.request.resource in input.capability.resources
  input.capability.not_expired
  not input.capability.revoked
  input.workload.approved
}
