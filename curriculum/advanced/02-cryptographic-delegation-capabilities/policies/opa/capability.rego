package agent.capability

import rego.v1

default allow := false

policy_version := "capability-policy-2026-10-07"

# Signature, chain, DPoP, and replay verification happen in the trusted gateway.
# OPA consumes their typed results; it never trusts caller-asserted raw claims.
proof_valid if {
  input.proof.signature_valid
  input.proof.chain_valid
  input.proof.attenuation_valid
  input.proof.dpop_valid
  input.proof.replay_consumed
}

current_authority if {
  input.now >= input.capability.issued_at
  input.now < input.capability.expires_at
  not input.capability.revoked
  input.capability.policy_version == policy_version
  input.current_policy.version == policy_version
}

request_bound if {
  input.request.agent_id == input.capability.subject
  input.request.tenant_id == input.capability.tenant_id
  input.request.task_id == input.capability.task_id
  input.request.audience in input.capability.audiences
  input.request.action in input.capability.actions
  input.request.resource in input.capability.resources
  input.request.tool in input.capability.tools
  input.request.purpose in input.capability.purposes
  input.request.amount_cents <= input.capability.max_amount_cents
}

trusted_current_state if {
  input.current_policy.workload_approved
  input.current_policy.task_active
  input.current_policy.relationship_valid
  input.current_policy.risk_score >= 0
  input.current_policy.risk_score < 50
}

allow if {
  proof_valid
  current_authority
  request_bound
  trusted_current_state
}

obligations := [
  {"id": "audit", "arguments": {"chain_digest": input.proof.chain_digest}},
  {"id": "consume_call_budget", "arguments": {"capability_jti_hash": input.proof.capability_jti_hash}},
  {"id": "idempotency", "arguments": {"operation_id": input.request.operation_id}},
] if { allow }

decision := {
  "outcome": "allow",
  "policy_version": policy_version,
  "obligations": obligations,
} if { allow }

decision := {
  "outcome": "deny",
  "policy_version": policy_version,
  "obligations": [],
} if { not allow }
