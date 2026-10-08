package agent.capability_test

import rego.v1
import data.agent.capability

base := {
  "now": 1800000000,
  "proof": {"signature_valid": true, "chain_valid": true, "attenuation_valid": true, "dpop_valid": true, "replay_consumed": true, "chain_digest": "synthetic-chain-digest", "capability_jti_hash": "synthetic-jti-hash"},
  "capability": {"subject": "agent:research", "tenant_id": "tenant:northstar", "task_id": "task:claim-483", "audiences": ["https://knowledge.northstar.example"], "actions": ["knowledge.search"], "resources": ["claim:483"], "tools": ["tool:knowledge"], "purposes": ["fraud-research"], "issued_at": 1799999970, "expires_at": 1800000300, "max_amount_cents": 0, "revoked": false, "policy_version": "capability-policy-2026-10-07"},
  "request": {"operation_id": "operation:search:483", "agent_id": "agent:research", "tenant_id": "tenant:northstar", "task_id": "task:claim-483", "audience": "https://knowledge.northstar.example", "action": "knowledge.search", "resource": "claim:483", "tool": "tool:knowledge", "purpose": "fraud-research", "amount_cents": 0},
  "current_policy": {"version": "capability-policy-2026-10-07", "workload_approved": true, "task_active": true, "relationship_valid": true, "risk_score": 20},
}

test_valid_request_allowed if { capability.allow with input as base }
test_tampered_signature_denied if { not capability.allow with input as object.union(base, {"proof": object.union(base.proof, {"signature_valid": false})}) }
test_invalid_attenuation_denied if { not capability.allow with input as object.union(base, {"proof": object.union(base.proof, {"attenuation_valid": false})}) }
test_dpop_failure_denied if { not capability.allow with input as object.union(base, {"proof": object.union(base.proof, {"dpop_valid": false})}) }
test_replay_denied if { not capability.allow with input as object.union(base, {"proof": object.union(base.proof, {"replay_consumed": false})}) }
test_expired_capability_denied if { not capability.allow with input as object.union(base, {"capability": object.union(base.capability, {"expires_at": 1800000000})}) }
test_revoked_capability_denied if { not capability.allow with input as object.union(base, {"capability": object.union(base.capability, {"revoked": true})}) }
test_cross_tenant_denied if { not capability.allow with input as object.union(base, {"request": object.union(base.request, {"tenant_id": "tenant:contoso"})}) }
test_audience_substitution_denied if { not capability.allow with input as object.union(base, {"request": object.union(base.request, {"audience": "https://claims.northstar.example"})}) }
test_action_escalation_denied if { not capability.allow with input as object.union(base, {"request": object.union(base.request, {"action": "claim.delete"})}) }
test_stale_policy_version_denied if { not capability.allow with input as object.union(base, {"current_policy": object.union(base.current_policy, {"version": "capability-policy-next"})}) }
test_revoked_workload_denied if { not capability.allow with input as object.union(base, {"current_policy": object.union(base.current_policy, {"workload_approved": false})}) }
test_high_risk_denied if { not capability.allow with input as object.union(base, {"current_policy": object.union(base.current_policy, {"risk_score": 50})}) }

test_decision_has_enforceable_obligations if {
  result := capability.decision with input as base
  result.outcome == "allow"
  {item.id | some item in result.obligations} == {"audit", "consume_call_budget", "idempotency"}
}
