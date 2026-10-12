package agent.evidence

default allow := false

# These fields are normalized by a trusted verifier. The model and tool request
# cannot populate them directly.
allow if {
  input.request.action == "claim.update"
  input.request.resource == "claim:483"
  input.request.tenant_id == "tenant:northstar"
  input.evidence.identity == "verified"
  input.evidence.workload == "verified"
  input.evidence.supply_chain == "verified"
  input.evidence.evaluation == "verified"
  input.evidence.governance == "verified"
  input.current.policy_version == "evidence-policy-2026-10-12"
  input.current.relationship_active
  input.current.task_active
  input.current.risk_score < 50
  not input.current.quarantined
}

deny_reason contains "agent_quarantined" if input.current.quarantined
deny_reason contains "relationship_inactive" if not input.current.relationship_active
deny_reason contains "task_inactive" if not input.current.task_active
deny_reason contains "runtime_risk_too_high" if input.current.risk_score >= 50
deny_reason contains "evaluation_unverified" if input.evidence.evaluation != "verified"
deny_reason contains "workload_unverified" if input.evidence.workload != "verified"
deny_reason contains "provenance_unverified" if input.evidence.supply_chain != "verified"
