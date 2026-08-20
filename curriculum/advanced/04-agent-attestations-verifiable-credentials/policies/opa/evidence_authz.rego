package agent.evidence
default allow := false

allow if {
  input.evidence.agent.registered
  input.evidence.workload.attested
  input.evidence.release.provenance_verified
  input.evidence.evaluation.passed
  input.evidence.governance.approved
  input.risk.level == "low"
  not input.evidence.agent.quarantined
}

step_up if {
  input.evidence.agent.registered
  input.evidence.workload.attested
  input.evidence.release.provenance_verified
  input.risk.level == "medium"
}

deny_reason contains "agent_quarantined" if input.evidence.agent.quarantined
deny_reason contains "evaluation_missing" if not input.evidence.evaluation.passed
