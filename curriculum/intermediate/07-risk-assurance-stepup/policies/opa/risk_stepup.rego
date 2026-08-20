package agent.risk_stepup

default decision := {"action":"deny","reason":"default deny"}

decision := {"action":"deny","reason":"prohibited action"} if {
  input.action in {"root_policy.disable_audit", "identity_policy.self_modify"}
}

decision := {"action":"deny","reason":"critical risk"} if {
  input.risk_score >= 80
}

decision := {"action":"step_up","reason":"fresh authentication and approval required"} if {
  input.risk_score >= 60
  input.risk_score < 80
}

decision := {"action":"constrain","reason":"elevated risk"} if {
  input.risk_score >= 30
  input.risk_score < 60
}

decision := {"action":"allow","reason":"low risk and assurance sufficient"} if {
  input.risk_score < 30
  input.workload.attested
}
