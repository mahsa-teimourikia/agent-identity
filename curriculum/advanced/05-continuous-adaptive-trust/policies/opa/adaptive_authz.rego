package agent.adaptive
default decision := "DENY"

decision := "QUARANTINE" if {
  input.state.quarantined
}

decision := "REVOKE" if {
  input.state.revoked
  not input.state.quarantined
}

decision := "STEP_UP" if {
  input.risk.score >= 70
  input.risk.score < 90
  not input.state.revoked
  not input.state.quarantined
}

decision := "REDUCE" if {
  input.risk.score >= 45
  input.risk.score < 70
  not input.state.revoked
  not input.state.quarantined
}

decision := "ALLOW" if {
  input.risk.score < 45
  not input.state.revoked
  not input.state.quarantined
}
