package agent.dynamic

default decision := {"action":"deny","reason":"default deny"}

decision := {"action":"revoke","reason":"agent quarantined"} if {
  input.agent.status == "quarantined"
}

decision := {"action":"revoke","reason":"task inactive"} if {
  not input.task.active
}

decision := {"action":"step_up","reason":"high risk"} if {
  input.agent.status == "active"
  input.task.active
  input.risk.score >= 60
  input.risk.score < 80
}

decision := {"action":"revoke","reason":"critical risk"} if {
  input.risk.score >= 80
}

decision := {"action":"continue","reason":"conditions valid"} if {
  input.agent.status == "active"
  input.task.active
  input.risk.score < 60
  input.policy.version == input.session.policy_version
}
