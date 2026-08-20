package agent.identity.governance
default deploy := false

deploy if {
  input.inventory.owner != ""
  input.inventory.status == "approved"
  not input.identity.static_secret
  input.identity.runtime_binding
  input.monitoring.enabled
  approvals_satisfied
}

approvals_satisfied if {
  input.inventory.risk == "low"
  "owner" in input.approvals
}

approvals_satisfied if {
  input.inventory.risk == "high"
  "owner" in input.approvals
  "security" in input.approvals
  input.requester != input.approver
}

deny contains "expired exception" if {
  input.exception.enabled
  input.exception.expired
}
