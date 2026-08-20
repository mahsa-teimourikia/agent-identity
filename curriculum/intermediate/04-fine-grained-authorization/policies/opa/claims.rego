package agent.claims

default allow := false

allow if {
  input.user.id == "alice"
  input.agent.id == "claims-agent"
  input.task.active
  input.resource.claim_id == input.task.claim_id
  input.action == "claim.read"
}

allow if {
  input.user.id == "alice"
  input.agent.id == "claims-agent"
  input.task.active
  input.resource.claim_id == input.task.claim_id
  input.action == "claim.update"
  input.context.risk_score < 50
}

allow if {
  input.user.id == "alice"
  input.agent.id == "claims-agent"
  input.task.active
  input.action == "payment.create"
  input.context.approved
  input.context.amount <= 500
}
