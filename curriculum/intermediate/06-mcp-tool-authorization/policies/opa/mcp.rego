package mcp.authz

default allow := false

allow if {
  input.token.valid
  input.token.audience == input.mcp_server
  input.user.id == input.resource.owner
  input.agent.id == "claims-agent"
  input.task.active
  input.task.resource == input.resource.id
  input.tool.name == "claim.read"
}

allow if {
  input.token.valid
  input.token.audience == input.mcp_server
  input.user.id == input.resource.owner
  input.agent.id == "claims-agent"
  input.task.active
  input.task.resource == input.resource.id
  input.tool.name == "payment.create"
  input.approval.valid
  input.args.amount <= input.approval.max_amount
}
