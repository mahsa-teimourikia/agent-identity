package agent.workload

default allow := false

allow if {
  input.logical_agent == "claims-agent"
  input.workload.spiffe_id == "spiffe://corp.example/prod/agents/claims-agent"
  input.workload.attested
  input.workload.node_attested
  input.workload.image_verified
  input.workload.provenance_verified
  input.workload.posture_fresh
  input.workload.status == "active"
  input.task.active
  input.action == "claim.update"
  input.resource.id == input.task.resource
}
