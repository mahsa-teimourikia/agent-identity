package agent.identity.threat
default allow := false
allow if {
  input.identity.status == "active"
  not input.credential.leaked
  input.credential.audience == input.resource.audience
  input.delegation.depth <= input.policy.max_delegation_depth
  input.delegation.scope <= input.parent.scope
  input.telemetry.healthy
}
deny contains "revoked identity" if { input.identity.status == "revoked" }
deny contains "delegation escalation" if { not input.delegation.scope <= input.parent.scope }
deny contains "telemetry unhealthy" if { not input.telemetry.healthy }
