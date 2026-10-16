package northstar.identity_threat

import rego.v1

default allow := false

allow if {
  input.identity.status == "active"
  input.telemetry.healthy
  input.credential.audience == input.resource.audience
  input.credential.version == input.credential.current_version
  input.runtime.workload_id == input.identity.expected_workload_id
  input.runtime.environment == input.resource.environment
  every action in input.delegation.scope {
    action in input.parent.scope
  }
}

deny contains "revoked identity" if input.identity.status == "revoked"
deny contains "audience mismatch" if input.credential.audience != input.resource.audience
deny contains "telemetry unhealthy" if not input.telemetry.healthy
deny contains "workload mismatch" if input.runtime.workload_id != input.identity.expected_workload_id
deny contains "delegation escalation" if {
  some action in input.delegation.scope
  not action in input.parent.scope
}
