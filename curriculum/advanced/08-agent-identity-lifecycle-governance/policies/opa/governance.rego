package northstar.agent_governance

import rego.v1

default allow := false

allow if {
  input.identity.state == "active"
  input.identity.credential_active
  input.identity.tenant_id == input.request.tenant_id
  input.identity.workload_id == input.request.workload_id
  input.request.action in input.identity.approved_actions
  some prefix in input.identity.resource_prefixes
  startswith(input.request.resource, prefix)
  input.request.now < input.identity.review_due
  input.request.policy_version == input.identity.policy_version
}

deny contains "retired identity" if input.identity.state == "retired"
deny contains "review overdue" if input.request.now >= input.identity.review_due
deny contains "tenant mismatch" if input.identity.tenant_id != input.request.tenant_id
deny contains "workload mismatch" if input.identity.workload_id != input.request.workload_id
deny contains "credential inactive" if not input.identity.credential_active
