package agent.authz_test

import rego.v1
import data.agent.authz

base := {
  "now": 1800000000,
  "policy_version": "advanced-authz-2026-10-07",
  "identity": {"subject_id": "user:alice", "agent_id": "agent:claims", "workload_id": "spiffe://northstar.example/claims/agent", "tenant_id": "tenant:northstar", "roles": ["claims-operator"], "authenticated": true, "workload_attested": true},
  "relationships": {"version": "relations:42", "observed_at": 1799999995, "user_operates_agent": true, "agent_assigned_to_task": true, "task_contains_resource": true, "task_permits_tool": true, "available": true},
  "task": {"task_id": "task:claim-483", "tenant_id": "tenant:northstar", "subject_id": "user:alice", "agent_id": "agent:claims", "resource_id": "claim:483", "tool_id": "tool:claims-update", "actions": ["claim.read", "claim.update", "claim.settle"], "purposes": ["claims-processing", "settle-claim"], "expires_at": 1800000600, "remaining_calls": 3, "active": true},
  "resource": {"resource_id": "claim:483", "tenant_id": "tenant:northstar", "owner_id": "user:alice", "classification": "restricted", "status": "open", "version": 9},
  "attributes": {"version": "attributes:17", "observed_at": 1799999995, "source": "risk-engine:v5", "risk_score": 20, "device_managed": true, "network_zone": "corporate", "available": true},
  "proposal": {"operation_id": "operation:read:483", "action": "claim.read", "resource_id": "claim:483", "tool_id": "tool:claims-update", "purpose": "claims-processing", "fields": [], "amount_cents": 0},
  "approval_valid": false,
}

update := object.union(base, {"proposal": object.union(base.proposal, {"action": "claim.update", "fields": ["status", "notes"]})})

test_read_allowed if { authz.allow with input as base }
test_update_allowed if { authz.allow with input as update }

test_cross_tenant_denied if {
  not authz.allow with input as object.union(base, {"resource": object.union(base.resource, {"tenant_id": "tenant:contoso"})})
}

test_unattested_workload_denied if {
  not authz.allow with input as object.union(base, {"identity": object.union(base.identity, {"workload_attested": false})})
}

test_missing_operator_edge_denied if {
  not authz.allow with input as object.union(base, {"relationships": object.union(base.relationships, {"user_operates_agent": false})})
}

test_stale_relationships_denied if {
  not authz.allow with input as object.union(base, {"relationships": object.union(base.relationships, {"observed_at": 1799999939})})
}

test_stale_attribute_version_denied if {
  not authz.allow with input as object.union(base, {"attributes": object.union(base.attributes, {"version": "attributes:16"})})
}

test_expired_task_denied if {
  not authz.allow with input as object.union(base, {"task": object.union(base.task, {"expires_at": 1800000000})})
}

test_exhausted_budget_denied if {
  not authz.allow with input as object.union(base, {"task": object.union(base.task, {"remaining_calls": 0})})
}

test_tool_substitution_denied if {
  not authz.allow with input as object.union(base, {"proposal": object.union(base.proposal, {"tool_id": "tool:wire-transfer"})})
}

test_field_constraint_denied if {
  not authz.allow with input as object.union(update, {"proposal": object.union(update.proposal, {"fields": ["bank_account"]})})
}

test_elevated_risk_steps_up if {
  request := object.union(base, {"attributes": object.union(base.attributes, {"risk_score": 50})})
  result := authz.decision with input as request
  result.outcome == "step_up"
}

test_critical_risk_denied if {
  request := object.union(base, {"attributes": object.union(base.attributes, {"risk_score": 80})})
  result := authz.decision with input as request
  result.outcome == "deny"
}

test_settlement_needs_approval if {
  request := object.union(base, {
    "proposal": {"operation_id": "operation:settle:483", "action": "claim.settle", "resource_id": "claim:483", "tool_id": "tool:claims-update", "purpose": "settle-claim", "fields": [], "amount_cents": 25000},
    "resource": object.union(base.resource, {"status": "settlement-approved"}),
  })
  not authz.allow with input as request
  authz.allow with input as object.union(request, {"approval_valid": true})
}

test_read_obligations_are_explicit if {
  result := authz.decision with input as base
  {item.id | some item in result.obligations} == {"audit", "redact"}
}
