package mcp.authz_test

import rego.v1
import data.mcp.authz

base := {
  "now": 1800000000,
  "policy_version": 12,
  "toolset_version": 7,
  "token": {"valid": true, "issuer": "https://id.northstar.example", "audience": "https://claims-mcp.northstar.example"},
  "caller": {"subject_id": "user:alice", "tenant_id": "tenant:northstar", "agent_id": "agent:claims-adjuster", "client_id": "client:claims-copilot", "workload_id": "spiffe://northstar.example/claims/adjuster", "task_id": "task:clm-100-review", "scopes": ["claims:search", "claims:read", "claims:update", "payments:create"]},
  "task": {"task_id": "task:clm-100-review", "subject_id": "user:alice", "tenant_id": "tenant:northstar", "agent_id": "agent:claims-adjuster", "active": true, "allowed_tools": ["claim.search", "claim.read", "claim.update", "payment.create"], "resources": ["claim:clm-100"]},
  "resource": {"resource_id": "claim:clm-100", "tenant_id": "tenant:northstar", "owner_id": "user:alice", "version": 4},
  "proposal": {"tool": "claim.read", "resource_id": "claim:clm-100", "digest": "sha256:read", "limit": 5, "expected_version": 4, "amount_cents": 0, "currency": "CAD", "approval_id": "approval-001"},
  "approval": {"id": "approval-001", "proposal_digest": "sha256:pay", "subject_id": "user:alice", "tenant_id": "tenant:northstar", "agent_id": "agent:claims-adjuster", "task_id": "task:clm-100-review", "policy_version": 12, "resource_version": 4, "expires_at": 1800000120, "used": false},
  "risk": {"level": "low"},
}

payment := object.union(base, {
  "proposal": object.union(base.proposal, {"tool": "payment.create", "digest": "sha256:pay", "amount_cents": 12500}),
})

test_read_allowed if { authz.allow with input as base }

test_search_is_bounded if {
  request := object.union(base, {"proposal": object.union(base.proposal, {"tool": "claim.search", "limit": 10})})
  authz.allow with input as request
  not authz.allow with input as object.union(request, {"proposal": object.union(request.proposal, {"limit": 1000})})
}

test_wrong_audience_denied if {
  not authz.allow with input as object.union(base, {"token": object.union(base.token, {"audience": "https://payments-api.northstar.example"})})
}

test_task_substitution_denied if {
  not authz.allow with input as object.union(base, {"caller": object.union(base.caller, {"task_id": "task:evil"})})
}

test_cross_tenant_resource_denied if {
  not authz.allow with input as object.union(base, {"resource": object.union(base.resource, {"tenant_id": "tenant:evil"})})
}

test_update_requires_current_resource_version if {
  request := object.union(base, {"proposal": object.union(base.proposal, {"tool": "claim.update"})})
  authz.allow with input as request
  not authz.allow with input as object.union(request, {"proposal": object.union(request.proposal, {"expected_version": 3})})
}

test_payment_needs_exact_approval_digest if {
  authz.allow with input as payment
  not authz.allow with input as object.union(payment, {"approval": object.union(payment.approval, {"proposal_digest": "sha256:other"})})
}

test_payment_rejects_consumed_or_stale_approval if {
  not authz.allow with input as object.union(payment, {"approval": object.union(payment.approval, {"used": true})})
  not authz.allow with input as object.union(payment, {"approval": object.union(payment.approval, {"policy_version": 11})})
}

test_high_risk_payment_is_policy_denial_not_scope_growth if {
  not authz.allow with input as object.union(payment, {"risk": {"level": "high"}})
}

test_decision_carries_versions_and_proposal_digest if {
  result := authz.decision with input as base
  result.allowed
  result.policy_version == 12
  result.toolset_version == 7
  result.proposal_digest == "sha256:read"
}
