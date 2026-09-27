package claims.authz_test

import rego.v1
import data.claims.authz

base := {
  "now": 1800000000,
  "policy_version": "claims-authz-2026-09-27",
  "caller": {"subject_id": "user:alice", "agent_id": "agent:claims-adjuster", "workload_id": "spiffe://northstar.example/claims/adjuster", "tenant_id": "tenant:northstar", "authenticated": true, "workload_attested": true, "scopes": ["claims:read", "claims:update", "payments:create"]},
  "task": {"task_id": "task:review-clm-100", "tenant_id": "tenant:northstar", "requester_id": "user:alice", "assignee_id": "agent:claims-adjuster", "resource_id": "claim:clm-100", "allowed_actions": ["claim.read", "claim.update", "payment.create"], "expires_at": 1800000600, "active": true},
  "resource": {"resource_id": "claim:clm-100", "tenant_id": "tenant:northstar", "owner_id": "user:alice", "status": "open", "version": 7},
  "risk": {"resource_id": "claim:clm-100", "tenant_id": "tenant:northstar", "score": 20, "source": "fraud-service:v4", "observed_at": 1799999995},
  "proposal": {"operation_id": "operation:read", "action": "claim.read", "resource_id": "claim:clm-100", "purpose": "adjust-claim", "amount_cents": 0},
  "approval_valid": false,
}

test_read_allowed if {
  authz.allow with input as base
}

test_wrong_tenant_denied if {
  not authz.allow with input as object.union(base, {"resource": object.union(base.resource, {"tenant_id": "tenant:contoso"})})
}

test_wrong_object_denied if {
  not authz.allow with input as object.union(base, {"proposal": object.union(base.proposal, {"resource_id": "claim:clm-900"})})
}

test_wrong_owner_denied if {
  not authz.allow with input as object.union(base, {"resource": object.union(base.resource, {"owner_id": "user:eve"})})
}

test_unattested_workload_denied if {
  not authz.allow with input as object.union(base, {"caller": object.union(base.caller, {"workload_attested": false})})
}

test_high_risk_update_denied if {
  request := object.union(base, {
    "proposal": object.union(base.proposal, {"action": "claim.update"}),
    "risk": object.union(base.risk, {"score": 50}),
  })
  not authz.allow with input as request
}

test_untrusted_risk_source_denied if {
  request := object.union(base, {
    "proposal": object.union(base.proposal, {"action": "claim.update"}),
    "risk": object.union(base.risk, {"source": "caller:self-report"}),
  })
  not authz.allow with input as request
}

test_payment_needs_exact_approval_signal if {
  request := object.union(base, {
    "proposal": {"operation_id": "operation:pay", "action": "payment.create", "resource_id": "claim:clm-100", "purpose": "settle:claim:clm-100", "amount_cents": 25000},
    "resource": object.union(base.resource, {"status": "settlement-approved"}),
  })
  not authz.allow with input as request
  authz.allow with input as object.union(request, {"approval_valid": true})
}

test_read_returns_mandatory_obligations if {
  result := authz.decision with input as base
  result.decision
  {o.id | some o in result.obligations} == {"audit", "redact_pii"}
}
