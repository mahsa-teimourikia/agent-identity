package northstar.dynamic_test

import rego.v1
import data.northstar.dynamic

base := {
  "caller": {
    "subject_id": "user:alice", "agent_id": "agent:claims-adjuster",
    "workload_id": "spiffe://northstar.example/claims/adjuster",
    "tenant_id": "tenant:northstar", "scopes": ["claims:read", "claims:update"],
    "token_expires_at": 1800000900,
  },
  "proposal": {
    "action": "claim.update", "resource_id": "claim:clm-100",
    "tenant_id": "tenant:northstar", "amount_cents": 0,
  },
  "projection": {
    "subject_id": "user:alice", "session_active": true, "claims_active": true,
    "risk_level": "low", "device_compliant": true, "task_active": true,
    "task_expires_at": 1800003600, "policy_version": 7,
    "resource_version": 4, "relationship_version": 9,
    "relationship_active": true, "approval_version": 2,
    "approval_active": true, "delegation_active": true,
    "workload_quarantined": false, "stream_fresh": true,
  },
  "approval": null,
  "now": 1800000000,
}

test_valid_update if dynamic.allow with input as base

test_revoked_session_denied if {
  changed := object.union(base, {"projection": object.union(base.projection, {"session_active": false})})
  not dynamic.allow with input as changed
}

test_high_risk_denied if {
  changed := object.union(base, {"projection": object.union(base.projection, {"risk_level": "high"})})
  not dynamic.allow with input as changed
}

test_stale_stream_blocks_write if {
  changed := object.union(base, {"projection": object.union(base.projection, {"stream_fresh": false})})
  not dynamic.allow with input as changed
}

test_stale_stream_allows_defined_read if {
  read := object.union(base, {
    "proposal": object.union(base.proposal, {"action": "claim.read"}),
    "projection": object.union(base.projection, {"stream_fresh": false}),
  })
  dynamic.allow with input as read
}

test_cross_tenant_denied if {
  changed := object.union(base, {"proposal": object.union(base.proposal, {"tenant_id": "tenant:other"})})
  not dynamic.allow with input as changed
}

test_payment_requires_exact_approval if {
  payment := object.union(base, {
    "caller": object.union(base.caller, {"scopes": ["payments:create"]}),
    "proposal": {
      "action": "payment.create", "resource_id": "claim:clm-100",
      "tenant_id": "tenant:northstar", "amount_cents": 25000,
      "digest": "proposal-digest",
    },
    "approval": {
      "proposal_digest": "proposal-digest", "subject_id": "user:alice",
      "agent_id": "agent:claims-adjuster", "tenant_id": "tenant:northstar",
      "action": "payment.create", "resource_id": "claim:clm-100",
      "approver_role": "claims-supervisor", "policy_version": 7,
      "approval_version": 2, "issued_at": 1799999970, "expires_at": 1800000300,
    },
  })
  dynamic.allow with input as payment
}

test_changed_payment_digest_denied if {
  payment := object.union(base, {
    "caller": object.union(base.caller, {"scopes": ["payments:create"]}),
    "proposal": {
      "action": "payment.create", "resource_id": "claim:clm-100",
      "tenant_id": "tenant:northstar", "amount_cents": 30000,
      "digest": "changed-digest",
    },
    "approval": {
      "proposal_digest": "old-digest", "subject_id": "user:alice",
      "agent_id": "agent:claims-adjuster", "tenant_id": "tenant:northstar",
      "action": "payment.create", "resource_id": "claim:clm-100",
      "approver_role": "claims-supervisor", "policy_version": 7,
      "approval_version": 2, "issued_at": 1799999970, "expires_at": 1800000300,
    },
  })
  not dynamic.allow with input as payment
}
