package agent.governance_test

import data.agent.governance

base_input := {
  "now": 1800000000,
  "agents": [{"agent_id": "agent:claims", "owner_id": "team:claims", "status": "active", "last_seen": 1799999900}],
  "entitlements": [{"entitlement_id": "ent:read", "principal_id": "agent:claims", "action": "claim.read", "resource": "claim:483", "risk": "medium"}],
  "delegations": [],
  "exceptions": [],
  "usage_90d": {"ent:read": 10}
}

codes(input_value) := result if {
  result := {finding.code | some finding in governance.deny} with input as input_value
}

test_clean_inventory_has_no_findings if {
  count(governance.deny) == 0 with input as base_input
}

test_orphaned_agent if {
  "ORPHANED_AGENT" in codes(object.union(base_input, {"agents": [{"agent_id": "agent:orphan", "owner_id": null, "status": "active", "last_seen": 1799999900}]}))
}

test_stale_agent if {
  "STALE_AGENT" in codes(object.union(base_input, {"agents": [{"agent_id": "agent:stale", "owner_id": "team:x", "status": "active", "last_seen": 1700000000}]}))
}

test_high_risk_wildcard if {
  "HIGH_RISK_WILDCARD" in codes(object.union(base_input, {"entitlements": [{"entitlement_id": "ent:wild", "principal_id": "agent:claims", "action": "claim.export", "resource": "claims/*", "risk": "critical"}], "usage_90d": {"ent:wild": 1}}))
}

test_unused_high_risk_permission if {
  "UNUSED_HIGH_RISK_PERMISSION" in codes(object.union(base_input, {"entitlements": [{"entitlement_id": "ent:unused", "principal_id": "agent:claims", "action": "claim.export", "resource": "claim:483", "risk": "high"}]}))
}

test_toxic_combination if {
  "TOXIC_COMBINATION" in codes(object.union(base_input, {"entitlements": [
    {"entitlement_id": "ent:create", "principal_id": "agent:finance", "action": "payment.create", "resource": "payments/*", "risk": "critical"},
    {"entitlement_id": "ent:approve", "principal_id": "agent:finance", "action": "payment.approve", "resource": "payments/*", "risk": "critical"}
  ]}))
}

test_expired_delegation if {
  "DELEGATION_EXPIRED" in codes(object.union(base_input, {"delegations": [{"delegation_id": "del:1", "delegatee": "agent:claims", "active": true, "expires_at": 1799999999, "depth": 0, "max_depth": 1, "parent_id": null, "permissions": []}]}))
}

test_depth_exceeded if {
  "DELEGATION_DEPTH_EXCEEDED" in codes(object.union(base_input, {"delegations": [{"delegation_id": "del:1", "delegatee": "agent:claims", "active": true, "expires_at": 1800001000, "depth": 2, "max_depth": 1, "parent_id": null, "permissions": []}]}))
}

test_widened_delegation if {
  "DELEGATION_WIDENED" in codes(object.union(base_input, {"delegations": [
    {"delegation_id": "del:root", "delegatee": "agent:claims", "active": true, "expires_at": 1800001000, "depth": 0, "max_depth": 2, "parent_id": null, "permissions": ["claim.read|claim:483"]},
    {"delegation_id": "del:child", "delegatee": "agent:research", "active": true, "expires_at": 1800001000, "depth": 1, "max_depth": 2, "parent_id": "del:root", "permissions": ["claim.delete|claim:483"]}
  ]}))
}

test_expired_exception if {
  "EXCEPTION_EXPIRED" in codes(object.union(base_input, {"exceptions": [{"exception_id": "exc:1", "principal_id": "agent:claims", "revoked": false, "expires_at": 1800000000}]}))
}
