package capstone.authz_test

import data.capstone.authz
import rego.v1

valid_input := {
    "principal": {"id": "user:alice", "tenant": "tenant:northstar", "authenticated": true, "active": true},
    "token": {"issuer": "https://id.northstar.example", "audience": "https://agent-gateway.northstar.example", "sender_bound": true, "scopes": ["claims:read"]},
    "agent": {"id": "agent:claims", "registered": true, "active": true, "review_current": true},
    "workload": {"id": "spiffe://northstar.example/prod/claims", "agent_id": "agent:claims", "approved": true, "artifact_approved": true},
    "task": {"id": "task:483"},
    "delegation": {"principal": "user:alice", "delegatee": "agent:claims", "workload": "spiffe://northstar.example/prod/claims", "tenant": "tenant:northstar", "task": "task:483", "active": true, "actions": ["claim.read"], "resources": ["claim:483"]},
    "resource": {"id": "claim:483", "tenant": "tenant:northstar"},
    "relationship": {"authorized": true},
    "action": "claim.read",
    "tool": {"name": "claims.get", "action": "claim.read", "server": "mcp://claims-prod", "audience": "https://claims-prod", "scope": "claims:read"},
    "request": {"tool": "claims.get", "server": "mcp://claims-prod", "audience": "https://claims-prod", "token_passthrough": false},
    "risk": "low",
    "policy": {"version": "capstone/2026-10-04"},
}

test_valid_request_allowed if authz.allow with input as valid_input
test_default_deny_empty if not authz.allow with input as {}
test_cross_tenant_denied if not authz.allow with input as object.union(valid_input, {"resource": {"id": "claim:483", "tenant": "tenant:evil"}})
test_wrong_issuer_denied if not authz.allow with input as object.union(valid_input, {"token": object.union(valid_input.token, {"issuer": "https://evil"})})
test_wrong_audience_denied if not authz.allow with input as object.union(valid_input, {"token": object.union(valid_input.token, {"audience": "https://other"})})
test_unbound_sender_denied if not authz.allow with input as object.union(valid_input, {"token": object.union(valid_input.token, {"sender_bound": false})})
test_unapproved_artifact_denied if not authz.allow with input as object.union(valid_input, {"workload": object.union(valid_input.workload, {"artifact_approved": false})})
test_revoked_delegation_denied if not authz.allow with input as object.union(valid_input, {"delegation": object.union(valid_input.delegation, {"active": false})})
test_relationship_denied if not authz.allow with input as object.union(valid_input, {"relationship": {"authorized": false}})
test_server_substitution_denied if not authz.allow with input as object.union(valid_input, {"request": object.union(valid_input.request, {"server": "mcp://evil"})})
test_token_passthrough_denied if not authz.allow with input as object.union(valid_input, {"request": object.union(valid_input.request, {"token_passthrough": true})})
test_stale_policy_denied if not authz.allow with input as object.union(valid_input, {"policy": {"version": "capstone/stale"}})

test_high_risk_requires_approval if authz.requires_approval with input as object.union(valid_input, {"risk": "high"})
test_low_risk_does_not_require_approval if not authz.requires_approval with input as valid_input
