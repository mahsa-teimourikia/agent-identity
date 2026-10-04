package agent.tools_test

import data.agent.tools
import rego.v1

valid_input := {
    "principal": {"id": "user:alice", "tenant": "tenant:northstar", "authenticated": true},
    "agent": {"id": "agent:claims"},
    "workload": {"id": "spiffe://northstar.example/prod/claims", "approved": true},
    "task": {"id": "task:483"},
    "delegation": {
        "principal": "user:alice",
        "delegatee": "agent:claims",
        "workload": "spiffe://northstar.example/prod/claims",
        "tenant": "tenant:northstar",
        "task": "task:483",
        "active": true,
        "actions": ["claim.read", "payment.create"],
        "resources": ["claim:483", "account:42"],
    },
    "resource": {"id": "claim:483", "tenant": "tenant:northstar"},
    "action": "claim.read",
    "tool": {"name": "claims.get", "action": "claim.read", "server": "mcp://claims-prod", "schema_hash": "sha256:v1"},
    "request": {"tool": "claims.get", "server": "mcp://claims-prod", "schema_hash": "sha256:v1"},
    "parameters": {},
    "policy": {"version": "agent-tools/2026-10-04"},
}

test_valid_request_allowed if tools.allow with input as valid_input
test_default_deny_empty if not tools.allow with input as {}
test_cross_tenant_denied if not tools.allow with input as object.union(valid_input, {"resource": {"id": "claim:483", "tenant": "tenant:evil"}})
test_untrusted_workload_denied if not tools.allow with input as object.union(valid_input, {"workload": {"id": "spiffe://evil", "approved": true}})
test_revoked_delegation_denied if not tools.allow with input as object.union(valid_input, {"delegation": object.union(valid_input.delegation, {"active": false})})
test_tool_substitution_denied if not tools.allow with input as object.union(valid_input, {"request": {"tool": "claims.update", "server": "mcp://claims-prod", "schema_hash": "sha256:v1"}})
test_server_substitution_denied if not tools.allow with input as object.union(valid_input, {"request": {"tool": "claims.get", "server": "mcp://evil", "schema_hash": "sha256:v1"}})
test_schema_substitution_denied if not tools.allow with input as object.union(valid_input, {"request": {"tool": "claims.get", "server": "mcp://claims-prod", "schema_hash": "sha256:v2"}})
test_stale_policy_denied if not tools.allow with input as object.union(valid_input, {"policy": {"version": "agent-tools/stale"}})

payment_input := object.union(valid_input, {
    "resource": {"id": "account:42", "tenant": "tenant:northstar"},
    "action": "payment.create",
    "tool": {"name": "payments.create", "action": "payment.create", "server": "mcp://payments-prod", "schema_hash": "sha256:payment"},
    "request": {"tool": "payments.create", "server": "mcp://payments-prod", "schema_hash": "sha256:payment"},
    "parameters": {"amount_cents": 75000},
})

test_high_payment_allowed_but_requires_approval if {
    tools.allow with input as payment_input
    tools.requires_approval with input as payment_input
}

test_low_payment_does_not_require_approval if not tools.requires_approval with input as object.union(payment_input, {"parameters": {"amount_cents": 1000}})
