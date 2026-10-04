package agent.authz_test

import rego.v1
import data.agent.authz

good := {
    "now": 1800200000,
    "token": {
        "verified": true,
        "issuer": "https://identity.northstar.example",
        "audience": "https://claims-api.northstar.example",
        "subject": "user:alice",
        "actor": "agent:claims",
        "workload_id": "spiffe://northstar.example/prod/claims",
        "tenant_id": "tenant:northstar",
        "task_id": "task:483",
    },
    "principal": {"id": "user:alice", "authenticated": true, "tenant": "tenant:northstar"},
    "agent": {"id": "agent:claims"},
    "workload": {"id": "spiffe://northstar.example/prod/claims", "approved": true},
    "task": {"id": "task:483"},
    "delegation": {
        "active": true, "revoked": false,
        "not_before": 1800199900, "expires_at": 1800200300,
        "delegatee": "agent:claims", "tenant_id": "tenant:northstar",
        "task_id": "task:483", "depth": 1, "max_depth": 2,
        "actions": ["claim.read"], "resources": ["claim:483"],
    },
    "action": "claim.read",
    "resource": {"id": "claim:483", "tenant": "tenant:northstar"},
    "tool": {"approved": true, "binding_valid": true},
    "request": {"binding_valid": true},
    "policy_data_fresh": true,
}

test_expected_allow if { authz.allow with input as good }
test_unverified_token_denied if {
    not authz.allow with input as object.union(good, {"token": object.union(good.token, {"verified": false})})
}
test_wrong_audience_denied if {
    not authz.allow with input as object.union(good, {"token": object.union(good.token, {"audience": "https://evil.example"})})
}
test_actor_substitution_denied if {
    not authz.allow with input as object.union(good, {"agent": {"id": "agent:attacker"}})
}
test_workload_substitution_denied if {
    not authz.allow with input as object.union(good, {"workload": {"id": "spiffe://evil/workload", "approved": true}})
}
test_cross_tenant_denied if {
    not authz.allow with input as object.union(good, {"resource": {"id": "claim:483", "tenant": "tenant:other"}})
}
test_wrong_resource_denied if {
    not authz.allow with input as object.union(good, {"resource": {"id": "claim:999", "tenant": "tenant:northstar"}})
}
test_revoked_delegation_denied if {
    not authz.allow with input as object.union(good, {"delegation": object.union(good.delegation, {"revoked": true})})
}
test_expired_delegation_denied if {
    not authz.allow with input as object.union(good, {"delegation": object.union(good.delegation, {"expires_at": 1800200000})})
}
test_depth_abuse_denied if {
    not authz.allow with input as object.union(good, {"delegation": object.union(good.delegation, {"depth": 3})})
}
test_tool_substitution_denied if {
    not authz.allow with input as object.union(good, {"tool": {"approved": true, "binding_valid": false}})
}
test_parameter_swap_denied if {
    not authz.allow with input as object.union(good, {"request": {"binding_valid": false}})
}
test_stale_policy_data_denied if {
    not authz.allow with input as object.union(good, {"policy_data_fresh": false})
}
