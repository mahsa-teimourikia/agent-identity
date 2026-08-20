package agent.authz_test

import data.agent.authz

good := {
  "principal": {"authenticated": true, "tenant": "acme"},
  "agent": {"id": "claims-agent"},
  "workload": {"approved": true},
  "delegation": {
    "active": true,
    "delegatee": "claims-agent",
    "actions": ["claim.read"],
    "resources": ["claim:483"]
  },
  "action": "claim.read",
  "resource": {"id": "claim:483", "tenant": "acme"}
}

test_expected_allow if {
  authz.allow with input as good
}

test_cross_tenant_denied if {
  not authz.allow with input as object.union(good, {
    "resource": {"id": "claim:483", "tenant": "other"}
  })
}

test_wrong_workload_denied if {
  not authz.allow with input as object.union(good, {
    "workload": {"approved": false}
  })
}

test_actor_substitution_denied if {
  not authz.allow with input as object.union(good, {
    "agent": {"id": "other-agent"}
  })
}
