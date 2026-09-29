package agent.governance

# Governance evaluation is deterministic: the caller supplies a trusted clock
# and a versioned inventory snapshot. Findings recommend controlled workflows;
# they do not mutate authority directly.

deny contains {"code": "ORPHANED_AGENT", "subject": agent.agent_id} if {
  some agent in input.agents
  agent.status == "active"
  object.get(agent, "owner_id", null) == null
}

deny contains {"code": "STALE_AGENT", "subject": agent.agent_id} if {
  some agent in input.agents
  agent.status == "active"
  input.now - agent.last_seen > 2592000
}

deny contains {"code": "HIGH_RISK_WILDCARD", "subject": entitlement.principal_id} if {
  some entitlement in input.entitlements
  entitlement.risk in {"high", "critical"}
  contains(entitlement.resource, "*")
}

deny contains {"code": "UNUSED_HIGH_RISK_PERMISSION", "subject": entitlement.principal_id} if {
  some entitlement in input.entitlements
  entitlement.risk in {"high", "critical"}
  object.get(input.usage_90d, entitlement.entitlement_id, 0) == 0
}

deny contains {"code": "TOXIC_COMBINATION", "subject": principal} if {
  some first in input.entitlements
  some second in input.entitlements
  first.principal_id == second.principal_id
  principal := first.principal_id
  first.action == "payment.create"
  second.action == "payment.approve"
}

deny contains {"code": "DELEGATION_EXPIRED", "subject": delegation.delegatee} if {
  some delegation in input.delegations
  delegation.active
  delegation.expires_at <= input.now
}

deny contains {"code": "DELEGATION_DEPTH_EXCEEDED", "subject": delegation.delegatee} if {
  some delegation in input.delegations
  delegation.active
  delegation.depth > delegation.max_depth
}

deny contains {"code": "DELEGATION_WIDENED", "subject": delegation.delegatee} if {
  some delegation in input.delegations
  delegation.active
  delegation.parent_id != null
  some parent in input.delegations
  parent.delegation_id == delegation.parent_id
  some permission in delegation.permissions
  not permission in parent.permissions
}

deny contains {"code": "EXCEPTION_EXPIRED", "subject": exception.principal_id} if {
  some exception in input.exceptions
  not exception.revoked
  exception.expires_at <= input.now
}
