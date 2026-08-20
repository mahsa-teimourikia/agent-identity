package agent.governance

deny contains {"code":"ORPHANED_AGENT","agent":a.agent_id} if {
  some a in input.agents
  a.status == "active"
  not a.owner
}

deny contains {"code":"WILDCARD_HIGH_RISK","principal":e.principal} if {
  some e in input.entitlements
  e.resource == "*"
  e.risk in {"high","critical"}
}

deny contains {"code":"EXPIRED_EXCEPTION","exception":x.id} if {
  some x in input.exceptions
  time.parse_rfc3339_ns(x.expires_at) < time.now_ns()
}
