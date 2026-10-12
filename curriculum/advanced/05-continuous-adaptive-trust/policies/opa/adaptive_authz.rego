package agent.adaptive

import rego.v1

default allow := false

# Input is normalized by the trusted signal receiver and projector. The agent
# cannot populate current state, risk, stream health, or governed versions.
allow if {
  input.request.tenant_id == "tenant:northstar"
  input.request.agent_id == "agent:claims-adjuster"
  input.request.workload_id == "spiffe://northstar.example/claims/adjuster"
  input.request.session_id == "session:claims:483"
  input.request.action == "claim.update"
  input.request.resource == "claim:483"
  input.current.session_active
  input.current.credential_active
  input.current.workload_trusted
  input.current.task_active
  input.current.relationship_active
  input.current.claims_current
  not input.current.quarantined
  input.current.policy_version == "adaptive-policy-2026-10-12"
  input.current.max_risk < 45
  input.signals.stream_available
  input.signals.pending_count == 0
  input.signals.fresh
}

deny_reason contains "agent_quarantined" if input.current.quarantined
deny_reason contains "session_revoked" if not input.current.session_active
deny_reason contains "credential_revoked" if not input.current.credential_active
deny_reason contains "workload_untrusted" if not input.current.workload_trusted
deny_reason contains "task_inactive" if not input.current.task_active
deny_reason contains "relationship_inactive" if not input.current.relationship_active
deny_reason contains "signal_stream_degraded" if not input.signals.stream_available
deny_reason contains "signal_backlog" if input.signals.pending_count > 0
deny_reason contains "risk_requires_adaptation" if input.current.max_risk >= 45
