package agent.workload_test

import data.agent.workload
import rego.v1

base := {
  "now": 1800000000,
  "action": "claim.update",
  "resource": {"id": "claim:clm-100"},
  "identity": {"verified": true, "trust_domain": "northstar.example", "spiffe_id": "spiffe://northstar.example/prod/agents/claims-adjuster", "credential_id": "cert-1"},
  "attestation": {"verified": true, "verifier_id": "verifier:northstar-runtime-v3", "policy_id": "runtime-baseline-v7", "spiffe_id": "spiffe://northstar.example/prod/agents/claims-adjuster", "artifact_digest": "sha256:approved", "result_id": "result-1", "expires_at": 1800000300},
  "provenance": {"verified": true, "artifact_digest": "sha256:approved", "builder_id": "https://github.com/northstar/secure-builders/claims@v4", "source_repository": "https://github.com/northstar/claims-agent", "signer_identity": "https://github.com/northstar/claims-agent/.github/workflows/release.yml@refs/tags/v4.3.1", "envelope_digest": "prov-1"},
  "posture": {"schema_version": 3, "status": "active"},
  "task": {"active": true, "actions": ["claim.read", "claim.update"], "resource_id": "claim:clm-100"},
}

test_valid_runtime_allowed if { workload.decision with input as base == {"outcome": "allow", "reason_codes": ["requirements_satisfied"]} }
test_wrong_identity_denied if { workload.decision.outcome with input as object.union(base, {"identity": object.union(base.identity, {"spiffe_id": "spiffe://northstar.example/prod/agents/evil"})}) == "deny" }
test_unverified_attestation_denied if { "attestation_result_unverified" in workload.decision.reason_codes with input as object.union(base, {"attestation": object.union(base.attestation, {"verified": false})}) }
test_artifact_substitution_denied if { "artifact_binding_invalid" in workload.decision.reason_codes with input as object.union(base, {"attestation": object.union(base.attestation, {"artifact_digest": "sha256:evil"})}) }
test_untrusted_builder_denied if { "builder_untrusted" in workload.decision.reason_codes with input as object.union(base, {"provenance": object.union(base.provenance, {"builder_id": "https://evil.example"})}) }
test_stale_result_requests_reattest if { workload.decision.outcome with input as object.union(base, {"attestation": object.union(base.attestation, {"expires_at": 1800000000})}) == "reattest" }
test_quarantine_overrides_valid_evidence if { workload.decision.outcome with input as object.union(base, {"posture": {"schema_version": 3, "status": "quarantined"}}) == "quarantine" }
test_business_action_still_authorized if { workload.decision.outcome with input as object.union(base, {"action": "payment.create"}) == "deny" }
test_evidence_is_versioned if {
  result := workload.evidence with input as base
  result.policy_version == 15
}
