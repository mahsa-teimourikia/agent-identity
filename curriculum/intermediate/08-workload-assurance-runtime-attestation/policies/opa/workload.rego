package agent.workload

import rego.v1

deny_reasons contains "identity_document_unverified" if { not input.identity.verified }
deny_reasons contains "trust_domain_untrusted" if { input.identity.trust_domain != "northstar.example" }
deny_reasons contains "agent_workload_binding_invalid" if { input.identity.spiffe_id != "spiffe://northstar.example/prod/agents/claims-adjuster" }
deny_reasons contains "attestation_result_unverified" if { not input.attestation.verified }
deny_reasons contains "attestation_verifier_untrusted" if { input.attestation.verifier_id != "verifier:northstar-runtime-v3" }
deny_reasons contains "attestation_policy_untrusted" if { input.attestation.policy_id != "runtime-baseline-v7" }
deny_reasons contains "identity_attestation_binding_invalid" if { input.attestation.spiffe_id != input.identity.spiffe_id }
deny_reasons contains "artifact_binding_invalid" if { input.attestation.artifact_digest != input.provenance.artifact_digest }
deny_reasons contains "provenance_unverified" if { not input.provenance.verified }
deny_reasons contains "builder_untrusted" if { input.provenance.builder_id != "https://github.com/northstar/secure-builders/claims@v4" }
deny_reasons contains "source_untrusted" if { input.provenance.source_repository != "https://github.com/northstar/claims-agent" }
deny_reasons contains "signer_untrusted" if { input.provenance.signer_identity != "https://github.com/northstar/claims-agent/.github/workflows/release.yml@refs/tags/v4.3.1" }
deny_reasons contains "posture_schema_untrusted" if { input.posture.schema_version != 3 }
deny_reasons contains "task_inactive" if { not input.task.active }
action_allowed if { input.action in input.task.actions }
deny_reasons contains "business_authority_invalid" if { not action_allowed }
deny_reasons contains "business_authority_invalid" if { input.resource.id != input.task.resource_id }

decision := {"outcome": "quarantine", "reason_codes": ["workload_quarantined"]} if {
  input.posture.status == "quarantined"
} else := {"outcome": "deny", "reason_codes": sort([reason | some reason in deny_reasons])} if {
  count(deny_reasons) > 0
} else := {"outcome": "reattest", "reason_codes": ["attestation_result_stale"]} if {
  input.attestation.expires_at <= input.now
} else := {"outcome": "allow", "reason_codes": ["requirements_satisfied"]}

evidence := {
  "outcome": decision.outcome,
  "reason_codes": decision.reason_codes,
  "spiffe_id": input.identity.spiffe_id,
  "identity_credential_id": input.identity.credential_id,
  "attestation_result_id": input.attestation.result_id,
  "artifact_digest": input.provenance.artifact_digest,
  "provenance_digest": input.provenance.envelope_digest,
  "policy_version": 15,
}
