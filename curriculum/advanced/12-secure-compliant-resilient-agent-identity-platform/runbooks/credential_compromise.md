# Credential Compromise Runbook

## Trigger and authority

Admit only an authenticated alert from a producer authorized for credential-compromise findings. Assign an incident ID, commander, severity, affected tenant, credential ID, agent, workload, first/last seen, and evidence checkpoint. Preserve the original alert before containment.

## Contain

1. Revoke the credential and its renewal path; record the request and independently verify token status.
2. Invalidate decisions and sessions derived from the credential and every affected delegation ancestor/descendant.
3. Quarantine the workload and logical agent when exposure scope is uncertain. Destructive or tenant-wide actions require the incident's approval policy.
4. Block new token exchange and MCP/tool execution for the affected identity while preserving investigation access.
5. Use stable action IDs. On timeout, reconcile the requested effect before retrying.

## Investigate and eradicate

1. Reconstruct actor chain, sender key, audience, policy version, approval receipts, tools, resources, and effects.
2. Inspect authorization-server, workload, PEP, protected-resource, KMS, and federation telemetry for reuse and persistence.
3. Rotate affected keys, remove attacker-created clients/delegations, rebuild the workload from an approved artifact, and re-attest it.

## Recover

Restore minimal authority only when credential rotation, fresh attestation, persistence removal, incident clearance, and explicit recovery approval are all current and independently evidenced. Monitor a heightened-risk window, checkpoint the final evidence root, and record residual risk and follow-up owners.
