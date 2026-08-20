# Credential Compromise Runbook

1. Identify credential and subject.
2. Revoke active credential and renewal path.
3. Invalidate authorization caches.
4. Quarantine affected workload/agent if scope is uncertain.
5. Remove delegated authority.
6. Rotate affected keys/secrets.
7. Inspect token exchange, tool, KMS and API telemetry.
8. Re-attest workload.
9. Reissue minimal credentials.
10. Restore authority gradually and document evidence.
