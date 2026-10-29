# Federation Compromise Runbook

## Trigger and scope

Identify the exact issuer, trust domain, trust anchor, bundle/metadata digest and version, endpoint profile, affected subjects, tenants, and validity interval. Preserve the last trusted and suspect metadata plus fetch logs in the evidence store.

## Contain

1. Block new sessions and token exchange from the affected relationship without pooling or substituting another trust-domain bundle.
2. Invalidate cached foreign-identity decisions and revoke affected cross-domain delegations.
3. Suspend destructive partner actions first; use a separately approved action if the blast radius is tenant-wide.
4. Verify each local effect by receipt. Treat response loss as unknown until reconciled.

## Investigate and repair

1. Reconstruct every local resource and MCP tool used by foreign subjects during the suspect interval.
2. Determine whether the anchor, bundle endpoint parameters, serving workload, signing keys, metadata policy, or local mapping was compromised.
3. Rotate keys and bootstrap material through a separately authenticated channel; bind the new digest to the exact trust domain.
4. Re-fetch and validate fresh metadata, then test wrong-anchor, stale-metadata, namespace-collision, and locally forbidden-action cases.

## Recover

Resume through a narrow canary relationship only after security approval, current bundle and entity-chain evidence, revoked old material, cleared persistence, successful adversarial tests, and a signed incident evidence checkpoint. Continue heightened monitoring and document residual risk.
