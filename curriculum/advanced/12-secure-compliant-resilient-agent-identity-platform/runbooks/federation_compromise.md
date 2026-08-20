# Federation Compromise Runbook

1. Identify affected trust domain / issuer / bundle.
2. Block new sessions from the affected trust relationship.
3. Preserve current federation metadata and evidence.
4. Invalidate cached foreign-identity authorization decisions.
5. Revoke active cross-domain delegations where required.
6. Review local resource access performed by foreign identities.
7. Rotate local trust configuration if compromise affects bootstrap.
8. Resume only after explicit security approval.
