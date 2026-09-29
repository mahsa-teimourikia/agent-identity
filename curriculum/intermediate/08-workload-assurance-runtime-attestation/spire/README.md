# Optional live SPIRE extension

The core course is deterministic and needs no cluster. This extension is for
learners who want to replace the local identity model with a real Workload API.

Use a maintained upstream path:

- [official Docker quickstart](https://spiffe.io/docs/latest/try/spire101/);
- [official Kubernetes quickstart](https://spiffe.io/docs/latest/try/getting-started-k8s/); or
- [SPIRE deployment options](https://spiffe.io/docs/latest/deploying/using_spire/).

## Exercise contract

1. Record the SPIRE release and immutable image digests you selected.
2. Configure a non-production trust domain such as `northstar.example`.
3. Select a node-attestation method appropriate to the environment; document
   why a join token is acceptable only for the bounded training bootstrap.
4. Register `spiffe://northstar.example/prod/agents/claims-adjuster` with a
   parent node and at least namespace, service-account, and image selectors.
5. Mount the Workload API Unix socket only into the intended workload and
   inspect its filesystem permissions and peer-credential boundary.
6. Fetch and rotate an X.509-SVID and trust bundle. Verify the URI SAN and use
   it in mTLS without exporting the private key to another workload.
7. Fetch a JWT-SVID for the claims API and prove replay at another audience is
   rejected.
8. Rotate a bundle with an overlap window, remove the old authority, and prove
   an old identity document is no longer accepted.
9. Feed only verified identity and attestation results—not self-reported
   flags—into `policies/opa/workload.rego`.
10. Tear down the environment and remove bootstrap material.

## Evidence to retain

Keep sanitized command versions, registration-entry output, SPIFFE IDs,
certificate serials and validity windows, JWT audience test results, bundle
rotation timestamps, OPA results, and teardown confirmation. Never commit
private keys, join tokens, workload JWTs, or raw hardware evidence.
