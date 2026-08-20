# SPIRE Lab Scaffold

This directory is intentionally a scaffold rather than a fake one-command production deployment.

For the hands-on extension:

1. Install SPIRE using the current official SPIFFE/SPIRE deployment documentation.
2. Configure a trust domain such as `corp.example`.
3. Configure node attestation appropriate for Docker, Kubernetes, cloud, or your local environment.
4. Register a workload with selectors that identify the claims agent.
5. Issue `spiffe://corp.example/prod/agents/claims-agent`.
6. Fetch an X.509-SVID through the Workload API.
7. Fetch a JWT-SVID for a specific audience.
8. Rotate credentials and observe Workload API updates.
9. Replace the notebook simulator with live identity evidence.

Do not use `latest` image tags or insecure bootstrap configuration in production.
