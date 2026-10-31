# Security policy

## Supported version

Only the latest commit on `main` is actively maintained. Historical branches, forks, and copied course artifacts may contain older dependencies or guidance.

## Reporting a vulnerability

Do not open a public issue for suspected secret exposure, dependency compromise, authorization bypass, cross-tenant disclosure, unsafe executable example, or Hub injection vulnerability.

Use GitHub's private reporting flow: **[Report a vulnerability](https://github.com/mahsa-teimourikia/agent-identity/security/advisories/new)**.

Include:

- the affected commit, path, course, and symbol or route;
- reproducible steps using synthetic data;
- the expected and observed security boundary;
- likely impact and affected versions; and
- a suggested mitigation, if known.

Do not attach real credentials, personal data, production logs, or exploit traffic containing sensitive information. Redact secrets and provide the smallest safe proof.

## Repository security model

The labs are deterministic teaching systems, not production identity providers or policy control planes. Production use requires managed key custody, authoritative identity and lifecycle sources, durable storage, availability engineering, current policy distribution, protected telemetry, incident procedures, and vendor-native conformance testing.

The committed environment is locked with `uv.lock`, audited with `make audit`, and monitored by Dependabot. Course examples should fail closed, use synthetic fixtures, avoid network side effects by default, and never treat prompts, model output, retrieved content, or caller-supplied identity fields as authority.
