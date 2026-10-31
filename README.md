# Agent identity and authorization

> An executable curriculum for building agents that can prove who they are, act only within delegated authority, and leave a trustworthy evidence trail.

[![Repository validation](https://github.com/mahsa-teimourikia/agent-identity/actions/workflows/test-notebooks.yml/badge.svg)](https://github.com/mahsa-teimourikia/agent-identity/actions/workflows/test-notebooks.yml)
[![Learning Hub](https://img.shields.io/badge/Learning%20Hub-open-b95a20)](https://mahsa-teimourikia.github.io/agent-identity/)

## Start with the Learning Hub

**[Open the Agent Identity Learning Hub →](https://mahsa-teimourikia.github.io/agent-identity/)**

Search or filter all 31 courses, follow each **Learn → Lab → Checkpoint** path, and save completion progress in your browser. The [quiz builder](https://mahsa-teimourikia.github.io/agent-identity/quiz/) creates course-specific, level-specific, 10-, 20-, 40-question, or full-curriculum checks from the 140-question bank, with explanations and performance breakdowns.

## What you will build

Identity establishes which human, logical agent, client, workload, or service is acting. Authorization separately determines which action that principal may perform on which resource, under which delegated scope and current conditions. Across the curriculum, learners implement and evaluate:

- human, agent, workload, tenant, task, and resource identity boundaries;
- OAuth/OIDC, token exchange, sender constraints, SPIFFE/SPIRE, and federation;
- RBAC, ABAC, ReBAC, capabilities, policy-as-code, and protected-resource enforcement;
- exact approval, bounded delegation, revocation, idempotency, and recovery;
- privacy-aware telemetry, audit evidence, compliance, and threat response; and
- realistic enterprise architectures using deterministic, credential-free fixtures.

Prompts, tool arguments, retrieved content, schemas, and model output remain untrusted data. Models may propose an action; trusted application code validates, authorizes, executes, verifies, and records it.

| Level | Focus | Exit capability |
| --- | --- | --- |
| Beginner | Principals, credentials, lifecycle, authorization, safe tools | Build and test a deterministic policy boundary |
| Intermediate | Workload identity, OAuth, fine-grained policy, risk, MCP, observability | Integrate identity and authorization across an agent workflow |
| Advanced | Delegation chains, federation, evidence, adaptive trust, governance, defense | Evaluate and operate a production-style control plane |

## Local setup

Prerequisites:

- Python 3.12 or newer;
- [uv](https://docs.astral.sh/uv/getting-started/installation/); and
- Node.js 24 or newer for the browser-independent Hub tests.

From the repository root:

```bash
make setup
make validate
```

Useful commands:

```bash
make help                 # list supported workflows
make test                 # run all 31 isolated course suites
make notebooks            # execute every notebook top to bottom
make hub-test             # regenerate and test Hub/quiz data
make site                 # build the production Pages layout in site/
make serve                # serve the built Hub at localhost:8000
make audit                # audit the committed lockfile for advisories
make ci                   # run the complete local CI gate
make lab COURSE=beginner/01-agent-identity-foundations
```

`pyproject.toml` and `uv.lock` define the canonical repository environment. Course-local `requirements.txt` files are smaller standalone slices and are checked against that environment. See [Dependency policy](DEPENDENCIES.md) before changing versions.

## Course artifact contract

Every published course contains:

- a source-backed technical chapter in `README.md`;
- exactly one primary, credential-free notebook;
- a reusable `lab.py` implementation;
- focused invariant and adversarial tests;
- a course-local dependency slice;
- a Hub checkpoint and full-quiz questions; and
- explicit production limitations and upgrade guidance.

The completed sequential review and claim-to-proof records are in the [course review ledger](COURSE_REVIEW_PROGRESS.md).

## Curriculum

### Beginner

- [Agent Identity Foundations](curriculum/beginner/01-agent-identity-foundations/)
- [Humans, Workloads and Agents](curriculum/beginner/02-humans-workloads-agents/)
- [Authentication, Credentials and Tokens](curriculum/beginner/03-authentication-credentials-tokens/)
- [Authorization for Agents](curriculum/beginner/04-authorization-for-agents/)
- [Least-Privilege Tool Access for Agents](curriculum/beginner/05-least-privilege-tool-access/)
- [Agent Identity Lifecycle](curriculum/beginner/06-agent-identity-lifecycle/)

### Intermediate

- [Workload Identity with SPIFFE and SPIRE](curriculum/intermediate/01-workload-identity-spiffe-spire/)
- [OAuth and OpenID Connect for Agents](curriculum/intermediate/02-oauth-oidc-for-agents/)
- [Token Exchange, Delegation, and Impersonation](curriculum/intermediate/03-token-exchange-delegation-impersonation/)
- [Fine-Grained Authorization with OPA, Cedar, and OpenFGA](curriculum/intermediate/04-fine-grained-authorization/)
- [Dynamic Authorization and Continuous Access Evaluation](curriculum/intermediate/05-dynamic-authorization-cae/)
- [Authorization for MCP and Tool Servers](curriculum/intermediate/06-mcp-tool-authorization/)
- [Risk, Assurance, and Step-Up Authorization](curriculum/intermediate/07-risk-assurance-stepup/)
- [Workload Assurance and Runtime Attestation](curriculum/intermediate/08-workload-assurance-runtime-attestation/)
- [Authorization Governance and Least Privilege at Scale](curriculum/intermediate/09-authorization-governance/)
- [Authorization Observability and Audit Analytics](curriculum/intermediate/10-authorization-observability-audit-analytics/)
- [Adversarial Authorization Testing](curriculum/intermediate/11-adversarial-authorization-testing/)
- [Integrating Authorization with Agents and Guardrails](curriculum/intermediate/12-integrating-authorization-agents-guardrails/)
- [Capstone: Secure Agent Identity and Authorization Architecture](curriculum/intermediate/13-capstone-secure-agent-identity/)

### Advanced

- [Advanced Authorization Models for Autonomous Agents](curriculum/advanced/01-advanced-authorization-models/)
- [Cryptographic Delegation, Capabilities, and Verifiable Provenance](curriculum/advanced/02-cryptographic-delegation-capabilities/)
- [Cross-Domain Identity Federation and Interoperability](curriculum/advanced/03-cross-domain-identity-federation/)
- [Agent Attestations, Verifiable Credentials, and Trust Evidence](curriculum/advanced/04-agent-attestations-verifiable-credentials/)
- [Continuous and Adaptive Trust](curriculum/advanced/05-continuous-adaptive-trust/)
- [Decentralized Identity and Multi-Agent Trust](curriculum/advanced/06-decentralized-identity-multi-agent-trust/)
- [Non-Human Identity Security and Key Management](curriculum/advanced/07-non-human-identity-security-key-management/)
- [Agent Identity Lifecycle and Governance](curriculum/advanced/08-agent-identity-lifecycle-governance/)
- [Agent Identity Security Posture and Threat Defense](curriculum/advanced/09-agent-identity-security-posture-threat-defense/)
- [Identity Observability, Telemetry, and Forensics](curriculum/advanced/10-identity-observability-telemetry-forensics/)
- [Compliance, Audit, and Forensic Readiness](curriculum/advanced/11-compliance-audit-forensic-readiness/)
- [Capstone: Secure, Compliant, and Resilient Agent Identity Platform](curriculum/advanced/12-secure-compliant-resilient-agent-identity-platform/)

## Repository layout

```text
curriculum/   31 chapters, notebooks, labs, tests, fixtures, and policy artifacts
hub/          static Learning Hub
quiz/         configurable full knowledge check
scripts/      deterministic generation and validation tools
assets/       shared One+i brand assets
```

## Contributing and security

Read [CONTRIBUTING.md](CONTRIBUTING.md) before changing course artifacts or dependencies. Security-sensitive reports should follow [SECURITY.md](SECURITY.md); do not place secrets, real credentials, personal data, or production endpoints in examples or issues.

## Curated standards and implementation references

Course chapters cite sources next to the claims they support. These are the cross-curriculum anchors:

- [NIST Software and AI Agent Identity and Authorization](https://www.nccoe.nist.gov/projects/software-and-ai-agent-identity-and-authorization)
- [NIST SP 800-207 — Zero Trust Architecture](https://csrc.nist.gov/pubs/sp/800/207/final)
- [NIST SP 800-63-4 — Digital Identity Guidelines](https://csrc.nist.gov/pubs/sp/800/63/4/final)
- [OAuth 2.0 Security Best Current Practice — RFC 9700](https://www.rfc-editor.org/rfc/rfc9700)
- [OAuth 2.0 Token Exchange — RFC 8693](https://www.rfc-editor.org/rfc/rfc8693)
- [OAuth 2.0 Protected Resource Metadata — RFC 9728](https://www.rfc-editor.org/rfc/rfc9728)
- [OpenID AuthZEN Authorization API 1.0](https://openid.net/specs/authorization-api-1_0.html)
- [SPIFFE specifications](https://spiffe.io/docs/latest/spiffe-specs/)
- [Model Context Protocol specification](https://modelcontextprotocol.io/specification/2026-07-28)
- [Open Policy Agent documentation](https://www.openpolicyagent.org/docs/)
- [Cedar documentation](https://docs.cedarpolicy.com/)
- [OpenFGA documentation](https://openfga.dev/docs)
- [W3C Verifiable Credentials Data Model 2.0](https://www.w3.org/TR/vc-data-model-2.0/)
- [OpenTelemetry specifications](https://opentelemetry.io/docs/specs/)
- [OWASP AI Agent Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html)

## License

See [LICENSE](LICENSE).
