# Agent identity and authorization

> A practical course for building agents that can prove who they are, act only within delegated authority, and leave an evidence trail.

## Start with the Learning Hub

**[Open the Agent Identity Learning Hub →](https://mahsa-teimourikia.github.io/agent-identity/)**

Choose Beginner, Intermediate, or Advanced, then work through each lesson's **Learn → Lab → Checkpoint** tabs. The [full interactive quiz](https://mahsa-teimourikia.github.io/agent-identity/quiz/) gives a cumulative knowledge check.

## Local Setup

We use `uv` and a centralized `pyproject.toml` to manage dependencies across all 31 courses, meaning you only have to set up your environment once. 

Run the following command at the repository root to bootstrap the virtual environment:
```bash
make setup
```

To run the Jupyter notebooks, start the server with:
```bash
make jupyter
```

## What this course teaches

Identity answers which human, workload, or delegated agent is acting. Authorization independently decides which action that principal may perform on which resource and under which conditions. This course covers workload identity, OAuth/token exchange, RBAC/ABAC/ReBAC, capabilities, policy-as-code, approval, delegation, auditability, revocation, and incident response. Prompts are untrusted input; identity and policy decisions belong in verifiable application code.

| Level | Focus | Outcome |
| --- | --- | --- |
| Beginner | Principals, identity context, RBAC, safe tools | Deterministic policy gate |
| Intermediate | OAuth exchange, ABAC/ReBAC, risk, audit | Down-scoped specialist token |
| Advanced | Delegation chains, operations, threat modeling | Production readiness decision |

Explore the structured lessons in `curriculum/<level>/<module>/`. Each module contains its own README, Python examples, and Jupyter notebooks to explain the concepts and execute the code.

## Curriculum

### Beginner
- [Agent Identity Foundations](curriculum/beginner/01-agent-identity-foundations/)
- [Humans, Workloads and Agents](curriculum/beginner/02-humans-workloads-agents/)
- [Authentication, Credentials and Tokens](curriculum/beginner/03-authentication-credentials-tokens/)
- [Authorization for Agents](curriculum/beginner/04-authorization-for-agents/)
- [Least-Privilege Tool Access for Agents](curriculum/beginner/05-least-privilege-tool-access/)
- [Agent Identity Lifecycle](curriculum/beginner/06-agent-identity-lifecycle/)

### Intermediate
- [Workload Identity with SPIFFE & SPIRE](curriculum/intermediate/01-workload-identity-spiffe-spire/)
- [OAuth 2.x and OpenID Connect for Agents](curriculum/intermediate/02-oauth-oidc-for-agents/)
- [Token Exchange, Delegation & Impersonation](curriculum/intermediate/03-token-exchange-delegation-impersonation/)
- [Fine-Grained Authorization with OPA, Cedar & OpenFGA](curriculum/intermediate/04-fine-grained-authorization/)
- [Dynamic Authorization & Continuous Access Evaluation](curriculum/intermediate/05-dynamic-authorization-cae/)
- [Authorization for MCP & Tool Servers](curriculum/intermediate/06-mcp-tool-authorization/)
- [Risk, Assurance & Step-Up Authorization for Agents](curriculum/intermediate/07-risk-assurance-stepup/)
- [Workload Assurance & Runtime Attestation for Agents](curriculum/intermediate/08-workload-assurance-runtime-attestation/)
- [Authorization Governance, Delegation & Least Privilege at Scale](curriculum/intermediate/09-authorization-governance/)
- [Authorization Observability & Audit Analytics for Agents](curriculum/intermediate/10-authorization-observability-audit-analytics/)
- [Adversarial Authorization Testing for Agents](curriculum/intermediate/11-adversarial-authorization-testing/)
- [Integrating Authorization with LLMs, Agents & Guardrails](curriculum/intermediate/12-integrating-authorization-agents-guardrails/)
- [Capstone: Secure Agent Identity & Authorization Architecture](curriculum/intermediate/13-capstone-secure-agent-identity/)

### Advanced
- [Advanced Authorization Models for Autonomous Agents](curriculum/advanced/01-advanced-authorization-models/)
- [Cryptographic Delegation, Capabilities & Verifiable Provenance for Agents](curriculum/advanced/02-cryptographic-delegation-capabilities/)
- [Cross-Domain Identity Federation & Interoperability for Agents](curriculum/advanced/03-cross-domain-identity-federation/)
- [Agent Attestations, Verifiable Credentials & Trust Evidence](curriculum/advanced/04-agent-attestations-verifiable-credentials/)
- [Continuous & Adaptive Trust for Autonomous Agents](curriculum/advanced/05-continuous-adaptive-trust/)
- [Decentralized Identity & Trust for Multi-Agent Ecosystems](curriculum/advanced/06-decentralized-identity-multi-agent-trust/)
- [Non-Human Identity Security & Key Management for Agents](curriculum/advanced/07-non-human-identity-security-key-management/)
- [Agent Identity Lifecycle, Governance & Operational Excellence](curriculum/advanced/08-agent-identity-lifecycle-governance/)
- [Agent Identity Security Posture Management & Threat Defense](curriculum/advanced/09-agent-identity-security-posture-threat-defense/)
- [Identity Observability, Telemetry & Forensics for Agents](curriculum/advanced/10-identity-observability-telemetry-forensics/)
- [Compliance, Audit & Forensic Readiness for Agent Identity](curriculum/advanced/11-compliance-audit-forensic-readiness/)
- [Capstone: Secure, Compliant & Resilient Enterprise Agent Identity Platform](curriculum/advanced/12-secure-compliant-resilient-agent-identity-platform/)

## References

[NIST AI Agent Standards Initiative](https://www.nist.gov/artificial-intelligence/ai-agent-standards-initiative) · [NIST concept paper](https://www.nccoe.nist.gov/sites/default/files/2026-02/accelerating-the-adoption-of-software-and-ai-agent-identity-and-authorization-concept-paper.pdf) · [OAuth RFCs](https://datatracker.ietf.org/doc/html/rfc8693) · [SPIFFE](https://spiffe.io/docs/latest/spiffe-about/overview/) · [OpenFGA](https://openfga.dev/docs) · [OWASP Agent Security](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html) · [MCP security](https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices) · [AgentDojo](https://arxiv.org/abs/2406.13352).

Learning with One+i · responsible AI, real-world impact. [oneplusi.io](https://oneplusi.io)
