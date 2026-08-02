# Agent identity and authorization

> A practical course for building agents that can prove who they are, act only within delegated authority, and leave an evidence trail.

## Start with the Learning Hub

**[Open the Agent Identity Learning Hub →](https://mahsa-teimourikia.github.io/agent-identity/)**

Choose Beginner, Intermediate, or Advanced, then work through each lesson's **Learn → Lab → Checkpoint** tabs. The [full interactive quiz](https://mahsa-teimourikia.github.io/agent-identity/quiz/) gives a cumulative knowledge check.

## What this course teaches

Identity answers which human, workload, or delegated agent is acting. Authorization independently decides which action that principal may perform on which resource and under which conditions. This course covers workload identity, OAuth/token exchange, RBAC/ABAC/ReBAC, capabilities, policy-as-code, approval, delegation, auditability, revocation, and incident response. Prompts are untrusted input; identity and policy decisions belong in verifiable application code.

| Level | Focus | Outcome |
| --- | --- | --- |
| Beginner | Principals, identity context, RBAC, safe tools | Deterministic policy gate |
| Intermediate | OAuth exchange, ABAC/ReBAC, risk, audit | Down-scoped specialist token |
| Advanced | Delegation chains, operations, threat modeling | Production readiness decision |

Read the [roadmap](docs/roadmap.md) and [complete theory guide](docs/identity-and-authorization.md). Run labs with `python3 labs/<level>/<file>.py`; notebooks explain the concept and execute the larger module.

## References

[NIST AI Agent Standards Initiative](https://www.nist.gov/artificial-intelligence/ai-agent-standards-initiative) · [NIST concept paper](https://www.nccoe.nist.gov/sites/default/files/2026-02/accelerating-the-adoption-of-software-and-ai-agent-identity-and-authorization-concept-paper.pdf) · [OAuth RFCs](https://datatracker.ietf.org/doc/html/rfc8693) · [SPIFFE](https://spiffe.io/docs/latest/spiffe-about/overview/) · [OpenFGA](https://openfga.dev/docs) · [OWASP Agent Security](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html) · [MCP security](https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices) · [AgentDojo](https://arxiv.org/abs/2406.13352).

Learning with One+i · responsible AI, real-world impact. [oneplusi.io](https://oneplusi.io)
