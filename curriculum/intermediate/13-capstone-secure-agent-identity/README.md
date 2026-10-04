# Intermediate 13 — Capstone: Secure Agent Identity & Authorization Architecture

> **Goal:** integrate human identity, logical agent identity, workload identity, delegation, OAuth/OIDC, MCP, policy engines, resource authorization, HITL, guardrails, observability, adversarial testing, and governance into one production-style enterprise architecture.

| Course facts | Value |
|---|---|
| Level | Intermediate capstone |
| Estimated time | 6–8 hours |
| Last reviewed | 2026-10-04 |
| Prerequisites | Intermediate Courses 1–12 |
| Credentials | None; every exercise is local and synthetic |

## Start here

From this directory:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python lab.py
pytest -q tests
```

Use the executed notebook for the guided investigation and `lab.py` as the
reusable system under test. The release gate requires 100% execution of valid
scenarios, 0% execution of invalid scenarios, 100% expected terminal-state
accuracy, and zero forbidden effects.

## Scenario and deliverable

You are the security architect for Northstar Insurance. Its claims agent can
read and update an assigned claim, search approved knowledge, write task
memory, delegate a read-only research subtask, and propose payments. Your
deliverable is not a diagram alone: it is an executable assurance case that
connects every architectural claim to implementation evidence and a failing
adversarial test.

## Success criteria

You must be able to prove that:

1. authenticated human, logical agent, workload, artifact, task, delegation, and sender identities remain distinct and bound;
2. OAuth scope, OpenFGA relationships, contextual policy, and resource-side constraints all agree before an effect;
3. RAG and memory are filtered before sensitive content reaches the model;
4. sub-agent authority is a strict subset of the parent delegation;
5. MCP server and audience substitution and token passthrough fail closed;
6. approval binds one exact proposal and commit-time state;
7. unknown outcomes reconcile without duplicate effects;
8. every allow and deny produces privacy-minimized, tamper-evident evidence.

## Scope and non-goals

The capstone is a deterministic reference architecture, not a production IdP,
SPIRE deployment, policy control plane, payment service, or audit ledger. Its
keys and identities are fixtures. Production deployment requires managed keys,
real attestation and authentication, transactional durable storage,
resource-service enforcement, policy distribution, telemetry access control,
and tested incident procedures.

## Current ecosystem map

| Concern | Executed artifact | Common production choices | Key boundary |
|---|---|---|---|
| Human/API identity | trusted `SecurityContext` | OIDC, OAuth 2.x, sender-constrained tokens | validation is not object authorization |
| Workload identity | SPIFFE ID + artifact binding | SPIFFE/SPIRE, cloud workload identity, attestation | workload is not the logical agent |
| Structured intent | strict Pydantic v2 model | JSON Schema, Pydantic, protobuf | schema validity is not authority |
| Context policy | reference PDP + OPA + Cedar | OPA, Cedar, cloud IAM, application ABAC | PDP decisions require a PEP |
| Relationships | OpenFGA tenant/task intersection | OpenFGA and other ReBAC systems | relationships do not model all risk |
| Agent runtime | OpenAI Agents SDK function tools | Agents SDK, custom runtimes | SDK approval is not application authorization |
| Durable orchestration | compiled LangGraph | LangGraph checkpointers, workflow engines | checkpoints do not make effects exactly-once |
| Tool protocol | MCP Python SDK v2 server | current MCP SDKs | tool annotations are not enforcement |
| Evidence | hash-chained minimal events | OpenTelemetry plus append-only audit | trace context is not identity |

The tested line for this revision uses OpenAI Agents SDK 0.22, MCP Python SDK
2.2, LangGraph 1.2, LangChain 1.3, Pydantic 2.13, CedarPy 4, and OPA 1.x.
These APIs evolve quickly; validate pinned versions and current primary
documentation before production adoption.

## Architecture

```text
Human / Enterprise IdP
        │ OIDC/OAuth
        ▼
Agent Gateway / PEP ─────────────── Audit / Tracing / SIEM
        │
        ▼
Agent Orchestrator / LLM
     untrusted planner
        │
        ▼
Structured Intent
        │
        ▼
Policy Decision Point
 OPA / Cedar / OpenFGA
   │       │       │
 DENY   STEP-UP   ALLOW
           │        │
          HITL      ▼
           └────► Tool Router / PEP
                    ├─ Claims API
                    ├─ RAG / Memory
                    ├─ MCP Server
                    └─ Sub-agent
                         │
                         └─ attenuated authority

Workload plane:
SPIFFE/SPIRE → workload attestation → logical-agent/workload binding
```

## Security invariants

The learner must prove:

1. model-generated identity claims are never trusted;
2. logical agent identity is bound to an approved workload;
3. every consequential operation crosses a PEP;
4. tenant and object-level authorization are enforced;
5. delegated authority cannot expand;
6. child-agent authority is attenuated;
7. high-risk actions use step-up/HITL;
8. approvals bind to the exact transaction and expire;
9. MCP access tokens are intended for the target MCP resource;
10. MCP tokens are not passed unchanged to unrelated downstream APIs;
11. revoked authority does not remain usable through stale caches;
12. a denied action produces no protected side effect;
13. consequential actions produce reconstructable evidence.

## 1. Identity planes

Model these independently:

```text
human identity
logical agent identity
runtime/workload identity
service/tool identity
delegation identity
task identity
```

A single `agent_id` is not enough for enterprise assurance.

## 2. Human identity

Human security context normally comes from enterprise authentication. Validate trusted claims such as issuer, subject, organization/tenant, authentication assurance, groups/roles, token audience and expiry. Never let conversation text override authenticated identity.

## 3. Logical agent identity

Register the governed software actor, for example `agent:claims-adjuster`, with owner, purpose, risk tier, approved environments, tools, models, data classes, delegation policy, version, and lifecycle status.

## 4. Workload identity

The process executing an agent needs an independently verifiable identity. SPIFFE/SPIRE provides a useful model using SPIFFE IDs, X.509-SVID/JWT-SVID credentials, workload attestation, trust domains and federation.

## 5. Logical agent ↔ workload binding

Policy should answer:

```text
Is the approved claims-agent actually executing in an approved workload?
```

Bind logical agent ID to workload identity, environment, deployment/artifact properties and attestation state as appropriate.

## 6. OAuth/OIDC boundary

Use OIDC for authentication context and OAuth for delegated API authorization. Validate issuer, resource/audience, expiry, scope, token type and other protocol-specific requirements. Cryptographic validity alone does not establish suitability for a target resource.

## 7. Delegation

Represent authority explicitly:

```json
{
  "delegator": "user:alice",
  "delegatee": "agent:claims",
  "actions": ["claim.read", "claim.update"],
  "resources": ["claim:483"],
  "purpose": "process claim 483",
  "redelegable": true,
  "max_depth": 1,
  "expires_at": "..."
}
```

## 8. Delegation attenuation

For a child delegation:

```text
child actions ⊆ parent actions
child resources ⊆ parent resources
child lifetime ≤ parent lifetime
child depth ≤ parent max depth
```

Communication between agents does not itself create authority.

## 9. Policy architecture

A useful enterprise combination is:

```text
OpenFGA/ReBAC → relationships
OPA/Rego or Cedar → contextual authorization
resource service → final enforcement
```

Relationship examples include assignment, ownership, team membership and agent-to-agent invocation. Dynamic context includes workload assurance, risk, delegation freshness, transaction amount and approval state.

## 10. Rich decision contract

Prefer:

```json
{
  "outcome": "allow",
  "decision_id": "dec-123",
  "reason": "TASK_SCOPE",
  "constraints": {"allowed_fields": ["status", "notes"]},
  "obligations": ["audit"],
  "expires_at": "..."
}
```

over a bare boolean.

## 11. PEP architecture

Inventory every route to protected resources:

```text
Agent → Tool Router → API
Agent → MCP → API
Agent → Queue → Worker → API
Agent → RAG/Search
Agent → Memory
Agent → Sub-agent
```

Every route needs equivalent enforcement.

## 12. LLM trust boundary

The model may propose tool, action, resource, arguments and sub-agent. It may not establish authenticated identity, tenant, workload assurance, delegated authority, policy outcome or approval validity.

## 13. Structured intent

Normalize free-form model output into typed authorization input:

```json
{
  "action": "claim.update",
  "resource": "claim:483",
  "tool": "claims.update",
  "parameters": {"status": "reviewed"},
  "purpose": "process assigned claim"
}
```

## 14. Tool least privilege

Use both tool exposure filtering and per-invocation authorization. Hiding a tool reduces attack surface but is not an authorization control.

## 15. Authorization-aware RAG

Apply tenant, document ACL, data-classification, task-scope and relationship filters before sensitive content reaches model context whenever possible.

## 16. Authorization-aware memory

Treat memory read, search, write, update and deletion as resource operations. Prevent cross-user, cross-task and cross-tenant leakage.

## 17. Multi-agent identity

Preserve initiating principal, parent agent, child agent, task, delegation chain, tenant and trace context during handoffs.

## 18. Authority attenuation

A research sub-agent needing `claim.read` and `knowledge.search` should not inherit `claim.update` or `payment.create`.

## 19. Confused-deputy prevention

A useful conceptual bound is:

```text
effective authority =
caller authority
∩ delegation
∩ agent policy
∩ workload policy
∩ resource policy
```

Avoid broad ambient credentials.

## 20. MCP authorization boundary

MCP connectivity is not business authorization. Verify MCP server identity, token resource/audience, scope, tool identity, tenant/resource and approval requirements.

## 21. MCP OAuth security

The stable 2025-11-25 MCP authorization baseline uses OAuth
protected-resource mechanisms including Protected Resource Metadata,
authorization-server discovery, resource indicators, PKCE and
audience/resource-bound tokens. MCP continues to evolve; record the exact
protocol and SDK version used by each deployment and do not silently adopt
release-candidate behavior.

## 22. Prevent token passthrough

Do not forward an incoming MCP access token unchanged to an unrelated downstream API. The MCP server should use credentials appropriate for the downstream resource.

## 23. Risk-based autonomy

Example:

| Risk | Operation | Control |
|---|---|---|
| Low | read assigned claim | automatic |
| Medium | update status/notes | constrained allow |
| High | sensitive export | step-up/HITL |
| Critical | large payment | specialist/dual control |

## 24. Human approval

Approval is a security event, not chat text. Bind approver, agent/task, action, resource, critical parameters and expiry. Re-authorize before execution.

## 25. Transaction binding

Compute a canonical digest over action, resource, tool, critical parameters, task and agent. A parameter change after approval must invalidate the approval.

## 26. Guardrails vs authorization

Guardrails validate input/output/tool content and schemas. Authorization decides who may perform an action on a resource. They complement each other and should remain separate.

## 27. Durable workflows

After a long pause, revalidate user status, delegation, policy, approval freshness, resource state, workload identity and transaction parameters.

## 28. Observability

Correlate:

```text
model turn → intent → decision → approval → tool execution → resource outcome
```

with trace and decision IDs.

## 29. Sensitive tracing

Prompts, tool arguments and outputs may contain sensitive data. Minimize, redact and access-control traces. Never log reusable bearer credentials.

## 30. Evidence schema

Capture timestamp, trace/task IDs, principal, agent, workload, delegation, tool/server, action, resource, tenant, decision/reason, constraints, approval, policy version and execution result.

## 31. Adversarial validation

Reuse attacks for identity spoofing, wrong audience, replay, confused deputy, delegation escalation, cross-tenant IDOR, PEP bypass, fail-open, stale cache, parameter swapping, MCP substitution, authority laundering and TOCTOU.

## 32. Mutation testing

Deliberately remove tenant checks, workload binding, approval requirements or audience validation; introduce wildcard resources or unlimited re-delegation. High-impact mutants must be caught.

## 33. Failure modes

Explicitly define behavior when PDP, IdP, MCP, relationship store, approval service or telemetry is unavailable, or policy data is stale. Sensitive operations must not silently fail open.

## 34. Revocation

Model user disablement, delegation revocation, agent quarantine, workload compromise, tool removal, approval expiry and policy changes. Define acceptable revocation latency.

## 35. Governance metadata

Agent registration should include owner, business purpose, risk tier, data classes, approved tools/models, workload bindings, delegation policy, review date, exceptions and test status.

## 36. CI/CD gates

Run schema validation, policy tests, relationship-model tests, negative authorization tests, property tests, mutation tests, integration tests, PEP-path tests and workload/artifact checks before release.

## 37. Current ecosystem

This course uses or references OAuth/OIDC, MCP, SPIFFE/SPIRE, OPA/Rego, Cedar, OpenFGA, OpenAI Agents SDK, LangGraph/LangChain patterns, OpenTelemetry-style evidence, NIST agent identity work and OWASP GenAI security guidance.

## 38. NIST direction

NIST NCCoE's 2026 concept paper specifically addresses applying identity standards and authorization best practices to software and AI agents as they gain access to data, tools and applications. This capstone uses that direction as an enterprise architecture input while retaining standards-based least privilege and explicit enforcement.

## 39. Framework integration

With OpenAI Agents SDK, learners can map the architecture to function tools, tool guardrails, human-in-the-loop interruptions, MCP tool filtering/approval and tracing. With LangGraph, make authorization an explicit graph node between planning and execution.

## 40. Final architecture review

For every consequential arrow answer:

1. Which identity crosses it?
2. How is that identity authenticated?
3. What authority is delegated?
4. What is the protected resource?
5. Which PDP decides?
6. Which PEP enforces?
7. What happens on dependency failure?
8. How is revocation handled?
9. What evidence is recorded?
10. Which adversarial test proves the boundary?

If an arrow has no clear answer, the design is incomplete.

## Practical notebook

The notebook builds one coherent claim workflow through registry and workload
binding, OAuth validation, typed intent, relationship and contextual policy,
RAG/memory isolation, attenuated sub-agent delegation, MCP authorization,
signed approval, commit-time reauthorization, unknown-outcome reconciliation,
result validation, hash-chained evidence, revocation, dependency failure,
framework adapters, and the quantitative release gate.

### Claim-to-proof map

| Claim | Implementation proof | Verification |
|---|---|---|
| Model output cannot create trusted identity | `ModelIntent(extra="forbid")` separate from `SecurityContext` | identity-injection tests |
| Agent execution binds approved runtime and artifact | registry + `_identity_failure` | workload/artifact/quarantine tests |
| OAuth and MCP tokens are resource bound | gateway and tool audiences plus no-passthrough rule | issuer/audience/server/passthrough tests |
| Relationship and contextual policies compose | relationship tuples plus reference PDP, OPA, Cedar | Python, Rego, Cedar, and OpenFGA suites |
| RAG/memory content stays task and class scoped | pre-effect resource checks | restricted-data and cross-task tests |
| Child authority only attenuates | exact child action/resource constraints | example and Hypothesis property tests |
| Approval is exact and single use | signed manifest + atomic registry | tamper/expiry/change/replay/race tests |
| Retries cannot duplicate an uncertain effect | operation ledger + proposal digest + receipt | lost-response reconciliation test |
| Evidence is reconstructable without secrets | hash-chained minimal events | privacy and tamper tests |

### Artifact map

| Artifact | Purpose | Validation |
|---|---|---|
| `lab.py` | End-to-end platform, 27 scenarios, release gate | `python lab.py` |
| `capstone_secure_agent_identity.ipynb` | Executed guided assurance case | notebook validator |
| `tests/test_capstone_platform.py` | 56 adversarial, property, SDK, and integration checks | `pytest -q tests` |
| `policies/opa/` | Rego v1 policy and 14 tests | `opa test policies/opa -v` |
| `policies/cedar/` | Executed default-deny/forbid policy | CedarPy integration test |
| `policies/openfga/` | Tenant/task intersection and 5 checks | `fga model test --tests ...` |
| `agents_sdk/secure_tools.py` | Strict function tools and SDK approval interruption | imported by tests |
| `langgraph/capstone_graph.py` | Compiled conditional workflow | imported by tests |
| `protocols/mcp_server.py` | MCP Python SDK v2 tool surface | imported by tests |
| `architecture/capstone_architecture.mmd` | Traceable enforcement diagram | architecture vocabulary test |

## Completion criterion

You should be able to answer:

> Who initiated this action, which agent acted, which workload executed it, what authority was delegated, which policy allowed it, what constraints applied, whether a human approved it, what resource actually changed, and what evidence proves all of that?

If the system cannot answer those questions, its agent identity architecture is incomplete.

## References

- [NIST NCCoE — Accelerating the Adoption of Software and AI Agent Identity and Authorization](https://csrc.nist.gov/pubs/other/2026/02/05/accelerating-the-adoption-of-software-and-ai-agent/ipd)
- [SPIFFE — Workload identity overview](https://spiffe.io/docs/latest/spiffe-about/overview/)
- [SPIFFE — Workload API](https://spiffe.io/docs/latest/spiffe-specs/spiffe_workload_api/)
- [OpenAI — Guardrails and approvals](https://developers.openai.com/api/docs/guides/agents/guardrails-approvals)
- [OpenAI Agents SDK — Python](https://openai.github.io/openai-agents-python/)
- [OpenAI Agents SDK — Human in the loop](https://openai.github.io/openai-agents-python/human_in_the_loop/)
- [OpenAI Agents SDK — MCP](https://openai.github.io/openai-agents-python/mcp/)
- [LangGraph — Thinking in LangGraph](https://docs.langchain.com/oss/javascript/langgraph/thinking-in-langgraph)
- [Model Context Protocol — Specification 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25)
- [Model Context Protocol — Authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
- [Open Policy Agent — Integration](https://www.openpolicyagent.org/docs/integration)
- [Open Policy Agent — Policy testing](https://www.openpolicyagent.org/docs/policy-testing)
- [Cedar — Authorization semantics](https://docs.cedarpolicy.com/auth/authorization.html)
- [Cedar — Policy validation](https://docs.cedarpolicy.com/policies/validation.html)
- [OpenFGA — Modeling](https://openfga.dev/docs/modeling)
- [OpenTelemetry — Security guidance](https://opentelemetry.io/docs/security/)
- [OWASP GenAI — Excessive Agency](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/)

## Next

The Intermediate track is now integrated end-to-end. The Advanced track can move into cryptographic and distributed identity: verifiable credentials, capabilities, cryptographic delegation, cross-domain federation, continuous trust, lifecycle/governance, autonomous multi-agent identity, and emerging agent-identity standards.
