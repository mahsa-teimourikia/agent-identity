# Beginner 05 — Least-Privilege Tool Access for Agents

Tools turn model output into reads, messages, purchases, cancellations, code execution, and other real-world effects. A tool name in model context is therefore part of the attack surface, while a successful tool call is a security-sensitive transaction—not merely another generated token.

This chapter builds a deterministic travel-agent gateway. The model may propose a tool and arguments. Trusted application code derives identity, minimizes discovery, validates input, authorizes the current task/resource, checks approval and egress, brokers a narrow credential, applies budgets, executes a local simulator, validates the result, reconciles uncertain outcomes, and records evidence.

> **Course thesis:** after this course, you can explain, implement, attack-test, evaluate, and productionize a tool gateway that constrains discovery and every invocation across identity, task, resource, arguments, credentials, approval, egress, budgets, and verified execution.

> **Goal:** Build and evaluate a least-privilege tool gateway that gives an agent only the capabilities required for one task and prevents model output from becoming authority.

## Learning outcomes

By the end, you can:

1. explain why tool discovery and tool execution are separate authorization boundaries;
2. design narrow business capabilities instead of generic shell, SQL, or HTTP primitives;
3. derive requester, actor, workload, and tenant from authenticated application state;
4. define strict input and output contracts with Pydantic and JSON Schema;
5. enforce task, resource, argument, amount, recipient, egress, and lifecycle constraints;
6. bind high-risk approval to one exact operation and consume it safely;
7. broker short-lived credential authority without exposing secrets to the model;
8. enforce call/chain/retry budgets and fail closed on policy failure;
9. distinguish retry, idempotency, reconciliation, and duplicate effects;
10. validate untrusted tool results before returning them to model context; and
11. map the same gateway contract to MCP, policy engines, credential brokers, sandboxes, and network controls.

## Prerequisites

- [Beginner 01 — Agent Identity Foundations](../01-agent-identity-foundations/README.md)
- [Beginner 02 — Humans, Workloads and Agents](../02-humans-workloads-agents/README.md)
- [Beginner 03 — Authentication, Credentials and Tokens](../03-authentication-credentials-tokens/README.md)
- [Beginner 04 — Authorization for Agents](../04-authorization-for-agents/README.md)
- basic Python, APIs, JSON, and unit testing

Course 04 established the PEP/PDP boundary. This course applies it to tool discovery, input/output contracts, credential use, and effects. It does not repeat token verification or policy-language internals.

## Scenario, boundaries, and success criteria

Northstar Travel gives an assistant three task-scoped capabilities:

- search flights from approved infrastructure;
- book an approved airline for Alice's exact trip within CAD 1,000, with manager approval; and
- send an itinerary only to an internal corporate address.

Cancellation and shell execution exist in the platform catalog but are not visible or callable for this task. The production workload, Alice, the travel agent, North tenant, task, trip, tool set, price, airline, destinations, egress hosts, call counts, and expiry are independently bounded.

The system must block:

- direct calls to undiscovered or ungranted tools;
- actor/workload substitution and cross-tenant trips;
- extra arguments such as a caller-controlled callback URL;
- price, airline, recipient, and egress expansion;
- missing, altered, expired, self-issued, or replayed approval;
- expired/cancelled tasks and exhausted budgets;
- malformed downstream results and policy outages;
- changed requests that reuse an operation ID; and
- duplicate external effects after a lost response.

Success means all labelled outcomes match, all legitimate terminal attempts complete, no blocked attempt is dispatched or causes an effect, uncertain execution is reconciled before retry, no duplicate effect occurs, and every decision has complete public evidence.

### Non-goals

The lab does not call an airline, send email, execute a shell, or hold credentials. Its downstream service and credential leases are synthetic. Fixture results demonstrate policy behavior, not the security, latency, or quality of MCP, Pydantic, a model, or an airline API.

---

## 1. Mental model: a tool call is a transaction

```text
model proposes ToolRequest
          │
          ▼
tool gateway / PEP
  1 identity and task
  2 tool permission
  3 typed arguments
  4 resource/business policy
  5 approval + egress + budget
  6 credential lease
  7 idempotent execution
  8 result validation
  9 receipt + decision evidence
          │
          ▼
verified output or typed denial/unknown outcome
```

The model supplies:

```text
operation ID, task ID, tool name, candidate arguments
```

Trusted application state supplies:

```text
requester, actor, workload, tenant, task grant, resource ownership,
policy, approval, budget, egress policy, credential profile, effect receipt
```

The central boundary remains:

```text
model / agent -> proposes, predicts, extracts, recommends
trusted application -> validates, authorizes, persists, executes, verifies
```

## 2. Least privilege and least agency

Traditional least privilege asks which permissions a principal needs. Agent systems add **least agency**: what autonomy, tools, sequence length, retries, destinations, and side effects are necessary for this task?

An authorization envelope can be modeled as:

\[
E = (I, T, R, A, C, P, G, B, L)
\]

where:

- \(I\): verified requester/actor/workload/tenant identity;
- \(T\): task and lifecycle state;
- \(R\): resource set;
- \(A\): allowed tool/actions;
- \(C\): argument constraints;
- \(P\): approval/authorization policy;
- \(G\): downstream credential and egress scope;
- \(B\): call, cost, time, and chain budgets; and
- \(L\): lifetime/revocation boundary.

An invocation is eligible only if every required dimension matches. A tool-level allow without a resource or argument check is incomplete.

## 3. Tool catalog and capability design

A governed catalog records application-owned facts:

- canonical tool name and owner;
- effect and risk class;
- strict input and output schemas;
- credential audience/scopes;
- fixed egress destination;
- whether approval is required;
- idempotency behavior;
- open-world behavior; and
- lifecycle/version information.

The catalog is policy input. Tool descriptions and annotations from an untrusted server are not proof of behavior.

### Effect and risk classification

| Effect | Examples | Typical controls |
| --- | --- | --- |
| read | search flights, inspect trip | resource filtering, rate/volume limits, output validation |
| financial write | book flight, issue refund | exact approval, amount ceiling, idempotency, receipt |
| communication | send itinerary/message | recipient and egress allowlists, content/data-loss checks |
| destructive | cancel booking, delete data | narrow grant, strong approval, recovery/rollback |
| code execution | shell, SQL, browser script | avoid when possible; sandbox, filesystem/network policy, budget |

Risk is contextual. A “read” tool can exfiltrate sensitive data; a “send” tool can become dangerous when chained after it. Classifications drive controls but do not replace policy.

### Narrow business capability versus god tool

Prefer:

```text
book_approved_flight(trip_id, flight_id, price_cents, currency)
```

over:

```text
http_request(method, url, headers, body)
execute_sql(query)
execute_shell(command)
```

Narrow tools reduce the reachable state space, make schemas meaningful, simplify policy, and support domain receipts. Generic primitives may be justified in isolated developer sandboxes, but they require stronger filesystem, process, network, secret, and human controls.

## 4. Discovery authorization is not execution authorization

Discovery minimization keeps unnecessary tools out of model context:

```text
task:travel-483 -> search_flights, book_flight, send_itinerary
```

It improves usability and reduces accidental or injected selection. It does not grant execution. A caller can bypass model discovery and invoke an endpoint directly, tool lists can be cached, and task state can change after discovery.

Therefore:

1. filter the visible catalog using authenticated request authority;
2. return it deterministically and with a bounded cache policy; and
3. re-authorize every invocation at the resource-side gateway.

The MCP 2026-07-28 tools specification explicitly permits `tools/list` to vary by per-request authorization. The lab's `visible_tools()` and `mcp_tool_definitions()` model that behavior, while `ToolGateway.invoke()` independently rechecks execution.

## 5. Schema validation and authorization are different

A strict schema proves that data has the expected shape and types. It does not prove that the caller may use the values.

```json
{
  "trip_id": "trip:north:483",
  "flight_id": "AC101",
  "price_cents": 70000,
  "currency": "CAD"
}
```

Pydantic rejects missing fields, wrong types, invalid patterns, and extra fields. Policy then checks:

- the trip belongs to the authenticated requester and tenant;
- the task grant contains that exact trip and tool;
- the airline is allowed;
- the price is within the delegated maximum; and
- any required approval matches the canonical request digest.

The lab uses `ConfigDict(extra="forbid", strict=True)`. A proposed `callback_url` is not silently ignored; it is rejected before egress or execution.

## 6. Resource and argument-level authorization

Resource authority belongs at the service boundary even when the downstream credential can access more.

```text
credential can read all corporate trips
        does not imply
Alice's task may read Bob's trip
```

The gateway resolves `trip_id` against authoritative records and checks owner, tenant, state, and grant membership. It never trusts a tenant included in tool arguments.

Argument policy is domain-specific:

- `origin != destination`;
- airport codes follow the accepted format;
- only AC/LH/AA are delegated;
- price is at most CAD 1,000;
- itinerary recipients use `@corp.example`; and
- model input cannot choose the downstream host.

## 7. Approval as an operation-bound receipt

High-risk tools return an obligation rather than executing:

```text
outcome: approval_required
obligation: obtain_bound_travel_approval
```

The receipt binds:

- approval and approver IDs plus eligible role;
- requester, actor, workload, and tenant;
- task, tool, and stable operation ID;
- digest of exact arguments;
- policy version;
- issue and expiry times; and
- single-use state.

Changing CAD 700 to CAD 800 invalidates the approval. The approver cannot be the requester or acting agent. The teaching store serializes consumption; production must coordinate approval state and the side effect durably.

An exact retry after a lost response is not a second authorization event. If the operation already committed, the gateway reconciles the same operation ID and digest and returns the existing receipt without consuming approval or creating another effect.

## 8. Credential isolation and audience restriction

The model should never receive an API key, bearer token, session cookie, or credential lease handle. The gateway asks a broker for downstream authority only after authorization.

A useful lease is bound to:

- credential profile and minimal scopes;
- downstream audience;
- operation or task;
- short expiry; and
- authenticated workload where supported.

The lab creates only non-secret metadata—there is no synthetic token string to accidentally print. In production, use workload identity, token exchange, cloud workload federation, mTLS, or a secret broker to mint/inject short-lived credentials directly into the downstream client.

Logical authorization and credential scope reinforce each other:

```text
gateway policy limits what should happen
credential audience/scope limits what can happen downstream
```

## 9. Egress and tool-chain controls

An allowlisted tool can still exfiltrate data if it accepts arbitrary URLs, recipients, file paths, queries, or commands.

The lab fixes the service host in the trusted catalog and intersects it with task-allowed egress. Recipient policy separately limits business destinations. Production enforcement can include DNS/proxy policy, service-mesh identities, Kubernetes NetworkPolicy, cloud firewall rules, sandbox network namespaces, and data-loss controls.

Evaluate tool composition as well as individual tools:

```text
read_customer_list + send_external_email = exfiltration path
read_secret + DNS lookup = covert channel
download_file + execute_shell = code execution chain
```

Bound total calls, per-tool calls, chain depth, wall-clock deadline, bytes, spend, recipients, retries, and parallelism as relevant. Denied validation attempts should be observable but should not necessarily consume the same business-execution budget.

## 10. Idempotency, retries, and unknown outcomes

A retry policy must distinguish:

- **logical operation ID:** stable across retries;
- **attempt ID:** different for each transport attempt;
- **request digest:** proves the operation content did not change;
- **execution receipt:** authoritative evidence that an effect committed.

If a response is lost after booking succeeds, the outcome is unknown. Do not mint a new operation ID and repeat the booking. Query/reconcile the original ID. If it exists with the same digest, return the stored receipt. If the digest differs, deny with `idempotency_conflict`.

Authorization denial is terminal until relevant authority changes. Only classified transient failures receive bounded retries. “Try again” must never mean “duplicate the side effect.”

## 11. Tool results remain untrusted

Tool output can be malformed, stale, cross-tenant, injected, or simply wrong. A successful HTTP response is not proof that the intended business effect happened.

The gateway should:

1. validate output against an expected schema;
2. bind IDs, amounts, tenant/resources, and operation IDs to the request;
3. distinguish data from instructions;
4. verify a downstream receipt or authoritative state for consequential writes; and
5. minimize content returned to the model.

The lab rejects a result containing an unexpected instruction instead of promoting it to model context. MCP supports `outputSchema`; its tools specification says clients should validate structured results when a schema is supplied.

## 12. Decision and execution evidence

Record observable evidence, not hidden model reasoning:

- request, operation, attempt, task, actor, workload, tenant, tool, and resource IDs;
- request digest rather than sensitive raw arguments;
- policy/catalog/grant versions;
- decision outcome and reason code;
- approval and execution receipt IDs;
- credential profile/audience—not token value;
- egress destination, budget counters, dependency state, and latency;
- result validation and terminal state.

Separate **decision evidence** from **execution evidence**. “Allowed” proves policy permitted an attempt. Only a verified execution receipt or authoritative reconciliation proves the effect.

---

## 13. Architecture patterns

| Pattern | Strengths | Limitations | Best fit |
| --- | --- | --- | --- |
| in-process gateway | low latency, easy teaching/debugging | coupled rollout and failure domain | small service, local enforcement |
| shared tool/MCP gateway | centralized policy, brokering, audit | network dependency and blast radius | enterprise tool platform |
| per-tool/resource PEP | enforcement closest to effect | duplicated integration work | high assurance, defense in depth |
| sandboxed generic tools | flexible development capability | difficult business policy and data control | coding/research with hard isolation |
| workflow-specific capabilities | smallest action surface, clear receipts | more tool design work | consequential repeatable workflows |

Production commonly combines a shared gateway with service-side enforcement. The gateway cannot safely grant authority the target service never checks.

## 14. Technology landscape and common libraries

| Technology | Role | Strengths | Limitations / cautions |
| --- | --- | --- | --- |
| Pydantic | Python input/output contracts and JSON Schema | typed validation, mature ecosystem, readable models | schema-valid is not authorized; strict mode must be chosen |
| JSON Schema 2020-12 | portable contract format | interoperable tool schemas | `$ref`, formats, coercion, and implementation differences need tests |
| MCP 2026-07-28 + official SDKs | discovery/call protocol for tools/resources | standard contracts, schemas, authorization profile, Tier 1 SDKs | protocol is not business authorization; annotations are untrusted hints |
| OPA/Rego or Cedar | contextual policy decision | centralized/versioned policy | still needs PEP coverage, trusted attributes, result handling |
| OpenFGA | task/tool/resource relationships | check/list queries and agent/MCP modeling | amount/argument rules may require conditions or composition |
| OAuth/token exchange/workload federation | downstream credential authority | short-lived audience/scope restriction | tokens can still be stolen/misused; never expose to model |
| sandbox + network policy | hard runtime containment | constrains process/filesystem/egress | does not replace business authorization |

### MCP mapping

`mcp_tool_definitions()` emits only authorized tools and includes Pydantic-generated `inputSchema` and `outputSchema`. It also emits cautious `readOnlyHint`, `destructiveHint`, `idempotentHint`, and `openWorldHint` values.

MCP states that annotations are hints and must be treated as untrusted unless they come from a trusted server. They can inform UI or preflight risk decisions; they cannot enforce filesystem, network, approval, or business policy.

The official Python SDK can host the same tool definitions and handlers, but the SDK registration decorator is not the authorization boundary. Route every call through the same gateway contract or an equivalent resource-side PEP.

## 15. State of the art as of September 2026

### Established practice

- minimize tools and downstream IAM scopes;
- validate all inputs at the resource boundary;
- re-authorize on every call;
- isolate secrets from prompts and results;
- require human confirmation for sensitive effects;
- enforce rate limits/timeouts and log tool usage; and
- validate/sanitize outputs before model reuse.

### Current protocol practice

MCP 2026-07-28 uses JSON Schema 2020-12 by default for tool schemas, supports output schemas, permits authorization-filtered tool lists, adds deterministic/cacheable discovery, and continues OAuth hardening. Tool names/methods can be surfaced in headers for gateway routing and metering. Per-request business authorization still belongs to the application.

OpenFGA now publishes agent and MCP authorization models covering public tools, roles/groups, temporal access, and resource permissions. These patterns are useful when task/tool/resource relationships are the hard part.

OWASP's 2026 Agentic Top 10 highlights misuse of legitimate tools and recommends per-tool least-privilege profiles including scope, rates, egress allowlists, minimal CRUD, approval, sandboxing, and monitoring. Treat this as risk guidance; verify concrete controls against the relevant protocol and platform documentation.

### Emerging work

MCP proposals are exploring structured authorization denials, asynchronous approval, signed execution records, stronger capability declarations, and tamper-evident audit contracts. These are promising but not all are final. Pin the exact accepted specification/extension version before production use.

### Open problems

- portable task-scoped authority across tools and organizations;
- end-to-end receipts that survive gateways and asynchronous execution;
- safe discovery caching under revocation;
- composition analysis for individually permitted tool chains;
- output/instruction separation across heterogeneous content;
- usable approval that resists fatigue while binding exact effects; and
- policy evaluation that is low latency without accepting stale authority.

NIST's February 2026 agent identity/authorization concept paper is an initial public draft, not a final standard. It frames identification, authorization, audit/non-repudiation, and prompt-injection controls as areas for applied standards work.

---

## 16. Worked travel trace

### Valid search

1. Middleware supplies Alice, travel agent, approved production workload, and North tenant.
2. The model proposes `search_flights` with YVR, YYZ, and a maximum price.
3. The gateway validates the active task and allowed tool.
4. Pydantic rejects extra/wrong fields; policy rejects identical airports.
5. The gateway checks fixed search egress and a per-task call budget.
6. A read-only credential lease is injected internally.
7. The service result is validated before flight IDs enter model context.

### Approved booking

1. The proposal identifies `trip:north:483`, AC101, and CAD 700.
2. The gateway resolves authoritative trip owner/tenant/state and task resource scope.
3. It checks airline and amount constraints.
4. Without approval it returns `APPROVAL_REQUIRED` and creates no effect.
5. A manager receipt binds the exact operation and digest.
6. The gateway consumes approval and budget inside its execution boundary and injects the lease only into the downstream client.
7. It validates the booking response and returns an execution receipt.

### Lost response

The simulator commits the booking but loses the first response. The gateway returns `UNKNOWN`. The retry reuses the same operation ID and digest, finds the stored effect, validates it, and returns the original receipt without another booking or approval consumption.

## 17. Hands-on lab

Artifacts:

- [guided notebook](least_privilege_tool_access.ipynb)
- [reusable implementation](lab.py)
- [focused invariant tests](tests/test_course05_tool_gateway.py)

From the repository root:

```bash
uv sync
uv run python curriculum/beginner/05-least-privilege-tool-access/lab.py
uv run pytest -q curriculum/beginner/05-least-privilege-tool-access/tests
```

The default path uses Pydantic plus the Python standard library and performs no external calls. Optional production exercises can use the official MCP Python SDK, OpenFGA SDK, OPA client, or cloud credential APIs while preserving the same gateway invariants.

### Lab components

| Component | Responsibility |
| --- | --- |
| `ToolRequest` | model-proposed tool and arguments; contains no identity/credential fields |
| `VerifiedContext` | authenticated requester/actor/workload/tenant |
| `ToolSpec` + Pydantic models | governed catalog and strict schemas |
| `TaskGrant` | tool, resource, argument, egress, budget, and lifetime scope |
| `UnsafeDispatcher` | intentionally unsafe baseline |
| `ToolGateway` | trusted discovery, authorization, execution, validation, evidence |
| `CredentialBroker` | opaque short-lived lease metadata |
| `ApprovalStore` / `BudgetStore` | concurrency-safe teaching stores |
| `TravelServiceSimulator` | deterministic effects and idempotency ledger |
| `mcp_tool_definitions()` | authorized MCP-compatible schema mapping |

## 18. Experiments and evaluation

The dataset contains 20 scenarios and 24 attempts:

- six expected terminal successes;
- seventeen expected denials or approval challenges; and
- one expected unknown outcome followed by successful reconciliation.

It covers valid reads/writes, approval, workload/resource boundaries, hidden-tool calls, price/airline/recipient policy, argument injection, lifecycle, budgets, malformed output, policy outage, uncertain execution, and idempotency conflict.

Metrics:

\[
terminal\ success\ rate = \frac{expected\ terminal\ successes\ reached}{expected\ terminal\ successes}
\]

\[
invalid\ dispatch\ rate = \frac{blocked/challenged\ attempts\ dispatched}{blocked/challenged\ attempts}
\]

\[
forbidden\ effect\ rate = \frac{blocked/challenged\ attempts\ causing\ a\ new\ write}{blocked/challenged\ attempts}
\]

| System | Outcome match | Terminal success | Invalid dispatch | Forbidden effect | Duplicate effect | Evidence complete |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| unrestricted dispatcher | 6/24 | 6/6 | 17/17 | 8/17 | 0/24 | 24/24 |
| hardened gateway | 24/24 | 6/6 | 0/17 | 0/17 | 0/24 | 24/24 |

The baseline's forbidden-effect rate is lower than its invalid-dispatch rate because some invalid calls are reads. Dispatching an unauthorized read is still a violation even when the simulator records no write.

### Release gate

The deterministic gate requires:

```text
outcome match == 100%
terminal success == 100%
invalid dispatch == 0%
forbidden effects == 0%
duplicate effects == 0%
evidence completeness == 100%
```

Production evaluation should additionally slice by tool/effect/risk/tenant, track valid work blocked, measure p50/p95/p99 gateway and tool latency, approval wait time, credential issuance failures, stale discovery, budget exhaustion, reconciliation rate, output-schema failures, cost per successful compliant task, and policy/catalog rollout errors.

## 19. Failure modes and mitigations

| Failure | Consequence | Control and proof |
| --- | --- | --- |
| expose every tool | larger prompt and attack surface | authorization-filtered discovery; hidden-tool direct-call test |
| rely on discovery only | endpoint bypass or stale cache | execution-time re-authorization |
| accept identity in arguments | model substitutes authority | separate `VerifiedContext` contract |
| schema equals authorization | valid cross-tenant or excessive values pass | authoritative resource and argument policy |
| ignore extra fields | caller adds URL/path/flags | strict `extra="forbid"` schema |
| generic shell/HTTP/SQL | unbounded capability | narrow business tools; sandbox generic primitives |
| long-lived broad credential | compromise blast radius | brokered audience/scope/operation-bound lease |
| credential in prompt/result | secret disclosure | inject only inside downstream client; evidence metadata only |
| approval Boolean/chat text | alteration and replay | exact expiring single-use receipt |
| caller-selected egress | exfiltration/SSRF | fixed catalog host plus network allowlist |
| unlimited calls/chains | cost, spam, cascading effects | per-tool/task/chain/retry/deadline budgets |
| retry with new operation ID | duplicate side effect | stable ID, digest, reconcile before retry |
| trust successful status | fabricated/malformed success | output schema and authoritative receipt |
| tool text treated as instruction | indirect prompt injection | keep result data typed/untrusted; minimize context |
| policy outage fails open | unavailable PDP becomes bypass | deny consequential dispatch and record reason |
| log raw args/tokens/results | audit system becomes data leak | IDs/digests, redaction, retention and access control |

## 20. Production upgrade path

| Teaching lab | Production upgrade |
| --- | --- |
| local catalog | signed/versioned registry with ownership, review, rollout, revocation |
| Pydantic only | Pydantic + cross-language JSON Schema contract tests |
| in-process PEP | gateway plus resource-side enforcement |
| in-memory task grant | durable task authorization or relationship/policy engine |
| synthetic lease | workload federation/token exchange/secret broker with PoP where appropriate |
| in-memory approval | durable state machine and atomic effect coordination |
| local call counter | distributed atomic rate/cost/deadline budget |
| fixed egress set | proxy/service-mesh/firewall/sandbox enforcement and DNS controls |
| simulator ledger | downstream idempotency API, reconciliation, outbox/workflow |
| local audit list | privacy-filtered append-only telemetry with policy/catalog versions |

### Operational checklist

- Who owns each tool and approves catalog/risk changes?
- Can a catalog update expand authority without task re-authorization?
- How quickly do task cancellation and credential revocation propagate?
- Are discovery caches scoped to the authenticated request and version?
- Does every write use a stable operation ID and produce a receipt?
- Which failures are retryable, and how are unknown outcomes reconciled?
- Are downstream services enforcing tenant/resource authority too?
- Can tool results introduce instructions, links, files, or resources into context?
- Are secrets and sensitive arguments excluded from traces and model-visible errors?
- Can operators roll back policy/catalog versions independently?

## 21. Exercises

### Implementation

1. Add a read-only `get_trip` tool with exact subject/tenant filtering and output validation.
2. Add a two-person approval state machine for cancellation.
3. Add a total task-spend budget alongside per-booking and per-tool limits.
4. Expose the catalog through the official MCP Python SDK while routing every call through `ToolGateway`.

### Diagnosis

5. Change Pydantic to ignore extra fields. Show how `callback_url` becomes invisible to policy review.
6. Remove reconciliation and retry the unknown booking with a new operation ID. Measure duplicate effects.
7. Trust a malicious `readOnlyHint` from an untrusted server and explain which hard controls remain necessary.

### Architecture judgment

8. Choose between a narrow booking capability and a sandboxed browser for a new airline without an API. Compare blast radius, reliability, observability, and maintenance.
9. Design a distributed transaction or workflow for approval consumption, budget reservation, booking, and receipt persistence.
10. Model task/tool/trip relationships in OpenFGA and keep price/recipient policy in OPA or Cedar. Explain why the composition is worth its operational cost.

## 22. Review questions

1. Why must an invocation be authorized even when the tool was absent from discovery?
2. What does strict schema validation prove—and what does it not prove?
3. Why should an MCP tool annotation not be treated as an enforcement guarantee?
4. Which identifiers remain stable across an uncertain retry?
5. What is the difference between an allow decision and an execution receipt?
6. How do credential audience/scope and gateway policy provide defense in depth?
7. Why can two individually permitted tools form a forbidden chain?

## 23. Key takeaways

1. Tools turn proposals into effects, so the tool gateway is a security boundary.
2. Minimize discovery, then independently authorize execution.
3. Identity, task, resource, arguments, approval, credential, egress, and budget remain separate controls.
4. Strict schemas reject ambiguity; policy rejects unauthorized valid values.
5. Narrow business capabilities are safer and easier to evaluate than god tools.
6. Credentials stay behind the gateway and are narrower than the service's total authority.
7. Approval binds one exact operation; retries reconcile the same operation.
8. Tool results are untrusted until their schema and business receipt are verified.
9. Measure dispatches and real effects—not only returned status strings.
10. Protocols and SDKs carry contracts; application policy and enforcement provide authority.

---

## References

### Standards and current protocol documentation

- Model Context Protocol, [2026-07-28 tools specification](https://modelcontextprotocol.io/specification/2026-07-28/server/tools).
- Model Context Protocol, [2026-07-28 authorization specification](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization).
- Model Context Protocol, [security best practices](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices).
- Model Context Protocol, [2026-07-28 specification release notes](https://blog.modelcontextprotocol.io/posts/2026-07-28/).
- Model Context Protocol, [official Python SDK](https://github.com/modelcontextprotocol/python-sdk).
- Pydantic, [strict mode](https://docs.pydantic.dev/latest/concepts/strict_mode/) and [JSON Schema generation](https://docs.pydantic.dev/latest/concepts/json_schema/).
- JSON Schema, [Draft 2020-12 specification](https://json-schema.org/draft/2020-12).

### Authorization and agent/tool security

- OpenFGA, [Authorization for MCP Servers](https://openfga.dev/docs/modeling/agents/mcp-authorization).
- OpenFGA, [Task-Based Authorization](https://openfga.dev/docs/modeling/agents/task-based-authorization).
- OWASP GenAI Security Project, [Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/).
- OWASP Cheat Sheet Series, [AI Agent Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html).
- NIST NCCoE, [Accelerating the Adoption of Software and AI Agent Identity and Authorization](https://csrc.nist.gov/pubs/other/2026/02/05/accelerating-the-adoption-of-software-and-ai-agent/ipd), initial public draft, February 2026.
- NIST, [IR 8587: Protecting Tokens and Assertions from Forgery, Theft, and Misuse](https://csrc.nist.gov/pubs/ir/8587/final), September 2026.

## Next course

[Beginner 06 — Agent Identity Lifecycle](../06-agent-identity-lifecycle/README.md) extends these runtime controls across registration, ownership, provisioning, activation, rotation, recertification, suspension, revocation, and retirement.
