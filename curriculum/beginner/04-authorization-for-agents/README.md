# Beginner 04 — Authorization for Agents

Authentication establishes identity. Authorization decides whether an authenticated principal may perform one exact action on one exact resource under the current conditions. For agents, that decision also needs to preserve who requested the work, which logical agent is acting, which workload is executing, which task delegated authority, and what obligations must be satisfied before a side effect.

This chapter teaches that boundary through a deterministic refund-agent system. The language model may propose a refund. Trusted application code derives identity, resolves authoritative resource state, evaluates policy, consumes any approval, executes the action, and records evidence.

> **Course thesis:** after this course, you can explain, implement, attack-test, evaluate, and productionize a default-deny authorization boundary without treating model output, role names, or approval booleans as authority.

> **Goal:** Build and evaluate a default-deny authorization boundary that binds verified identity, task delegation, resource state, amount limits, and exact approval evidence before an agent action executes.

## Learning outcomes

By the end, you can:

1. distinguish authentication, authorization, delegation, consent, and approval;
2. model a decision as principal/requester, actor, workload, action, resource, context, and policy;
3. explain when RBAC, ABAC, ReBAC, capabilities, or a composition is appropriate;
4. place a Policy Enforcement Point (PEP) and Policy Decision Point (PDP) outside the model;
5. enforce default deny, tenant isolation, resource lifecycle, task scope, amount bounds, and fail-closed behavior;
6. issue narrower child authority without privilege amplification;
7. represent high-risk authorization as an obligation backed by an exact, expiring, single-use approval receipt;
8. authorize protected data before retrieval or tool execution;
9. map the same trusted request to OPA, Cedar, Amazon Verified Permissions, and OpenFGA; and
10. evaluate false allows, false denies, challenge behavior, evidence completeness, and operational trade-offs.

## Prerequisites

- [Beginner 01 — Agent Identity Foundations](../01-agent-identity-foundations/README.md)
- [Beginner 02 — Humans, Workloads and Agents](../02-humans-workloads-agents/README.md)
- [Beginner 03 — Authentication, Credentials and Tokens](../03-authentication-credentials-tokens/README.md)
- basic Python, JSON, APIs, and unit testing

Authentication is assumed to have produced a verified requester, actor, workload, and tenant. This chapter does not teach login, token signature verification, or credential issuance again.

## Scenario, boundaries, and success criteria

Northstar Commerce lets a customer ask an AI assistant to refund an order. A production refund agent may inspect that customer's order and propose a refund. Refunds up to CAD 200 may execute automatically. Larger refunds up to CAD 1,000 require a manager. Authority is limited to one task, one workload, one tenant, explicit actions and resources, an amount, and an expiry.

The system must block:

- a broad role used against another tenant or resource;
- a prompt that substitutes requester, actor, workload, or tenant;
- a different workload using the refund agent's logical name;
- expired, absent, or widened delegation;
- a refund exceeding the order balance or delegated limit;
- approval for a changed proposal, an expired approval, self-approval, or replay;
- retrieval of unauthorized order context; and
- execution when the PDP is unavailable.

Success means all labelled valid attempts execute, no labelled invalid attempt executes, every decision has reproducible public evidence, and the default notebook runs without credentials or network access.

### Non-goals

The lab is not a payment processor, identity provider, durable workflow engine, or production policy service. Its in-memory approval store demonstrates semantics, not distributed atomicity. The production section explains where OPA, Cedar/Amazon Verified Permissions, OpenFGA, an identity provider, and durable storage fit.

---

## 1. The mental model: proposal is not authority

An agent is good at interpreting intent and proposing actions. It is not a trusted source for its own identity, permissions, resource ownership, or approval state.

```text
user intent
   │
   ▼
model / agent ── proposes ──► typed refund proposal
                                  │
authenticated application state ─┤
authoritative order state ────────┤
task delegation ──────────────────┤
policy + approval store ──────────┤
                                  ▼
                         PDP returns a decision
                                  │
                         PEP enforces decision
                                  │
                    execute, verify, and audit
```

The core boundary is:

```text
model / agent -> proposes, predicts, extracts, recommends
trusted application -> validates, authorizes, persists, executes, verifies
```

A system prompt saying “only refund Alice's orders” is useful behavioral guidance. It is not an authorization control because prompts and retrieved content are model inputs and may be manipulated.

## 2. Authentication, authorization, delegation, consent, approval

| Concept | Question | Example | What it does not prove |
| --- | --- | --- | --- |
| Authentication | Who or what presented verifiable evidence? | the workload has a valid SPIFFE identity | permission to refund |
| Authorization | May this principal perform this action now? | agent may refund `order:north:123` | that the user asked for it |
| Delegation | Who intentionally granted bounded authority? | Alice delegates one refund task | that a manager approved a high amount |
| Consent | Did the affected party agree to a use? | Alice consents to refund processing | enterprise policy permission by itself |
| Approval | Did an authorized reviewer approve this exact proposal? | Mira approves CAD 450 | reusable permission for other proposals |

All five may be relevant to one action. Collapsing them into `authenticated = true` or `approved = true` destroys the boundary.

## 3. The authorization tuple

A useful request is:

\[
R = (S, Q, A, W, O, X, T)
\]

where:

- \(S\): authenticated principal or subject evaluated by policy;
- \(Q\): requester who originated the business intent;
- \(A\): logical actor performing the task;
- \(W\): authenticated workload executing the actor;
- \(O\): exact operation/action;
- \(X\): exact protected resource; and
- \(T\): trusted context: tenant, task, time, amount, risk, and policy-relevant state.

For the valid low-value case:

```json
{
  "requester": "user:alice",
  "actor": "agent:refund",
  "workload": "spiffe://corp.example/ns/refunds/sa/refund-prod",
  "tenant": "tenant:north",
  "task": "task:refund-928",
  "action": "refund:create",
  "resource": "order:north:123",
  "amount_cents": 12500,
  "currency": "CAD"
}
```

The trusted gateway supplies identity. The agent proposal contains only request/task IDs, action, resource, amount, and currency. A prompt cannot change authenticated context by adding a field.

## 4. Default deny and composed authorization

Let each required predicate return true or false:

- \(I\): requester and actor are active;
- \(B\): workload is bound to the actor and tenant;
- \(R\): resource exists, is refundable, and belongs to the tenant/requester;
- \(D\): active delegation matches requester, actor, workload, task, action, and resource;
- \(M\): amount is within resource, policy, and delegation limits;
- \(P\): any required approval is valid and consumed exactly once.

Then:

\[
allow = I \land B \land R \land D \land M \land P
\]

If no explicit rule permits the action, deny it. If a required attribute is absent or stale, deny it. If the PDP is unavailable, consequential writes fail closed. Availability policy can differ for low-risk reads, but that choice must be explicit and measured.

The decision is not only a Boolean. The lab uses:

```text
ALLOW | DENY | REQUIRE_APPROVAL
```

with a reason code, policy version, proposal digest, evaluated checks, grant ID, optional approval ID, and obligations. `REQUIRE_APPROVAL` does not execute.

---

## 5. Authorization models

### 5.1 RBAC: Role-Based Access Control

RBAC assigns permissions to roles and roles to principals:

```text
agent:refund -> refund_agent -> refund:create
```

RBAC is understandable, widely supported, and appropriate for coarse job-function permissions. Its weakness appears when every tenant, order, task, amount, workload, and time window needs a new role. “Refund agent” is eligibility, not sufficient authority for a particular refund.

### 5.2 ABAC: Attribute-Based Access Control

ABAC evaluates attributes of principals, resources, actions, and environment. NIST SP 800-162 defines ABAC and the PEP/PDP separation used here.

```text
allow when
  actor.department == "customer-service"
  and workload.environment == "production"
  and resource.tenant == context.tenant
  and amount <= grant.max_amount
  and current_time < grant.expires_at
```

ABAC expresses rich context but creates attribute-authority and freshness questions. Policy is only as trustworthy as the source of each attribute.

### 5.3 ReBAC: Relationship-Based Access Control

ReBAC evaluates graph relationships:

```text
user:alice --customer_of--> order:north:123
agent:refund --assigned_to--> task:refund-928
task:refund-928 --can_refund--> order:north:123
```

It fits collaboration, hierarchies, multi-tenant sharing, RAG, and agent/task relationships. Zanzibar demonstrated a global relationship-based authorization design; OpenFGA is a commonly used open-source implementation inspired by that model.

### 5.4 Capabilities and task grants

A capability is an unforgeable reference or token carrying authority. A task grant can be capability-like even when stored server-side:

```text
holder: agent:refund + bound workload
action: refund:create
resource: order:north:123
maximum: CAD 600
task: task:refund-928
expiry: 12:10 UTC
```

Capabilities make delegation and attenuation natural but require secure issuance, storage, revocation, replay handling, and proof of possession when bearer theft is a concern.

### 5.5 Composition, not model tribalism

The lab composes:

- RBAC for manager eligibility;
- ABAC for tenant, amount, environment, lifecycle, and time;
- ReBAC-like customer/order and task/resource relationships; and
- a capability-like task grant for bounded delegation.

| Model | Best fit | Main strength | Main limitation in agent systems |
| --- | --- | --- | --- |
| RBAC | stable job functions | simple administration | role explosion; weak per-task/resource scope |
| ABAC | dynamic context | expressive conditions | attribute trust/freshness and policy complexity |
| ReBAC | graph-shaped sharing | natural resource relationships | modeling and consistency complexity |
| Capability | explicit delegation | portable, attenuable authority | theft, revocation, discovery, and lifecycle |
| Composed | consequential agent actions | layered constraints | more operational and testing cost |

Choose the smallest model that correctly represents the domain. Composition is justified when it closes a real gap and its coordination cost is measured.

## 6. PEP, PDP, policy information, and administration

- **PEP — Policy Enforcement Point:** intercepts the operation and enforces the answer. In this course, `RefundGateway` is the PEP.
- **PDP — Policy Decision Point:** evaluates policy and returns a decision. `RefundPDP` is the local teaching implementation.
- **PIP — Policy Information Point:** supplies trusted attributes such as order ownership or workload state.
- **PAP — Policy Administration Point:** manages, tests, reviews, and publishes policies.

The PEP must sit at every protected boundary that can cause the effect: tool gateway, service API, database access layer, or resource server. A model-side check is bypassable. A user-interface check is bypassable. A central PDP without complete PEP coverage is also bypassable.

### Local, sidecar, and remote PDPs

| Placement | Advantages | Risks / costs | Typical fit |
| --- | --- | --- | --- |
| in-process library | low latency, simple failure domain | policy rollout coupling; language-specific | Cedar library, embedded checks |
| sidecar/host agent | low network distance, independent bundles | fleet lifecycle and local cache consistency | OPA alongside workloads |
| remote service | centralized governance and telemetry | network latency/availability; larger blast radius | managed authorization or shared platform |

Policy caching needs a freshness contract. Cache keys must include all decision-relevant inputs and a policy/data version. Never turn “PDP unavailable” into “allow” accidentally.

---

## 7. Delegation and attenuation

An agent acting for a user should not silently clone all user permissions. Delegation must be explicit and independently constrained.

For parent authority \(G_p\) and child authority \(G_c\):

\[
actions_c \subseteq actions_p
\]

\[
resources_c \subseteq resources_p
\]

\[
amount_c \le amount_p, \quad expiry_c \le expiry_p
\]

The parent must also permit re-delegation. A child agent starts with zero authority; the parent's ability to spawn a process does not imply permission to delegate business authority.

The lab's `attenuate()` rejects action, resource, amount, or expiry widening and disables further re-delegation on the child.

## 8. Approval is a bound receipt, not a Boolean

For a CAD 450 refund, policy returns an obligation instead of executing:

```text
outcome: require_approval
obligation: obtain_bound_manager_approval
```

A useful approval receipt binds:

- stable approval ID;
- approver identity and eligible role;
- tenant;
- digest of the exact request ID, task, action, resource, amount, and currency;
- policy version;
- issue and expiry times; and
- single-use state.

Changing CAD 450 to CAD 460 changes the digest and invalidates the approval. The approver cannot be the requester or actor. Replay fails. The in-memory store serializes consumption with a lock; production must atomically consume the approval and commit the external effect, or use an equivalent durable workflow/outbox design.

## 9. Authorization before retrieval and tool execution

Filtering after retrieval is too late: unauthorized content may already have entered model context, traces, caches, or logs.

Correct order:

```text
authenticated context
  -> determine exact candidate resource IDs
  -> authorize each resource or compute authorized set
  -> fetch/rank only authorized content
  -> provide minimal context to the model
```

`authorized_order_context()` demonstrates exact resource filtering before returning order records. At scale, a relationship engine's list/search APIs, security filters, or an authorization-aware query planner may be more efficient than one check per item. Preserve the same tenant and delegation invariants.

## 10. Policy decision evidence

Record observable facts, not private model reasoning:

- request, task, decision, grant, approval, actor, workload, tenant, and resource identifiers;
- action, bounded attributes or their digests;
- allow/deny/challenge outcome and reason code;
- policy and authoritative-data versions;
- obligations and whether the PEP fulfilled them;
- latency, dependency errors, retry/attempt ID, execution receipt, and terminal state.

Do not log bearer credentials, approval contents, sensitive resource bodies, or free-form chain-of-thought. OPA decision logs support decision IDs, bundle revisions, inputs/results, and masking; apply data minimization before export.

---

## 11. Technology landscape and common SDKs

The lab implements the primitive first and exposes `policy_engine_inputs()` so learners can see what an adapter must preserve.

| Technology | Model / interface | Strengths | Limitations | Python / integration path |
| --- | --- | --- | --- | --- |
| Open Policy Agent (OPA) | general policy-as-code with Rego | portable, mature, bundles, decision logs, broad ecosystem | Rego/data modeling and control-plane operations | REST API or `opa-python-client`; OPA commonly runs as sidecar/daemon |
| Cedar | principal-action-resource-context policies | schema validation, default deny, forbid-overrides-permit, analyzable language | relationship-heavy domains need entity modeling; skip-on-error diagnostics require application judgment | `cedarpy` for local teaching; Cedar SDKs in supported ecosystems |
| Amazon Verified Permissions | managed Cedar authorization | managed policy stores and APIs, AWS integration | service dependency, cloud-specific operations and pricing | AWS SDK for Python (`boto3`) `is_authorized` API |
| OpenFGA | relationship tuples and graph checks | strong ReBAC, list/check APIs, task/agent modeling guidance | contextual attributes/amount rules may need conditions or a composed PDP | official `openfga-sdk` for Python or HTTP API |
| OpenID AuthZEN Authorization API 1.0 | interoperable PEP-to-PDP API | standard request/decision boundary and discovery | does not choose policy language or data model | HTTP client generated or implemented from the final specification |
| application-local policy | typed code | easy to debug and teach; low latency | policy drift, rollout coupling, limited governance at scale | this course's standard-library implementation |

Selection questions:

1. Is the hard part contextual policy, graph relationships, portable delegation, or all three?
2. What consistency and decision-latency SLOs are required?
3. Can the system explain the exact policy/data versions used?
4. How are policies validated, reviewed, rolled out, and rolled back?
5. Can decisions be replayed offline without sensitive logs?
6. How does the system list authorized resources without leaking candidates?
7. What happens during policy-service or attribute-source failure?

### Mapping the lab request

`policy_engine_inputs()` maps the same trusted context to:

- OPA's `input` document;
- Cedar's principal/action/resource/context request; and
- OpenFGA checks for task-to-tool and customer-to-order relationships.

The mapping does not claim semantic equivalence by itself. Production adapters must validate schemas, resolve authoritative entities/tuples, interpret diagnostics, preserve reason/evidence IDs, and fail closed for this write path.

### Minimal adapter sketches

OPA via HTTP or its Python client should send the trusted input to a fixed policy path, verify the response schema, and treat timeout/malformed response as denial. OpenFGA's official Python SDK can check relationships, but an amount ceiling still belongs in a condition or composed policy. Amazon Verified Permissions accepts Cedar principal/action/resource/context through the AWS SDK; validate policies against a schema before publication and inspect decision errors rather than ignoring them.

Keep these optional integrations separate from the default lab so learners do not need credentials or running infrastructure.

## 12. State of the art as of September 2026

### Established practice

- Put enforcement at the resource/tool boundary and separate it from decision logic.
- Use default deny and explicit principal-action-resource-context requests.
- Externalize policy when multiple services need consistent governance.
- Test policies with positive, negative, boundary, lifecycle, and dependency-failure cases.
- Record policy/data versions and privacy-filtered decision evidence.

### Current agent-specific practice

- Treat agents as first-class principals while preserving the human requester and workload identity.
- Grant task- or session-scoped authority instead of copying a user's entire permission set.
- Bind an agent to the task and to the workload performing the call.
- Give sub-agents zero authority by default and create a narrower task when delegation is needed.
- Authorize before RAG retrieval and at MCP/tool boundaries, including parameter-level constraints.

OpenFGA's current agent guidance documents task grants, session and agent scoping, expiration/call-count conditions, agent-to-task binding, sub-agent narrowing, and tuple cleanup when a task completes.

### Interoperability direction

The OpenID Foundation approved Authorization API 1.0 as a final specification in January 2026. It standardizes communication between PEPs and PDPs while remaining independent of policy language. AuthZEN working drafts also explore obligations, request/approval workflows, and an MCP binding. Those profiles are emerging: pin the exact version and do not treat a draft as a stable production contract.

### Research and open problems

- atomic authorization, approval consumption, and effects across distributed systems;
- policy/data consistency during revocation and long-running agent tasks;
- efficient “list authorized resources” for retrieval without side channels;
- portable, attenuable delegation across organizational and tool boundaries;
- formal analysis of composed RBAC/ABAC/ReBAC/capability policies;
- usable explanations that do not disclose sensitive policy structure; and
- measuring policy complexity, privilege exposure, and valid work blocked—not merely decision latency.

No policy engine makes an untrusted model safe by itself. Enforcement coverage, authoritative data, identity binding, and the side-effect transaction remain application responsibilities.

---

## 13. Worked refund trace

### Low-value valid request

1. Authentication middleware produces the verified Alice/refund-agent/production-workload/North context.
2. The model proposes CAD 125 for `order:north:123` under `task:refund-928`.
3. The PEP validates the request shape and calls the PDP.
4. The PDP validates principal lifecycle, workload binding, authoritative order state, tenant/customer relationship, task grant, resource/action scope, expiry, and amount.
5. Amount is below the automatic limit, so the PDP returns `ALLOW` with evidence.
6. The PEP executes once and records an execution receipt linked to the decision.

### High-value request

1. The same checks pass for CAD 450.
2. The PDP returns `REQUIRE_APPROVAL`; nothing executes.
3. An eligible manager approves the digest of that exact proposal.
4. On resubmission, the PDP validates and consumes the receipt once, then returns `ALLOW`.
5. Changing the amount or replaying the receipt returns `DENY`.

### Cross-tenant attempt

The broad RBAC baseline sees `refund_agent + refund:create` and executes. The hardened PDP reads the South tenant from the authoritative order record, detects the tenant mismatch, denies, and produces no execution receipt.

## 14. Hands-on lab

The primary lab artifacts are:

- [guided notebook](authorization_for_agents.ipynb)
- [reusable implementation](lab.py)
- [focused invariant tests](tests/test_course04_authorization.py)

From the repository root:

```bash
uv sync
uv run python curriculum/beginner/04-authorization-for-agents/lab.py
uv run pytest -q curriculum/beginner/04-authorization-for-agents/tests
```

The implementation uses only the standard library so its security semantics remain visible. The repository also provides `opa-python-client`, `openfga-sdk`, and `cedarpy` for optional adapter exercises.

### Lab architecture

| Component | Responsibility |
| --- | --- |
| `VerifiedContext` | trusted identity context from authentication middleware |
| `RefundProposal` | untrusted action parameters proposed by the agent |
| `BroadRolePDP` | intentionally unsafe role-only baseline |
| `RefundPDP` | composed default-deny policy and approval semantics |
| `RefundGateway` | PEP, fail-closed adapter, execution, decision log |
| `ApprovalStore` | exact single-use approval consumption demonstration |
| `attenuate()` | rejects child authority widening |
| `authorized_order_context()` | filters protected resources before retrieval |
| `policy_engine_inputs()` | OPA/Cedar/OpenFGA request mappings |

## 15. Experiments and evaluation

The labelled dataset contains 16 cases and 17 attempts: three expected to execute and fourteen expected to be blocked or challenged. It includes valid low/high refunds, missing approval, cross-tenant access, tenant substitution, wrong workload, wrong actor, expired or missing delegation, an unauthorized action, amount escalation, closed resource, altered approval, approval replay, PDP outage, and invalid input.

For labelled executable attempts \(V\) and labelled blocked/challenged attempts \(N\):

\[
valid\ execution\ rate = \frac{executed\ attempts\ in\ V}{|V|}
\]

\[
invalid\ execution\ rate = \frac{executed\ attempts\ in\ N}{|N|}
\]

\[
evidence\ completeness = \frac{decisions\ with\ required\ public\ evidence}{all\ decisions}
\]

The deterministic fixture produces:

| System | Valid execution rate | Invalid execution rate | Invalid block rate | Evidence completeness |
| --- | ---: | ---: | ---: | ---: |
| broad role baseline | 3/3 | 12/14 | 2/14 | 17/17 |
| hardened PEP/PDP | 3/3 | 0/14 | 14/14 | 17/17 |

These are fixture results, not a benchmark of OPA, Cedar, or OpenFGA. They measure policy correctness on this labelled scenario, not model quality or production reliability.

### Release gate

The lab's gate requires:

```text
valid execution rate == 100%
invalid execution rate == 0%
evidence completeness == 100%
```

Production gates should also slice by tenant, action, resource class, policy version, approval path, and dependency state; track valid work blocked; and measure p50/p95/p99 decision latency, availability, policy rollout errors, cache staleness, and cost per successful compliant task.

---

## 16. Failure modes and mitigations

| Failure | Why it fails | Mitigation / test |
| --- | --- | --- |
| authentication equals authorization | identity does not grant an action | explicit PDP request after authentication |
| role-only write permission | ignores tenant, task, resource, amount, time | composed resource/task policy; compare baseline |
| identity fields from tool arguments | model can substitute authority | derive context from authenticated application state |
| user-token pass-through | agent becomes indistinguishable from user | separate requester, actor, workload, delegation |
| authorization in prompt | prompt injection/bypass | PEP at tool/resource boundary |
| authorize after retrieval | data already entered model context | filter exact IDs before fetch/rank |
| approval Boolean | not bound, expiring, attributable, or single use | signed/server-side receipt bound to proposal digest |
| child inherits parent | privilege amplification | zero-default child plus attenuation checks |
| fail open on timeout | outage becomes authorization bypass | deny this write path and surface dependency failure |
| stale policy/data cache | revoked access remains usable | versioned TTL, revocation propagation, consistency tests |
| logs contain request bodies/tokens | observability becomes data leak | structured IDs/digests, minimization, masking |
| policy engine result used blindly | malformed/errors may be treated as allow | validate response schema and diagnostics at PEP |
| one check before a long task | authority may change before effect | re-authorize near consequential actions |

## 17. Production upgrade path

| Lab choice | Production upgrade |
| --- | --- |
| in-process dictionaries | authoritative identity/resource services with versioned snapshots |
| local `RefundPDP` | OPA, Cedar/Verified Permissions, OpenFGA, or composed service |
| in-memory grant | durable task authority with revocation and cleanup |
| in-memory approval lock | transactionally consumed receipt plus effect/outbox |
| fixed clock | trusted UTC clock, bounded skew, explicit time semantics |
| direct function call | authenticated, encrypted PEP-to-PDP channel with timeout/budget |
| one process | horizontally scaled service with consistency and cache policy |
| deterministic cases | policy unit/property tests, shadow decisions, canary rollout, replay corpus |
| local audit list | append-only privacy-filtered events, retention, access control, correlation |

### Policy lifecycle

1. Define typed request/entity schemas and policy ownership.
2. Unit-test permits, forbids, boundaries, missing data, errors, and policy conflicts.
3. Validate policy against schema and lint unsafe patterns.
4. Replay a representative, privacy-safe decision corpus.
5. Run new policy in shadow mode and compare disagreements.
6. Canary by service/tenant, monitor false denies and unexpected allows, then expand.
7. Keep an immediate rollback path and policy/data version in every decision.

### Reliability and security questions

- Is authorization evaluated again immediately before the external effect?
- Are retries idempotent, and are unknown outcomes reconciled before retrying?
- Can an approval be consumed concurrently?
- Does cancellation prevent the next action?
- Can revoked task tuples/grants remain in a cache?
- Are list/search operations authorized as carefully as point checks?
- Are decision inputs privacy-filtered before central logging?
- Are policy administrators separated from approvers and service operators where required?

## 18. Exercises

### Implementation

1. Add `refund:read` without allowing it to create refunds. Update the task grant, PDP, fixtures, and tests.
2. Add a CAD 0 boundary case and a refund exactly at CAD 200 and CAD 1,000.
3. Add a durable-style approval state machine: issued, reserved, consumed, expired, revoked.
4. Implement one optional adapter using `opa-python-client`, `openfga-sdk`, or the AWS SDK. Keep the existing `RefundGateway` contract and fail closed on timeouts or malformed responses.

### Diagnosis

5. Remove the workload-binding check. Which cases regress, and why do role and tenant checks fail to catch all of them?
6. Change authorization-aware retrieval to fetch then filter. List every place unauthorized text could leak before filtering.
7. Create a stale resource snapshot in which a refunded order still appears paid. Define the version/freshness evidence needed to reject it.

### Architecture judgment

8. Choose OPA, Cedar/Verified Permissions, OpenFGA, or a composition for a multi-tenant support platform. Justify model fit, consistency, latency, list/search needs, policy lifecycle, and failure behavior.
9. Design an approval transaction that remains safe if execution succeeds but the response is lost.
10. Define an AuthZEN-compatible PEP/PDP request for this scenario. State which emerging obligation/approval features you would avoid depending on until their exact specification version is fixed.

## 19. Review questions

1. Why is a verified workload identity still insufficient to authorize a refund?
2. Which values may come from the agent proposal, and which must come from trusted application state?
3. Why can `REQUIRE_APPROVAL` not be treated as a soft allow?
4. How does ReBAC complement rather than replace an amount-based ABAC rule?
5. Why must a child grant be narrower in every authority dimension?
6. What does an evidence-complete denial contain without exposing private model reasoning?
7. When could a cached allow be unsafe even if its policy version is current?

## 20. Key takeaways

1. Authentication identifies; authorization constrains a specific action.
2. Requester, actor, workload, task, tenant, action, and resource remain distinct.
3. The model proposes; the trusted PEP/PDP boundary decides and enforces.
4. Default deny and authoritative attributes are the safe starting point.
5. RBAC, ABAC, ReBAC, and capabilities solve different parts of the problem.
6. Delegation is explicit, expiring, revocable, and attenuated.
7. Approval is a bound, single-use receipt—not a Boolean or chat message.
8. Authorization occurs before protected retrieval and again near side effects.
9. Policy availability, consistency, rollout, evidence, and privacy are production requirements.
10. Evaluate actual executions and blocks on labelled cases, not printed expectations.

---

## References

### Foundations and architecture

- NIST, [Guide to Attribute Based Access Control (ABAC), SP 800-162](https://csrc.nist.gov/pubs/sp/800/162/upd2/final).
- NIST, [Role Based Access Control project](https://csrc.nist.gov/projects/role-based-access-control).
- Google Research, [Zanzibar: Google's Consistent, Global Authorization System](https://research.google/pubs/zanzibar-googles-consistent-global-authorization-system/) (USENIX ATC 2019).
- OpenID Foundation, [Authorization API 1.0](https://openid.net/specs/authorization-api-1_0.html), final specification approved January 2026.
- OpenID AuthZEN, [specification status and emerging profiles](https://openid.net/wg/authzen/specifications/).

### OPA

- Open Policy Agent, [deployment and PEP/PDP architecture](https://www.openpolicyagent.org/docs/deploy).
- Open Policy Agent, [policy language](https://www.openpolicyagent.org/docs/policy-language).
- Open Policy Agent, [management APIs and architecture](https://www.openpolicyagent.org/docs/management-introduction).
- Open Policy Agent, [decision logs and masking](https://www.openpolicyagent.org/docs/management-decision-logs).
- `opa-python-client`, [Python client repository](https://github.com/permitio/opa-python-client).

### Cedar and managed authorization

- Cedar, [how authorization works](https://docs.cedarpolicy.com/auth/authorization.html).
- Cedar, [security and schema-validation guidance](https://docs.cedarpolicy.com/other/security.html).
- Amazon Web Services, [Verified Permissions documentation](https://docs.aws.amazon.com/verifiedpermissions/).
- `cedarpy`, [Python bindings](https://github.com/k9securityio/cedar-py).

### OpenFGA and agent authorization

- OpenFGA, [Authorization for Agents](https://openfga.dev/docs/modeling/agents).
- OpenFGA, [Task-Based Authorization](https://openfga.dev/docs/modeling/agents/task-based-authorization).
- OpenFGA, [RAG authorization](https://openfga.dev/docs/modeling/agents/rag-authorization).
- OpenFGA, [Python SDK](https://github.com/openfga/python-sdk).

## Next course

[Beginner 05 — Least-Privilege Tool Access for Agents](../05-least-privilege-tool-access/README.md) applies this authorization boundary to tool catalogs, argument-level permissions, high-risk actions, credentials, approvals, and tool-gateway enforcement.
