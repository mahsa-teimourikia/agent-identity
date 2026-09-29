# Intermediate 06 — Authorization for MCP and Tool Servers

> **Goal:** build and attack-test an HTTP MCP protected resource that authenticates an audience-bound access token, preserves human, agent, client, workload, and task identities, independently authorizes tool discovery, invocation, exact arguments, target resources, approvals, and downstream delegation, and executes consequential effects exactly once under current policy.

**Level:** intermediate · **Time:** 3–4 hours · **Format:** reading + executed notebook + reusable lab + policy exercises

This course targets the **2026-07-28 MCP specification generation** and the official Python SDK 2.2 line. MCP defines how a client discovers and calls a server; it does not make every advertised tool safe. A production server still needs OAuth resource-server controls, business authorization, schema enforcement, current-state checks, safe delegation, and auditable execution semantics.

## Learning outcomes

By the end, you can:

- separate the MCP client, protected resource, authorization server, tool, target resource, and downstream API;
- explain why MCP authorization applies to HTTP transport and why stdio has a different credential boundary;
- publish OAuth Protected Resource Metadata and return useful `WWW-Authenticate` challenges;
- validate token signature, profile, issuer, audience/resource, time bounds, client, scopes, and identity bindings;
- keep requester, subject, logical agent, OAuth client, workload, task, and downstream actor identities distinct;
- authorize discovery, invocation, strict arguments, target objects, and effects as separate decisions;
- prevent token passthrough, audience confusion, confused-deputy behavior, state-handle theft, and tool-name collisions;
- bind a one-time approval to the canonical action, arguments, identities, versions, expiry, and operation ID;
- re-authorize immediately before a side effect and reconcile unknown outcomes without duplicate execution;
- attenuate downstream tokens by audience, scope, actor, task, and lifetime;
- validate tool outputs before returning them to an agent or model;
- distinguish OAuth scope step-up from business-policy denial; and
- evaluate a gateway with a labeled attack matrix and a zero-invalid-acceptance release gate.

## Prerequisites

Complete Intermediate 02–05 or be comfortable with OAuth resource indicators, delegated tokens, fine-grained authorization, and continuous authorization. You need Python 3.10+ and `uv` for the lab. OPA is optional for the Rego exercise.

## Start here

```bash
uv sync
uv run python curriculum/intermediate/06-mcp-tool-authorization/lab.py
uv run pytest curriculum/intermediate/06-mcp-tool-authorization/tests -q
```

Open [`mcp_authorization.ipynb`](mcp_authorization.ipynb) for the guided investigation. The notebook imports [`lab.py`](lab.py); the tests and notebook therefore exercise the same implementation.

---

## 1. The trust boundary is larger than `tools/call`

A simplified diagram hides the important principals:

```text
Human requester / resource owner
             |
             | bounded business intent
             v
Logical agent inside an authenticated MCP client
             |
             | access token for the MCP resource
             v
HTTP MCP protected resource  <---- authorization server
             |
             +-- tool discovery authorization
             +-- tool invocation authorization
             +-- argument and target-resource authorization
             +-- approval and current-state authorization
             |
             v
Business adapter / downstream API
             |
             +-- new audience-limited delegated credential
             +-- idempotent effect and execution receipt
```

The server must answer all of these questions from verified or authoritative data:

1. Is this token authentic, current, and intended for this MCP resource?
2. Which client, workload, agent, task, tenant, and user are involved?
3. May that combination discover or call this tool?
4. Are these exact arguments valid and within the task grant?
5. Is the target object owned by the right tenant and subject?
6. Is current policy still permissive at commit time?
7. Does a consequential action have a fresh approval for this exact proposal?
8. What narrower authority may be delegated downstream?
9. Did the side effect happen once, not zero or twice?

A valid bearer token answers only part of question 1.

## 2. Transport boundary: HTTP is not stdio

The MCP authorization specification is defined for HTTP-based transports. An HTTP MCP server that chooses authorization should follow the OAuth protected-resource pattern. A stdio server should not start an HTTP OAuth flow; its launcher supplies credentials through the local process environment or another operating-system boundary.

| Transport | Authentication boundary | Main operational risks |
|---|---|---|
| HTTP | OAuth access token at the protected resource | token audience, discovery, redirects, SSRF, issuer mix-up, proxy routing |
| stdio | local launcher, process identity, environment, filesystem | malicious local server, environment leakage, unsafe proxying, weak sandboxing |

An HTTP-to-stdio proxy joins both risk sets. Authenticate at the HTTP edge, define which local server binary and arguments may run, scrub the environment, constrain filesystem/network access, and never turn arbitrary client input into a process command.

## 3. MCP OAuth resource-server flow

The MCP server is the **OAuth resource server**. The client learns which authorization server can issue a suitable token from RFC 9728 Protected Resource Metadata.

```json
{
  "resource": "https://claims-mcp.northstar.example",
  "authorization_servers": ["https://id.northstar.example"],
  "scopes_supported": [
    "claims:search",
    "claims:read",
    "claims:update",
    "payments:create"
  ],
  "bearer_methods_supported": ["header"]
}
```

The client includes the canonical MCP resource in authorization and token requests using the OAuth Resource Indicators `resource` parameter. The resource server accepts tokens intended for that same canonical resource.

The OAuth 2.1 reference in MCP is still an IETF draft, so implementations must follow the MCP version they claim and the cited RFCs rather than treating “OAuth 2.1” as a finished, self-contained control set.

### Correct HTTP failures

No usable token or an invalid token is an HTTP authentication failure:

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer resource_metadata="https://claims-mcp.northstar.example/.well-known/oauth-protected-resource/mcp"
```

A valid token missing an obtainable scope can use a bounded scope challenge:

```http
HTTP/1.1 403 Forbidden
WWW-Authenticate: Bearer error="insufficient_scope", scope="claims:read"
```

A tenant mismatch, inactive task, high-risk denial, stale approval, or forbidden resource is a business-policy denial—not an invitation to request broader OAuth scopes. Return 403 without suggesting that more privilege will fix an ineligible action.

Do not hide HTTP authentication failures inside a successful MCP tool result.

## 4. Strict token validation

The lab's `NorthstarTokenVerifier` implements the official Python SDK `TokenVerifier` protocol and produces an SDK `AccessToken`. It enforces:

```text
alg = EdDSA
typ = at+jwt
trusted verification key
iss = configured authorization server
aud = canonical MCP protected resource
required identity and task claims
iat / nbf / exp are current
short maximum lifetime
requested per-tool scope
```

The SDK server also enables `validate_token_resource=True`. In production, use issuer-bound JWKS discovery and controlled key rotation. Never:

- decode a JWT without verifying its signature;
- fetch a verification key from an attacker-supplied `jku` or `x5u` header;
- accept a token because its issuer and scope “look right” while ignoring audience;
- put bearer tokens in URLs;
- accept a token issued to a downstream API at the MCP server; or
- forward the received MCP token to another service.

## 5. Preserve every identity plane

The reference context keeps these values separate:

| Plane | Example | What it proves |
|---|---|---|
| subject/requester | `user:alice` | represented resource owner |
| logical agent | `agent:claims-adjuster` | governed agent identity |
| OAuth client | `client:claims-copilot` | registered client that acquired authority |
| workload | `spiffe://northstar.example/claims/adjuster` | executing deployment |
| task | `task:clm-100-review` | bounded business purpose |
| tenant | `tenant:northstar` | isolation domain |
| token ID | `at-001` | replay/evidence correlation, not raw-token storage |

Do not derive a user by splitting a subject string, infer an agent from a tool name, or trust a caller-provided task independently of the verified token and task store. Each identity is compared with authoritative bindings. A token for Alice used by an unapproved workload is not equivalent to Alice acting through the approved claims agent.

## 6. Discovery and invocation are separate gates

`tools/list` is an information boundary. Filtering it reduces capability leakage and helps clients avoid presenting impossible actions. It is not an authorization grant.

The lab's discovery method filters by:

- current subject/client/workload state;
- active task;
- task-delegated tools; and
- token scopes.

Every `tools/call` then repeats authorization independently. Cached discovery results can outlive revocation or policy changes.

The 2026-07-28 protocol can expose `Mcp-Method` and `Mcp-Name` request headers for routing. A gateway may use them as an optimization, but it must reject a mismatch with the JSON-RPC body. Header-only enforcement creates a routing-confusion bypass.

Tool names are scoped to a server and are case-sensitive. An aggregator needs a stable server identity plus tool identity; server display names alone are not globally unique.

## 7. Schema validity is necessary, not authority

The SDK/tool definition's `inputSchema` describes shape. It does not prove that the caller owns the target claim.

The reference tools use strict Pydantic models:

- unknown fields are forbidden;
- strings are not silently coerced from integers;
- resource IDs follow a constrained format;
- search limits are bounded;
- currency is an explicit enum;
- amounts have business bounds; and
- writes require stable operation IDs and expected versions.

Then the policy layer independently verifies resource existence, tenant, owner, task grant, version, current state, and approval.

This distinction matters for “resource-less” search tools. An unrestricted search can become a cross-tenant enumeration API. `claim.search` searches only the caller's authorized task resources and caps the result size.

## 8. State handles are capabilities with context

Pagination, resumable tasks, and other opaque handles are security-sensitive. A random-looking string is insufficient. Persist a server-side record binding the handle to:

```text
subject + tenant + task + canonical query digest + expiry
```

The lab rejects a handle copied to another subject/task, reused with a changed filter, missing from the store, or expired. Use cryptographically random values in production; the deterministic lab value exists only to make results reproducible.

## 9. Exact approval, not `approved: true`

A boolean approval can be replayed for a different amount, target, payee, or action. The lab hashes a canonical proposal containing:

```text
tool + exact effect arguments + operation ID
subject + tenant + agent + client + workload + task
```

The approval record additionally binds policy and resource versions, expiration, and single-use state. Changing CAD 125.00 to CAD 125.01 changes the proposal digest and invalidates the approval. A consumed approval cannot authorize a different operation.

Approval does not override current policy. A newly high-risk state or revoked task still denies the action. Intermediate 07 deepens the risk and assurance model; this course establishes the exact transaction boundary that step-up must authorize.

## 10. Re-authorize at the side-effect boundary

The unsafe sequence is:

```text
authorize -> wait -> execute using the old decision
```

The lab executes:

```text
authenticate
  -> strict parse
  -> preflight authorize
  -> optional planning/work
  -> commit-time authorize against current state
  -> validate tool output
  -> persist operation receipt
  -> consume approval
  -> return result
```

If the task is revoked between preflight and commit, no effect occurs. Production implementations should make approval consumption, idempotency reservation, business effect, and execution receipt atomic when the storage system permits it, or use a durable saga/outbox with explicit reconciliation.

### Unknown outcomes and idempotency

A timeout does not prove failure. The downstream system may have committed before the response was lost. The safe rule is:

1. bind a stable operation ID to the canonical request digest;
2. persist the outcome/effect receipt;
3. on an exact retry, reconcile and return the prior result;
4. reject the same operation ID with changed content; and
5. never mint a second effect merely because the transport retried.

The lab injects a lost response after commit and proves the exact retry leaves the effect count at one.

## 11. Downstream authorization without token passthrough

The MCP token is for the MCP resource. Passing it to a business API:

- violates audience separation;
- hides the tool server as the actor;
- increases bearer-token exposure; and
- makes independent downstream policy difficult.

Use token exchange, workload federation, or another brokered credential flow. The lab's exchange adapter allows only configured audiences, intersects scopes with both caller authority and target policy, preserves `sub` and an `act` identity, carries the task, and issues a 60-second result. It never forwards the source token.

For a server that needs user authorization to an unrelated third party, URL-mode elicitation can let the server own that authorization relationship without asking the MCP client to reveal credentials. Bind the callback to the authenticated user and server-side transaction state.

## 12. Tool outputs are untrusted input

MCP tools can declare JSON Schema 2020-12 `outputSchema` and return `structuredContent`. A server or gateway should validate the structured result before exposing it to an agent/model. The lab rejects an injected, schema-invalid response with a 502-style tool failure.

Output controls should also include:

- size, item-count, and recursion limits;
- explicit content types;
- secret and sensitive-data detection;
- safe rendering/escaping;
- provenance for externally sourced content; and
- separation between tool data and instructions to a model.

Tool annotations such as read-only or destructive hints are metadata, not enforcement guarantees, unless the server that asserted them is independently trusted. The policy engine remains authoritative.

## 13. Current MCP security threats

### Confused deputy and consent

A public MCP-facing proxy can become a deputy for a third-party authorization server. Bind authorization transactions to the correct client, user, redirect URI, PKCE verifier, state, issuer, and resource. Obtain meaningful per-client consent where the upstream relationship requires it.

### OAuth metadata SSRF and DNS rebinding

Discovery URLs and redirect chains can reach internal hosts. Apply URL allow/deny policy, resolve and validate every hop, constrain schemes and ports, block private/link-local/loopback destinations where inappropriate, and protect against DNS rebinding. Do not follow arbitrary redirects with credentials.

### State-handle hijacking

OAuth `state` and MCP resumable handles must be bound server-side to the authenticated user/session and transaction. A client-supplied handle alone is not proof of ownership.

### Authorization-server mix-up

Store the chosen authorization-server issuer with the transaction and validate the returned `iss` per RFC 9207 before token redemption. Isolate client credentials by exact issuer.

### Redirect impersonation

Loopback/localhost callbacks can be intercepted by another local process. Follow native-app redirect guidance, use PKCE, prefer claimed HTTPS or platform-specific redirects where supported, and validate exact redirect URIs.

### Scope minimization abuse

An attacker can attempt to turn repeated 403 challenges into automatic privilege growth. Accumulate only server-requested, policy-approved scopes, cap retries, show consequential changes to the user, and never interpret an ordinary policy denial as a scope request.

### Local server compromise

Treat third-party stdio servers like installed code. Pin provenance, inspect manifests, isolate files/network/secrets, show executable and argument changes, and require re-consent after material upgrades.

### Supply-chain and tool-definition drift

Inventory server version, package digest, tool schemas, annotations, and policy compatibility. Reject an unexpected schema or toolset version before use. Sign and scan release artifacts and stage updates through canaries.

## 14. Client registration and enterprise control

Current MCP clients should support Client ID Metadata Documents (CIMD). Dynamic Client Registration remains a compatibility option, not the default trust answer for every server. A server or authorization service needs a trust policy for which client metadata URLs and redirect URIs it accepts; successful metadata retrieval is not proof that a client is safe.

Enterprise-Managed Authorization (EMA) allows centrally managed authorization for enterprise MCP clients and servers. It helps administrators provision and govern access, but it does not replace per-tool, per-resource, transaction, or commit-time authorization.

The Python SDK also documents identity-assertion support as an extension for enterprise non-human flows. Treat it as an explicit, issuer-trusted grant with narrow audience and policy—not a reason to merge workload and user identity.

## 15. Common libraries and where they fit

| Component | Lab choice | Production alternatives | Responsibility |
|---|---|---|---|
| MCP server/client | official Python `mcp` SDK 2.2 | official TypeScript, Java, C#, Go, Kotlin, Rust SDKs | protocol, transports, schemas, auth integration |
| token validation | PyJWT + `cryptography` Ed25519 | Authlib, JOSE libraries, managed API gateway | cryptographic/profile validation |
| strict inputs | Pydantic 2 | JSON Schema validators, Zod/Ajv | shape and type enforcement |
| output validation | `jsonschema` | Ajv, framework-native validation | structured result contract |
| attribute policy | OPA/Rego | Cedar, Casbin, cloud policy services | contextual allow/deny and obligations |
| relationship policy | task/resource store in lab | OpenFGA, SpiceDB, Zanzibar-like service | subject-agent-task-resource relationships |
| HTTP testing | HTTPX/ASGI test clients | SDK-specific harnesses, contract tests | challenges, metadata, transport behavior |
| identity/workload | deterministic fixture | OIDC AS, SPIFFE/SPIRE, cloud workload identity | trustworthy principal evidence |
| durable effects | in-memory ledger in lab | transactional database, outbox, workflow engine | idempotency, receipts, reconciliation |

Choose libraries that validate the protocol/profile you actually use. A generic JWT decoder is not an OAuth access-token policy, and an MCP schema is not resource authorization.

## 16. Practical lab

The scenario is a claims-adjuster agent. It may search one task's claims, read and update an assigned claim, and create an exactly approved payment. The system includes a malicious cross-tenant claim and attack fixtures.

### Part A — Baseline

Run the deliberately weak decode-only evaluator:

```python
baseline_metrics, rows = evaluate(build_cases(), hardened=False)
```

It accepts most invalid cases because it treats parseable claims and a tool name as authority. Record which identity and transaction dimensions it ignores.

### Part B — SDK resource server

Inspect `build_sdk_server()`, `NorthstarTokenVerifier`, and `protected_resource_metadata()`. Confirm:

- the official SDK owns the HTTP resource-server integration;
- resource validation is explicitly enabled;
- per-tool scope remains a business invocation decision; and
- no network or external credential is needed for the training fixture.

### Part C — Discovery, invocation, and strict arguments

Discover with a read-only token, revoke the task's tool grant, then attempt the cached call. Try an extra argument, integer resource ID, cross-tenant target, unbounded search, and stolen state handle.

### Part D — Consequential action

Create a payment approval, mutate one cent, restore the action, then attempt replay. Inspect the proposal digest and versions. Inject revocation between preflight and commit.

### Part E — Failure injection

Inject:

- wrong signature, issuer, audience, profile, expiry, and lifetime;
- subject, tenant, agent, client, workload, and task substitution;
- missing scope and stale resource version;
- routing header/body mismatch;
- malicious output;
- arbitrary downstream audience and scope widening; and
- a lost response after the business effect commits.

### Part F — Evaluation

```python
metrics, rows = evaluate(build_cases())
assert release_gate(metrics)
```

The gate requires:

```text
invalid acceptances = 0
valid work blocked = 0
every labeled outcome matches
duplicate effect count = 0
```

The matrix has 44 cases: five valid workflows and 39 abuse/failure conditions. Add a case before changing a control so regressions are visible.

### Part G — Policy engines

The course includes equivalent examples:

- [`policies/opa/mcp.rego`](policies/opa/mcp.rego) with Rego tests; and
- [`policies/cedar/mcp.cedar`](policies/cedar/mcp.cedar) with a validated Cedar schema.

Run OPA when installed:

```bash
opa test curriculum/intermediate/06-mcp-tool-authorization/policies/opa -v
```

The Python test suite parses and validates the Cedar policy with `cedarpy`. Notice that neither policy accepts a bare `approval.valid` boolean; the exact digest, identities, versions, expiry, and consumption state are compared.

## 17. Production hardening checklist

### Protocol and OAuth

- [ ] Pin a supported MCP protocol and official SDK version.
- [ ] Publish canonical RFC 9728 protected-resource metadata.
- [ ] Include `resource` in authorization and token requests.
- [ ] Validate exact issuer and audience/resource on every request.
- [ ] Validate RFC 9207 issuer on authorization responses.
- [ ] Keep authorization-server client credentials isolated by issuer.
- [ ] Return HTTP 401/403 challenges with bounded scope retry.
- [ ] Never accept tokens from query parameters or pass MCP tokens downstream.

### MCP and tools

- [ ] Authorize discovery and invocation independently.
- [ ] Reject `Mcp-Method`/`Mcp-Name` mismatches with the request body.
- [ ] Namespace tools by a stable server identity in aggregators.
- [ ] Reject unknown input fields and validate every output.
- [ ] Treat annotations as hints unless their source is trusted.
- [ ] Bind state handles to subject, tenant, task, query, and expiry.

### Business authorization

- [ ] Derive identity context from verified and authoritative sources.
- [ ] Enforce tenant, subject, task, resource, purpose, and version.
- [ ] Bind approval to an exact canonical proposal and consume it once.
- [ ] Re-authorize immediately before every consequential effect.
- [ ] Fail closed when policy/current-state dependencies are unavailable.
- [ ] Keep OAuth step-up distinct from business risk/assurance step-up.

### Effects and operations

- [ ] Bind operation IDs to request digests.
- [ ] Reconcile unknown outcomes before retrying.
- [ ] Make effect and receipt atomic or use a durable saga/outbox.
- [ ] Persist privacy-aware decision evidence with policy/tool/resource versions.
- [ ] Alert on repeated token, handle, approval, routing, and output failures.

### Client and local-server security

- [ ] Defend discovery/redirect fetches from SSRF, rebinding, and unsafe redirects.
- [ ] Bind OAuth state to the authenticated session and chosen issuer.
- [ ] Validate CIMD origins/redirects under an explicit trust policy.
- [ ] Sandbox local MCP servers and minimize their environment and egress.
- [ ] Re-consent when local executable, arguments, schemas, or provenance change.

## 18. Knowledge check

1. Why can a tool omitted from `tools/list` still require an invocation-time denial?
2. Which failures should trigger an OAuth scope challenge, and which should not?
3. Why is `approval.valid = true` weaker than an approval bound to a proposal digest?
4. What must an exact retry prove before the server returns an earlier result?
5. Why must a downstream API receive a different, narrower token?
6. What does strict JSON Schema validation still fail to prove?
7. How do the HTTP and stdio authorization boundaries differ?
8. Which versions belong in decision evidence, and why?

## 19. References and currency

Primary sources, checked for this course revision:

- [MCP Authorization specification, 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)
- [MCP Security Best Practices, 2026-07-28](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)
- [MCP Tools specification, 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/server/tools)
- [MCP 2026-07-28 release overview](https://blog.modelcontextprotocol.io/posts/2026-07-28/)
- [Official MCP Python SDK authorization guide](https://github.com/modelcontextprotocol/python-sdk/blob/main/docs/run/authorization.md)
- [Official MCP Python SDK OAuth client guide](https://github.com/modelcontextprotocol/python-sdk/blob/main/docs/client/oauth-clients.md)
- [Official MCP Python SDK 2.2.0 release](https://github.com/modelcontextprotocol/python-sdk/releases/tag/v2.2.0)
- [Enterprise-Managed Authorization](https://blog.modelcontextprotocol.io/posts/enterprise-managed-auth/)
- [RFC 9728 — OAuth 2.0 Protected Resource Metadata](https://www.rfc-editor.org/rfc/rfc9728)
- [RFC 8707 — Resource Indicators for OAuth 2.0](https://www.rfc-editor.org/rfc/rfc8707)
- [RFC 6750 — OAuth 2.0 Bearer Token Usage](https://www.rfc-editor.org/rfc/rfc6750)
- [RFC 9207 — OAuth 2.0 Authorization Server Issuer Identification](https://www.rfc-editor.org/rfc/rfc9207)
- [RFC 8693 — OAuth 2.0 Token Exchange](https://www.rfc-editor.org/rfc/rfc8693)
- [RFC 9449 — OAuth 2.0 Demonstrating Proof of Possession](https://www.rfc-editor.org/rfc/rfc9449)
- [Open Policy Agent documentation](https://www.openpolicyagent.org/docs/latest/)
- [Cedar Policy Language documentation](https://docs.cedarpolicy.com/)
- [OpenFGA documentation](https://openfga.dev/docs)

Re-check the MCP version, SDK release notes, OAuth drafts, and extension status before production adoption. Pin both protocol and SDK compatibility in tests.

## 20. Handoff to Intermediate 07

This module establishes **what exact transaction is being authorized** and how the PEP enforces it. Intermediate 07 adds the richer question: **what human, workload, and contextual assurance is proportional to this action's current risk, and what step-up can satisfy it?** Keep the boundaries separate: stronger authentication cannot fix a forbidden resource, and a broader OAuth scope cannot satisfy a missing transaction approval.
