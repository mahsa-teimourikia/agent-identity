# Intermediate 05 — Dynamic Authorization & Continuous Access Evaluation

> **Goal:** build and test a continuous-authorization control loop for a long-running agent: validate standards-conformant security event tokens, durably project subject-scoped state, bound stale authority with decision leases, re-authorize at every side effect, and prove behavior under duplicates, gaps, reordering, outages, and revocation races.

This course uses a realistic insurance workflow. Alice delegates a claims-adjuster agent to review one claim. The agent may wait for documents or approval and resume later. During that time, Alice's session, the task, the delegation, the approval, the workload, the claim, or the policy can change. A token that remains cryptographically valid is not evidence that the action is still authorized.

The practical lab is [`dynamic_authorization.ipynb`](dynamic_authorization.ipynb). Its reusable implementation is [`lab.py`](lab.py), with executable invariants in [`tests/test_dynamic_authorization.py`](tests/test_dynamic_authorization.py).

## Learning outcomes

By the end, you can:

- distinguish credential validity, relationship authority, and current contextual authorization;
- explain SSF, CAEP, Security Event Tokens (SETs), and push/poll delivery roles;
- validate a signed SET's algorithm, key, issuer, audience, media type, required claims, subject identifier, event type, and freshness;
- persist an authenticated event before acknowledging it and process it asynchronously and idempotently;
- scope events to the correct subject and order independent signal domains without dropping late revocations;
- define safe cache keys and short decision leases that bind exact proposals and trusted state versions;
- re-authorize at tool execution, commit, retry, and resume boundaries;
- combine OpenFGA relationship checks with OPA contextual policy;
- choose explicit fail-closed and degraded-mode behavior for stream or policy outages;
- measure receive-to-enforcement latency with lifecycle timestamps; and
- operate release gates for invalid acceptance, valid-work blockage, and propagation SLOs.

## Prerequisites and time

You should already understand JWT validation, OAuth audiences and scopes, delegated tasks, policy enforcement points, and fine-grained authorization. Complete Intermediate 03 and 04 first.

Allow 3–4 hours:

| Part | Time | Deliverable |
|---|---:|---|
| Concepts and threat model | 45 min | trust-boundary sketch |
| SET receiver and projection | 60 min | durable, idempotent event path |
| PEP, leases, cache, policy engines | 60 min | current-state enforcement |
| Failure injection and release gate | 45 min | evidence and metrics |

## 1. The core problem: authority changes during execution

A conventional request often completes quickly:

```text
authenticate -> authorize -> execute -> respond
```

An agent may instead:

```text
authenticate -> plan -> retrieve -> wait -> request approval
             -> resume -> call another agent -> invoke tool -> commit
```

Between those steps:

- the human account can be disabled;
- token claims or assurance can change;
- a device can become noncompliant;
- the agent workload can be quarantined;
- a task, delegation, or approval can be revoked;
- a relationship can be removed;
- a claim can change tenant, owner, status, or classification;
- policy can be replaced; or
- a risk engine can raise the subject or operation risk.

The correct model is not “allowed once, therefore allowed forever.” It is:

```text
effective_authority(t) =
  authenticated_identity(t)
  ∩ current_claims(t)
  ∩ active_delegation(t)
  ∩ active_task(t)
  ∩ relationship_authority(t)
  ∩ resource_state(t)
  ∩ current_policy(t)
  ∩ risk_and_posture(t)
  ∩ exact_approval(t)
```

Token expiry is only one bound. A ten-minute token still creates up to ten minutes of stale authority if revocation is checked only at expiry.

## 2. Architecture and trust boundaries

```text
identity/risk/task/policy sources
              |
              v
       SSF transmitter
              |
      signed SET over TLS
              |
              v
  receiver: authenticate + profile validate
              |
       durable inbox  ----> 202 Accepted
              |
       async projector
              |
              v
  subject-scoped authorization projection
              |
              +------> OPA contextual decision
              +------> OpenFGA relationship check
              |
              v
   PEP at tool/resource boundary
       re-check before effect
```

The model proposes an action. It does not supply identity, tenant, current policy version, relationships, risk, or approval validity. Trusted application components derive those facts.

Trust boundaries:

1. **Transmitter configuration:** issuer, keys, audience, stream, and allowed event types are administrative trust, not token-controlled discovery.
2. **Receiver:** rejects unauthenticated or profile-invalid SETs before storage or state mutation.
3. **Inbox:** provides durable deduplication and separates protocol acknowledgement from business processing.
4. **Projector:** resolves `sub_id`, applies domain-specific ordering, and records gaps.
5. **PDPs:** decide from verified current facts but do not perform effects.
6. **PEP:** fulfills obligations, consumes approval, controls idempotency, and commits the side effect.

## 3. Standards landscape

### Security Event Token

[RFC 8417](https://www.rfc-editor.org/rfc/rfc8417) defines a SET as a JWT carrying security event information. A valid JWT signature is necessary but insufficient: the receiver must also apply the expected SET profile and trust configuration.

### Shared Signals Framework 1.0

[OpenID Shared Signals Framework 1.0 Final](https://openid.net/specs/openid-sharedsignals-framework-1_0-final.html) defines transmitter/receiver configuration, streams, subject identifiers, verification, and delivery. Important profile points used in this lab include:

- explicit JOSE `typ` of `secevent+jwt`;
- top-level `sub_id` rather than top-level `sub`;
- no `exp` claim in an SSF SET;
- normally one event member in `events`;
- a unique `jti` for SET deduplication; and
- `txn` for correlation with the underlying event.

Subject identifiers follow [RFC 9493](https://www.rfc-editor.org/rfc/rfc9493). The lab uses the `iss_sub` format and checks its issuer before selecting projection state.

### Continuous Access Evaluation Profile 1.0

[OpenID CAEP 1.0 Final](https://openid.net/specs/openid-caep-1_0-final.html) defines interoperable security events that let receivers attenuate access for human or robotic users, devices, sessions, and applications. It became an OpenID Final Specification in August 2025.

The lab exercises these CAEP event types:

- `session-revoked`;
- `token-claims-change`;
- `risk-level-change`; and
- `device-compliance-change`.

It also uses clearly namespaced internal events for task, policy, resource, approval, delegation, and workload changes. These are application events, not invented CAEP standards.

The [CAEP interoperability profile](https://openid.net/specs/openid-caep-interoperability-profile-1_0.html) is a separate draft profile. Do not describe draft interoperability requirements as part of CAEP 1.0 Final.

### Push and poll delivery

[RFC 8935](https://www.rfc-editor.org/rfc/rfc8935) defines push-based SET delivery. A receiver validates the SET, persists it, and can return HTTP 202 before asynchronous processing. Retransmission is expected, so duplicate delivery must have a consistent result.

[RFC 8936](https://www.rfc-editor.org/rfc/rfc8936) defines poll-based delivery. Polling can suit receivers that cannot expose an inbound endpoint, but the same authentication, idempotency, ordering, and freshness requirements remain.

### Vendor CAE is not the protocol itself

Microsoft Entra Continuous Access Evaluation combines critical-event evaluation with Conditional Access location-policy evaluation and may return a claims challenge. That is a valuable production example, but its claims challenge and operational behavior are vendor-specific. Use the vendor documentation rather than assuming every CAEP receiver behaves the same way.

## 4. Receiver validation pipeline

The lab's `SecurityEventInbox.receive()` performs this order:

1. require an enabled, preconfigured stream;
2. parse the protected header without trusting it;
3. require `typ=secevent+jwt` and an allowed algorithm;
4. select a key only from the configured issuer-bound key set;
5. verify signature, issuer, and audience;
6. require `iss`, `aud`, `iat`, `jti`, `sub_id`, and `events`;
7. reject forbidden `sub` and `exp` profile claims;
8. enforce a deterministic event-time acceptance window;
9. require exactly one recognized event type;
10. validate the `iss_sub` subject identifier and event sequence;
11. insert the event into a durable SQLite inbox under unique `jti`; then
12. return HTTP 202 semantics.

Do not fetch a verification key from an arbitrary `jku` or `x5u` header. Do not decode without verifying. Do not mutate authorization state and then attempt persistence. Do not return a permanent failure for a valid retransmission whose `jti` was already stored.

The sample uses Ed25519/EdDSA through `cryptography` and PyJWT. Production deployments usually use an issuer metadata and JWKS lifecycle with controlled refresh, key overlap, and alerts for unknown key IDs.

## 5. Durable projection and event semantics

Delivery is at least once, not exactly once. The inbox makes `jti` the deduplication key. Processing has a separate status, so a process restart can resume an acknowledged but unprojected event.

### Subject scoping

An event for `user:mallory` must never revoke `user:alice`. The projector resolves the verified `sub_id` and selects that subject's state. A global “current session” variable is not safe in a multi-tenant service.

### Ordering is per domain

A single timestamp or cursor across every event type is incorrect. A newer low-risk observation must not suppress an older but previously unseen session revocation. The lab therefore keeps independent cursors for session, claims, risk, device, task, policy, resource, approval, delegation, and workload domains.

### Restriction before relaxation

The sample follows a conservative rule:

- a late restrictive signal can still attenuate authority;
- a stale relaxation is ignored; and
- a sequence gap marks the stream not fresh.

This is a teaching policy, not a universal protocol rule. In production, define the authoritative version or ordering field for each source, how snapshots repair gaps, and who may issue a relaxation. Timestamp order alone is vulnerable to clock skew and delayed delivery.

The lab's `sequence` member is a Northstar source extension used to teach ordering and gap repair; CAEP does not define that member as a universal event-ordering mechanism.

### Gaps and reconciliation

If sequence 3 arrives after sequence 0, the projector applies a restrictive change but marks the stream stale. Sensitive writes fail closed until a snapshot or replay repairs the gap. The course permits a specifically defined claim read during degraded mode. This exception is policy, not a default recommendation.

## 6. Decision leases, caches, and stale authority

A cache entry is a short lease over an exact decision, not a cached role name. Its key binds:

- subject, agent, workload, and tenant;
- action, resource, purpose, amount, and operation ID;
- the projection fingerprint;
- policy, resource, relationship, approval, and delegation versions; and
- a `valid_until` bounded by credential, task, and policy limits.

The notebook demonstrates the classic bug:

```python
def vulnerable_cache_key(proposal):
    return f"{proposal.action}:{proposal.resource_id}"
```

That key treats a payment of CAD 300 and CAD 900 as the same request. The corrected key hashes the complete canonical proposal and current trusted state.

Cache invalidation should be driven by versioned state. Deleting process-local keys in response to an event is useful but insufficient: another instance may retain an entry, and a restart may recover it. A version mismatch makes the stale item unusable everywhere.

## 7. Re-authorization boundaries

Re-evaluate when:

- a tool call is about to cross the trust boundary;
- an action changes from read to write;
- the target resource or parameters change;
- a workflow resumes after a wait;
- a retry follows an unknown outcome;
- an approval arrives or is replaced;
- a policy, relationship, task, or delegation version changes; or
- a side effect is about to commit.

The lab's PEP deliberately does not execute from the first decision. It obtains an initial decision, permits a simulated mid-flight event, reads current state, and makes a final decision immediately before the effect. This closes the demonstrated time-of-check/time-of-use revocation race.

No distributed system can make the stale window literally zero. Define and measure the bound:

```text
event created -> received -> validated -> persisted -> projected -> enforced
```

For high-impact operations, also use downstream controls such as idempotency keys, transaction limits, reversible staging, and reconciliation.

## 8. Exact approvals and operation idempotency

A payment approval binds the canonical proposal digest, subject, agent, task, policy version, approval version, and expiry. Changing the amount or operation ID changes the digest and invalidates the receipt.

The PEP consumes an approval only after the final authorization decision. It binds an operation ID to the proposal digest:

- exact retry returns the prior result;
- changed retry with the same operation ID is a conflict; and
- a lost response is reconciled before another effect is attempted.

Continuous authorization does not replace transactional safety. It decides whether an effect may occur now; idempotency and reconciliation decide whether it has already occurred.

## 9. OPA and OpenFGA integration

The lab demonstrates a two-plane decision:

1. OpenFGA answers whether the agent is both assigned and delegated to a task connected to the claim.
2. OPA evaluates current identity, tenant, token lifetime, task lifetime, risk, posture, policy, stream freshness, amount, and approval.

The PEP requires both. Relationship authority cannot override a revoked session or cross-tenant resource. Contextual policy cannot invent the task-to-claim relationship.

Artifacts:

- [`policies/openfga/model.fga`](policies/openfga/model.fga) — intersection-based task relationship model;
- [`policies/opa/dynamic.rego`](policies/opa/dynamic.rego) — conflict-free Rego v1 contextual policy; and
- [`policies/opa/dynamic_test.rego`](policies/opa/dynamic_test.rego) — executable policy tests.

The Python adapters construct real SDK request types but make no external network call. Production code should configure timeouts, circuit breakers, TLS, authenticated service identity, bounded retries, and decision telemetry.

## 10. Failure policy

Write the policy before the outage:

| Failure | Claim read | Claim update | Payment |
|---|---|---|---|
| PDP unavailable | deny | deny | deny |
| relationship check unavailable | deny | deny | deny |
| signal stream stale/gapped | explicitly permitted degraded read | deny | deny |
| approval store unavailable | not needed | not needed | deny |
| audit sink delayed | buffer within bounded durable queue | buffer or deny by policy | normally deny if evidence cannot be guaranteed |

“Fail open for availability” is not a sufficient design. If a degraded path exists, name the action, data class, maximum duration, compensating monitoring, and recovery behavior.

## 11. Observability and privacy

Record enough to explain the decision without logging bearer credentials or raw approval contents:

- hashed proposal and projection fingerprints;
- subject, actor, workload, tenant, task, action, and resource identifiers;
- SET `jti`, `txn`, type, domain, and sequence;
- policy, relationship, resource, delegation, and approval versions;
- decision ID, reason codes, and outcome;
- lifecycle timestamps; and
- trace/operation identifiers.

Protect these records: identifiers and risk states may be sensitive. Apply access control, retention, regional handling, and integrity controls. Never record private signing keys, bearer tokens, full document contents, or unrestricted model prompts.

## 12. Practical lab

### Setup

From this course directory:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
pytest -q
jupyter lab dynamic_authorization.ipynb
```

No cloud account, API key, or network service is required.

### Notebook sequence

The notebook asks you to:

1. label a 32-case authorization matrix;
2. measure the invalid acceptances from one-time scope authorization;
3. issue and inspect an Ed25519-signed SET;
4. validate, persist, acknowledge, and asynchronously project it;
5. prove subject isolation and duplicate idempotency;
6. inject cross-domain reordering, stale relaxation, and a gap;
7. exploit an incomplete payment cache key and compare the corrected key;
8. revoke a session between initial authorization and commit;
9. resume a task after its authority changed;
10. construct OPA and OpenFGA inputs using current trusted state;
11. inspect lifecycle metrics with deterministic logical milliseconds; and
12. apply the release gate.

### Required checkpoint

Before continuing, predict all three outcomes and explain why:

1. Risk sequence 9 reports `low`; session sequence 1 later reports revoked.
2. A CAD 300 payment is cached; the proposal changes to CAD 900.
3. The PEP allows an update; the task is revoked before commit.

Correct answers: session revocation applies because ordering is per domain; the changed amount misses the safe cache and invalidates exact approval; and the commit is denied after current-state reauthorization.

### Validation commands

```bash
pytest -q tests/test_dynamic_authorization.py
opa test policies/opa
fga model validate --file policies/openfga/model.fga
```

The tests include receiver profile failures, wrong signatures, duplicates, restart recovery, subject isolation, independent domain ordering, stale relaxations, gaps, cache-key completeness, mid-flight revocation, resume, exact approval, idempotency, dependency failure, policy adapters, privacy-safe evidence, and the labeled release matrix.

## 13. Evaluation and release gate

The hardened matrix must satisfy:

```text
invalid_acceptances == 0
valid_work_blocked == 0
observed_outcomes == expected_outcomes
receive_to_enforce_ms <= stated SLO
```

The notebook's time values are deterministic **logical milliseconds** assigned at each lifecycle stage. They test metric math and gate behavior; they are not fabricated wall-clock benchmark results. Measure real deployments with a monotonic clock and report percentiles by event type, region, and enforcement path.

Recommended production indicators:

- SET verification failure rate by issuer and reason;
- duplicate, delayed, and gap rates by stream;
- persisted-but-unprojected backlog age;
- receive-to-project and receive-to-enforce p50/p95/p99;
- stale-stream duration;
- decisions by reason, action, and policy version;
- mid-flight revocation blocks;
- decision-cache hit rate and version-mismatch rate; and
- approval replay and operation-conflict counts.

## 14. Production hardening checklist

- [ ] Receiver endpoints require TLS and authenticated stream configuration.
- [ ] Algorithms, issuer, audience, key IDs, event types, and subject formats are allowlisted.
- [ ] Key refresh is issuer-bound and tested through overlap and unknown-key failures.
- [ ] Valid SETs are durably stored before HTTP 202.
- [ ] `jti` deduplication survives restart and concurrent delivery.
- [ ] Event data has a schema and size limit for every allowed type.
- [ ] Subject resolution is tenant-aware and collision-resistant.
- [ ] Every signal domain has documented ordering and repair semantics.
- [ ] Restrictive state cannot be undone by an unauthoritative stale relaxation.
- [ ] Snapshot/replay repairs gaps and records provenance.
- [ ] Decision leases bind exact inputs, trusted versions, and a short lifetime.
- [ ] Writes and consequential actions fail closed on stale critical dependencies.
- [ ] PEPs re-check after waits and immediately before effects.
- [ ] Approval is exact, expiring, revocable, and single-use where required.
- [ ] Operation IDs bind canonical requests and support reconciliation.
- [ ] OPA/OpenFGA outages, timeouts, and partial failures are tested.
- [ ] Evidence excludes credentials and sensitive payloads.
- [ ] Propagation SLOs have alerts and error budgets.
- [ ] Incident drills cover stream compromise, key rotation, replay storms, and projector lag.

## 15. Exercises

### Beginner — add credential change

Add the CAEP `credential-change` event to the allowlist and projection. Define which credential statuses attenuate authority. Add receiver, projection, and policy tests.

### Intermediate — repair a sequence gap

Add a trusted snapshot API fixture. A gap must mark state stale; a signed snapshot with an authoritative version repairs it. Prove an older snapshot cannot relax newer restrictive state.

### Intermediate — safe multi-instance cache

Replace the local decision cache with a Redis-shaped adapter. Keep exact proposal and state-version binding. Test two PEP instances, eviction, stale entries, and cache unavailability.

### Advanced — transactional outbox

Add an outbox next to the business effect so decision evidence and the effect commit atomically. Simulate crashes before and after commit and prove reconciliation does not duplicate payment.

### Advanced — production transport

Put the receiver behind mTLS or sender-authenticated HTTPS, add rate and body-size limits, issuer-bound JWKS refresh, dead-letter handling, and replay/snapshot recovery. Threat-model SSRF, algorithm confusion, key compromise, and event floods.

## 16. Common anti-patterns

- **Decode-only JWT handling:** claims without verified signature and issuer are attacker input.
- **Global session state:** an event for one subject changes another subject's authority.
- **One `last_event_time`:** unrelated new events suppress older critical signals.
- **Mark-before-persist:** a crash loses an event that the transmitter believes was accepted.
- **First delivery wins:** retransmission becomes an error rather than an idempotent outcome.
- **Cache by action only:** changed resource, amount, purpose, tenant, or policy reuses authority.
- **Caller-supplied policy version:** untrusted input chooses which policy is “current.”
- **Approval boolean:** the system cannot prove what exact action was approved.
- **PDP allow equals execution:** obligations and commit-time state are bypassed.
- **`sleep()` as latency evidence:** artificial delay is not propagation measurement.
- **CAE means instant:** distributed enforcement always has a measurable bound.
- **Vendor behavior equals CAEP:** proprietary claims challenges are mislabeled as the standard.

## 17. Course handoff

This course establishes that authority must be fresh at the point of effect. Intermediate 06 applies that invariant to Model Context Protocol tool boundaries: tool discovery is not authorization, client annotations are not trusted policy, and every tool invocation still needs server-side identity, argument, resource, and current-state enforcement.

## References

Primary specifications and official documentation:

- [OpenID Shared Signals Framework 1.0 Final](https://openid.net/specs/openid-sharedsignals-framework-1_0-final.html)
- [OpenID Continuous Access Evaluation Profile 1.0 Final](https://openid.net/specs/openid-caep-1_0-final.html)
- [OpenID CAEP Interoperability Profile 1.0 — draft](https://openid.net/specs/openid-caep-interoperability-profile-1_0.html)
- [OpenID announcement: SSF, CAEP, and RISC Final Specifications](https://openid.net/three-shared-signals-final-specifications-approved/)
- [RFC 8417 — Security Event Token](https://www.rfc-editor.org/rfc/rfc8417)
- [RFC 8935 — Push-Based Security Event Token Delivery](https://www.rfc-editor.org/rfc/rfc8935)
- [RFC 8936 — Poll-Based Security Event Token Delivery](https://www.rfc-editor.org/rfc/rfc8936)
- [RFC 9493 — Subject Identifiers for Security Event Tokens](https://www.rfc-editor.org/rfc/rfc9493)
- [Microsoft Entra: How to use Continuous Access Evaluation-enabled APIs](https://learn.microsoft.com/en-us/security/zero-trust/develop/secure-with-cae)
- [Microsoft Entra: Continuous access evaluation](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-continuous-access-evaluation)
- [Open Policy Agent documentation](https://www.openpolicyagent.org/docs)
- [OpenFGA documentation](https://openfga.dev/docs)
- [PyJWT usage](https://pyjwt.readthedocs.io/en/stable/usage.html)
- [Cryptography Ed25519](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ed25519/)

Further architecture guidance:

- [NIST SP 800-207 — Zero Trust Architecture](https://csrc.nist.gov/pubs/sp/800/207/final)
- [NIST SP 800-162 — Guide to Attribute Based Access Control](https://csrc.nist.gov/pubs/sp/800/162/upd2/final)
- [OWASP Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)
