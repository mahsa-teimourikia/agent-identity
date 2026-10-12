# Continuous and Adaptive Trust for Autonomous Agents

**Level:** Advanced

**Estimated time:** 5–7 hours

**Format:** chapter, executed notebook, reusable Python lab, signed event fixtures, policy examples, and adversarial tests

**Last reviewed:** 2026-10-12

> **Goal:** keep an agent's authority synchronized with current identity, workload, behavior, threat, transaction, and governance state—including while a long-running operation is already in progress.

A claims-adjustment agent has a valid session and permission to update
`claim:483`. Minutes later, its session is revoked, the workload becomes
noncompliant, a threat detector raises risk, or the task assignment ends. A
point-in-time gateway continues to trust the old allow. The adaptive control
plane in this course consumes authenticated signals, projects current state,
and reauthorizes immediately before the business effect.

```text
identity / security / workload / governance transmitters
                         |
                signed Security Event Tokens
                         |
        authenticate -> validate -> persist -> HTTP 202
                         |
              ordered, tenant-scoped projection
                         |
     current state + multidimensional risk + stream health
                         |
  ALLOW / OBSERVE / REDUCE / STEP_UP / PAUSE / REVOKE / QUARANTINE
                         |
              commit-time reauthorization + evidence
```

The lab is deterministic, offline, and credential-free. It uses real Ed25519
JWS signatures and standards-shaped SET claims, but it is not a conformant SSF
server. For teaching clarity, it requires one event and an `event_timestamp`
per SET, uses fixed keys and time, and models delivery in-process. Production
deployments need protected key discovery, OAuth-protected stream management,
TLS, receiver authentication, durable infrastructure, and conformance testing.

## Learning outcomes

After this course, you can:

1. distinguish continuous authentication, continuous authorization, risk
   adaptation, and token revocation;
2. explain the roles of SSF, CAEP, RISC, SET, subject identifiers, and push or
   poll delivery;
3. validate a signed SET before acknowledging it and separate durable receipt
   from asynchronous projection;
4. correlate a signal to the exact tenant, agent, workload, and session without
   accepting ambiguous identifiers;
5. handle duplicates, late delivery, stale relaxation, backlog, stream outage,
   and recovery without reopening access unsafely;
6. combine identity, workload, behavior, threat, transaction, and governance
   state without treating a scalar score as authority;
7. implement proportional actions, negative-evidence precedence, hysteresis,
   cooldown, and explicit recovery evidence;
8. bind short decision leases to intent and current state, and reauthorize at
   side-effect boundaries;
9. produce privacy-aware decision evidence and evaluate a control against a
   labelled adversarial corpus; and
10. map the teaching runtime to common event, policy, cache, telemetry, and
    identity tooling.

## Prerequisites

- Advanced 04: attestations, credentials, status, and composite assurance;
- OAuth/OIDC token validation and sender/resource binding;
- policy enforcement points and fail-closed dependency behavior;
- Python dataclasses, JSON, SQLite, and basic JWS concepts.

## Success criteria

You are finished when you can run:

```bash
python3 -m pip install -r curriculum/advanced/05-continuous-adaptive-trust/requirements.txt
python3 curriculum/advanced/05-continuous-adaptive-trust/lab.py
pytest -q curriculum/advanced/05-continuous-adaptive-trust/tests/test_adaptive_runtime.py
```

The hardened evaluator must match all 40 labelled cases with zero invalid
allows and zero valid blocks. The intentionally unsafe point-in-time baseline
accepts 35 invalid cases, so the security improvement is measurable rather
than anecdotal.

## Non-goals

This course does not claim that:

- every system must use one universal risk score;
- CAEP defines business authorization policy;
- receipt of an event proves its contents are authoritative;
- revoking a token automatically reverses completed side effects;
- all positive changes are safe to apply out of order; or
- continuous evaluation means sending every raw telemetry record to a central
  engine.

## 1. Continuous trust is a state-synchronization problem

An authorization decision is true only for a bounded instant and input set.
For an agent, relevant inputs change independently:

| Plane | Examples | Trusted owner |
| --- | --- | --- |
| identity | session, credential, token claims, assurance level | identity provider |
| workload | SVID, attestation, device/runtime compliance, release | workload authority |
| behavior | tool sequence, rate, destination, model-independent anomaly | security analytics |
| threat | compromised key, malicious artifact, IOC match | threat/security service |
| transaction | amount, destination, purpose, object state | business system |
| governance | task, relationship, approval, policy version, quarantine | control plane |

The agent and model are not trusted sources for these fields. A trusted adapter
resolves them from authoritative systems. Signals update the verifier's view;
the local policy still decides what the update means for a specific action.

### Authentication, authorization, and adaptation

- Continuous authentication asks whether identity/session assurance changed.
- Continuous authorization asks whether the exact action is still permitted.
- Adaptive enforcement selects a proportionate control when state changes.
- Revocation ends a credential, session, delegation, or lease.
- Quarantine isolates a principal or workload pending governed recovery.

These controls compose, but they are not synonyms. A high-risk event might
require stronger evidence for a read, pause a write, revoke a session, or
quarantine a workload depending on the event authority and local policy.

## 2. Standards stack

### Security Event Tokens

[RFC 8417](https://www.rfc-editor.org/rfc/rfc8417) defines a Security Event
Token as a JWT whose `events` claim describes security events. A receiver still
has to validate the JWS algorithm and key, issuer, audience, profile, time,
identifier, event type, subject, and event-specific schema. Signature validity
proves who signed the bytes; it does not give that issuer unlimited authority.

A lab SET has this shape:

```json
{
  "iss": "https://id.northstar.example",
  "aud": "https://signals.northstar.example/ssf",
  "iat": 1800000000,
  "jti": "set:session-revoked",
  "txn": "txn:claims:483",
  "sub_id": {
    "format": "complex",
    "tenant": {"format": "opaque", "id": "tenant:northstar"},
    "agent": {"format": "opaque", "id": "agent:claims-adjuster"},
    "workload": {"format": "uri", "uri": "spiffe://northstar.example/claims/adjuster"},
    "session": {"format": "opaque", "id": "session:claims:483"}
  },
  "events": {
    "https://schemas.openid.net/secevent/caep/event-type/session-revoked": {
      "event_timestamp": 1800000000
    }
  }
}
```

The JOSE header is `{"alg":"EdDSA","kid":"id-2026","typ":"secevent+jwt"}`.
The receiver never trusts the decoded `iss` until it selects a configured
issuer policy and verifies the signature under that issuer's allowed key.

### Shared Signals Framework 1.0

The OpenID Shared Signals Framework and CAEP became OpenID Final
Specifications in August 2025. [SSF 1.0
Final](https://openid.net/specs/openid-sharedsignals-framework-1_0-final.html)
profiles SETs and defines transmitter metadata, event streams, stream
management, subject handling, and delivery integration. It profiles:

- [RFC 8935 push delivery](https://www.rfc-editor.org/rfc/rfc8935);
- [RFC 8936 poll delivery](https://www.rfc-editor.org/rfc/rfc8936); and
- [RFC 9493 subject identifiers](https://www.rfc-editor.org/rfc/rfc9493).

SSF is the transport and stream-governance layer. It does not define an
enterprise's final authorization decision.

### CAEP 1.0

[CAEP 1.0 Final](https://openid.net/specs/openid-caep-1_0-final.html) defines
events used by cooperating transmitters and receivers to attenuate access for
human or robotic users, devices, sessions, and applications. Its event set
includes:

- session revoked;
- token claims change;
- credential change;
- assurance level change;
- device compliance change;
- session established and session presented; and
- risk level change.

CAEP event payloads have specified semantics. Do not invent a similarly named
field and call it interoperable CAEP. Agent-specific behavior, workload,
transaction, task, and quarantine events in this lab use a private
collision-resistant namespace and an explicit bilateral contract.

### RISC and adjacent profiles

[OpenID RISC 1.0
Final](https://openid.net/specs/openid-risc-1_0-final.html)
defines account-security events on the same framework. As of October 2026,
[RFC 9967](https://www.rfc-editor.org/rfc/rfc9967) adds a SCIM profile for SETs.
These profiles are useful when workforce/account lifecycle or SCIM resource
changes must feed the same control plane, but profile semantics must remain
distinct.

## 3. Receiver pipeline: verify, persist, acknowledge, project

For push delivery, the receiver's safe path is:

1. enforce transport and receiver authentication outside the JWT;
2. parse only enough untrusted data to select configured verification policy;
3. require `typ=secevent+jwt` and an approved asymmetric algorithm/key;
4. verify signature, issuer, audience, required claims, time, and freshness;
5. validate the subject identifier and tenant mapping;
6. require an event type authorized for that transmitter;
7. validate the event payload;
8. persist under a unique `jti` in a durable transaction;
9. return HTTP 202 only after persistence; and
10. project the event asynchronously and record projection latency.

The acknowledgement means “durably accepted for processing,” not “the business
state is already updated.” If the queue is full, the lab returns backpressure
instead of dropping events or acknowledging work it cannot retain.

### Duplicate delivery

Delivery is at least once. `jti` is an idempotency key. The lab's SQLite unique
constraint and lock ensure that 24 concurrent copies create one pending record;
the others receive an idempotent 202 duplicate outcome.

### Push versus poll

| Property | Push (RFC 8935) | Poll (RFC 8936) |
| --- | --- | --- |
| delivery initiation | transmitter calls receiver | receiver calls transmitter |
| inbound exposure | receiver endpoint required | no transmitter-initiated callback |
| pressure control | receiver status/retry behavior | receiver poll rate and requested count |
| outage recovery | transmitter retries | receiver resumes polling |
| shared invariant | authenticate, validate, deduplicate, persist, project | authenticate, validate, deduplicate, persist, project |

Choose based on network boundaries and operations, not on a belief that one
delivery mode changes event trust semantics.

## 4. Subject correlation and authority

RFC 9493 standardizes formats such as `iss_sub`, `opaque`, `uri`, `did`, and
aliases. SSF also supports complex subjects. Format correctness says how an
identifier is encoded; the receiver still needs an independently governed
mapping to a local principal.

The lab intentionally requires all four components:

```text
tenant + agent + workload + session
```

Dropping tenant enables cross-tenant confusion. Dropping workload lets one
runtime borrow another agent instance's state. Dropping session can revoke too
broadly or too narrowly. Unknown components and extra fields fail closed rather
than being silently ignored.

Transmitter authority is scoped too:

| Source | Allowed authority |
| --- | --- |
| identity | CAEP session, credential, assurance, device, identity-risk events |
| security | behavior, threat, transaction-risk, quarantine restriction |
| workload | workload-posture events |
| governance | task, relationship, policy, and governed recovery |

A valid identity-provider signature on a task-change event is rejected because
the identity provider is not the task authority.

## 5. Ordering, freshness, and convergence

`iat` describes the SET issuance time. CAEP's optional `event_timestamp`
describes when the event occurred. Receipt time describes when the receiver
saw it. They are different clocks.

The lab keeps a high-water mark per subject and domain:

- newer state normally replaces older state;
- stale relaxations are ignored;
- a late restriction is still applied;
- duplicate `jti` values do not project twice; and
- events in unrelated domains do not overwrite one another.

This asymmetric merge rule prevents a delayed “low risk” event from erasing a
newer “high risk” state and prevents a new benign update from hiding a late
session revocation. Production systems need documented conflict rules for ties,
source precedence, clock skew, tombstones, full-state snapshots, and replay
after disaster recovery.

### Stream health is authorization input

Silence is ambiguous: nothing changed, or the signal path failed. Sensitive
writes pause when:

- the stream is unavailable;
- the last successful contact exceeds the freshness budget;
- restrictive events remain unprojected; or
- required risk dimensions are missing or stale.

Reads may use a separately approved degraded policy, but the exception must be
explicit, time bounded, observable, and tested.

## 6. Multidimensional risk without assurance laundering

The lab keeps five independent dimensions:

```text
identity | workload | behavior | threat | transaction
```

Its maximum-of-dimensions heuristic makes the exercise deterministic. It is not
a universal trust score and must not be treated as one. Production policy should
retain source, confidence, freshness, reason, and calibration metadata and use
hard predicates for non-negotiable controls.

Negative state has precedence:

```text
quarantine > revocation > workload/task/relationship invalidity
           > signal health > risk adaptation > allow
```

Setting every risk dimension to zero cannot override a revoked session or
quarantined workload.

## 7. Adaptive actions

| Mode | Meaning in this scenario | Allowed effect |
| --- | --- | --- |
| `ALLOW` | current low-risk state and healthy signals | exact read or write |
| `OBSERVE` | moderate risk on a read | read with enhanced evidence |
| `REDUCE` | moderate risk on a write | no write; offer read-only path |
| `STEP_UP` | high risk or changed token claims | require fresh independent evidence |
| `PAUSE` | stale/unavailable/backlogged signal state | no sensitive effect |
| `REVOKE` | session, credential, task, or relationship ended | end bounded authority |
| `QUARANTINE` | critical threat or untrusted workload | isolate agent/workload |
| `DENY` | request binding or policy mismatch | no effect |

An adaptive action is enforceable only when a PEP can implement it. A policy
must not return `read_only` or `isolate_agent` as decorative text that the caller
can ignore.

## 8. Hysteresis, cooldown, and recovery

Escalation is immediate. Recovery is deliberately slower:

```text
authorized recovery = governance source
                    + incident cleared
                    + fresh workload attestation
                    + human approval
                    + cooldown elapsed
```

This prevents threshold flapping and forged “all clear” events. Recovery is a
new decision based on current evidence, not deletion of the incident record.
The state machine retains the more restrictive mode until all conditions hold.

## 9. Long-running agents and time-of-check/time-of-use

Agent work often crosses minutes, approvals, queues, or human review:

```text
plan -> fetch -> reason -> wait -> propose -> authorize -> side effect
```

An allow at plan time cannot authorize the final effect. Reevaluate at:

- tool invocation;
- retrieval of a new sensitive object;
- resumption after a wait or handoff;
- approval consumption;
- token or capability exchange; and
- immediately before an irreversible business effect.

`CommitGate` performs the final check under an operation lock. It binds retries
to a digest of the exact request. An exact retry returns the recorded outcome;
a changed request under the same operation ID is a conflict.

## 10. Decision leases and cache safety

A cache entry is a short lease over a complete decision context, not a reusable
boolean. The lab binds a lease to:

- canonical request digest;
- projected state version;
- signal-stream epoch; and
- expiry.

Any trusted state change, outage transition, request change, or timeout misses
the cache. Production keys often also include policy/bundle version, resource
version, relationship tuple version, delegation family, approval receipt, and
workload attestation digest.

## 11. Policy engines and event infrastructure

The reference Python controller is the executable oracle. The repository also
includes equivalent policy-shape examples for:

- [Open Policy Agent](https://www.openpolicyagent.org/docs/latest/) using Rego;
- [Cedar](https://docs.cedarpolicy.com/) with explicit `forbid` precedence.

Relationship engines such as [OpenFGA](https://openfga.dev/docs) can resolve
task, ownership, and delegation relationships, but contextual current state
still belongs in an attribute-aware decision. Common production components
include:

| Concern | Common choices | Required invariant |
| --- | --- | --- |
| JWT/JWS validation | PyJWT, Authlib, jose libraries, platform SDKs | fixed algorithms, issuer/audience/key policy |
| durable event transport | Kafka, Pulsar, NATS JetStream, cloud queues | at-least-once, partitioning, replay, backpressure |
| projection/state | PostgreSQL, Redis, DynamoDB, stream processors | per-subject ordering and versioning |
| policy | OPA, Cedar, OpenFGA plus contextual PDP, cloud IAM engines | semantic parity with reference decisions |
| telemetry | OpenTelemetry, SIEM, metrics/log platforms | correlation without raw sensitive tokens |
| key distribution | JWKS with governed metadata and rotation | issuer-bound trust, cache limits, rollback plan |

Libraries implement mechanics. They do not choose trusted issuers, event
authority, subject mapping, recovery policy, or fail-open behavior for you.

## 12. Threat model

The lab and tests cover:

- forged signatures, unknown issuers, wrong audiences, keys, and token types;
- stale/future SETs and malformed subjects;
- cross-tenant subject substitution;
- multi-event ambiguity and transmitter overreach;
- duplicate delivery and concurrent replay;
- event flood and receiver backpressure;
- delayed relaxations and late restrictions;
- point-in-time authorization after session, credential, workload, task,
  relationship, claims, or policy changes;
- risk-source staleness and missing dimensions;
- stream outage and projection backlog;
- forged or incomplete quarantine recovery;
- cache reuse after a trusted state or stream epoch change;
- queued effects after mid-flight revocation; and
- changed-request idempotency conflicts.

Signals can create denial of service as well as unauthorized access. Source
authority, rate limits, circuit breakers, dead-letter handling, and operator
recovery therefore belong in the security design.

## 13. Privacy and evidence

SETs can contain sensitive security and identity information. Follow RFC 8417's
confidentiality guidance, minimize event payloads, constrain retention, encrypt
at rest and in transit, and authorize access to raw events separately from
decision evidence.

The lab evidence record keeps:

- operation ID;
- a hash of tenant/agent/workload binding;
- action and resource;
- allow/mode/reason;
- obligations;
- state and policy versions; and
- dimension values used by the decision.

It does not store compact SETs or the plain agent identifier. In production,
use a protected correlation service or keyed pseudonym when an unkeyed hash
would permit dictionary correlation.

## 14. Reliability and observability

Useful SLOs and alerts include:

- durable receipt latency and error rate;
- receipt-to-projection and projection-to-enforcement latency;
- oldest pending event age and backlog depth;
- duplicate, invalid-signature, unauthorized-type, and malformed-subject rates;
- transmitter/JWKS freshness and key-rotation health;
- policy decision latency by mode/reason;
- cache invalidation rate;
- time to revoke, quarantine, and safely recover;
- percentage of decisions made with stale or incomplete evidence; and
- false-positive/false-negative outcomes from labelled review.

Do not report “instant revocation” from an in-process demo. Measure each stage
with event time, receive time, persist time, project time, decide time, and
enforce time.

## 15. Safe rollout

1. inventory effects and classify their consequence;
2. establish authoritative subjects, sources, schemas, and trust metadata;
3. receive and persist in observe-only mode;
4. compare proposed adaptive outcomes with current enforcement;
5. label disagreements and tune per action/resource slice;
6. enforce negative lifecycle events first;
7. add step-up/reduce/pause modes with tested obligations;
8. rehearse outages, replay, key rotation, backlog, and recovery;
9. canary by tenant/workload; and
10. promote only when the zero-invalid-allow release gate passes.

Shadow mode must not leak proposed decisions back to the agent as a way to game
detectors. Detector internals stay outside model context; the agent receives
only the enforceable result and appropriate user-safe explanation.

## 16. Evaluation

The labelled corpus contains 40 cases:

- 3 expected allowed;
- 37 expected blocked;
- lifecycle, workload, governance, negative-state, risk, binding, authority,
  identity, resilience, ordering, recovery, freshness, and correlation slices.

The hardened path must achieve:

```text
invalid allows = 0
valid blocks   = 0
accuracy       = 1.0
```

The point-in-time baseline checks only action and resource. It accepts 35
invalid cases. This is not a production benchmark; it is a deterministic
regression gate that makes the missing controls visible.

## 17. Lab map

| Artifact | Purpose |
| --- | --- |
| `lab.py` | signed SETs, durable receiver, projection, controller, cache, commit gate, evaluation |
| `advanced_adaptive_runtime.py` | collision-safe import facade |
| `advanced_05_continuous_adaptive_trust.ipynb` | guided incident and experiments |
| `configs/shared-signals/receiver.json` | receiver and fail-safe operating contract |
| `data/adversarial_cases.json` | labelled 40-case corpus |
| `policies/opa/adaptive_authz.rego` | normalized Rego policy shape |
| `policies/cedar/adaptive_authz.cedar` | Cedar permit/forbid shape |
| `tests/test_adaptive_runtime.py` | protocol, concurrency, policy, recovery, cache, and TOCTOU tests |

Run the lab:

```bash
python3 curriculum/advanced/05-continuous-adaptive-trust/lab.py
```

Expected summary:

```text
hardened: 40/40 matches, 0 invalid allows, release gate true
point-in-time baseline: 35 invalid allows
```

## 18. Production upgrade path

Replace training shortcuts before production:

1. discover SSF metadata over authenticated, policy-controlled channels;
2. validate HTTPS issuer and endpoint rules and bind cached JWKS to issuer;
3. protect stream management and delivery endpoints with suitable OAuth/mTLS;
4. implement RFC 8935 or RFC 8936 fully, including normative error behavior;
5. use durable replicated storage, partitioning, retry, and dead-letter policy;
6. formalize schemas for every private event and version them compatibly;
7. add key rotation, compromise response, replay windows, and trust rollback;
8. validate OPA/Cedar/OpenFGA semantic parity against labelled decisions;
9. integrate PEP obligations with actual tool and business-system controls;
10. run OpenID SSF conformance tests and ecosystem interoperability tests.

## 19. State of the art in October 2026

### Established

- SSF 1.0, CAEP 1.0, and RISC 1.0 are OpenID Final Specifications published
  on 29 August 2025 and approved as final in September 2025;
- SET, push delivery, poll delivery, and subject identifiers are standardized
  in RFC 8417, RFC 8935, RFC 8936, and RFC 9493;
- OpenID provides SSF transmitter conformance testing for metadata, stream
  management, stream verification, and push/poll delivery;
- NIST Zero Trust places continual evaluation and least privilege in a wider
  enterprise architecture.

### Emerging

- the CAEP interoperability profile remains an Implementer's Draft/workgroup
  deliverable rather than a Final Specification;
- RFC 9967's SCIM SET profile, published in 2026, extends standardized event
  integration for identity lifecycle changes;
- agent-specific behavior, tool-risk, workload, task, and transaction events
  still require governed private schemas or future standard profiles;
- cross-vendor semantics, subject mapping, recovery, and measurable end-to-end
  enforcement latency remain harder than token transport alone.

### Open problems

- calibration drift and adversarial gaming of behavior models;
- safe recovery after compromised signal authorities;
- privacy-preserving cross-domain correlation;
- causal ordering across independent transmitters;
- partial failure and regional partition policy; and
- proving that every business side effect passed a fresh decision.

## 20. Exercises

### Beginner

1. Add a signed device-compliance event and explain its resulting mode.
2. Compare the decoded SET with the receiver's normalized state.
3. Change a SET audience and observe the exact rejection reason.

### Intermediate

1. Add a poll-delivery fixture while preserving durable deduplication.
2. Add a dead-letter state for payloads that verify but cannot project.
3. Implement a separately approved degraded-read policy for stream outage.

### Advanced

1. Replace SQLite with a partitioned event log and projection checkpoint.
2. Add key rotation with overlapping issuer-bound JWKS generations.
3. Model two transmitters updating one domain and specify deterministic source
   precedence and tie behavior.
4. Add a conformance-inspired push endpoint with normative error payloads.

### Enterprise

1. Define SLOs and a rollback plan for one real sensitive agent effect.
2. Build a shadow evaluation report sliced by tenant, action, and reason.
3. Rehearse transmitter compromise, stream outage, backlog, and false-positive
   quarantine recovery.
4. Prove policy parity across the reference controller and your deployed PDP.

## 21. Review questions

1. Why must a receiver persist a valid SET before returning HTTP 202?
2. Why is a signed event not automatically authoritative for every event type?
3. How do `iat`, `event_timestamp`, and receipt time differ?
4. Why should a late restriction be treated differently from a stale
   relaxation?
5. Which exact fields must a safe decision lease bind?
6. Why is commit-time reauthorization required for long-running agents?
7. What evidence should be required before leaving quarantine?
8. How can stream silence create a false sense of low risk?

## Primary references

- OpenID Foundation, [Shared Signals Framework 1.0 Final](https://openid.net/specs/openid-sharedsignals-framework-1_0-final.html)
- OpenID Foundation, [Continuous Access Evaluation Profile 1.0 Final](https://openid.net/specs/openid-caep-1_0-final.html)
- OpenID Foundation, [RISC Profile 1.0 Final](https://openid.net/specs/openid-risc-1_0-final.html)
- OpenID Foundation, [Shared Signals specifications and status](https://openid.net/wg/sharedsignals/specifications/)
- OpenID Foundation, [SSF conformance testing](https://openid.net/certification/ssf_testing/)
- IETF, [RFC 8417: Security Event Token](https://www.rfc-editor.org/rfc/rfc8417)
- IETF, [RFC 8935: Push-Based SET Delivery](https://www.rfc-editor.org/rfc/rfc8935)
- IETF, [RFC 8936: Poll-Based SET Delivery](https://www.rfc-editor.org/rfc/rfc8936)
- IETF, [RFC 9493: Subject Identifiers for SETs](https://www.rfc-editor.org/rfc/rfc9493)
- IETF, [RFC 9967: SCIM Profile for SETs](https://www.rfc-editor.org/rfc/rfc9967)
- NIST, [SP 800-207: Zero Trust Architecture](https://csrc.nist.gov/pubs/sp/800/207/final)
- NIST, [SP 800-207A: Cloud-Native Zero Trust](https://csrc.nist.gov/pubs/sp/800/207/a/final)
- Open Policy Agent, [documentation](https://www.openpolicyagent.org/docs/latest/)
- Cedar, [policy language documentation](https://docs.cedarpolicy.com/)
- OpenFGA, [documentation](https://openfga.dev/docs)

## Next course

Advanced 06 covers decentralized identity and trust for multi-agent ecosystems:
DID resolution, portable credentials, trust registries, key recovery,
cross-domain governance, Sybil resistance, and the limits of reputation.
