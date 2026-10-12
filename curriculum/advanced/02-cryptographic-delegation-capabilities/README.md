# Cryptographic Delegation, Capabilities & Verifiable Provenance for Agents

**Level:** Advanced<br>
**Estimated time:** 5–7 hours<br>
**Format:** chapter, executed notebook, reusable Python lab, OPA and Cedar policies, and adversarial tests<br>
**Last reviewed:** 2026-10-07

> **Goal:** design, implement, and evaluate attenuated, sender-constrained agent delegation that combines verifiable capability chains with current policy and signed provenance.

An agent rarely needs all of its caller's authority. It needs a narrow, short-lived
proof that it may perform one part of one task. This course builds that proof,
attenuates it across an agent-to-agent handoff, binds its use to a key, combines
it with current policy, and produces signed evidence.

The runnable scenario is a synthetic insurer. A claims agent delegates only
`knowledge.search` on `claim:483` to a research agent. The knowledge API must
reject wider actions, a different claim, another tenant, another audience,
replays, expired or revoked capabilities, and stale policy—even when a signature
is otherwise valid.

> This lab teaches security invariants, not a production token format. Its fixed
> timestamps, deterministic keys, and in-memory stores are intentionally
> reproducible and must not be copied into production.

## Learning outcomes

By the end, you can:

1. distinguish identity, authentication, delegation, impersonation, and
   capability-based authority;
2. define and test monotonic attenuation across subject, tenant, task,
   audience, action, resource, tool, purpose, time, budget, depth, and parent;
3. verify every signature and every link in a delegation chain;
4. bind use of authority to a client key with DPoP and explain when mTLS is a
   better fit;
5. combine portable proof with revocation, risk, workload, and relationship
   state in OPA or Cedar;
6. use Macaroons and assess Biscuit without overstating library maturity;
7. distinguish a signed, hash-linked evidence chain from an unsigned hash log;
8. evaluate the design against labelled adversarial cases and a release gate.

## Prerequisites

Complete the intermediate courses on OAuth/OIDC, token exchange, fine-grained
authorization, and MCP tool authorization. You should be comfortable with JWTs,
public-key signatures, policy decision points, and Python tests.

## Success criteria

The reference implementation is successful only when:

- all 27 labelled cases match their expected outcome;
- there are zero invalid allows and zero valid-request blocks;
- all 78 Python tests pass, including property, budget, and Cedar execution tests;
- all 14 OPA tests pass;
- every notebook cell executes from a clean environment; and
- logs contain hashes and reason codes, not bearer credentials or raw proofs.

## 1. Identity is not authority

Authentication answers “which principal controls this session or key?” A
capability answers “what operation may its holder perform?” Neither answer is a
complete authorization decision.

| Concept | Proof or decision | What it does **not** establish |
|---|---|---|
| Identity | principal controls a credential | permission for this resource |
| Workload identity | running workload maps to an identity | caller intent or task scope |
| Delegation | principal A authorizes B to act within bounds | that current policy still allows it |
| Impersonation | B acts as A | a visible, constrained delegation chain |
| Capability | possession proves bounded authority | holder identity unless explicitly bound |
| Authorization | current request satisfies proof and policy | that a downstream effect succeeded |

OAuth 2.0 Token Exchange [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693)
distinguishes delegation from impersonation. In a delegation token, the
`subject` remains the original subject while `act` names the current actor.
Nested `act` claims record actor history; only the outermost `act` is the current
actor. `may_act` expresses who may be authorized to act, but is not itself a
grant: the authorization server still applies policy.

## 2. Capability envelope

The lab signs canonical claims with Ed25519. The envelope contains:

- unique capability ID (`jti`), issuer, and subject;
- tenant and task boundaries;
- exact audiences, actions, resources, tools, and purposes;
- issue and expiry times;
- call and monetary budgets;
- delegation depth, parent ID, and parent digest;
- a DPoP public-key thumbprint; and
- the policy version used to issue it.

For parent claims `P` and child claims `C`, attenuation requires:

```text
C.audiences ⊆ P.audiences
C.actions   ⊆ P.actions
C.resources ⊆ P.resources
C.tools     ⊆ P.tools
C.purposes  ⊆ P.purposes
C.expiry    ≤ P.expiry
C.max_calls ≤ P.max_calls
C.max_amount≤ P.max_amount
C.depth     = P.depth + 1
C.issuer    = P.subject
C.parent_id = P.jti
C.parent_digest = H(P)
```

Tenant, task, and policy version must remain equal. A child may narrow authority;
it cannot widen or silently move it. Re-signing a widened child does not help:
signature validity and attenuation validity are separate invariants.

### Canonicalization and algorithm handling

A signature is over bytes, not an abstract object. Production formats need a
normative serialization and strict duplicate-key handling. The lab uses sorted,
compact JSON for a controlled data model; use an established format and its
canonicalization rules in production.

Never accept the token's algorithm as policy. Pin allowed algorithms per issuer,
resolve keys from a trusted registry, reject private key material in presented
JWKs, and treat unknown issuers and ambiguous key IDs as failures. The lab uses
Ed25519 because it is compact and widely supported, not because every deployment
must use it.

### Key lifecycle

A production issuer needs hardware-backed or managed keys, rotation overlap,
key-status metadata, emergency disablement, audit trails, and cache expiry.
Verifier behavior during registry failure must be explicit. High-impact actions
normally fail closed; a bounded degraded mode may be acceptable only where the
risk has been deliberately designed and tested.

## 3. Verify the whole chain

The resource gateway verifies, in order:

1. a trusted root and bounded maximum depth;
2. every issuer key and every signature;
3. issue and expiry time for every link;
4. revocation of any ancestor or leaf;
5. current policy version;
6. parent identifier and digest binding; and
7. every attenuation dimension.

Checking only the leaf signature proves that one issuer signed one object. It
does not prove that the issuer possessed the delegated authority or that the
child stayed within its parent.

Revoking a parent invalidates descendants. At scale, use short lifetimes plus a
revocation strategy such as introspection, event-driven caches, deny sets, or
epoch/version changes. Document the maximum revocation propagation delay and
test it as a service objective.

## 4. Prevent bearer-token replay

A stolen bearer capability can be replayed. The lab binds the leaf to a DPoP key
thumbprint and requires a fresh DPoP proof for the HTTP request.

Per [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449), the verifier checks:

- protected header `typ=dpop+jwt`;
- an allowed asymmetric `alg` and a public `jwk`;
- the proof signature and JWK thumbprint (`cnf.jkt` binding);
- HTTP method (`htm`) and normalized URI (`htu`);
- access-token hash (`ath`) when an access token is used;
- issue time, server nonce, and a bounded unique `jti`; and
- atomic replay consumption.

Query and fragment are excluded from `htu` by RFC normalization, so request data
still needs normal integrity and authorization checks. A nonce helps a server
force freshness, while `jti` storage prevents reuse. The consume operation must
be atomic across gateway replicas.

Mutual-TLS-bound access tokens [RFC 8705](https://www.rfc-editor.org/rfc/rfc8705)
bind a token to the client certificate. mTLS is attractive inside managed
service meshes; DPoP is often easier across public HTTP clients. Both are
sender-constraining mechanisms, not substitutes for audience, resource, or
business-policy checks.

OAuth Resource Indicators [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707)
let a client request a token for a specific resource. Restricting audience and
resource prevents a token intended for the knowledge API from becoming a
confused-deputy credential at the claims API.

## 5. Portable proof plus current policy

Cryptography preserves statements. It does not make them current. The gateway
therefore combines the verified capability with trusted facts:

- workload approval or attestation status;
- task and relationship status;
- current risk score and policy version;
- revocation and replay state; and
- request-to-capability bindings.

OPA and Cedar receive typed verification results produced by trusted gateway
code. They do not parse caller-controlled claims and simply assume
`signature_valid=true`. The included policies deny by default and demonstrate:

- OPA/Rego composition plus explicit audit, idempotency, and budget obligations;
- Cedar schema validation and `forbid` precedence; and
- denial on stale policy, replay, revocation, cross-tenant access, and risk.

An allow is still not the side effect. Before calling the downstream system,
the policy enforcement point must atomically reserve call budgets, enforce an
idempotency key, pass constrained parameters, and record the effect outcome.

## 6. Macaroons and Biscuit

### Macaroons

Macaroons use chained MACs and caveats. A holder can add first-party caveats
without the issuer's root key, so authority naturally becomes more restrictive.
The notebook executes the real
[PyMacaroons](https://github.com/ecordell/pymacaroons) library: tenant, task,
action, resource, expiry, and result-count caveats must all be satisfied.

The foundational [Macaroons paper](https://research.google/pubs/macaroons-cookies-with-contextual-caveats-for-decentralized-authorization-in-the-cloud/)
also describes third-party caveats and discharge macaroons. They enable external
authorization facts but introduce discharge acquisition, binding, privacy,
availability, and replay questions. This lab stays with first-party caveats so
the central attenuation property remains visible.

Macaroons are bearer credentials unless an application adds holder binding.
Location is a routing hint, not an authorization boundary by itself.

### Biscuit

[Biscuit](https://www.biscuitsec.org/) is a public-key capability token with
append-only blocks and Datalog-style authorization. A holder may append checks
or facts that restrict use but cannot delete earlier blocks; sealing prevents
further attenuation. Its cryptographic design and specification are mature
enough to study, but SDK availability and operational maturity vary by language.
Evaluate the maintained implementation for your platform rather than assuming
feature parity. This course models the comparison and does not claim a Python
SDK execution it does not perform.

| Mechanism | Delegation model | Strength | Watch for |
|---|---|---|---|
| OAuth token exchange | authorization-server-issued token | ecosystem integration | actor semantics, audience, exchange policy |
| Macaroon | append caveats to chained MAC | decentralized attenuation | bearer replay, caveat semantics, root-key verification |
| Biscuit | append signed logic blocks | expressive offline proof | verifier logic, token size, SDK maturity |
| Custom signed envelope | application-defined chain | transparent teaching model | format/protocol design burden |

## 7. Agent and MCP boundaries

An LLM-generated tool call is untrusted input. The model may propose an action,
but the trusted gateway selects credentials, verifies proof, constrains
parameters, authorizes, and invokes the tool. Never place credentials in prompts,
tool descriptions, model-visible logs, or notebook output.

The [MCP authorization specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
uses OAuth concepts and requires resource-server behavior. The November 2025
specification is the stable reference used here. Later release-candidate or draft
material should be labelled emerging until it becomes stable. For external
services, use a controlled OAuth flow or token exchange; do not pass an inbound
token through to an unrelated downstream service.

For an MCP tool call, bind authority to the MCP server audience, concrete tool,
resource, task, purpose, and workload. Reauthorize at the tool boundary and again
before delayed or high-impact effects.

## 8. Signed provenance and evidence

A hash chain detects reordering or deletion only if a trusted checkpoint exists.
If an attacker can rewrite the whole local log, it can recompute every hash. The
lab therefore signs each event with the producer's key and links it to the prior
event hash. Verification rejects:

- modified events;
- broken links and reordering;
- duplicate event identifiers;
- unknown producers; and
- invalid signatures.

Production evidence should also use independent checkpoints—such as an
append-only service, transparency log, write-once storage, or external timestamp
anchor—and protect the signing service from the application it observes.

Record observed facts separately from inferred facts. A gateway can truthfully
record “proof verified” and “request sent”; it cannot record “claim updated”
until the system of record confirms that effect. Store hashes or identifiers for
credentials and proofs, not secret material.

## 9. Threat model and failure behavior

| Threat | Control | Required failure behavior |
|---|---|---|
| widened child capability | set/subset attenuation checks | deny with dimension-specific reason |
| forged or modified claim | every-link signature verification | deny before policy evaluation |
| stolen capability | DPoP or mTLS binding | deny wrong key and replay |
| confused deputy | audience/resource/tool binding | deny service or tool substitution |
| cross-tenant access | immutable tenant binding | deny even if action name matches |
| stale authority | short expiry, revocation, policy version | deny or explicit bounded degradation |
| compromised parent | ancestor revocation cascade | invalidate descendants |
| policy-engine outage | local bounded policy or fail closed | never silently allow |
| replay-store race | atomic consume, shared durable state | one winner, all repeats denied |
| audit tampering | signed links and external checkpoints | detect and alert; do not “repair” silently |

Availability decisions are risk decisions. A public search may tolerate a
short-lived cached policy. A wire transfer should not. Define fail-open or
fail-closed by operation, maximum stale age, monitoring, and recovery—not with a
single platform-wide default.

## 10. State of practice and emerging work

| Area | Established practice | Emerging or deployment-dependent |
|---|---|---|
| OAuth delegation | RFC 8693 token exchange, audience restriction | cross-domain agent actor chains |
| sender constraint | RFC 8705 mTLS, RFC 9449 DPoP | workload-to-user composite binding |
| capabilities | Macaroons, service-specific signed grants | broader Biscuit adoption and interop |
| policy | OPA/Rego, Cedar, relationship and attribute systems | common agent authorization profiles |
| agent protocols | stable MCP authorization release | later MCP release candidates and drafts |
| assurance guidance | NIST identity/zero-trust publications | NIST NCCoE Agent Identity and Authorization concept paper, an Initial Public Draft as of February 2026 |

The [NIST NCCoE Agent Identity and Authorization project page](https://www.nccoe.nist.gov/projects/agent-identity-and-authorization)
is useful directional material, but its February 2026 concept paper is an
Initial Public Draft, not finalized normative guidance.

## 11. Lab map

| Artifact | Purpose |
|---|---|
| `advanced_02_cryptographic_delegation.ipynb` | guided, executed investigation |
| `lab.py` | canonical reference runtime and 27-case corpus |
| `advanced_delegation_runtime.py` | collision-safe notebook/test import facade |
| `policies/opa/` | Rego v1 policy and 14 executable tests |
| `policies/cedar/` | Cedar policy and schema, executed from Python |
| `tests/test_cryptographic_delegation.py` | unit, property, integration, SDK, and policy tests |

Install and run:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python lab.py
python -m pytest tests -q
opa test policies/opa --fail-on-empty
```

The lab prints only aggregate metrics and mismatches. A passing release gate is
not proof of universal security; it is evidence that a declared test corpus has
no known regression.

## 12. Evaluation design

The labelled corpus contains one valid flow and 26 denials across identity,
isolation, binding, attenuation, cryptography, lifecycle, revocation, DPoP, and
current policy. Report at least:

```text
invalid_allow_rate = invalid requests allowed / invalid requests
valid_block_rate   = valid requests denied / valid requests
accuracy           = matching outcomes / all labelled cases
```

Security release gate:

```text
cases >= 25
invalid allows == 0
valid blocks == 0
accuracy == 1.0
```

Also monitor latency, revocation propagation, replay-store consistency,
unresolved issuer keys, policy-version mismatch, denial-reason distribution,
and budget-consumption failures. A perfect lab accuracy score can coexist with
poor production availability or missing threat coverage.

## 13. Production upgrade path

Replace the training shortcuts deliberately:

1. deterministic private keys → KMS/HSM or managed signing service;
2. custom JSON envelope → reviewed standard/profile and strict parser;
3. in-memory replay set → durable, atomic, expiring shared store;
4. static key map → authenticated issuer registry with rotation metadata;
5. in-process revocation set → event-driven/introspection-backed status;
6. in-memory budget → transactional reservation and idempotency ledger;
7. local evidence list → append-only sink with external checkpoints;
8. synthetic risk facts → authenticated, versioned policy inputs;
9. one resource gateway → consistent enforcement at every effect boundary;
10. fixed cases → continuously expanded incidents, mutations, and property tests.

Keep the capability verifier small. Fuzz parsers, bound token and chain size,
measure worst-case verification cost, avoid network calls during critical
parsing, and expose stable reason codes without leaking secrets.

## 14. Practical exercises

1. Add a third delegation hop. Show one valid narrowing and one depth failure.
2. Implement atomic call-budget consumption and a race test with two workers.
3. Add key rotation: accept old and new keys during overlap, then revoke old.
4. Add a third-party Macaroon caveat and model discharge-service failure.
5. Translate the valid chain into RFC 8693 `sub` and nested `act` claims.
6. Create a resource-indicator mix-up and prove the wrong API denies it.
7. Anchor the evidence head externally and test full local-log replacement.
8. Define fail behavior for search, claim update, and payment actions.

## 15. Review questions

1. Why can a correctly signed child capability still be invalid?
2. Which DPoP fields prevent method, URI, token, key, and replay substitution?
3. Why must revoking a parent affect every descendant?
4. What can current policy decide that a portable capability cannot?
5. Why is a local unsigned hash chain insufficient forensic evidence?

## Primary references

- IETF, [OAuth 2.0 Token Exchange (RFC 8693)](https://www.rfc-editor.org/rfc/rfc8693)
- IETF, [OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens (RFC 8705)](https://www.rfc-editor.org/rfc/rfc8705)
- IETF, [Resource Indicators for OAuth 2.0 (RFC 8707)](https://www.rfc-editor.org/rfc/rfc8707)
- IETF, [OAuth 2.0 Demonstrating Proof of Possession (DPoP) (RFC 9449)](https://www.rfc-editor.org/rfc/rfc9449)
- Birgisson et al., [Macaroons: Cookies with Contextual Caveats for Decentralized Authorization in the Cloud](https://research.google/pubs/macaroons-cookies-with-contextual-caveats-for-decentralized-authorization-in-the-cloud/)
- [Biscuit specification and documentation](https://www.biscuitsec.org/)
- [Open Policy Agent documentation](https://www.openpolicyagent.org/docs/latest/)
- [Cedar policy language documentation](https://docs.cedarpolicy.com/)
- [Model Context Protocol authorization specification, 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
- NIST NCCoE, [Agent Identity and Authorization](https://www.nccoe.nist.gov/projects/agent-identity-and-authorization)

## Further authoritative reading

- IETF, [JSON Web Key Thumbprint (RFC 7638)](https://www.rfc-editor.org/rfc/rfc7638)
- IETF, [JSON Web Token Best Current Practices (RFC 8725)](https://www.rfc-editor.org/rfc/rfc8725)
- NIST, [Zero Trust Architecture (SP 800-207)](https://csrc.nist.gov/pubs/sp/800/207/final)
- [PyJWT documentation](https://pyjwt.readthedocs.io/)
- [PyMacaroons source and examples](https://github.com/ecordell/pymacaroons)
