# Agent Attestations, Verifiable Credentials & Trust Evidence

**Level:** Advanced

**Estimated time:** 5–7 hours

**Format:** chapter, executed notebook, reusable Python lab, signed fixtures, policy examples, and adversarial tests
**Last reviewed:** 2026-10-12

> **Goal:** turn claims about an agent into independently verifiable,
> freshness-aware, revocable, and correctly bound evidence—then use local
> policy, not the credential itself, to decide whether an action is allowed.

An insurer wants a claims-research agent to update one claim. The agent says it
is registered, evaluated, governed, running an approved release, and low risk.
None of those statements is trusted because the model said so. The evidence
gateway instead composes five independently verified dimensions:

```text
holder-bound presentation ─┬─ registration credential
                            ├─ evaluation credential
                            └─ governance credential
fresh workload attestation ─── release + config + tool measurements
signed build provenance ────── exact release + builder + source
current local state ────────── status + quarantine + risk + policy
                                      │
                                      ▼
                       deterministic local authorization
```

The valid request may perform `claim.update` on `claim:483`. A forged proof,
wrong subject, revoked credential, replayed presentation, stale status list,
release mismatch, bad workload measurement, untrusted builder, quarantine, or
policy-version mismatch denies the request.

> The lab is a security-focused teaching profile. It uses real Ed25519 JWS
> signatures, JSON Schema, DSSE pre-authentication encoding, and EAT-shaped
> claims, but it is not a conformant W3C VC, OpenID4VC, EAT, Bitstring Status
> List, or SLSA implementation. Deterministic keys and fixed time are for
> reproducibility only.

## Learning outcomes

After this course you can:

1. distinguish a claim, credential, verifiable credential, presentation,
   attestation evidence, attestation result, and authorization decision;
2. explain why signature validity proves authorship and integrity—not truth,
   issuer authority, fitness for purpose, or permission;
3. verify credential type, issuer policy, proof, schema, subject, audience,
   lifetime, status, and allowed claim vocabulary;
4. bind a presentation to its holder, verifier, challenge, subject, and a
   single-use replay record;
5. use W3C VC 2.0, OpenID4VCI, OpenID4VP/DCQL, RFC 9901 SD-JWT, and status-list
   concepts without confusing their distinct roles;
6. model RATS evidence and EAT measurements separately from the verifier's
   attestation result and the relying party's policy;
7. verify DSSE/in-toto/SLSA provenance against an exact release, builder, and
   source;
8. compose registration, evaluation, governance, workload, provenance, and
   current negative evidence without collapsing them into an opaque score;
9. preserve `verified true`, `verified false`, and `unknown/not disclosed` as
   different states; and
10. evaluate invalid allows, valid blocks, replay, revocation, freshness,
    cross-binding, privacy, and operational recovery.

## Prerequisites

Complete the intermediate workload assurance, OAuth/OIDC, authorization
governance, and observability courses, plus Advanced 01–03. You should recognize
JWT/JWS claims, JWK key identifiers, asymmetric verification, JSON Schema,
workload identity, policy enforcement points, and content digests.

## Success criteria

The reference path is complete when:

- all 42 labelled scenarios match their expected decision;
- invalid allows and valid-request blocks are both zero;
- all credentials, status lists, presentations, workload evidence, and
  provenance are verified with pinned algorithms and keys;
- every evidence item binds to the same agent, holder, release, configuration,
  tenant, action, resource, verifier, and current policy where applicable;
- the notebook runs top to bottom without credentials; and
- evidence records contain IDs and digests, never credentials, presentations,
  signatures, raw subject identifiers, or private keys.

## Non-goals

The course does not implement JSON-LD canonicalization, complete Data Integrity
cryptosuites, full Bitstring Status List compression/privacy behavior, SD-JWT
disclosure processing, an OpenID4VC network flow, hardware attestation, DID
resolution, transparency logs, or SLSA conformance. Those require maintained,
profile-conformant implementations and operational infrastructure. The lab
makes their core trust boundaries and composition failures observable.

## 1. Mental model: evidence is input, not authority

Keep these operations separate:

| Operation | Question | Output |
|---|---|---|
| Issuance | Who packages claims into a credential? | credential |
| Verification | Is the credential/presentation authentic, current, and structurally valid? | verified facts or error |
| Validation | Are those facts fit for this verifier's purpose? | locally meaningful evidence |
| Attestation appraisal | Do measurements satisfy reference values and appraisal policy? | attestation result |
| Authorization | May this principal perform this exact action now? | allow/deny/step-up/constrain |

The [VC Data Model 2.0](https://www.w3.org/TR/vc-data-model-2.0/)
explicitly distinguishes verification from evaluating the truth and fitness of
claims. A valid signature from an unapproved issuer is not useful evidence. A
valid evaluation about release A says nothing about release B. A valid
registration credential does not grant `claim.update`.

The effective authority in this scenario is an intersection:

```text
trusted issuer/type/schema
∩ current, unrevoked credential
∩ holder + subject + audience + challenge binding
∩ exact release/config/tool measurements
∩ exact build subject/builder/source
∩ tenant/action/resource governance scope
∩ current quarantine/risk/task/policy state
```

Any empty intersection denies.

## 2. Credential and presentation mechanics

### VC Data Model 2.0

W3C VC Data Model 2.0 became a W3C Recommendation on 15 May 2025. It defines
roles and a data model, including issuer, credential subject, type, validity,
status, schema, securing mechanisms, and presentations. It does not mandate one
identifier system, one proof mechanism, one issuance protocol, or one trust
policy.

The lab creates VC-shaped documents with:

```json
{
  "@context": ["https://www.w3.org/ns/credentials/v2"],
  "type": ["VerifiableCredential", "AgentEvaluationCredential"],
  "issuer": "https://evaluation.corp.example",
  "credentialSubject": {
    "id": "urn:agent:claims-research",
    "releaseDigest": "sha256:…",
    "configDigest": "sha256:…",
    "suite": "agent-security-v7",
    "result": "pass",
    "criticalFailures": 0
  }
}
```

The document is carried in a compact JWS for a transparent offline exercise.
This is a training envelope, not a claim of W3C conformance. Production choices
include [VC Data Integrity 1.0](https://www.w3.org/TR/vc-data-integrity/),
the EdDSA/ECDSA cryptosuites, and
[Securing VCs using JOSE and COSE](https://www.w3.org/TR/vc-jose-cose/).
Select a complete ecosystem profile and interoperable implementation rather
than combining examples from incompatible formats.

### Issuer and type policy

Trust is scoped. The registry issuer may issue registration credentials; the
evaluation issuer may issue evaluation credentials. A correctly signed
evaluation credential from the registry is type confusion, not valid evidence.

The local issuer registry binds:

```text
issuer identifier
→ active/blocked state
→ accepted key IDs and algorithms
→ allowed credential types and subject claims
→ schema/profile
→ maximum lifetime
→ status-list location
```

Key discovery is security-sensitive. Protect identifier resolution, TLS,
redirects, cache lifetime, algorithm policy, key rotation, and compromise
response. Never fetch arbitrary `issuer`, schema, or context URLs merely because
they appear inside an untrusted credential.

### Holder, subject, and presentation binding

Holder and credential subject are roles, not synonyms. A runtime can hold
evidence about a logical agent. The course binds the holder key thumbprint in
the registration credential, then signs a presentation containing:

```text
holder + subject + verifier audience + nonce + issued/expiry + presentation ID
```

The replay cache atomically consumes the presentation ID. A signature without
the expected verifier and challenge is replayable proof.

## 3. Status, freshness, and negative evidence

[Bitstring Status List v1.0](https://www.w3.org/TR/vc-bitstring-status-list/)
is a 2025 W3C Recommendation for privacy-preserving, space-efficient credential
status. It can express revocation or suspension without one network endpoint per
credential.

The lab executes a small signed bitset profile. It verifies the status-list
issuer and signature, purpose, subject URI, time window, index bounds, and bit.
It also limits the age of the cached status evidence. Production implementations
must follow the complete encoding, minimum-size, caching, privacy, and retrieval
requirements of the selected profile.

Expiry is not revocation. A credential can remain unexpired while its subject
is quarantined, its release withdrawn, or its issuer compromised. Safe
composition gives explicit negative evidence precedence:

```text
quarantined > registered
revoked > unexpired
failed evaluation > older pass
release mismatch > generic approval
current local policy > portable historical claim
```

Fail-open behavior must be an explicit, risk-tiered decision. A cached status
list might support a bounded low-risk read during an outage; a sensitive write
normally fails closed.

## 4. Selective disclosure and OpenID4VC

### SD-JWT and SD-JWT VC

[RFC 9901](https://www.rfc-editor.org/rfc/rfc9901) standardized selective
disclosure for JWTs in November 2025. It signs digests of salted disclosures so
a holder can reveal a subset. Selective disclosure is not automatically
unlinkable, and disclosing stable identifiers, signature material, or rare
attribute combinations can still enable correlation.

SD-JWT VC remains an Internet-Draft as of this review
([draft-ietf-oauth-sd-jwt-vc-19](https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/)).
Do not describe it as an RFC or hand-roll it for production. The lab teaches the
privacy and policy invariant only:

```text
verified true ≠ verified false ≠ unknown / not disclosed
```

An undisclosed `approved` claim cannot be treated as true. It also cannot be
silently reported as false.

### OpenID4VCI and OpenID4VP

[OpenID4VCI 1.0 Final](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-final.html)
defines an OAuth-based issuance API. It covers authorization, credential offers,
proofs, nonce handling, immediate/deferred issuance, and metadata. It does not
define whether an agent deserves a credential.

[OpenID4VP 1.0 Final](https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html)
defines presentation requests and responses. Its Digital Credentials Query
Language (DCQL) requests credential combinations and claim paths. The lab builds
a minimal DCQL query for only the facts the policy needs. Production wallets and
verifiers must also implement client identification, request/response security,
holder binding, nonce/state, redirect or response-mode rules, and privacy/user
or operator consent appropriate to their profile.

The LLM never receives wallet keys or raw credentials. It proposes the action;
the trusted runtime selects and presents evidence.

## 5. Workload attestation: RATS and EAT

[RFC 9334](https://www.rfc-editor.org/rfc/rfc9334) defines the Remote
ATtestation procedureS architecture:

```text
Attester -- Evidence --> Verifier -- Attestation Result --> Relying Party
                          ↑
             reference values + endorsements + appraisal policy
```

Evidence is not the same as an attestation result. The verifier appraises
evidence; the relying party decides how much trust to place in the result.

[RFC 9711](https://www.rfc-editor.org/rfc/rfc9711) standardizes the Entity
Attestation Token (EAT) claims framework for JWT or CWT. The lab's EAT-shaped
JWS binds a fresh nonce and verifier audience to:

- exact workload identity;
- release digest;
- agent configuration digest; and
- tool-manifest digest.

It is deliberately not a hardware-backed EAT profile. A production verifier
needs a platform-specific evidence format, endorsement and reference-value
lifecycle, appraisal policy, nonce/replay behavior, trust anchors, and an EAT
profile. SPIFFE proves workload identity; it does not by itself prove measured
boot state or the exact release/configuration.

## 6. Supply-chain provenance: in-toto, DSSE, and SLSA

The agent is software. A registration or evaluation should not float free from
the artifact that is actually deployed.

[SLSA v1.2](https://slsa.dev/spec/v1.2/) is the current approved SLSA
specification at this review. Its Build Track describes increasing guarantees
about provenance and build platforms. SLSA recommends provenance and
verification-summary attestation formats; an attestation's existence does not
prove a level unless the system satisfies the level's requirements.

The lab signs an [in-toto Statement v1](https://in-toto.io/Statement/v1) with a
SLSA provenance predicate inside a DSSE-style envelope. Verification checks:

```text
DSSE signature
∩ exact in-toto subject digest
∩ expected predicate type
∩ approved builder identity
∩ expected source reference
```

DSSE signs an unambiguous pre-authentication encoding of payload type and bytes.
Production tooling should use maintained in-toto/Sigstore libraries, keyless or
managed signing policy as appropriate, transparency verification, builder trust,
and SLSA verification policy. A valid envelope from an arbitrary builder is not
trusted provenance.

## 7. Composite assurance without blind trust scores

The gateway produces an explainable profile:

```json
{
  "identity": "verified",
  "workload": "verified",
  "supply_chain": "verified",
  "evaluation": "verified",
  "governance": "verified",
  "evidence_ids": ["urn:vc:…"]
}
```

It does not compute `trust_score = 0.82`. A scalar hides which evidence is
missing, stale, contradictory, or outside scope. A score can support operations
when its calibration and limits are understood, but sensitive authorization
should retain the dimensions and provenance behind the decision.

The evidence graph makes bindings inspectable:

```text
registry ─registration─> agent ─runs-release─> digest
evaluator ─evaluation──> agent
governance ─approval───> agent
workload ─measured-as────────────────────────> digest
builder ─provenance──────────────────────────> digest
```

Graph reachability is not authorization. Every edge needs verified provenance,
scope, freshness, and local policy meaning.

## 8. Technology landscape

| Layer | Common options | Strengths | Selection questions |
|---|---|---|---|
| Credential data | W3C VC 2.0, ISO mdoc, SD-JWT VC draft | portable typed claims and ecosystem profiles | required ecosystem, privacy, format maturity, conformance tooling |
| Proof | VC Data Integrity, JOSE/COSE, SD-JWT | different JSON-LD, JWT/CBOR, and disclosure trade-offs | exact profile, cryptosuite, canonicalization, holder binding, library maturity |
| Exchange | OpenID4VCI, OpenID4VP/DCQL, Digital Credentials API profiles | interoperable issuance/presentation flows | client identity, wallet model, response mode, consent, verifier trust |
| Status | Bitstring Status List, short lifetime, issuer-specific services | privacy/scale or simpler freshness | outage behavior, cache age, suspension vs revocation, correlation |
| Workload evidence | RATS/EAT profiles, cloud confidential-computing evidence, TPM/TEE stacks | measured runtime claims | reference values, endorsements, verifier ownership, freshness |
| Workload identity | SPIFFE/SPIRE, cloud workload identity | short-lived runtime identity | identity is not measurement or business approval |
| Supply chain | in-toto, SLSA, Sigstore/cosign | artifact-bound provenance and signatures | builder trust, transparency, digest coverage, verification policy |
| Local policy | OPA, Cedar, relationship stores, cloud IAM | deterministic enforcement and reason codes | verified inputs, conflict precedence, policy lifecycle, fail behavior |

The lab uses PyJWT, `cryptography`, `jsonschema`, and NetworkX because they make
the primitive checks visible. Production teams should prefer a conformant
credential/OpenID4VC implementation for the selected profile, platform EAT
verifiers, Sigstore/in-toto tooling, protected KMS/HSM keys, and official
conformance suites. A generic JWT library is not a complete VC verifier.

## 9. Architecture patterns

### Central verifier service

One service resolves issuer policy, verifies evidence, normalizes facts, and
returns a signed result. It centralizes expertise and caching but becomes
critical infrastructure. Preserve raw-evidence hashes and policy versions; do
not create an unauditable universal trust score.

### Embedded verification

Each relying service verifies evidence locally. This reduces dependency on a
central online service but multiplies library upgrades, key/status caches, and
policy drift. Use a shared tested library and consistent profiles.

### Brokered local credential

A gateway verifies diverse evidence and issues a narrow local, short-lived
credential. This simplifies downstream enforcement but can lose provenance or
widen authority. Bind the new credential to source evidence IDs, exact audience,
subject, action/resource scope, and policy version.

### Evidence wallet plus policy gateway

The trusted agent runtime holds credentials and responds to minimal presentation
requests; the verifier and policy gateway remain separate. This is the course's
pattern because it exposes holder, verifier, and authorization boundaries.

## 10. Threat model and failure behavior

| Threat | Required control | Expected outcome |
|---|---|---|
| self-reported approval | evidence fields come only from verified pipeline | ignore/deny |
| forged or algorithm-swapped proof | pinned asymmetric algorithm, key ID, signature | deny |
| valid proof from wrong issuer/type | issuer/type/claim/schema policy | deny |
| assurance laundering | subject, holder, audience, nonce, release binding | deny |
| replayed presentation | short expiry plus atomic ID consumption | deny |
| revoked but unexpired credential | signed fresh status evidence | deny |
| unavailable/stale status | explicit risk-tier fail behavior | deny sensitive write |
| schema/type confusion | exact JSON Schema and claim allowlist | deny |
| unknown selective disclosure | tri-state representation | no privilege |
| evaluation for old release/config | exact digest binding | deny |
| workload evidence replay/substitution | nonce, audience, identity, measurements | deny |
| provenance for different artifact | exact in-toto subject digest | deny |
| provenance from arbitrary builder/source | local builder/source policy | deny |
| positive credentials plus quarantine | negative/current state precedence | deny |
| issuer key compromise | disable issuer/key, invalidate caches, reissue | deny/recover |
| resolver poisoning | pinned methods, TLS/redirect limits, allowlists | deny |

## 11. Evidence lifecycle and operations

Treat every evidence source as a lifecycle system:

```text
propose issuer/profile → approve keys/schemas → issue → present → verify
→ refresh/status → suspend/revoke → rotate/reissue → retire → retain audit
```

Define objectives such as:

```text
agent quarantine → sensitive authorization denied within 30 seconds
issuer compromise → key disabled and verifier caches invalidated immediately
planned key rotation → overlapping verification without unauthorized acceptance
release rollout → evaluation and provenance available before traffic shift
```

Status-list and key caches need maximum age, stale-on-error policy, stampede
control, emergency refresh, rollback, and observability. A successful cache hit
does not prove currentness unless age is measured.

## 12. Observability and privacy

Record observable facts:

- trace and logical operation IDs;
- decision and stable reason code;
- hashed agent identifier and verified workload ID;
- release/config/tool digests;
- evidence IDs, issuer IDs, status versions, and policy version; and
- verification latency, cache age, key/status refresh outcome, and terminal
  effect receipt where applicable.

Do not log raw credentials, presentations, disclosures, private keys, nonces,
signatures, full personal claims, or hidden model reasoning. Separate
"authorization allowed" from proof that the system of record completed the
effect.

Privacy review must consider correlation through stable subjects, status-list
lookups, holder keys, signatures, rare attribute combinations, and repeated
presentation requests. Data minimization is necessary but not sufficient for
unlinkability.

## 13. Evaluation

The labelled corpus contains one valid scenario and 41 denials across
presentation, credential, status, cross-binding, negative evidence, workload,
supply chain, and lifecycle controls.

```text
invalid_allow_rate = invalid cases allowed / invalid cases
valid_block_rate   = valid cases denied / valid cases
accuracy           = matching labels / all labelled cases
```

Release gate:

```text
cases >= 40
invalid allows == 0
valid blocks == 0
accuracy == 1.0
```

The complete gateway scores 42/42. The deliberately unsafe baseline verifies
only the presentation signature and allows 40 invalid scenarios. This
comparison shows that cryptographic validity is one control, not the trust
decision.

The corpus proves only declared invariants. Production assurance also needs
official conformance tests, parser and JSON-LD fuzzing where relevant, network
resolution tests, privacy analysis, key/status rotation drills, concurrency and
restart tests, verifier interoperability, performance/load testing, and incident
exercises.

## 14. Lab map

| Artifact | Purpose |
|---|---|
| `advanced_04_agent_attestations_credentials.ipynb` | executed learner journey, experiments, and failure analysis |
| `lab.py` | canonical evidence verification and authorization runtime |
| `advanced_evidence_runtime.py` | collision-safe import facade |
| `data/trusted_issuers.json` | issuer/type/schema/lifetime/status policy |
| `data/adversarial_cases.json` | labelled 42-scenario evaluation corpus |
| `schemas/*.schema.json` | exact registration, evaluation, and governance profiles |
| `policies/opa/evidence_authz.rego` | OPA expression of the final verified-fact boundary |
| `policies/cedar/evidence_authz.cedar` | Cedar forbid precedence for negative evidence |
| `tests/test_evidence_runtime.py` | crypto, schema, replay, binding, privacy, property, and integration tests |

Run locally:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python lab.py
python -m pytest tests -q
```

## 15. Production upgrade path

| Training shortcut | Production replacement |
|---|---|
| deterministic Ed25519 keys | KMS/HSM-backed keys, provenance, rotation, compromise state |
| JWS-carried VC-shaped JSON | complete conformant VC securing mechanism and ecosystem profile |
| local JSON Schema files | governed immutable schemas/contexts with integrity and version policy |
| small signed status bitset | conformant Bitstring Status List or selected status profile |
| in-memory replay cache | durable atomic expiring store shared across verifier replicas |
| static issuer registry | authenticated configuration, safe resolution, audited lifecycle |
| EAT-shaped JWT | platform EAT profile, endorsements, reference values, verifier appraisal |
| hand-built DSSE envelope | maintained in-toto/Sigstore tooling and SLSA verification policy |
| fixed DCQL query | interoperable OpenID4VP client with consent/privacy controls |
| in-process evidence log | append-only privacy-governed telemetry plus effect receipts |
| fixed attack corpus | conformance, mutation, fuzz, rotation, outage, load, and incident suites |

Separate verifier, policy, and effect availability. Reauthorize at the effect
boundary and after any subject, holder, release, configuration, status, risk,
task, relationship, or policy-version change.

## 16. State of the art

### Established

- W3C VC 2.0, Data Integrity 1.0, JOSE/COSE, EdDSA/ECDSA cryptosuites, and
  Bitstring Status List 1.0 are 2025 W3C Recommendations;
- OpenID4VP 1.0 and OpenID4VCI 1.0 are 2025 OpenID Final Specifications;
- RFC 9901 defines SD-JWT, RFC 9334 defines the RATS architecture, and RFC 9711
  defines EAT;
- in-toto, SLSA, and Sigstore provide widely used supply-chain evidence
  patterns and tooling.

### Emerging in October 2026

- VC Data Model 2.1, Data Integrity 1.1, and Bitstring Status List 1.1 are W3C
  Working Drafts; use the 2.0/1.0 Recommendations as the stable baseline;
- SD-JWT VC draft 19 is in the IETF publication process but is not yet an RFC;
- digital credential browser/platform APIs and cross-ecosystem profiles continue
  to mature, so deployment profiles and conformance matter more than nominal
  format support.

### Open problems

- portable, interoperable agent registration and evaluation claim semantics;
- revocation and emergency offboarding across verifier caches and organizations;
- privacy-preserving proof of assurance without creating correlation handles;
- trustworthy model/config/tool-manifest measurement and invalidation rules;
- composing evidence with different authorities, clocks, scopes, and confidence;
- issuer and verifier governance when an AI evaluation itself is probabilistic;
- recovery after issuer, builder, wallet, or attester compromise.

## 17. Exercises

1. Add a suspension-purpose status list and define how suspension differs from
   revocation and expiry.
2. Add a second evaluator, then implement explicit conflict policy for one pass
   and one fail about the same release.
3. Add expiry and persistence to `ReplayCache`; prove two concurrent verifier
   replicas cannot both consume one presentation.
4. Implement an issuer key rotation with an overlap window and emergency
   compromise path.
5. Extend the DCQL query with a credential-set alternative while preserving
   minimum disclosure.
6. Replace the teaching status bitset with a conformant library and compare
   privacy, size, and caching behavior.
7. Verify a real Sigstore/in-toto fixture offline and bind it to the same release
   digest used by evaluation and workload evidence.
8. Design fail behavior for low-risk reads, claim updates, and payments during a
   status or attestation-verifier outage.

## 18. Review questions

1. What does a credential signature prove, and what does it not prove?
2. Why must issuer authority be scoped by credential type and claim vocabulary?
3. How do holder, subject, audience, nonce, and replay state prevent assurance
   laundering?
4. Why are `false` and `not disclosed` different policy inputs?
5. What is the difference between RATS Evidence, an Attestation Result, and a
   relying party authorization decision?
6. Why must registration, evaluation, workload evidence, and provenance share
   the exact release digest?
7. Which current negative evidence must override still-valid positive evidence?

## Primary references

- W3C, [Verifiable Credentials Data Model v2.0](https://www.w3.org/TR/vc-data-model-2.0/)
- W3C, [Verifiable Credential Data Integrity 1.0](https://www.w3.org/TR/vc-data-integrity/)
- W3C, [Securing Verifiable Credentials using JOSE and COSE](https://www.w3.org/TR/vc-jose-cose/)
- W3C, [Bitstring Status List v1.0](https://www.w3.org/TR/vc-bitstring-status-list/)
- W3C, [VC standards and drafts index](https://www.w3.org/TR/?tag=credentials)
- IETF, [Selective Disclosure for JWTs (RFC 9901)](https://www.rfc-editor.org/rfc/rfc9901)
- IETF, [SD-JWT-based Verifiable Digital Credentials draft](https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/)
- OpenID Foundation, [OpenID4VCI 1.0 Final](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-final.html)
- OpenID Foundation, [OpenID4VP 1.0 Final](https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html)
- IETF, [RATS Architecture (RFC 9334)](https://www.rfc-editor.org/rfc/rfc9334)
- IETF, [Entity Attestation Token (RFC 9711)](https://www.rfc-editor.org/rfc/rfc9711)
- SLSA, [SLSA specification v1.2](https://slsa.dev/spec/v1.2/)
- SLSA, [Build provenance v1](https://slsa.dev/spec/v1.2/build-provenance)
- in-toto, [Attestation Framework](https://github.com/in-toto/attestation/tree/main/spec)
- Secure Systems Lab, [DSSE specification](https://github.com/secure-systems-lab/dsse/blob/master/protocol.md)
- Sigstore, [cosign attestations](https://docs.sigstore.dev/cosign/verifying/attestation/)
- SPIFFE, [SPIFFE specifications](https://spiffe.io/docs/latest/spiffe-specs/)

## Next course

Advanced 05 moves from point-in-time evidence to continuously changing trust:
risk signals, event-driven revocation, trust decay, quarantine, step-up, and
adaptive privilege reduction during long-running agent activity.
