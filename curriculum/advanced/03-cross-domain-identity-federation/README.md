# Cross-Domain Identity Federation & Interoperability for Agents

**Level:** Advanced<br>
**Estimated time:** 5–7 hours<br>
**Format:** chapter, executed notebook, reusable Python lab, signed fixtures, configuration examples, and adversarial tests<br>
**Last reviewed:** 2026-10-12

> **Goal:** design, implement, and evaluate cross-domain agent access that verifies a foreign trust chain and workload identity, resists OAuth/MCP mix-up, preserves namespaces, and keeps authorization local and revocable.

An insurer sometimes needs a specialist agent operated by a partner. The partner
can prove the agent's identity, but it must not decide what that agent may do in
the insurer's environment. This course builds a credential-free version of that
boundary:

```text
partner federation metadata ─┐
partner OAuth access token ───┼─> corp federation gateway ─> local policy ─> MCP tool
partner X.509-SVID ───────────┤
corp delegation grant ────────┘
```

The valid agent can perform `knowledge.search` for one claim and one task. The
gateway rejects another issuer, trust anchor, bundle, workload, tenant, resource,
action, authorization server, policy version, or stale lifecycle state.

> The lab implements a small, security-focused teaching profile. It is not a
> complete OpenID Federation, OAuth, SPIFFE, or MCP implementation. Fixed time,
> deterministic private keys, and in-memory state are for reproducibility only.

## Learning outcomes

After this course you can:

1. separate discovery, trust establishment, authentication, identity mapping,
   delegation, and local authorization;
2. construct and verify signed OpenID Federation-style entity statements that
   terminate at a locally configured trust anchor;
3. explain deterministic hierarchical metadata-policy resolution and why a
   conflicting policy invalidates a chain;
4. verify a real X.509-SVID against an exact `<trust domain, bundle>` binding;
5. validate an access token against its verified federation subject, audience,
   lifetime, sender key, agent class, and local partner agreement;
6. preserve `(issuer, subject)` as a compound identity without importing
   foreign roles;
7. prevent OAuth authorization-server mix-up and unsafe MCP authorization-server
   selection;
8. constrain cross-domain delegation by tenant, task, audience, action,
   resource, purpose, lifetime, depth, and current policy;
9. test offboarding, stale metadata, rotation, namespace collision, and trust
   substitution; and
10. define measurable release and revocation objectives.

## Prerequisites

Complete the intermediate OAuth/OIDC, token exchange, MCP authorization, and
fine-grained authorization courses, followed by Advanced 01 and 02. You should
recognize JWT claims, JWKs, X.509 certificates, SPIFFE IDs, sender constraints,
and policy enforcement points.

## Success criteria

The reference path is complete when:

- all 46 labelled cases match their expected decision;
- invalid allows and valid-request blocks are both zero;
- all focused Python tests pass, including real JWT and X.509 verification;
- trust-chain, token, SVID, delegation, OAuth transaction, lifecycle, and local
  policy failures have stable reason codes;
- all notebook code runs top to bottom without credentials; and
- evidence records contain identifiers and hashes, never tokens or signatures.

## Non-goals

This course does not implement network discovery, the complete OpenID
Federation metadata-policy language, a SPIRE control plane, browser redirects,
dynamic client registration, or production key storage. Those belong to mature
libraries and deployed infrastructure. The lab makes the trust and authorization
invariants observable before introducing those systems.

## 1. Mental model: six separate decisions

“Federation” often hides several different operations:

| Decision | Question | Local source of authority |
|---|---|---|
| Discovery | Where is metadata or a key set? | protocol plus pinned starting point |
| Trust establishment | Why trust this issuer or workload domain? | trust anchor, bundle, partner agreement |
| Authentication | Which issuer and subject control this credential? | verified signature and claims |
| Mapping | Which local principal represents that compound identity? | deterministic namespace-preserving map |
| Delegation | What authority was intentionally conveyed? | verified, bounded grant |
| Authorization | May this exact request happen now? | local policy and current resource state |

Discovery is not trust. Authentication is not authorization. A trust mark is
evidence, not permission. A valid partner role named `admin` has no local meaning
unless local policy explicitly maps it—and broad role import is usually the
wrong design.

The effective authority is an intersection:

```text
verified federation subject
∩ verified workload identity
∩ valid delegation
∩ partner agreement
∩ protected-resource and AS binding
∩ local resource policy
∩ current lifecycle and risk state
```

Any empty intersection denies.

## 2. Trust domains and compound identity

A trust domain is an administrative and cryptographic boundary, not merely a
DNS suffix. These identities are different even when their local strings match:

```text
(https://id.partner-a.example, agent:research)
(https://id.partner-b.example, agent:research)
```

The lab maps the verified pair to a stable opaque local principal. It never
drops the issuer. Human-readable aliases may be displayed, but authorization
and audit evidence retain the qualified identity.

Never trust `email.endswith("@partner.example")`, an agent's self-declared
provider, a prompt claim, or a tool argument as identity. Derive issuer,
subject, workload, tenant, and relationship from authenticated application
state.

## 3. OpenID Federation 1.0 mechanics

[OpenID Federation 1.0](https://openid.net/specs/openid-federation-1_0.html)
became an OpenID Final Specification on 17 February 2026. It supports
multilateral trust through signed entity statements and configured trust
anchors. It standardizes trust operations and resolved metadata; it does not
replace OAuth/OIDC protocol operations or local authorization.

### Entity statements and chain order

The lab chain is:

```text
ES[0]  issuer leaf,         subject leaf          (self-issued configuration)
ES[1]  issuer intermediate, subject leaf          (subordinate statement)
ES[2]  issuer trust anchor, subject intermediate  (subordinate statement)
```

For each adjacent pair:

```text
ES[j].iss == ES[j+1].sub
```

The accepted trust anchor is the **issuer of the final statement**, not its
subject. Every statement is signed and time-bounded. The verifier also checks
authority hints, distinct statement IDs, maximum chain length, path constraints,
and exact leaf approval.

The anchor identifier and public key are local configuration. Finding an anchor
name in a downloaded document is not sufficient.

### Federation entity discovery

In a real deployment, discovery begins with the leaf entity identifier and a
local list of trust-anchor identifiers and keys. Entity configurations and
subordinate statements are collected until one or more candidate chains reach
an accepted anchor. Every candidate is independently validated. If several
chains are valid, deterministic local selection policy chooses one.

Network retrieval adds SSRF, redirect, DNS, TLS, size, timeout, caching, and
content-type concerns. The offline lab deliberately begins after retrieval and
does not imply that arbitrary URLs are safe to fetch.

### Metadata policy

Superior entities can constrain subordinate metadata. Policies are resolved
from the most superior statement toward the leaf. A subordinate can narrow a
constraint; it cannot repeal or widen a superior constraint. Conflicts make the
chain invalid.

The lab executes a documented subset—`essential`, `subset_of`, and `one_of`—for
authorization-server metadata. The anchor permits `private_key_jwt` or
`tls_client_auth`; the intermediate narrows this to `private_key_jwt`; the leaf
must comply. A production implementation must support the complete Final
Specification, critical operators, metadata overlays, constraints, and all
required validation.

### Trust marks

A trust mark is a signed statement of conformance to a well-scoped requirement.
Local policy still decides:

- whether the trust-mark issuer is approved;
- which mark type matters for this operation;
- whether the mark is current and unrevoked; and
- what, if any, authorization attribute it contributes.

Do not convert “member of federation” into “may access every member.”

## 4. SPIFFE federation mechanics

A SPIFFE ID is a URI such as:

```text
spiffe://partner.example/prod/research-agent
```

An X.509-SVID proves control of a private key and carries the SPIFFE ID in a URI
SAN. A bundle contains the public trust material for one trust domain. The key
invariant from the
[SPIFFE Trust Domain and Bundle specification](https://spiffe.io/docs/latest/spiffe-specs/spiffe_trust_domain_and_bundle/)
is the independently managed tuple:

```text
<trust-domain name, bundle>
```

If an attacker can replace both sides of that association, certificate
verification can succeed for the attacker's domain material. The lab pins a
SHA-256 fingerprint for its synthetic bundle, verifies the X.509 signature and
lifetime, extracts exactly one URI SAN, and requires the exact allowed SPIFFE
ID.

### Bundle endpoints and rotation

[SPIFFE Federation](https://spiffe.io/docs/latest/spiffe-specs/spiffe_federation/)
defines `https_web` and `https_spiffe` bundle endpoint profiles. Endpoint
configuration is security-sensitive. TLS validation, expected host or endpoint
SPIFFE ID, redirects, bootstrap bundle, and profile must be protected.

New signing keys should be published before use; old keys remain until all SVIDs
they signed have expired. The lab's rotation test proves that a new bundle is
rejected until the local fingerprint binding is explicitly updated.

Federation is directional. If corp accepts partner SVIDs, partner does not
automatically accept corp SVIDs. Mutual authentication requires deliberate
configuration in both directions.

SPIFFE authenticates workloads. It does not prove a user delegation, task,
purpose, or permission on `claim:483`.

## 5. OAuth and MCP across multiple issuers

The partner issuer signs a short-lived access token. The gateway checks:

- `typ`, pinned asymmetric algorithm, exact `kid`, and signature;
- issuer equality with the verified federation leaf and partner agreement;
- exact MCP resource audience;
- current `iat`/`exp` and maximum partner TTL;
- non-empty subject, tenant, task, and token ID;
- allowed agent class, action set, and resource set; and
- sender-key thumbprint when the agreement requires sender constraint.

The token does not import foreign roles into local roles.

### Protected Resource Metadata

[RFC 9728](https://www.rfc-editor.org/rfc/rfc9728) defines OAuth Protected
Resource Metadata. Its `authorization_servers` list advertises issuer
identifiers that can be used with the resource. The RFC explicitly leaves
secure determination of an appropriate authorization server to the application.

Therefore the gateway requires:

```text
metadata.resource == exact expected resource
advertised AS ∩ locally approved AS == exactly one issuer
authorization response issuer == transaction's expected issuer
```

Metadata naming an authorization server does not automatically approve it.

### Mix-up defense

An OAuth client that supports multiple authorization servers can be tricked into
combining an authorization endpoint from one issuer with credentials or a token
endpoint from another. [OAuth 2.0 Security Best Current Practice, RFC 9700](https://www.rfc-editor.org/rfc/rfc9700)
requires a mix-up defense. The lab binds a transaction to the expected issuer
and state, compares the authorization response `iss`, and consumes the response
once. Production clients should follow RFC 9207 and the applicable OIDC/OAuth
profile, use PKCE, exact redirect matching, and issuer-bound client credentials.

### MCP state of practice

The [MCP 2026-07-28 release](https://modelcontextprotocol.io/specification/2026-07-28)
is the current stable protocol revision as of this review. Its authorization
hardening includes RFC 9207 issuer validation and binding registered credentials
to their issuer. The older 2025-11-25 revision remains relevant for migration,
but new course guidance targets the current stable release.

An MCP server must not pass an inbound token blindly to a downstream API. Use a
resource-specific token or controlled token exchange, and reauthorize at each
effect boundary.

## 6. Local cross-domain delegation

The corp authority signs a delegation grant for the foreign compound identity.
It binds:

```text
grant ID + issuer
foreign issuer + subject
tenant + task
MCP audience
actions + resources + purpose
issue time + expiry
delegation depth
local policy version
```

Verification checks the signature and intersects grant authority with both the
partner token and the federation agreement. The grant cannot outlive the access
token or exceed maximum depth. The gateway then compares the exact request to
the grant and current local policy.

This is deliberately asymmetric: the partner proves its identity and token
claims; corp grants access to corp resources.

## 7. Trust registry and lifecycle

`data/trust_registry.json` models locally governed trust, not model context. A
relationship records status, exact issuers and anchor, bundle fingerprint,
audiences, agent classes, actions, resources, workload IDs, authorization
servers, time and depth bounds, sender-constraint requirement, freshness, and
policy version.

Lifecycle states should distinguish at least proposed, active, suspended,
terminating, and removed. Partner offboarding must invalidate more than a portal
record:

1. disable the federation relationship;
2. reject new trust chains and tokens;
3. remove or quarantine foreign bundles and keys;
4. invalidate local mappings and authorization caches;
5. revoke delegations and issuer-bound OAuth client credentials;
6. stop affected MCP and API sessions; and
7. retain immutable evidence for investigation and compliance.

Define measurable objectives such as:

```text
partner suspension → sensitive authorization denied within 30 seconds
key compromise     → emergency bundle/JWKS refresh begins immediately
planned rotation   → no valid SVID or token interruption
```

Availability posture is operation-specific. A low-risk read might use a bounded
last-known-good metadata window. A financial write should normally fail closed.
Staleness must be measured and visible—not hidden behind a successful cache hit.

## 8. Technology landscape

| Approach | Best fit | Strengths | Limitations / selection questions |
|---|---|---|---|
| Bilateral OIDC/OAuth | a few known partners | mature libraries and operations | configuration grows pairwise; mix-up and issuer isolation matter |
| OpenID Federation 1.0 | multilateral trust ecosystems | signed metadata, chains, hierarchical policy | newer Final Specification; require complete compliant implementation and governance |
| SAML federation | existing workforce/B2B estates | mature enterprise support | XML and browser-centric profiles; weak fit for workload identity alone |
| SPIFFE/SPIRE | workload-to-workload federation | short-lived SVIDs, automated rotation, platform neutrality | authenticates workload, not business delegation; control-plane operations required |
| Cloud workload federation | cross-cloud or CI access | avoids static secrets, native IAM integration | provider-specific semantics and subject mapping |
| Identity broker/gateway | legacy translation and protocol mediation | central integration and policy point | concentration risk, namespace errors, evidence loss, availability dependency |
| Local policy engine | resource authorization | explicit local control and reason codes | requires trusted, current inputs; foreign role names are not portable policy |

### Common implementation tools

- **PyJWT + cryptography:** transparent teaching of JWT and Ed25519/X.509
  primitives; production code still needs a complete protocol library.
- **Authlib or mature OIDC client libraries:** OAuth/OIDC protocol handling,
  discovery, PKCE, and response validation; confirm OpenID Federation support
  rather than assuming ordinary discovery implements it.
- **SPIRE:** CNCF reference implementation for SPIFFE issuance and federation.
  Officially maintained workload libraries are strongest in Go and Java;
  evaluate community-language clients deliberately.
- **MCP Tier 1 SDKs:** current protocol and authorization integration for remote
  MCP clients/servers; enable and test current issuer-hardening behavior.
- **OPA, Cedar, relationship stores, or cloud IAM:** local authorization after
  foreign identity verification. Engine choice does not change the trust
  boundary.

## 9. Architecture patterns

### Bilateral

Each pair configures the other directly. It is simple and explicit for a small
partner set, but rotation, policy consistency, and offboarding scale poorly.

### Hub-and-spoke federation authority

A governed authority anchors many participants. It reduces pairwise
configuration and can apply common metadata policy. It also becomes critical
infrastructure and a governance concentration point.

### Brokered identity translation

A gateway verifies the foreign identity and issues a local short-lived
credential. Preserve original issuer, subject, chain, and mapping policy in
evidence. The new credential must be narrower, audience-bound, and short-lived.

### Workload federation plus local delegation

SPIFFE authenticates the foreign runtime; a signed business delegation and local
policy determine resource authority. This is the pattern implemented by the lab
because it exposes each trust layer instead of collapsing them.

## 10. Threat model and failure behavior

| Threat | Required control | Expected outcome |
|---|---|---|
| valid token from unknown issuer | exact issuer and verified chain | deny |
| substituted anchor or chain link | pinned anchor, every signature/link | deny |
| permissive or conflicting metadata | hierarchical policy resolution | invalidate chain |
| algorithm downgrade | local algorithm allowlist plus superior policy | deny |
| namespace collision | issuer-qualified subject mapping | distinct principals |
| bundle substitution | exact domain-to-bundle binding | deny |
| wrong SPIFFE path | exact workload allowlist | deny |
| foreign `admin` role | no direct local-role import | no local privilege |
| authorization-server mix-up | issuer-bound transaction and response `iss` | abort flow |
| malicious PRM advertisement | intersect with local AS allowlist | deny/require selection |
| token redirection | resource/audience binding | deny |
| delegation widening | set intersection and independent local policy | deny |
| stale metadata or partner suspension | freshness and current relationship checks | deny or explicit bounded mode |
| trust path exists through another partner | directed path is not an implicit trust edge | no authority |

## 11. Evidence and observability

The gateway records observable facts:

- trace and logical operation IDs;
- decision and stable reason code;
- foreign issuer and hashed foreign subject;
- verified workload ID;
- audience and resource;
- trust-chain digest; and
- federation-policy version.

Do not log raw tokens, private keys, authorization codes, DPoP proofs,
delegation signatures, or unnecessary personal data. A “request authorized”
event is not proof that a downstream effect completed. Record effect receipts
from the system of record separately.

Operational metrics include trust-resolution latency, chain cache age, unknown
key IDs, metadata-policy conflicts, bundle/JWKS refresh errors, mix-up attempts,
denials by reason, partner offboarding propagation, valid work blocked, and
invalid requests allowed.

## 12. Evaluation

The lab contains one valid scenario and 45 labelled denials across trust chain,
metadata policy, token, workload, delegation, MCP/OAuth, lifecycle, and local
policy.

```text
invalid_allow_rate = invalid cases allowed / invalid cases
valid_block_rate   = valid cases denied / valid cases
accuracy           = matching labels / all labelled cases
```

Release gate:

```text
cases >= 30
invalid allows == 0
valid blocks == 0
accuracy == 1.0
```

This gate validates declared invariants, not Internet-scale interoperability.
Production assurance also requires official conformance tests, parser fuzzing,
network and redirect tests, multiple valid-chain selection, latency/load tests,
key and bundle rotation drills, restart and cache consistency, and partner
incident exercises.

## 13. Lab map

| Artifact | Purpose |
|---|---|
| `advanced_03_cross_domain_federation.ipynb` | executed learner journey and failure analysis |
| `lab.py` | canonical reference implementation and labelled corpus |
| `advanced_federation_runtime.py` | collision-safe import facade |
| `data/trust_registry.json` | locally governed relationship example |
| `configs/mcp/protected-resource-metadata.json` | RFC 9728 resource metadata example |
| `configs/spiffe/federation-example.yaml` | bundle endpoint plus separate application policy example |
| `tests/test_federation_runtime.py` | cryptographic, policy, property, SDK, and integration tests |

Run locally:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python lab.py
python -m pytest tests -q
```

## 14. Production upgrade path

| Training shortcut | Production replacement |
|---|---|
| deterministic Ed25519 keys | KMS/HSM-backed keys, rotation state, key provenance |
| pre-fetched JWT strings | bounded network fetcher with SSRF/redirect/TLS controls |
| partial metadata operators | complete compliant OpenID Federation implementation |
| one candidate chain | discover, validate, and deterministically select among chains |
| synthetic X.509-SVID | SPIRE Workload API, automated SVID and bundle rotation |
| pinned fingerprint in JSON | protected federation configuration and audited rollout |
| in-memory OAuth transaction | encrypted durable, atomic, expiring transaction store |
| custom delegation envelope | reviewed capability/token-exchange profile |
| static local policy facts | authenticated, versioned relationship/resource/risk services |
| in-process evidence list | append-only privacy-governed telemetry and effect receipts |
| fixed case set | incidents, mutations, conformance, fuzz, load, and chaos suites |

Separate control-plane and data-plane availability. Cache only validated
artifacts until their bounded expiry. Protect against stampedes. Define unknown
key behavior, emergency refresh, rollback, and stale-on-error by risk tier.
Reauthorize on delayed effects and after any identity, delegation, relationship,
resource, or policy version changes.

## 15. State of the art

### Established

- issuer/audience/time/signature validation, OAuth metadata, PKCE, and mix-up
  defenses from current OAuth BCP;
- workload federation with short-lived identities and rotating bundles;
- explicit local policy after federated authentication; and
- namespace-qualified principal mapping and governed partner lifecycle.

### Newly standardized and rapidly maturing

- OpenID Federation 1.0 is a 2026 Final Specification. Its trust-chain and
  metadata-policy model is standardized, while deployment experience,
  conformance tooling, and library coverage are still growing relative to OIDC;
- MCP 2026-07-28 strengthens issuer validation and issuer-bound client
  credentials for its many-server authorization setting.

### Emerging and open problems

- interoperable identity and delegation profiles for autonomous agents;
- portable assurance without converting trust marks into ambient authority;
- revocation and emergency offboarding across organizational caches;
- privacy-preserving cross-domain correlation and audit;
- safe automated trust discovery without configuration poisoning; and
- consistent policy semantics across heterogeneous organizations.

## 16. Exercises

1. Add a second valid trust chain and implement deterministic selection policy.
2. Add the full OpenID Federation `value`, `add`, and `default` operators with
   conflict tests; compare your behavior with a conformant implementation.
3. Model planned SPIFFE bundle rotation with old/new overlap and prove there is
   neither unauthorized acceptance nor an availability gap.
4. Add an OAuth transaction expiry and concurrent double-completion test.
5. Implement a signed trust mark, then prove that it contributes one attribute
   without granting an action directly.
6. Add a brokered local credential and verify it is narrower and retains source
   evidence.
7. Define fail behavior for read-only research, claim updates, and payments.
8. Design an offboarding drill with measurable cache and authorization SLOs.

## 17. Review questions

1. Why is the final entity statement's issuer—not subject—the trust anchor in
   this chain shape?
2. Why must metadata policy be resolved before using discovered endpoints?
3. What does an X.509-SVID prove, and which business facts does it not prove?
4. How does preserving `(issuer, subject)` prevent namespace collision?
5. Why is an authorization server advertised by an MCP resource not
   automatically acceptable?
6. Which state must be invalidated when a partner is suspended?

## Primary references

- OpenID Foundation, [OpenID Federation 1.0 Final](https://openid.net/specs/openid-federation-1_0.html)
- OpenID Foundation, [Final Specification approval announcement](https://openid.net/openid-federation-1-0-final-specification-approved/)
- SPIFFE, [SPIFFE Identity and Verifiable Identity Document](https://spiffe.io/docs/latest/spiffe-specs/spiffe-id/)
- SPIFFE, [SPIFFE Trust Domain and Bundle](https://spiffe.io/docs/latest/spiffe-specs/spiffe_trust_domain_and_bundle/)
- SPIFFE, [SPIFFE Federation](https://spiffe.io/docs/latest/spiffe-specs/spiffe_federation/)
- IETF, [OAuth 2.0 Authorization Server Metadata (RFC 8414)](https://www.rfc-editor.org/rfc/rfc8414)
- IETF, [OAuth 2.0 Authorization Server Issuer Identification (RFC 9207)](https://www.rfc-editor.org/rfc/rfc9207)
- IETF, [OAuth 2.0 Security Best Current Practice (RFC 9700)](https://www.rfc-editor.org/rfc/rfc9700)
- IETF, [OAuth 2.0 Protected Resource Metadata (RFC 9728)](https://www.rfc-editor.org/rfc/rfc9728)
- IETF, [OAuth 2.0 Resource Indicators (RFC 8707)](https://www.rfc-editor.org/rfc/rfc8707)
- Model Context Protocol, [2026-07-28 specification](https://modelcontextprotocol.io/specification/2026-07-28)
- [PyJWT documentation](https://pyjwt.readthedocs.io/)
- [cryptography X.509 documentation](https://cryptography.io/en/latest/x509/)
- [NetworkX documentation](https://networkx.org/documentation/stable/)

## Next course

Advanced 04 moves from federation to portable evidence about agents:
attestations, verifiable credentials, assurance signals, trust evidence,
revocation, selective disclosure, and policy use of claims.
