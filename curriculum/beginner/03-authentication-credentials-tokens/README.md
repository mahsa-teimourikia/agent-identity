# Beginner 03 — Authentication, Credentials and Tokens

> **Goal:** understand how humans, agents, workloads, and services prove identity, how credentials differ, and how to validate tokens safely before moving into OAuth/OIDC and production workload identity.

Course 01 separated identity, authentication, authorization, and delegation. Course 02 separated human, logical-agent, application, workload, service, and resource identities. This course adds the next layer:

> **How does a principal prove an identity claim?**

The answer is a credential plus a verification process—not an agent name, prompt, decoded JWT payload, or arbitrary metadata.

---

## Learning outcomes

By the end you should be able to:

- distinguish identifiers, secrets, keys, credentials, certificates, and tokens;
- explain shared-secret versus asymmetric authentication;
- explain bearer versus sender-constrained credentials;
- understand JWT, JWS, JWK, and JWKS roles;
- create and verify signed JWTs;
- validate issuer, audience, expiry, not-before, token type, and algorithm;
- explain why decoding a JWT is not authentication;
- understand key IDs and key rotation;
- explain X.509 certificates and mTLS conceptually;
- understand replay attacks and proof-of-possession;
- compare API keys, bearer tokens, signed assertions, certificates, and workload credentials;
- choose safer credential patterns for agents.

## Prerequisites, success criteria, and non-goals

Complete [Course 01 — Agent Identity Foundations](../01-agent-identity-foundations/README.md) and [Course 02 — Humans, Workloads and Agents](../02-humans-workloads-agents/README.md) first. You need basic Python and HTTP concepts. The practical work uses the repository-managed PyJWT and cryptography libraries without credentials or network access.

The practical work succeeds when:

- valid tokens signed by the active key and an intentionally overlapping retiring key remain accepted;
- signature tampering, wrong issuer/audience/type, unknown or revoked keys, invalid time windows, missing claims, unknown subjects/actions, and replay fail closed;
- invalid acceptance falls from `12/14` attempts in the signature-only baseline to `0/14` in the hardened verifier;
- the second use of the synthetic single-use action assertion is rejected atomically; and
- decisions record a digest, key ID, policy version, checks, and reason code—never the raw token.

The course lab defines a synthetic `agent-action+jwt` profile to teach verification mechanics. It is not an OAuth access-token, ID-token, DPoP, mTLS, or SPIFFE implementation. Ordinary access tokens are not generally single-use; the replay cache here applies to a consequential action assertion. Later courses cover OAuth, token exchange, workload identity, and authorization.

---

# 1. Identifier, credential, secret, and key

These terms are often mixed together.

## Identifier

An identifier names a principal:

```text
agent:procurement
user:alice
spiffe://corp.example/prod/refund-agent
```

It is not proof.

## Secret

A secret is confidential data whose possession may authenticate a party:

```text
API key
client secret
password
symmetric signing key
```

Secrets must remain confidential.

## Cryptographic key

A symmetric key is shared by parties.

An asymmetric key pair contains:

```text
private key -> kept secret
public key  -> distributable
```

The private key can create signatures; the public key can verify them.

## Credential

A credential is evidence presented or used to establish a security property about a principal.

Examples:

- password;
- API key;
- signed JWT;
- X.509 certificate plus proof of private-key possession;
- OAuth access token;
- SPIFFE SVID.

---

# 2. Authentication is verification

A robust mental model:

```text
Principal
   |
   | presents credential / proof
   v
Verifier
   |
   +-- validate cryptography
   +-- validate issuer/trust
   +-- validate time
   +-- validate audience
   +-- validate token/profile rules
   |
   v
Authenticated principal
```

Do not start authorization until authentication succeeds.

---

# 3. Shared-secret authentication

A simple API key model:

```text
Agent ----------------> API
       X-API-Key: ...
```

Advantages:

- simple;
- widely supported.

Weaknesses:

- whoever possesses it can normally use it;
- difficult attribution when shared;
- static keys become long-lived standing credentials;
- rotation can be operationally painful;
- accidental logging/exfiltration is common;
- often no built-in audience, expiry, or scope semantics.

An API key is not automatically bad. A **shared, long-lived, overprivileged key embedded in agent code** is.

---

# 4. Asymmetric authentication

With public-key cryptography:

```text
Agent                         Verifier
private key                   public key
    |                             |
    +---- sign challenge -------->|
                                  |
                            verify signature
```

The verifier does not need the private key.

This supports stronger patterns such as:

- signed client assertions;
- certificate authentication;
- mTLS;
- proof-of-possession;
- signed tokens.

Current OAuth security BCP recommends asymmetric client authentication where feasible, including mTLS or `private_key_jwt`.

---

# 5. Bearer credentials

A bearer credential follows the basic rule:

> Whoever bears the credential can use it.

Conceptually:

```text
Authorization: Bearer eyJ...
```

If an attacker steals the token and the resource server accepts it, the attacker can replay it until it expires or is revoked/otherwise invalidated.

Mitigations include:

- TLS;
- short lifetimes;
- narrow audience;
- narrow privileges;
- secure storage;
- preventing tokens from entering prompts/logs;
- sender-constrained tokens where appropriate.

---

# 6. Sender-constrained credentials

A sender-constrained token is bound to a cryptographic key or certificate.

A stolen token alone is insufficient.

```text
Access Token
     +
proof of private key possession
     |
     v
Resource Server
```

Modern OAuth security guidance recommends sender-constraining access tokens where appropriate, using mechanisms such as:

- mutual TLS;
- DPoP (Demonstrating Proof of Possession).

This is particularly interesting for autonomous agents because token replay is a realistic consequence of logs, traces, tool arguments, prompt injection, compromised plugins, or middleware.

---

# 7. JWT is a format, not an authentication strategy

A JSON Web Token is a compact claims container.

Typical signed JWT:

```text
BASE64URL(header)
.
BASE64URL(payload)
.
BASE64URL(signature)
```

Example header:

```json
{
  "alg": "RS256",
  "kid": "agent-key-2026-08",
  "typ": "JWT"
}
```

Example claims:

```json
{
  "iss": "https://identity.example",
  "sub": "agent:procurement",
  "aud": "https://purchasing.example",
  "iat": 1787090000,
  "exp": 1787090300
}
```

A JWT may play different protocol roles:

- access token;
- ID token;
- client assertion;
- workload identity token;
- custom application token.

**Do not infer semantics merely because something is a JWT.**

---

# 8. JWT versus JWS versus JWE

## JWT

Defines claims and token structure.

## JWS

JSON Web Signature provides integrity/authenticity through digital signatures or MACs.

A signed JWT is normally represented as a JWS.

## JWE

JSON Web Encryption protects confidentiality.

A signed JWT is not encrypted merely because it looks unreadable.

Anyone holding a normal signed JWT can generally Base64URL-decode its header and payload.

Therefore:

> Never put secrets in JWT claims just because the token is signed.

---

# 9. Claims that matter

Common registered claims:

| Claim | Meaning |
|---|---|
| `iss` | issuer |
| `sub` | subject |
| `aud` | intended audience |
| `exp` | expiration |
| `nbf` | not valid before |
| `iat` | issued at |
| `jti` | unique token identifier |

For agent identity:

```json
{
  "iss": "https://sts.corp.example",
  "sub": "agent:refund-specialist",
  "aud": "refund-api",
  "exp": 1787090300
}
```

These values are security-relevant only when the verifier validates them according to the expected token profile.

---

# 10. Decoding is not verifying

This is one of the most important practical lessons.

Unsafe:

```python
claims = jwt.decode(token, options={"verify_signature": False})
print(claims["sub"])
```

The payload can be created by anyone.

Safe verification must establish at least the relevant combination of:

```text
signature
algorithm
trusted key
issuer
audience
expiry
not-before
token type/profile
required claims
```

The exact rules depend on the protocol.

---

# 11. Algorithm confusion and allowlists

JWT libraries should not blindly trust an incoming `alg`.

RFC 8725's JWT Best Current Practices requires algorithm verification and recommends explicit application-level algorithm choices.

Conceptually:

```python
jwt.decode(
    token,
    public_key,
    algorithms=["RS256"],
    issuer=EXPECTED_ISSUER,
    audience=EXPECTED_AUDIENCE,
)
```

Do not derive your trusted algorithm set from attacker-controlled token input.

---

# 12. Issuer validation

Suppose two identity systems both issue valid RS256 JWTs.

A cryptographically valid token from the wrong issuer must not authenticate into your security domain.

```text
signature valid != issuer trusted
```

The verifier needs an expected issuer:

```text
iss == https://identity.corp.example
```

and the correct trust material for that issuer.

---

# 13. Audience restriction

Audience answers:

> For which recipient/service is this token intended?

Without audience restriction:

```text
token issued for Analytics API
          |
          | replay
          v
Payments API
```

may become possible if both accept the same token format/key.

Correct:

```text
aud = payments-api
```

and Payments API validates it.

SPIFFE JWT-SVID requires an audience and recommends keeping it narrowly scoped to the intended service.

---

# 14. Time validation

Short-lived credentials reduce exposure.

Relevant claims:

```text
iat -> issued at
nbf -> not valid before
exp -> expires
```

Resource servers should reject expired credentials.

Small clock-skew allowances may be necessary, but large leeway silently extends credential life.

For autonomous workloads, minutes are often preferable to months where infrastructure supports automatic renewal.

---

# 15. Token type confusion

Two JWTs may look almost identical but represent different things:

```text
ID Token
Access Token
Client Assertion
Agent Delegation Token
JWT-SVID
```

A validator must apply **mutually exclusive validation rules** for different token kinds.

RFC 8725 specifically warns about cross-JWT confusion and recommends explicit typing and distinct validation rules.

Never accept an ID token as an API access token merely because its signature verifies.

---

# 16. JWK and JWKS

A JSON Web Key represents cryptographic key material.

Example public RSA JWK:

```json
{
  "kty": "RSA",
  "kid": "2026-08-key-1",
  "use": "sig",
  "alg": "RS256",
  "n": "...",
  "e": "AQAB"
}
```

A JWKS is a set of JWKs:

```json
{
  "keys": [
    {...},
    {...}
  ]
}
```

Why sets?

Key rotation.

```text
token header: kid=key-B
                 |
                 v
             JWKS lookup
                 |
                 v
          public key B
```

---

# 17. Key rotation

A safe issuer must rotate signing keys without breaking all outstanding tokens.

Typical transition:

```text
T0: publish A, sign A
T1: publish A+B, sign B
T2: old A tokens expire
T3: remove A
```

Consumers should support multiple currently valid public keys.

Do not immediately delete an old verification key while valid tokens signed by it still exist.

---

# 18. JWKS trust is not "fetch any URL"

A dangerous anti-pattern is allowing a token to dictate an arbitrary key location and then trusting it.

The verifier should bind:

```text
expected issuer
     |
     v
configured/discovered trusted JWKS
```

not:

```text
attacker token -> attacker URL -> attacker key -> "valid"
```

Treat key-discovery configuration as security-sensitive.

---

# 19. X.509 certificates

An X.509 certificate binds identity-related information to a public key and is signed by a certificate authority.

Conceptually:

```text
Certificate
  subject / SAN
  public key
  validity
  issuer
  extensions
  CA signature
```

Verification includes:

- chain to a trusted CA;
- validity period;
- expected identity/name;
- intended usage;
- revocation/status where applicable;
- proof that the peer possesses the corresponding private key.

A certificate file by itself is not proof of private-key possession.

---

# 20. TLS versus mutual TLS

Ordinary HTTPS commonly authenticates the server:

```text
Client ---- verifies server certificate ----> Server
```

mTLS authenticates both peers:

```text
Client <---- mutual certificate proof ----> Server
```

For workload-to-workload communication this can provide strong, key-bound identity.

SPIFFE X.509-SVIDs are designed to support workload authentication and mTLS-like patterns without provisioning static certificates manually.

---

# 21. SPIFFE SVIDs

SPIFFE separates:

```text
SPIFFE ID -> identity
SVID      -> verifiable identity document
```

Current Workload API profiles include:

- X.509-SVID;
- JWT-SVID;
- WIT-SVID (incubating/optional).

X.509-SVID and JWT-SVID profiles are mandatory in the current Workload API specification, though operators may disable profiles administratively.

SPIRE can obtain evidence about the workload and deliver short-lived SVIDs through the Workload API.

This eliminates many long-lived secret-distribution patterns.

---

# 22. X.509-SVID versus JWT-SVID

## X.509-SVID

Good fit for:

- direct workload-to-workload connections;
- mutual TLS;
- automatic rotation;
- strong proof-of-possession through TLS private keys.

## JWT-SVID

Useful when:

- authentication must cross Layer-7 boundaries;
- a proxy/load balancer makes direct mTLS identity difficult;
- JWT-compatible infrastructure is required.

But JWT-SVID is a bearer-style token and replay must be considered. SPIFFE documentation recommends X.509-SVID where practical because token credentials are susceptible to replay.

---

# 23. Replay attack

Imagine:

```text
Agent -> API
Authorization: Bearer TOKEN-123
```

An attacker obtains `TOKEN-123` from:

- application logs;
- tracing;
- debug output;
- compromised middleware;
- accidental prompt inclusion;
- browser storage;
- network compromise without TLS.

Then:

```text
Attacker -> API
Authorization: Bearer TOKEN-123
```

The API cannot distinguish the attacker from the original bearer based on token possession alone.

Short expiry limits the window; sender constraint changes the proof requirement.

---

# 24. DPoP mental model

DPoP binds an OAuth token to a public key.

The client creates a signed proof for a request.

Conceptually:

```text
client key pair
     |
     +--> token bound to public key
     |
     +--> signed DPoP proof for HTTP request
                    |
                    v
             Resource Server
             validates:
             - token
             - key binding
             - proof
             - request target/method
```

Stealing only the access token is therefore insufficient.

We implement the real protocol later in the OAuth course; here the important concept is **proof of possession**.

---

# 25. Credential comparison

| Credential | Typical proof model | Strengths | Common risks |
|---|---|---|---|
| Password | shared knowledge | human-compatible | phishing/reuse |
| API key | bearer/shared secret | simple | leakage, no built-in expiry |
| Bearer access token | possession | scoped/protocol-friendly | replay |
| Signed JWT assertion | private-key signature | asymmetric | validation mistakes |
| X.509 cert + TLS proof | private-key possession | strong mutual auth | PKI complexity |
| JWT-SVID | signed bearer token | workload-friendly L7 | replay |
| X.509-SVID | cert + private key | short-lived workload identity | direct PKI integration needed |
| DPoP-bound token | token + key proof | replay resistance | implementation complexity |

---

# 26. Credentials should not enter prompts

Never intentionally put credentials into:

```text
system prompts
user prompts
tool descriptions
retrieved documents
model-visible scratchpads
```

The model does not need raw secrets to decide that a tool should be called.

Preferred architecture:

```text
LLM
 |
 | proposes tool call
 v
Trusted Tool Gateway
 |
 | obtains/selects credential
 v
Protected API
```

Credential management belongs outside model context.

---

# 27. Credential broker pattern

A mature agent platform can separate reasoning from credential issuance.

```text
Agent Runtime
     |
     | requests credential for:
     | actor + task + audience
     v
Credential Broker / STS
     |
     | policy
     v
short-lived credential
     |
     v
Target API
```

Later courses add OAuth Token Exchange, workload federation, and task-scoped authorization to this pattern.

---

# 28. Common anti-patterns

### Decode JWT without signature verification
Claims are attacker-controlled.

### Validate signature but not audience
A token may be replayed at the wrong service.

### Validate signature but not issuer
A token from an untrusted domain may be accepted.

### Accept arbitrary algorithms
Creates algorithm-confusion risk.

### Use one symmetric JWT key everywhere
Compromise of any verifier that knows the secret may enable token forgery.

### Put API keys in source code
Creates long-lived secret exposure.

### Put tokens in logs
Turns observability systems into credential stores.

### Months-long workload tokens
Increase compromise window.

### Use ID tokens as access tokens
Creates token-type confusion.

### Trust arbitrary JWKS URLs from token data
Can turn attacker-controlled keys into trusted verification material.

---

# 29. Technology landscape

| Technology | Best fit | Strengths | Important boundary |
| --- | --- | --- | --- |
| [PyJWT](https://pyjwt.readthedocs.io/en/stable/usage.html) | focused Python JWT/JWS encoding and verification | widely used, explicit algorithm list, issuer/audience/required-claim validation, JWK/JWKS helpers | application must define token profile, trusted issuer/key source, time/lifetime, subject, type, and replay semantics |
| [joserfc](https://jose.authlib.org/en/guide/) | broader JOSE/JWK/JWS/JWE work | explicit registry and key models, part of Authlib ecosystem | flexibility increases the need for a narrow application profile |
| [cryptography](https://cryptography.io/en/latest/) | keys, signatures, X.509, TLS-adjacent primitives | maintained low-level primitives and certificate APIs | not an identity protocol, issuer registry, or authorization engine |
| OAuth/OIDC client and resource-server SDKs | standards-based delegated API access and login | discovery, grants, token validation, refresh/session support | ID tokens, access tokens, client assertions, and DPoP proofs have different profiles |
| SPIFFE SDKs / Workload API | attested, rotated workload identity | X.509-SVID/JWT-SVID retrieval, trust bundles, federation | establishes workload identity; application authorization remains separate |
| API gateway / service mesh validators | consistent edge or service authentication | centralized configuration, telemetry, mTLS integration | downstream resources must prevent bypass and retain consequential authorization |

The lab uses PyJWT and cryptography because they expose the primitive directly. Production code should normally use the official SDK or middleware for its identity provider and protocol profile, then apply resource-side policy to the verified result.

# 30. State of the art (September 2026)

## Established practice

- JWT/JWS/JWK are stable JOSE building blocks. RFC 8725 remains the JWT Best Current Practice: allowlist algorithms, bind keys to issuers, validate audience, avoid blindly following received URLs, and use explicit typing where cross-JWT confusion is possible ([RFC 8725](https://www.rfc-editor.org/rfc/rfc8725.html)).
- OAuth 2.0 Security BCP recommends audience restriction, short privilege, asymmetric client authentication where feasible, and sender-constrained access tokens using mTLS or DPoP where appropriate ([RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html)).
- Key rotation requires an overlap window: a new key signs while an old key may remain trusted only until tokens it signed can no longer be valid. Revoked keys are terminal, not merely “old.”
- Resource servers validate the token profile they accept; successful parsing or signature validation is not sufficient.

## Emerging practice

- Identity systems increasingly broker short-lived credentials from workload/platform identity rather than distribute static application secrets.
- SPIFFE’s stable Workload API includes mandatory X.509-SVID and JWT-SVID profiles and an optional WIT-SVID profile. Implementations identify the local caller before returning entitled material ([SPIFFE Workload API](https://spiffe.io/docs/latest/spiffe-specs/spiffe_workload_api/)).
- Sender-constrained token use is growing, but DPoP and mTLS protect different architectures and still require proof replay prevention, key protection, audience validation, and correct resource-server behavior.

## Open operational problems

Cross-domain key discovery, emergency revocation, cache staleness, issuer migration, hardware-backed sender keys, multi-hop agent delegation, and consistent identity context across gateways remain system problems. A new token format does not remove ownership, policy, lifecycle, or incident-response requirements.

# 31. Worked action-token verifier

The practical scenario uses a deliberately narrow profile:

```text
token type       agent-action+jwt
issuer           https://identity.corp.example
audience         purchasing-api
algorithm        EdDSA
subject          agent:procurement
action           purchase:create
maximum lifetime 300 seconds
replay rule      one successful use per (issuer, jti)
```

The verifier’s order is intentional:

```text
parse header without trusting it
→ reject remote key references and wrong alg/type
→ validate bounded kid syntax
→ select key only from configured issuer key set
→ reject unknown/revoked/mismatched key
→ verify signature, issuer, audience, and required claims
→ validate fixed-clock iat/nbf/exp and maximum lifetime
→ validate subject and action against application policy
→ atomically consume issuer+jti
→ return typed decision without raw token
```

The fixture derives synthetic Ed25519 keys deterministically so repeated runs create identical tokens. That is appropriate only for offline tests. Production private keys belong in an authorization server, KMS/HSM, platform identity system, or SPIFFE implementation—not source code.

# 32. Practical lab

The canonical implementation is [`lab.py`](lab.py). From the repository root:

```bash
uv run python curriculum/beginner/03-authentication-credentials-tokens/lab.py
uv run pytest curriculum/beginner/03-authentication-credentials-tokens/tests -q
```

Use the [guided notebook](authentication_credentials_tokens.ipynb) for the baseline → key/JWK inspection → controlled verifier → attack matrix → rotation → replay → evaluation sequence.

| Case | Expected | Invariant |
| --- | --- | --- |
| Active signing key | allow | current trusted key works |
| Retiring signing key | allow | bounded overlap avoids breaking live tokens |
| Replayed action token | first allow, second deny | single-use assertion is atomically consumed |
| Wrong audience / issuer | deny | token cannot cross resource or trust boundary |
| Expired / future / excessive lifetime | deny | time and maximum credential lifetime are enforced |
| Missing or wrong `typ` | deny | ID/access/action token confusion is blocked |
| Unknown `kid` | deny | received key ID cannot introduce trust |
| Revoked key | deny | emergency revocation is terminal |
| Tampered payload | deny | signature binds header and claims |
| Missing `jti` | deny | required profile claims are not optional |
| Unknown subject / action | deny | authenticated claims still meet application policy |

# 33. Experiments and evaluation

The **signature-only baseline** selects a configured key and verifies the signature, but ignores key lifecycle, type, issuer, audience, time, subject/action policy, and replay. The **hardened verifier** applies the full application profile to the same attempts.

```text
valid_attempt_success_rate = accepted expected-valid attempts / expected-valid attempts
invalid_acceptance_rate = accepted expected-invalid attempts / expected-invalid attempts
invalid_block_rate = rejected expected-invalid attempts / expected-invalid attempts
replay_block_rate = rejected labelled replay attempts / labelled replay attempts
evidence_completeness_rate = decisions with ID, digest, policy, checks, reason / all attempts
```

| Metric | Better | Signature-only | Hardened |
| --- | --- | ---: | ---: |
| Valid attempt success | higher | `3/3` | `3/3` |
| Invalid acceptance | lower | `12/14` | `0/14` |
| Invalid block | higher | `2/14` | `14/14` |
| Replay block | higher | `0/1` | `1/1` |
| Decision evidence completeness | higher | `17/17` | `17/17` |

Evidence completeness does not mean the decision is correct: the baseline is observable but unsafe. A production corpus should additionally cover discovery/JWKS outages, cache and rotation races, multiple audiences, clock skew distributions, duplicate concurrent requests, issuer migration, key compromise, token size limits, Unicode/JSON edge cases, and provider-specific profiles.

# 34. Failure modes and production upgrades

| Failure | Consequence | Upgrade |
| --- | --- | --- |
| Trust `alg` from token | algorithm-confusion or unsupported algorithm | application-owned algorithm allowlist and per-key algorithm |
| Treat `kid` as key material or query text | key injection, SQL/LDAP injection | bounded syntax and lookup only in issuer-bound trusted set |
| Follow `jku`/`x5u` from token | SSRF or attacker-controlled keys | configured discovery/JWKS endpoint for an exact trusted issuer |
| Signature-only validation | accepts expired, wrong-audience, wrong-type tokens | explicit profile and required claims |
| Cache JWKS forever | revoked key remains trusted | bounded TTL, refresh, version/metrics, emergency invalidation |
| Drop old key immediately | valid in-flight tokens fail | rotation overlap no longer than maximum token validity |
| Reuse generic access-token rules for action assertions | incorrect replay or one-time semantics | separate token types and mutually exclusive validation rules |
| Process `jti` with check-then-write | concurrent replay succeeds | atomic conditional insert with expiry |
| Log raw bearer token | observability becomes credential exfiltration | digest/reference only, structured reason and key ID |
| Put token in model context | prompt/tool path can leak or transform it | trusted credential broker and server-side tool adapter |
| Retry authentication denial | waste and possible abuse | terminal denial; retry only bounded transient key/discovery failures |

Production design also needs issuer metadata pinning, safe HTTP/JWKS timeouts and size limits, stale-cache policy, negative caching, KMS/HSM ownership, rotation drills, revocation propagation SLOs, clock synchronization, privacy retention, rate limits, library patching, audit correlation, and incident response.

# 35. Enterprise review checklist

Before accepting a credential, ask:

- Which exact token or certificate profile is accepted, and how is it distinguished from others?
- Who configured the issuer and key source? Can received data redirect lookup?
- Are algorithm, key use, key status, signature, issuer, audience, required claims, time, and maximum lifetime all enforced?
- Is the subject valid for this issuer, tenant, identity kind, and lifecycle state?
- Is replay expected, prevented through sender constraint, or prevented through single-use consumption?
- How do active, retiring, and revoked keys behave during overlap and emergency response?
- What happens when discovery/JWKS is unavailable, slow, stale, oversized, or inconsistent?
- Are denial reasons observable without logging tokens, secrets, or unnecessary claims?
- Does authentication produce trusted identity context for Course 04 authorization rather than directly executing an action?

# 36. Exercises

1. Add a wrong-algorithm token and prove that the header is rejected before cryptographic verification.
2. Add a two-second clock-skew policy. Predict which future/expired boundaries change and write exact tests.
3. Model a key rotation timeline with active, retiring, and revoked states. Calculate the minimum safe overlap from maximum token lifetime and cache TTL.
4. Replace the local key set with a mock issuer-metadata/JWKS cache. Add bounded refresh, last-known-good behavior, and emergency invalidation.
5. Design concurrency tests for atomic `jti` consumption. Explain why an in-memory set is insufficient across processes.
6. Compare DPoP and mTLS for a mobile agent client, a Kubernetes workload, and a service-mesh workload. Include key storage, proxy behavior, proof replay, and operational cost.
7. Map the verifier’s accepted result into Course 04’s authorization tuple without letting token claims choose resource ownership or permission.

# 37. Checkpoint

A signed token contains an unknown `kid` and a `jku` URL controlled by the caller. What should the purchasing API do?

- A. Fetch the URL so it can verify the signature.
- B. Decode the payload and allow if issuer and audience strings look correct.
- C. Deny because key discovery must come from configuration bound to a trusted issuer, not received token headers.

**Answer: C.** The header helps select among already trusted keys; it cannot create a new trust anchor or redirect the verifier.

# 38. Key takeaways

1. Identifiers and decoded claims are assertions; verification establishes evidence.
2. Signature verification is necessary but not a complete token profile.
3. Algorithms, token type, issuer, audience, required claims, time, subject, key lifecycle, and application policy are independent checks.
4. `kid` selects among configured issuer keys; it does not make a key trusted.
5. Active, retiring, and revoked keys need explicit behavior and bounded overlap.
6. Bearer-token replay, sender-constrained proof replay, and single-use assertion replay require different controls.
7. Credentials and raw token values remain in trusted infrastructure, outside prompts and logs.
8. Authentication produces validated identity context; Course 04 independently decides authority.

# References

## Standards and primary guidance

- IETF, [JSON Web Token, RFC 7519](https://www.rfc-editor.org/rfc/rfc7519.html), [JSON Web Signature, RFC 7515](https://www.rfc-editor.org/rfc/rfc7515.html), and [JSON Web Key, RFC 7517](https://www.rfc-editor.org/rfc/rfc7517.html).
- IETF, [JSON Web Token Best Current Practices, RFC 8725](https://www.rfc-editor.org/rfc/rfc8725.html).
- IETF, [OAuth 2.0 Bearer Token Usage, RFC 6750](https://www.rfc-editor.org/rfc/rfc6750.html).
- IETF, [OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens, RFC 8705](https://www.rfc-editor.org/rfc/rfc8705.html).
- IETF, [OAuth 2.0 Demonstrating Proof of Possession, RFC 9449](https://www.rfc-editor.org/rfc/rfc9449.html).
- IETF, [Best Current Practice for OAuth 2.0 Security, RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html).
- IETF, [JSON Web Algorithms for CFRG Elliptic Curve Algorithms, RFC 8037](https://www.rfc-editor.org/rfc/rfc8037.html).
- SPIFFE, [Workload API](https://spiffe.io/docs/latest/spiffe-specs/spiffe_workload_api/), [X.509-SVID](https://spiffe.io/docs/latest/spiffe-specs/x509-svid/), and [JWT-SVID](https://spiffe.io/docs/latest/spiffe-specs/jwt-svid/).

## Official implementation guidance

- PyJWT, [usage and claim validation](https://pyjwt.readthedocs.io/en/stable/usage.html) and [API reference](https://pyjwt.readthedocs.io/en/stable/api.html).
- Authlib, [joserfc guide](https://jose.authlib.org/en/guide/).
- cryptography, [Ed25519](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ed25519/) and [X.509](https://cryptography.io/en/latest/x509/).
- SPIFFE, [working with SVIDs](https://spiffe.io/docs/latest/deploying/svids/).

## Next course

Continue to [Beginner 04 — Authorization for Agents](../04-authorization-for-agents/README.md) to move from proving identity to deciding authority: default deny, RBAC, ABAC, ReBAC, capabilities, PEP/PDP architecture, delegated scope, and policy regression tests.
