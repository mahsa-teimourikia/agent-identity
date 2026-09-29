# Intermediate 07 — Risk, Assurance, and Step-Up Authorization for Agents

> **Goal:** make agent authority proportional to the risk of an exact transaction and the current, independently verified strength of human, workload, task, resource, and approval evidence—without allowing step-up to repair an ineligible action.

**Level:** intermediate · **Time:** 3–4 hours · **Format:** reading + executed notebook + reusable lab + policy exercises

Agent authorization is not `authenticated → allowed`. A production enforcement point first establishes whether an action is eligible at all, then determines which assurance and approvals are proportional to its current risk, emits the correct remediation challenge, and rechecks everything at the effect boundary.

This course uses NIST SP 800-63 Revision 4 for human digital identity concepts, RFC 9470 for interoperable OAuth user-authentication step-up, OAuth Rich Authorization Requests for structured transaction authority, and SPIFFE-shaped workload evidence. It does **not** invent a NIST “agent AAL.”

## Learning outcomes

By the end, you can:

- distinguish identity proofing, authentication, federation, workload, task, approval, and transaction assurance;
- describe NIST IAL, AAL, and FAL without turning them into a generic trust score;
- map only explicitly trusted `acr` values to local assurance properties;
- evaluate `auth_time` independently of token issuance and expiry;
- emit and consume a correct RFC 9470 `WWW-Authenticate` challenge;
- separate user step-up, missing OAuth scope, workload re-attestation, and business approval;
- prove that stronger authentication cannot fix a wrong tenant, resource, task, or prohibited action;
- combine deterministic policy ceilings with explainable risk scoring;
- govern signal source, freshness, model version, and evidence version;
- implement progressive autonomy and task-scoped budgets that can shrink dynamically;
- bind informed approval to the exact proposal, identities, risk, policy, signals, resource version, and expiry;
- preserve separation of duties and multi-approver requirements;
- re-evaluate immediately before a side effect and reconcile unknown outcomes exactly once; and
- test valid work, challenges, constraints, denials, downgrade attacks, races, and replay.

## Prerequisites

Complete Intermediate 02–06 or be comfortable with OIDC/OAuth claims, workload identity, fine-grained policy, continuous authorization, and exact transaction authorization.

```bash
uv sync
uv run python curriculum/intermediate/07-risk-assurance-stepup/lab.py
uv run pytest curriculum/intermediate/07-risk-assurance-stepup/tests -q
```

Open [`risk_stepup_authorization.ipynb`](risk_stepup_authorization.ipynb) for the guided lab. The notebook imports [`lab.py`](lab.py), so its results and the automated tests use one implementation.

---

## 1. Start with eligibility, not risk score

The safe order is:

```text
authenticate token and derive trusted session
  -> validate strict action arguments
  -> enforce absolute eligibility
       tenant + subject + agent + client + task + resource + action ceiling
  -> assess current transaction risk from authoritative signals
  -> derive assurance and approval requirements
  -> choose one precise remediation or allow/constraint/deny
  -> re-evaluate at commit
  -> execute and record exactly once
```

A step-up prompt must never be offered for:

- another tenant's object;
- an inactive or unrelated task;
- a caller/agent/workload binding mismatch;
- an action outside the delegation;
- a prohibited self-administration action;
- compromised device/account state; or
- a hard policy ceiling.

Those are denials. Asking a user to authenticate more strongly suggests an unsafe and impossible path to authorization.

## 2. Risk and assurance are different dimensions

**Risk** asks: what harm could this exact action cause under current conditions?

**Assurance** asks: how much confidence do we have in each piece of evidence supporting the decision?

```text
transaction risk
  = action impact + resource sensitivity + amount + beneficiary
  + delegation + behavioral/environmental signals

decision evidence
  = verified human session + verified workload + active task
  + authoritative resource + fresh risk signals + exact approval
```

Do not add every input into one score and let good signals cancel hard failures. The lab uses an explainable score for gradated requirements and separate `hard_denials` for non-compensating constraints.

## 3. NIST SP 800-63 Revision 4

NIST finalized the Revision 4 suite in July 2025:

| Publication | Primary concern |
|---|---|
| SP 800-63-4 | overall digital identity risk management |
| SP 800-63A-4 | identity proofing and enrollment; IAL |
| SP 800-63B-4 | authentication and authenticator management; AAL |
| SP 800-63C-4 | federation and assertions; FAL |

### IAL, AAL, and FAL

- **IAL** expresses confidence in identity proofing—the process that establishes which person is represented.
- **AAL** expresses confidence that the claimant controls authenticator(s) bound to a subscriber account.
- **FAL** expresses requirements for conveying authentication/identity information through federation assertions.

They are related but not interchangeable. A strongly authenticated account can still lack authority over a claim or payment.

### AAL facts that matter here

NIST defines AAL1, AAL2, and AAL3—there is no NIST AAL4.

- AAL2 requires proof of two distinct authentication factors. Verifiers must offer a phishing-resistant option; federal staff, contractors, and partners must use phishing-resistant authentication for federal systems.
- AAL3 uses a public-key cryptographic protocol, requires phishing resistance, a non-exportable key, two factors, and authentication intent.

The lab represents these as separate properties:

```python
AcrProfile(
    aal=3,
    phishing_resistant=True,
    non_exportable_key=True,
)
```

That makes a policy such as “AAL2 plus phishing resistance” precise. Numeric comparison alone cannot express it.

## 4. ACR is a trust-framework identifier, not a number

OIDC `acr` is an Authentication Context Class Reference. Its string is meaningful only under an agreement with the authorization server. Never parse `urn:caller:aal999` and conclude it is stronger than AAL3.

The lab has an issuer-bound registry:

```text
urn:northstar:auth:aal1
urn:northstar:auth:aal2
urn:northstar:auth:aal2:phishing-resistant
urn:northstar:auth:aal3
```

The verifier maps those values to local properties after validating token signature, issuer, audience, profile, key ID, lifetime, subject, client, agent, tenant, task, and scopes. Unknown ACR values fail closed.

Production governance for an ACR mapping should record:

- owning authorization server and trust framework;
- authenticator combinations and factor independence;
- phishing/replay resistance and authentication intent;
- key exportability/hardware requirements;
- effective dates and change process; and
- conformance evidence and exceptions.

## 5. Authentication time is not token time

`auth_time` records when the user actively authenticated. `iat` records when a token was issued. Refreshing a token does not necessarily make the authentication event fresh.

```text
auth_age = policy_clock - verified auth_time
```

OIDC says that when `max_age` is requested, the authorization server must actively reauthenticate if necessary and the resulting ID Token must include `auth_time`. RFC 9470 extends that pattern to access-token information, either in a JWT access token or introspection response.

The lab uses a fixed policy clock, not wall-clock calls embedded in business logic. Tests can therefore cover boundary conditions without flakiness.

## 6. RFC 9470 step-up authentication

RFC 9470 lets a resource server say that the user authentication associated with a valid access token is too weak or too old.

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer error="insufficient_user_authentication",
  error_description="Stronger or more recent user authentication is required",
  acr_values="urn:northstar:auth:aal2:phishing-resistant urn:northstar:auth:aal3",
  max_age="300"
```

The client parses the challenge and starts a new authorization request containing `acr_values` and/or `max_age`. The authorization server returns a new access token only after satisfying its policy. The resource server validates the new token and repeats the authorization decision.

Important protocol details:

- `acr_values` is a space-separated preference list.
- `max_age` is a non-negative number of seconds since active authentication.
- both may appear in one challenge;
- access tokens are opaque to clients, even when they happen to be JWTs;
- the resource validates `acr`/`auth_time` from a verified JWT or trusted introspection response; and
- unsupported requirements must fail cleanly instead of causing an infinite prompt loop.

### Challenge privacy and abuse

RFC 9470 warns that challenges can disclose information about a resource or high-privilege user. Validate the token before returning detailed requirements when practical, minimize descriptions, rate-limit challenges, cap retry loops, and do not let an untrusted resource force arbitrary user prompts.

## 7. Four different remediation paths

| Condition | Result | Protocol/control |
|---|---|---|
| user auth too weak/stale | `user_step_up` | HTTP 401, RFC 9470 challenge |
| OAuth permission absent | `scope_required` | HTTP 403 insufficient scope / authorization flow |
| trusted workload evidence stale | `workload_step_up` | workload re-attestation/reissue workflow |
| exact approval absent/expired | `approval_required` | business approval workflow |

Do not collapse these into a generic “step up” boolean. Each has a different actor, evidence issuer, UX, retry condition, and audit trail.

Some problems are not remediable:

```text
wrong tenant/resource -> deny
unapproved image/workload -> deny
compromised device/account -> deny
prompt-injection signal on a side effect -> deny or pause
absolute agent ceiling -> deny
```

## 8. Human and workload assurance remain separate

The human session answers how Alice authenticated. Workload evidence answers what deployment is running the claims agent.

The lab's workload evidence includes:

```text
SPIFFE ID
approved image digest
production environment
attested state
observation and expiry times
trusted verifier identity
evidence version
```

Known workload identity with expired/stale evidence can request re-attestation. A different SPIFFE ID, development environment, or unapproved image is a binding failure and is denied. Intermediate 08 deepens the attestation protocol; this course focuses on how verified workload properties influence a transaction decision.

## 9. Explainable risk with non-compensating rules

The lab's deterministic model starts with action impact and adds explicit signals:

```text
resource classification
amount band
new beneficiary
account state
device state
behavior score and provenance
prompt-injection score
```

It also enforces hard rules:

- task and enterprise payment ceilings;
- suspended account or compromised device;
- untrusted/stale behavior signal for a write;
- prompt-injection signal blocking a side effect;
- prohibited self-administration; and
- overall risk ceiling.

The resulting evidence carries reason codes, model version, signal version, and score. A model update is a policy change: test it against labeled cases, assess calibration and disparate impact, stage it, and retain the version needed to reconstruct decisions.

### Risk signals need provenance and freshness

For each signal define:

| Property | Question |
|---|---|
| source | which authenticated service produced it? |
| subject/resource | what entity does it describe? |
| observed time | when was the state measured? |
| expiry/SLA | how old may it be for this action? |
| version | which schema/rules produced it? |
| failure mode | deny, constrain, pause, or last-known-good lease? |

Caller-provided `risk=low`, `device_compliant=true`, or `workload_attested=true` is not authoritative evidence.

## 10. Requirements are organizational policy

The reference policy illustrates—not standardizes—this mapping:

| Action/context | User assurance | Workload freshness | Approval |
|---|---|---|---|
| FAQ search | optional | identified/current | none |
| claim read | AAL1+; up to 8-hour auth age | 30 minutes | none |
| claim update | fresh AAL2 | 10 minutes | risk-dependent |
| ordinary payment | fresh phishing-resistant AAL2 | 5 minutes | one independent approver |
| higher-value payment | fresh AAL3 properties | 5 minutes | two distinct independent approvers |
| disable authorization audit | prohibited for agents | irrelevant | cannot override ceiling |

NIST does not prescribe these transaction mappings. Your risk assessment, legal obligations, fraud model, and operating environment do.

## 11. Exact informed approval

An approval button is useful only if the approver sees and authorizes the exact action. The lab binds:

```text
action + target + amount + currency + beneficiary + operation ID
subject + tenant + agent + client + task
risk score + risk model version + signal version
policy version + resource version + expiry
approver identities + consumed state
```

For higher-value payments it requires two distinct approvers. Neither the requester nor the agent may approve its own action. A one-cent change, new beneficiary, new risk/signal version, resource update, expired receipt, or replay fails the binding.

Present approvers with:

- who requested and which agent/workload will act;
- target resource and tenant;
- exact consequential fields and before/after state;
- risk reasons and source freshness;
- data classification and irreversibility;
- policy obligations and expiry; and
- a clear reject/escalate path.

## 12. Rich and protected authorization requests

OAuth scope strings are often too coarse for payments and other structured transactions. RFC 9396 Rich Authorization Requests define `authorization_details`, which can carry action, locations, amount, currency, creditor, and other API-specific fields.

RAR can complement the exact approval record, but it does not remove resource-server policy. Protect high-value front-channel authorization details from tampering and swapping with signed request objects or Pushed Authorization Requests (PAR). The final FAPI 2.0 Security Profile uses PAR, authorization code flow, PKCE, and sender-constrained access tokens for high-security APIs.

Do not put sensitive transaction details into URLs where referrer/history leakage is possible. Prefer back-channel PAR and minimize what appears in logs.

## 13. Progressive autonomy and budgets

Autonomy is not a global boolean. Model bounded levels such as:

```text
L0 observe
L1 recommend
L2 autonomous read/low-risk action
L3 bounded write with current assurance
L4 exact approved high-impact action
```

A task budget can limit cumulative amount, message count, data classification, delegation depth, and time. Risk changes can move authority down immediately. Budget reservations and side effects must be atomic; otherwise concurrent calls can each observe the same remaining budget and overspend.

Never let a model choose its own level or edit its budget. The trusted PEP applies the budget to validated arguments and authoritative counters.

## 14. Commit-time re-evaluation and exactly-once effects

Step-up and approval can become stale before execution. The lab performs:

```text
preflight decision
  -> optional work / user interaction
  -> atomic idempotency lookup
  -> current risk + assurance + approval decision
  -> effect
  -> receipt + approval consumption
```

The test suite changes device state between preflight and commit and proves the write is stopped. It also sends eight concurrent identical retries and proves one effect plus seven reconciliations.

A timeout after commit is an unknown outcome. Retry the same operation ID and canonical request digest, retrieve the prior receipt, and reject changed content under the same ID.

## 15. Evidence and privacy

Decision evidence should contain:

```text
subject / agent / client / workload / task identifiers
action and proposal digest
outcome and reason codes
risk tier, score, model, and signal versions
ACR and authentication age (not authenticators)
workload evidence version and freshness
approval identifier/approvers (not secrets)
policy and resource versions
operation/effect receipt
```

Never log access tokens, authenticator outputs, biometric samples, private keys, or sensitive approval payloads. The lab fingerprints token IDs instead of storing raw credentials.

## 16. Common libraries and services

| Layer | Lab | Production options | Responsibility |
|---|---|---|---|
| OIDC/OAuth | PyJWT + Ed25519 fixture | Authlib, oauthlib, certified IdP SDK/gateway | validate token, `acr`, `auth_time`, scope |
| user authenticator | trusted ACR registry | WebAuthn/passkeys, PIV/CAC, platform authenticators | phishing resistance, factors, intent |
| workload identity | SPIFFE-shaped evidence | SPIRE, cloud workload identity, attestation service | workload and deployment evidence |
| strict actions | Pydantic | JSON Schema, Zod/Ajv | argument contract |
| risk engine | deterministic rules | OPA, Cedar, fraud/risk services, feature platform | explainable policy and signals |
| relationship policy | task store | OpenFGA, SpiceDB | subject-agent-task-resource relations |
| authorization requests | Python structures | RFC 9396 RAR, PAR, FAPI 2.0 stack | exact structured authority |
| approval | in-memory receipt | workflow/approval service with signed evidence | informed consent, SoD, expiry |
| durable execution | locked ledger | database transaction, outbox, workflow engine | budgets, idempotency, reconciliation |

An identity provider's “MFA” flag is not enough. Verify what the provider's ACR actually means, whether phishing resistance and intent were achieved, and when the authentication occurred.

## 17. Practical lab

Northstar's claims agent can search FAQs, read/update one assigned claim, and propose a payment. The fixtures include a trusted ACR registry, signed sessions, workload evidence, dynamic signals, task/resource state, risk model, approval store, RFC 9470 transaction store, and idempotent effect adapter.

### Part A — Baseline

```python
baseline, rows = evaluate(build_cases(), hardened=False)
```

The deliberately weak baseline treats any request as allowed. Identify why authentication alone cannot decide resource, risk, assurance, approval, and effect safety.

### Part B — Trusted session and ACR mapping

Verify an ordinary AAL2 token, an AAL3 token, an unknown ACR, a wrong audience, and future `auth_time`. Inspect the derived `UserSession`; no caller-supplied numeric AAL is used.

### Part C — Risk and requirements

Compare ordinary and new-beneficiary payments, internal and restricted resources, fresh and stale behavior signals, and low/high prompt-injection scores. Separate additive reasons from hard denials.

### Part D — RFC 9470

Start with an AAL1/stale payment session. Inspect the 401 header, authorization URL, bound state handle, `acr_values`, and `max_age`. Complete with:

- a valid fresh matching session;
- a different subject/client/task;
- a weaker ACR;
- a stale `auth_time`; and
- replay of an already consumed transaction.

### Part E — Approval and execution

Record one- and two-person approvals, mutate amount/beneficiary/versions, attempt self-approval, inject a commit-time signal change, lose the post-commit response, and run concurrent retries.

### Part F — Failure injection and evaluation

```python
metrics, rows = evaluate(build_cases())
assert release_gate(metrics)
```

The 55 cases cover valid work, constraints, user/workload/scope/approval remediation, identity and resource substitution, ACR downgrade, stale evidence, compromised signals, risk ceilings, approval tampering, and schema attacks. The release gate requires every label to match, zero invalid allows, and zero valid work blocked.

### Part G — Policy engines

- [`policies/opa/risk_stepup.rego`](policies/opa/risk_stepup.rego) returns a structured multi-outcome decision and has 11 Rego tests.
- [`policies/cedar/risk_stepup.cedar`](policies/cedar/risk_stepup.cedar) models final grants after requirements are met and is type-checked against its Cedar schema.

```bash
opa test curriculum/intermediate/07-risk-assurance-stepup/policies/opa -v
```

Use Rego when flexible multi-outcome policy and obligations are central. Use Cedar for typed permit/forbid decisions. In either case, the PEP—not the policy language—must authenticate inputs, fulfill obligations, manage step-up state, and guard the effect.

## 18. Production checklist

### Eligibility

- [ ] Validate token signature/profile/issuer/audience/key/time before policy.
- [ ] Bind subject, agent, client, workload, tenant, task, action, and resource.
- [ ] Enforce non-remediable ceilings before offering step-up.
- [ ] Validate exact arguments and authoritative resource versions.

### Human assurance

- [ ] Maintain an issuer-specific ACR semantics registry.
- [ ] Check AAL properties, phishing resistance, key exportability, and intent separately.
- [ ] Compute age from verified `auth_time`, not `iat` or client time.
- [ ] Define acceptable authentication age per action.
- [ ] Revalidate the stepped-up token like any other access token.

### RFC 9470 client/resource

- [ ] Return HTTP 401 with `insufficient_user_authentication`.
- [ ] Encode space-separated `acr_values` and numeric `max_age` correctly.
- [ ] Bind OAuth state to user, client, task, and exact pending transaction.
- [ ] Cap retries and detect unmet requirements to prevent loops.
- [ ] Minimize challenge detail and rate-limit prompt abuse.
- [ ] Keep tokens opaque at the client.

### Workload and signals

- [ ] Verify workload identity, image/environment binding, issuer, freshness, and revocation.
- [ ] Authenticate every risk-signal producer and bind its subject/resource.
- [ ] Define stale/missing-source behavior per action class.
- [ ] Keep hard denials outside compensating risk arithmetic.
- [ ] Version and regression-test risk models and signal schemas.

### Approval and authority

- [ ] Show approvers exact identities, action, target, parameters, risk, and expiry.
- [ ] Bind approval to proposal/risk/policy/signal/resource versions.
- [ ] Enforce separation of duties and approver count.
- [ ] Consume approvals exactly once.
- [ ] Use RAR/PAR or equivalent structured, integrity-protected authority for high-value APIs.
- [ ] Make post-step-up tokens short-lived, audience-limited, sender-constrained where appropriate, and no broader than necessary.

### Execution and operations

- [ ] Re-evaluate at commit and atomically reserve budgets/operations.
- [ ] Reconcile unknown outcomes before retrying.
- [ ] Record privacy-aware reasoned evidence.
- [ ] Alert on prompt loops, ACR downgrade, approval replay, signal outages, and ceiling attempts.
- [ ] Exercise failover, concurrency, time boundaries, clock skew, and incident revocation.

## 19. Knowledge check

1. Why must eligibility be evaluated before step-up requirements?
2. What do IAL, AAL, and FAL each describe?
3. Why can two AAL2 sessions have different phishing-resistance properties?
4. Why is an unknown `acr` string not comparable with a trusted one?
5. What is the difference between `auth_time` and token `iat`?
6. What belongs in an RFC 9470 challenge?
7. How do missing scope, stale workload evidence, and missing approval differ from user step-up?
8. Which risk conditions must never be offset by positive signals?
9. Why must an approval bind risk and resource versions as well as amount?
10. How does PAR help protect a Rich Authorization Request?
11. What must be atomic when multiple agent actions consume an autonomy budget?
12. Why can AAL3 still produce a deny?

## 20. References and currency

Primary and authoritative sources checked for this revision:

- [NIST SP 800-63-4 — Digital Identity Guidelines](https://pages.nist.gov/800-63-4/sp800-63.html)
- [NIST SP 800-63A-4 — Identity Proofing and Enrollment](https://pages.nist.gov/800-63-4/sp800-63a.html)
- [NIST SP 800-63B-4 — Authentication and Authenticator Management](https://pages.nist.gov/800-63-4/sp800-63b.html)
- [NIST SP 800-63C-4 — Federation and Assertions](https://pages.nist.gov/800-63-4/sp800-63c.html)
- [RFC 9470 — OAuth 2.0 Step Up Authentication Challenge Protocol](https://www.rfc-editor.org/rfc/rfc9470)
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [RFC 9068 — JWT Profile for OAuth 2.0 Access Tokens](https://www.rfc-editor.org/rfc/rfc9068)
- [RFC 7662 — OAuth 2.0 Token Introspection](https://www.rfc-editor.org/rfc/rfc7662)
- [RFC 9396 — OAuth 2.0 Rich Authorization Requests](https://www.rfc-editor.org/rfc/rfc9396)
- [RFC 9126 — OAuth 2.0 Pushed Authorization Requests](https://www.rfc-editor.org/rfc/rfc9126)
- [RFC 9101 — JWT-Secured Authorization Request](https://www.rfc-editor.org/rfc/rfc9101)
- [RFC 9700 — Best Current Practice for OAuth 2.0 Security](https://www.rfc-editor.org/rfc/rfc9700)
- [RFC 9449 — OAuth 2.0 DPoP](https://www.rfc-editor.org/rfc/rfc9449)
- [RFC 8705 — OAuth 2.0 Mutual TLS](https://www.rfc-editor.org/rfc/rfc8705)
- [FAPI 2.0 Security Profile, final](https://openid.net/specs/fapi-security-profile-2_0-final.html)
- [W3C Web Authentication Level 3](https://www.w3.org/TR/webauthn-3/)
- [SPIFFE specifications](https://spiffe.io/docs/latest/spiffe-specs/spiffe/)
- [SPIRE concepts](https://spiffe.io/docs/latest/spire-about/spire-concepts/)
- [Open Policy Agent documentation](https://www.openpolicyagent.org/docs/latest/)
- [Cedar Policy Language documentation](https://docs.cedarpolicy.com/)

Re-check NIST errata, authorization-server ACR semantics, OAuth/FAPI conformance, authenticator restrictions, and SDK behavior before production use.

## 21. Handoff to Intermediate 08

This course consumes verified workload identity, image, environment, issuer, and freshness as authorization evidence. Intermediate 08 goes deeper into how those facts are produced: node and workload attestation, SVID issuance/rotation, Kubernetes selectors, provenance, runtime posture, and agent-to-workload binding. Keep the separation intact: human step-up cannot repair an untrusted workload, and fresh workload attestation cannot grant an ineligible human/task transaction.
