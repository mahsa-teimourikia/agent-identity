# Course review progress

This ledger tracks the sequential deep review of the curriculum. A course is complete only when its important claims map to teaching material, an implemented control, an executable learner experience, and verification evidence.

## Status

| Course | Status | Review focus |
| --- | --- | --- |
| Beginner 01 — Agent Identity Foundations | Deep pass complete | Evidence-bound identity, delegation, failure cases, measurable evaluation |
| Beginner 02 — Humans, Workloads and Agents | Deep pass complete | Principal taxonomy, multi-hop provenance, deployment and delegation relationships |
| Beginner 03 — Authentication, Credentials and Tokens | Deep pass complete | Token profiles, issuer-bound key selection, rotation, replay, observable decisions |
| Beginner 04 — Authorization for Agents | Deep pass complete | Default deny, policy models, scoped delegation, approval receipts, PEP/PDP enforcement |
| Beginner 05 — Least-Privilege Tool Access | Deep pass complete | Tool discovery/execution, typed contracts, credentials, egress, approval, budgets, verified effects |
| Beginner 06 — Agent Identity Lifecycle | Deep pass complete | Governed state transitions, exact approvals, attested provisioning, recertification, revocation, verified retirement |
| Intermediate 01 — Workload Identity with SPIFFE & SPIRE | Deep pass complete | Attestation, unambiguous registration, SVID verification, full-state updates, rotation, federation |
| Intermediate 02 — Agent Authentication with OAuth 2.0 & OIDC | Deep pass complete | Transaction binding, token profiles, broker attenuation, DPoP, resource authorization, MCP |
| Intermediate 03 — Token Exchange, Delegation & Impersonation | Deep pass complete | RFC 8693 profiles, actor chains, multidimensional attenuation, exact approval, idempotency, revocation |
| Intermediate 04 — Fine-Grained Authorization with OPA, Cedar & OpenFGA | Deep pass complete | Trusted authorization tuple, engine semantics, object policy, consistency, obligations |
| Intermediate 05 — Dynamic Authorization & Continuous Access Evaluation | Deep pass complete | SET validation, durable projection, domain ordering, decision leases, commit-time reauthorization |
| Intermediate 06 — MCP Tool Authorization | Next | Discovery versus execution, server-side PEPs, tool arguments, resources, transport, current authority |
| Remaining courses | Queued in curriculum order | Reviewed after prerequisites are stable |

## Beginner 01 — claim-to-proof map

| Claim | Teaching artifact | Implementation proof | Verification |
| --- | --- | --- | --- |
| Human, logical-agent, and workload identities must remain distinct | README taxonomy, architecture, and worked trace | `PrincipalKind`, governed registry, and `AgentWorkloadBinding` in `lab.py` | `test_valid_decision_preserves_distinct_identities` |
| A declared agent name is not authentication | README anti-patterns and notebook baseline | `declared_agent_baseline` compared with `evidence_bound_gate` | `test_declared_agent_name_cannot_override_workload_binding` plus nine labelled negative cases |
| Delegation must be explicit, bounded, and attributable | README delegation predicate and procurement trace | `DelegationGrant` checks subject, actor, audience, lifetime, resource, action, and amount | Grant attenuation and expiry tests |
| Tenant and resource identity must come from authoritative state | README trust-boundary guidance | `ResourceRecord` and registry-derived tenant comparison | Cross-tenant and unknown-requester tests |
| Security improvements need measurable evidence | README evaluation section and notebook experiment | Baseline/control evaluator with four defined rates | Release-gate assertions and deterministic test suite |

## Beginner 01 — validation record

- Ten deterministic scenarios: one valid and nine adversarial or lifecycle failures.
- Eight focused unit tests for identity separation, workload binding, tenant authority, delegation attenuation, lifecycle, and metrics.
- Lab-backed notebook exercises covering baseline, controlled implementation, evaluation, failure injection, and sub-agent attenuation.
- Learning Hub checkpoint and direct links to the guided notebook and reusable lab.
- Course-local references prioritize standards, primary documentation, and clearly label emerging work.

## Beginner 02 — claim-to-proof map

| Claim | Teaching artifact | Implementation proof | Verification |
| --- | --- | --- | --- |
| Human, application, agent, workload, service, and resource identities answer different questions | README taxonomy and worked travel path | `PrincipalKind` and governed `Principal` registry in `lab.py` | Valid-path test asserts every distinct identity |
| A logical agent must be bound to an approved application and runtime | README deployment model and notebook trace | `DeploymentBinding` matches application, agent, workload, environment, version, and status | Spoofed-agent, application-collision, development, and disabled-workload tests |
| Multi-agent attribution is an ordered relationship chain | README propagation and multi-agent sections | Canonical `actor_chain`, `parent_actor_id`, and pairwise `DelegationEdge` validation | Missing-parent, cyclic-chain, and task-substitution tests |
| Presented identity labels are not validated principals | README failure modes and notebook baseline | Separate presented/validated decision fields | Denial non-promotion test |
| Shared accounts create security and attribution collisions | README evaluation and notebook comparison | Collapsed-platform baseline versus provenance-bound control | Defined identity-collision and unauthorized-success metrics |

## Beginner 02 — validation record

- Ten deterministic scenarios: one valid multi-hop path and nine adversarial, mapping, chain, tenant, or lifecycle failures.
- Eight focused unit tests for identity separation, deployment binding, chain topology, task delegation, lifecycle, denial semantics, and metric populations.
- Lab-backed notebook covering taxonomy, relationship inspection, baseline, controlled trace, evaluation, reordered-chain failure injection, lifecycle failure, and production mapping.
- Learning Hub checkpoint asks for a resource-side judgment when the authenticated workload and claimed agent disagree.
- State-of-the-art review distinguishes established platform/workload mechanisms, emerging agent identity practice, and active IETF drafts.

## Beginner 03 — claim-to-proof map

| Claim | Teaching artifact | Implementation proof | Verification |
| --- | --- | --- | --- |
| A valid signature is necessary but not sufficient | README verification model and notebook baseline | `signature_only_baseline` compared with `hardened_verifier` | Baseline accepts `12/14` invalid attempts; control accepts `0/14` |
| Key IDs select only among issuer-bound trusted keys | README key/JWKS and SSRF guidance | bounded `kid`, local `TrustedKeySet`, forbidden `jku`/`x5u` | Unknown/revoked-key tests and notebook key-reference failure injection |
| Token types and validation rules must be mutually exclusive | README cross-JWT confusion guidance | exact `agent-action+jwt` profile | Missing/wrong type tests |
| Time and lifecycle checks are independent | README claims, rotation, and production sections | fixed-clock `iat`/`nbf`/`exp`, maximum lifetime, active/retiring/revoked states | Expired, future, lifetime, active, retiring, and revoked fixtures |
| Replay semantics depend on credential purpose | README bearer/sender-constraint/single-use distinction | atomic-style `(issuer, jti)` consumption for the action assertion | First use accepted; second use denied with `replay_detected` |
| Verification evidence must not leak credentials | README logging boundary and notebook evidence inspection | token digest and typed public decision without raw token | Decision-record test |

## Beginner 03 — validation record

- Sixteen deterministic token cases producing seventeen attempts: three expected-valid and fourteen expected-invalid.
- Eleven focused tests for reproducibility, public JWK safety, issuer-bound key trust/lifecycle, issuer/audience/type, time, tampering, replay, logging, and metric populations.
- Lab-backed notebook covering profile and JWK inspection, a real signature-only baseline, hardened verification, rotation, replay, evaluation, malicious key references, and production mapping.
- Learning Hub checkpoint tests trust-anchor judgment rather than JWT vocabulary.
- Current references prioritize JOSE/OAuth RFCs, official library guidance, and SPIFFE specifications.

## Beginner 04 — claim-to-proof map

| Claim | Teaching artifact | Implementation proof | Verification |
| --- | --- | --- | --- |
| A broad role is eligibility, not sufficient authority | README model comparison and notebook baseline | `BroadRolePDP` compared with `RefundPDP` | Baseline executes `12/14` invalid attempts; hardened control executes `0/14` |
| Identity and authority cannot come from model arguments | README trust boundary and notebook field inspection | separate `VerifiedContext` and `RefundProposal` contracts | Proposal-field test plus workload, actor, and tenant substitution cases |
| Delegation is task/resource bounded and attenuated | README delegation predicates and worked trace | `DelegationGrant` and `attenuate()` | expiry/amount tests and rejection of action, resource, amount, and expiry widening |
| High-risk authorization is an obligation backed by exact evidence | README approval lifecycle and notebook challenge flow | proposal-bound `ApprovalReceipt` plus single-use `ApprovalStore` | missing, altered, expired, self-approved, and replayed approval tests |
| The PEP enforces typed decisions and fails closed | README PEP/PDP architecture | `RefundGateway` executes only `ALLOW` and converts PDP failure to denial | outage case creates no execution receipt |
| Protected context is authorized before retrieval | README RAG/tool ordering and notebook resource filter | `authorized_order_context()` | cross-tenant candidate never enters returned context |
| Common engines preserve one trusted request tuple | technology landscape and notebook adapter mapping | `policy_engine_inputs()` for OPA, Cedar, and OpenFGA | mapping test plus schema/diagnostic production guidance |

## Beginner 04 — validation record

- Sixteen deterministic cases producing seventeen attempts: three expected executions and fourteen expected denials or approval challenges.
- Fourteen focused tests for identity separation, workload binding, tenant/resource authority, scoped delegation, exact approval, replay, failure behavior, retrieval, engine mappings, evidence, and metric populations.
- Lab-backed notebook covering trust boundaries, role-only baseline, hardened PEP/PDP flow, approval obligations, failure injection, evaluation, retrieval, attenuation, and common policy-engine mappings.
- Learning Hub checkpoint asks for a cross-tenant authorization judgment rather than a PDP vocabulary definition.
- Current references prioritize NIST, Zanzibar, OPA, Cedar, Amazon Verified Permissions, OpenFGA, and the final OpenID AuthZEN Authorization API 1.0 specification.

## Beginner 05 — claim-to-proof map

| Claim | Teaching artifact | Implementation proof | Verification |
| --- | --- | --- | --- |
| Discovery minimization does not replace execution authorization | README boundary and notebook visible catalog | `visible_tools()` plus independent `ToolGateway.invoke()` checks | hidden cancellation and shell direct-call tests |
| Typed arguments are necessary but not sufficient | README schema/policy separation and notebook JSON Schema | strict Pydantic input models plus `_authorize_arguments()` | extra URL, price, airline, recipient, resource, and tenant cases |
| Credentials remain behind the gateway and narrower than service authority | README credential model and notebook lease inspection | `CredentialBroker` issues audience/scope/operation-bound non-secret metadata | lease-field and decision-evidence tests |
| High-risk approval binds one exact operation | README approval lifecycle and notebook challenge | typed `ApprovalReceipt`, canonical request digest, single-use store | missing/altered approval and exact retry reconciliation tests |
| Retry safety requires stable operations and reconciliation | README unknown-outcome mechanics and notebook failure injection | service idempotency ledger and digest comparison | lost-response recovery and changed-request conflict tests |
| Tool outputs and claimed success are untrusted | README result boundary and notebook malformed-output injection | strict output models and execution receipts | malformed instruction result is denied and not promoted |
| Tool safety includes egress, budgets, lifecycle, and policy availability | production chapter and adversarial matrix | fixed catalog egress, task allowlist, atomic counters, fail-closed gateway | egress, budget, expiry/cancellation, and outage tests |
| MCP schemas/annotations carry contracts but not authority | technology/state-of-art sections and notebook mapping | `mcp_tool_definitions()` emits authorized Pydantic schemas and cautious hints | definition visibility/schema/annotation test |

## Beginner 05 — validation record

- Twenty deterministic scenarios producing twenty-four attempts: six expected terminal successes, seventeen expected denials or approval challenges, and one unknown outcome followed by reconciliation.
- Nineteen focused tests for identity separation, discovery/execution, strict schemas, tenant/resource/argument constraints, exact approval, credentials, egress, budgets, task lifecycle, output validation, idempotency, failure behavior, evidence, and metric populations.
- Lab-backed notebook covers catalog/schema inspection, unsafe baseline, hardened gateway, approval, exact retry, unknown outcomes, egress injection, budgets, credential isolation, result validation, MCP mapping, and quantitative evaluation.
- Learning Hub checkpoint tests whether learners distinguish MCP risk hints from trusted enforcement.
- Current references prioritize the MCP 2026-07-28 specification and official SDK, Pydantic/JSON Schema documentation, OpenFGA, OWASP, and NIST.

## Beginner 06 — claim-to-proof map

| Claim | Teaching artifact | Implementation proof | Verification |
| --- | --- | --- | --- |
| Lifecycle requests propose changes but cannot supply administrative authority | README trust boundary and notebook field inspection | Separate `VerifiedAdminContext` and `LifecycleRequest` | Request-field and strict-payload tests |
| Registration requires accountable identities and an approved blueprint | README registration mechanics and Northstar trace | Directory, tenant, sponsor, owner, blueprint, and version checks | Active-accountability and cross-tenant tests |
| Approval binds the exact manifest and operation with separation of duties | README approval model and notebook approval experiment | `LifecycleApproval`, canonical digests, and single-use `ApprovalStore` | Self, altered, replay, and reconciliation tests |
| Provisioning cannot widen approved authority or bind an untrusted runtime | README provisioning/workload sections | Exact manifest equality, blueprint subsets, and `WorkloadAttestation` | Capability-escalation and wrong-workload tests |
| Activation and continued operation require current lifecycle evidence | README activation/review sections | Sponsor/owner, review, grant, binding, and credential invariants | Overdue, missing-artifact, and sponsor-review tests |
| Material change cannot silently inherit runtime authority | README change-management section and notebook experiment | New manifest digest plus suspended grants/credentials and revoked sessions | Material-change invariant test |
| Concurrency and retries must not duplicate or overwrite lifecycle effects | README version/idempotency mechanics | Optimistic record versions and operation digest ledger | Concurrent-review, exact-retry, and changed-request tests |
| Revocation and retirement apply to the complete access graph | README incident/retirement sections and failure injection | Propagated status updates and resumable idempotent cleanup adapter | Revocation-propagation and partial-cleanup recovery tests |
| Audit shape alone is insufficient; outcomes and tamper evidence both matter | README evaluation/evidence sections | Hash-chained frozen events plus defined safety metrics | Tamper test and baseline-versus-control release gate |

## Beginner 06 — validation record

- Twenty deterministic scenarios: seven legitimate lifecycle applications, twelve expected denials or approval challenges, and one expected partial-cleanup outcome.
- Twenty-one focused invariant tests for trust separation, strict payloads, accountability, authoritative approver roles, exact approval, attested provisioning, activation, concurrency, sponsor succession, material change, reactivation, revocation, retirement, audit integrity, schemas, evidence, and metric populations.
- Lab-backed notebook covering the unsafe baseline, governed controller, quantitative evaluation, approval, provisioning, concurrency, material change, revocation, cleanup failure, audit tampering, production mapping, and exercises.
- Learning Hub checkpoint tests lifecycle architecture and failure recovery rather than state-name vocabulary.
- Current references distinguish established SCIM/SPIFFE/Shared Signals practice, current product capabilities, the draft NIST agent-identity concept work, and final NIST IR 8587 token guidance.

## Intermediate 01 — claim-to-proof map

| Claim | Teaching artifact | Implementation proof | Verification |
| --- | --- | --- | --- |
| A workload cannot choose its own SPIFFE ID | README trust pipeline and notebook issuance walkthrough | `ObservedWorkload`, `RegistrationEntry`, and `WorkloadAPI.fetch()` derive identity from trusted node/selectors | caller-requested-identity and request-field tests |
| Attestation must resolve to exactly one active registration | README selector mechanics and selector-precision experiment | parent plus conjunctive selector matching with zero/multiple-match denial | unknown, incomplete, wrong-parent, collision, and endpoint-locality tests |
| SVID verification is contextual, not signature-only | README X.509/JWT verification sequences and notebook failure matrix | `WorkloadGateway` enforces bundle/key, profile, time, lifetime, audience, exact peer, and lifecycle | X.509 and JWT invariant tests across nine negative cases |
| Workload API removal state invalidates cached credentials | README streaming/redaction mechanics and notebook cache experiment | `WorkloadClientCache` replaces monotonic full-state snapshots | redaction, replayed-update, and partial-update tests |
| Rotation requires verifier-ready bundle overlap | README rotation lifecycle and notebook old/overlap comparison | deterministic issuer generations and multi-root `TrustBundle` | old-only denial and overlap acceptance test |
| Federation authenticates but does not authorize | README authorization boundary and federated experiment | partner bundle verification followed by exact `AccessRule` evaluation | federated identity authenticates but receives `resource_not_authorized` |
| Security improvement requires labelled evidence | README metric definitions and notebook baseline/control comparison | 20-case evaluator with explicit denominators and release gate | baseline accepts 18 invalid attempts; hardened path matches all 20 |

## Intermediate 01 — validation record

- Twenty deterministic scenarios: two expected valid and eighteen expected blocked across attestation, selectors, endpoint locality, X.509/JWT verification, rotation, lifecycle, federation, and resource scope.
- Twenty-four focused test cases, including eight malformed-identity variants, for syntax, issuance authority, registration ambiguity, SVID profiles, bundle rotation, full-state redaction, authorization, evidence safety, and metrics.
- Lab-backed 42-cell executed notebook covering architecture, unsafe baseline, controlled path, X.509/JWT internals, failure injection, rotation, redaction, federation, evaluation, production mapping, and exercises.
- Learning Hub checkpoint asks learners to diagnose ambiguous registration; three additional quiz questions cover federation, redaction, and bundle-rollout judgment.
- References prioritize SPIFFE standards, current SPIRE documentation/releases, official Go/Java client guidance, maintained examples, and clearly label the Python package as community maintained.

## Intermediate 02 — claim-to-proof map

| Claim | Teaching artifact | Implementation proof | Verification |
| --- | --- | --- | --- |
| Authorization Code/OIDC security is one bound, one-time transaction | README mechanics and notebook callback failure injection | `AuthorizationServer` binds issuer, state, redirect, PKCE, resource, workload, delegation, expiry, and atomic consumption | substitution, replay, and concurrent-redemption tests |
| ID Tokens and access tokens have mutually exclusive consumers/profiles | README token model and notebook claim inspection | separate `issue_id_token`, `validate_id_token`, and resource-server `typ=at+jwt` path | nonce validation and ID-token-at-API denial tests |
| Client Credentials does not create a human subject | README flow comparison and notebook machine-token inspection | `TokenBroker.client_credentials()` uses the client as subject with no actor/task | machine-subject and authority-limit test |
| An agent broker must attenuate, never copy requested authority | README authority equation and broker experiment | trusted workload/client binding plus user-grant, task, resource, and scope intersection | scope, resource, task, actor, lifecycle, and idempotency tests |
| Token verification does not replace object authorization | README validation order and notebook audience/object experiment | `ResourceServer` verifies profile then checks tenant, owner, action, and object state | audience, cross-subject, cross-tenant, scope, and action tests |
| DPoP needs token-key and request/replay binding | README DPoP mechanics and seven-case notebook experiment | `cnf.jkt`, signature, method, URI, `ath`, freshness, and atomic `(jkt,jti)` checks | missing/wrong key/method/URI/token/time/replay tests |
| Security improvement requires explicit populations and safety slices | README evaluation definitions and notebook comparison | 25-case baseline/control evaluator with a release gate | baseline accepts 19 invalid attempts; hardened path matches all 25 |

## Intermediate 02 — validation record

- Twenty-five deterministic scenarios: two expected valid and twenty-three expected blocked across token profile, key/time/audience, client/actor/workload policy, object policy, and DPoP boundaries.
- Twenty-two focused test cases, including transaction substitution, concurrent one-time redemption, ID/access separation, broker attenuation, Client Credentials semantics, DPoP replay, MCP metadata, and evidence safety.
- Lab-backed 43-cell executed notebook covers transaction internals, token profiles, unsafe baseline, controlled evaluation, failure injection, broker attenuation, DPoP, MCP discovery, production mapping, and reflection exercises.
- Learning Hub checkpoint tests cross-resource audience judgment; three additional questions cover DPoP binding, issuer mix-up, and Client Credentials attribution.
- References distinguish final RFCs and FAPI 2.0 from the active OAuth 2.1, OAuth SPIFFE client-authentication, Workload Authorization Grant, and other agent-oriented draft work.

## Intermediate 03 — claim-to-proof map

| Claim | Teaching artifact | Implementation proof | Verification |
| --- | --- | --- | --- |
| RFC 8693 token types are declarations plus validated credential profiles | README protocol mechanics and notebook request inspection | `TokenCodec.validate` plus exact grant, subject, actor, and requested-type checks | protocol/profile parametrized tests and ID-token substitution case |
| Delegation preserves subject and makes the outer actor current | README `act` mechanics and notebook real child derivation | issuer-qualified `build_actor_claim` and bounded `actor_chain` | subject-continuity, nested-chain, malformed, cycle, and depth tests |
| Every child must be derived from the actual parent and monotonically narrower | attenuation equation, worked trace, and notebook child experiment | broker intersection/subset checks across scope, audience, resource, action, amount, purpose, lifetime, and redelegation | six dimension-specific amplification tests plus child-claim assertions |
| Client, caller workload, desired actor, and current presenter are independent bindings | README identity table and notebook principal inspection | `VerifiedCaller`, `ActorPolicy`, direct actor credential, and current-presenter checks | client/workload/tenant/actor/presenter substitution tests |
| Impersonation is exceptional and loses consumer-visible actor attribution | README comparison and notebook delegation/impersonation experiment | legacy-only semantics plus exact `ApprovalStore` receipt and broker evidence | missing/altered/wrong-role/concurrent-replay tests |
| Retry and lifecycle behavior are part of authorization safety | README replay/revocation sections and notebook failure injection | canonical operation ledger, family state, resource-side revocation, and sender binding | exact retry/conflict, existing-token revocation, and sender tests |
| Security improvement needs labelled outcome and safety populations | README metric definitions and notebook baseline/control comparison | 33-case evaluator and explicit release gate | scope-only baseline accepts 28 invalid attempts; hardened path matches all 33 |

## Intermediate 03 — validation record

- Thirty-three deterministic scenarios: four expected valid and twenty-nine expected blocked across protocol, token profile, identity, authority, approval, replay, lifecycle, and sender boundaries.
- Thirty-six focused test cases for request/response shape, subject/actor semantics, real multi-hop derivation, multidimensional attenuation, exact approval, concurrency, idempotency, revocation, sender/object authorization, key lifecycle, and evidence safety.
- Lab-backed 37-cell executed notebook covers the RFC contract, unsafe baseline, controlled evaluation, failure slices, real child derivation, impersonation, retry, revocation, resource enforcement, evidence, technology comparison, production mapping, and exercises.
- Learning Hub checkpoint tests current-actor semantics; three additional questions cover resource widening, impersonation controls, and changed-request retry conflict.
- References distinguish final OAuth/JWT/RAR/sender-constraint standards and AuthZEN 1.0 from active Transaction Token, identity-chaining, delegated-refresh, actor-profile, and agent-chain drafts.

## Intermediate 04 — claim-to-proof map

| Claim | Teaching artifact | Implementation proof | Verification |
| --- | --- | --- | --- |
| Agent proposals cannot create identity, tenant, scope, workload trust, or approval authority | README trust boundary and notebook field inspection | separate `ActionProposal`, `VerifiedCaller`, authoritative task/resource/risk records, and exact `ApprovalReceipt` | proposal-field, substitution, isolation, and approval tests |
| A valid scope is necessary but insufficient for object-level authorization | README five-plane model and baseline experiment | `ReferencePDP` intersects identity, workload, task, tenant, object/owner, action, lifecycle, state, risk provenance, purpose, amount, and approval | 33-case baseline/control matrix; scope-only baseline accepts 28 invalid cases |
| A PDP decision does not execute the business effect | README mechanics and notebook decision/receipt comparison | separate `ReferencePDP` and `PolicyEnforcementPoint` | repeated-PDP, obligation, approval-consumption, and evidence tests |
| Consequential approval binds one exact proposal and is single use | README payment walkthrough and notebook retry experiment | digest-bound `ApprovalReceipt` and locked `ApprovalStore` | changed-proposal and concurrent-consumption tests |
| Policy engines need explicit semantic-parity evidence | README engine comparison and notebook parity evaluation | one trusted adapter contract plus executable Cedar policy/schema and OPA/OpenFGA artifacts | Cedar validates and matches all 30 normal labeled cases |
| Relationship policy complements rather than replaces contextual policy | README OpenFGA composition and notebook SDK request inspection | OpenFGA task intersection plus attribute-aware reference/Cedar/OPA policy | SDK tuple test and risk/approval/state negative cases |
| Obligations, version mismatches, dependency failures, and retries are enforcement concerns | README failure/production sections and notebook injection | fail-closed PEP, obligation allowlist, policy-version check, and operation ledger | outage, stale-policy, unsupported-obligation, exact-retry, and conflict tests |
| Decision evidence should be reconstructable without credentials or private reasoning | README observability guidance and notebook evidence inspection | IDs, policy version, reasons, obligation IDs, input digest, and outcome | privacy-safe evidence test |

## Intermediate 04 — validation record

- Thirty-three deterministic scenarios: four expected valid and twenty-nine expected blocked across identity, isolation, lifecycle, authority, ownership, state, risk provenance, approval, policy dependency, and obligation boundaries.
- Forty-eight focused tests for the reference PDP/PEP, exact approval, concurrency, idempotency, AuthZEN request shape, OPA input, real Cedar execution, real OpenFGA SDK request construction, failure evidence, evidence safety, and metrics.
- OPA 1.21 validates the Rego package and passes nine policy tests; OpenFGA CLI 0.8.1 validates the relationship model; Cedar validates and executes in the focused suite.
- Lab-backed executed notebook covers the unsafe baseline, hardened decision, AuthZEN, OPA/Cedar/OpenFGA representations, exact approval, retries, failure injection, semantic parity, evaluation, production mapping, and exercises.
- Learning Hub checkpoint tests composition of relationship and attribute policy; two additional questions cover mandatory obligations and changed-proposal approval invalidation.
- Current references prioritize final AuthZEN Authorization API 1.0, official OPA operations guidance, Cedar policy/schema documentation, OpenFGA task-based agent authorization, and NIST ABAC/Zero Trust publications.

## Intermediate 05 — claim-to-proof map

| Claim | Teaching artifact | Implementation proof | Verification |
| --- | --- | --- | --- |
| A signed event is not trusted until its SET/SSF profile and configured stream are validated | README receiver pipeline and notebook token/profile inspection | Ed25519 `SetTransmitter`, issuer-bound `StreamConfig`, and `SecurityEventInbox.receive()` | wrong type, issuer, audience, signature, profile, event count/type, sequence, and subject tests |
| Push acknowledgement follows durable acceptance, not business processing | README delivery architecture and notebook receive/project split | SQLite inbox persists under unique `jti` before 202 semantics; projector marks processing separately | persistence-order, duplicate, and restart-recovery tests |
| Signal state must be subject scoped and independently ordered by domain | README projection semantics and notebook subject/order experiments | `ProjectionStore` resolves verified `sub_id` and keeps per-domain cursors | cross-subject isolation, newer-risk/older-session, stale-relaxation, late-restriction, and gap tests |
| Cached authorization is a bounded lease over exact intent and trusted state | README lease model and notebook cache exploit | `DecisionCache` binds full proposal, caller, tenant, workload, projection fingerprint, versions, and lifetime | changed amount/purpose/tenant/state key tests plus intentionally vulnerable comparison |
| An earlier allow cannot authorize a later side effect | README reauthorization boundaries and notebook TOCTOU/resume experiments | `PolicyEnforcementPoint.execute()` decides again from current projection immediately before effect | mid-flight session revocation and post-wait task revocation tests |
| Relationship and contextual policies are both necessary | README OPA/OpenFGA composition and notebook SDK inputs | OpenFGA task intersection plus conflict-free Rego v1 policy and reference PDP | SDK tuple assertions, OPA policy tests, OpenFGA validation, and 32-case matrix |
| Exact approval and idempotency remain necessary under continuous authorization | README approval/retry section and notebook payment evidence | proposal-bound versioned `ApprovalReceipt`, locked consumption, and operation digest ledger | changed proposal, replay, exact retry, and changed-request conflict tests |
| Propagation claims need lifecycle timestamps and a release gate, not artificial sleep | README observability/evaluation and notebook metrics | deterministic logical stage timestamps plus `propagation_metrics()` and `release_gate()` | metric-arithmetic test and zero-invalid-acceptance gate |

## Intermediate 05 — validation record

- Thirty-two deterministic scenarios: five expected allowed and twenty-seven expected blocked across identity, isolation, session/claims/device/risk, task, relationship, delegation, workload, stream, approval, purpose, amount, and policy boundaries.
- Sixty-five focused tests for SET profile/trust, durable acknowledgement, duplicate delivery, restart recovery, fail-closed subject isolation, per-domain ordering, stale relaxation, gaps, cache/approval binding, commit-time revocation and dependency failure, resume, exact approval, retry, policy adapters, evidence, and metrics.
- The executed notebook covers the unsafe baseline, signed SET inspection, validate/persist/ack/project flow, duplicates, subject scope, ordering, gaps, cache poisoning, TOCTOU, resume, restart, OPA/OpenFGA inputs, lifecycle metrics, release gating, and production exercises.
- OPA uses a conflict-free Rego v1 package with explicit degraded-read semantics; OpenFGA requires the intersection of assigned and delegated task relationships.
- Learning Hub questions test durable acknowledgement, per-domain ordering, exact cache/approval binding, commit-time reauthorization, and sequence-gap policy.
- References prioritize final SSF 1.0, CAEP 1.0, RFC 8417/8935/8936/9493, official OPA/OpenFGA/library guidance, and explicitly distinguish the draft CAEP interoperability profile and vendor-specific claims challenges.

## Review sequence

Each subsequent course will be audited against its immediate prerequisites and successor. The implementation pass will update the chapter, lab, notebook, tests, checkpoint, references, and Hub metadata together so the learner path and code cannot silently drift apart.
