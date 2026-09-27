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
| Intermediate 01 — Workload Identity with SPIFFE & SPIRE | Next | Trust domains, attestation, SVID lifecycle, Workload API, rotation, federation |
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

## Review sequence

Each subsequent course will be audited against its immediate prerequisites and successor. The implementation pass will update the chapter, lab, notebook, tests, checkpoint, references, and Hub metadata together so the learner path and code cannot silently drift apart.
