# Course review progress

This ledger tracks the sequential deep review of the curriculum. A course is complete only when its important claims map to teaching material, an implemented control, an executable learner experience, and verification evidence.

## Status

| Course | Status | Review focus |
| --- | --- | --- |
| Beginner 01 — Agent Identity Foundations | Deep pass complete | Evidence-bound identity, delegation, failure cases, measurable evaluation |
| Beginner 02 — Humans, Workloads and Agents | Deep pass complete | Principal taxonomy, multi-hop provenance, deployment and delegation relationships |
| Beginner 03 — Authentication, Credentials and Tokens | Deep pass complete | Token profiles, issuer-bound key selection, rotation, replay, observable decisions |
| Beginner 04 — Authorization for Agents | Next | Default deny, policy models, delegated scope, PEP/PDP enforcement |
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

## Review sequence

Each subsequent course will be audited against its immediate prerequisites and successor. The implementation pass will update the chapter, lab, notebook, tests, checkpoint, references, and Hub metadata together so the learner path and code cannot silently drift apart.
