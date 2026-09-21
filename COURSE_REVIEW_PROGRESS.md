# Course review progress

This ledger tracks the sequential deep review of the curriculum. A course is complete only when its important claims map to teaching material, an implemented control, an executable learner experience, and verification evidence.

## Status

| Course | Status | Review focus |
| --- | --- | --- |
| Beginner 01 — Agent Identity Foundations | Deep pass complete | Evidence-bound identity, delegation, failure cases, measurable evaluation |
| Beginner 02 — Humans, Workloads and Agents | Next | Principal taxonomy, requester/actor provenance, impersonation boundaries |
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

## Review sequence

Each subsequent course will be audited against its immediate prerequisites and successor. The implementation pass will update the chapter, lab, notebook, tests, checkpoint, references, and Hub metadata together so the learner path and code cannot silently drift apart.
