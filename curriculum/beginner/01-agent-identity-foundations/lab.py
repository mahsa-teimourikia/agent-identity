"""Course 01 lab: bind agent claims to verified workload identity and authority.

This credential-free lab begins after cryptographic authentication.
``IdentityEvidence`` is the sanitized output of a production authenticator, not
a caller-supplied token payload. Course 03 covers credential validation.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum
from typing import Callable, Iterable, Mapping


POLICY_VERSION = "procurement-boundary-v1"
EXPECTED_ISSUER = "https://identity.example.com"
EXPECTED_AUDIENCE = "purchasing-api"
TRUST_DOMAIN = "example.com"
NOW = 30


class PrincipalKind(str, Enum):
    USER = "user"
    AGENT = "agent"
    WORKLOAD = "workload"
    RESOURCE = "resource"


@dataclass(frozen=True)
class Principal:
    """Governed registry record controlled by the trusted application."""

    principal_id: str
    kind: PrincipalKind
    tenant: str
    trust_domain: str
    owner: str
    active: bool = True


@dataclass(frozen=True)
class IdentityEvidence:
    """Non-secret output of a trusted workload authenticator."""

    evidence_id: str
    workload_id: str
    issuer: str
    audience: str
    tenant: str
    trust_domain: str
    authenticated_at: int
    expires_at: int
    method: str


@dataclass(frozen=True)
class AgentWorkloadBinding:
    """Registry-owned link between a logical agent and an approved runtime."""

    binding_id: str
    agent_id: str
    workload_id: str
    environment: str
    active: bool = True


@dataclass(frozen=True)
class DelegationGrant:
    """Bounded authority from the human requester to the agent."""

    grant_id: str
    delegator_id: str
    delegate_id: str
    tenant: str
    audience: str
    action: str
    resource_prefix: str
    max_amount_cad: int
    issued_at: int
    expires_at: int


@dataclass(frozen=True)
class IdentityContext:
    """Trusted application context; models cannot create or widen it."""

    requester_id: str
    actor_id: str
    workload_id: str
    tenant: str
    task_id: str
    purpose: str
    correlation_id: str


@dataclass(frozen=True)
class PurchaseProposal:
    """Untrusted model/tool proposal."""

    action: str
    resource_id: str
    sku: str
    amount_cad: int


@dataclass(frozen=True)
class ResourceRecord:
    """Authoritative target metadata loaded by the purchasing service."""

    resource_id: str
    tenant: str
    supported_actions: frozenset[str]


@dataclass(frozen=True)
class Decision:
    """Public policy trace; never private model reasoning."""

    allowed: bool
    reason_code: str
    policy_version: str
    correlation_id: str
    authenticated_workload: str | None
    validated_actor: str | None
    validated_requester: str | None
    evidence_id: str | None
    binding_id: str | None
    grant_id: str | None
    checks: tuple[str, ...]


@dataclass(frozen=True)
class Case:
    case_id: str
    context: IdentityContext
    proposal: PurchaseProposal
    evidence: IdentityEvidence
    binding: AgentWorkloadBinding
    grant: DelegationGrant
    resource: ResourceRecord
    expected_allow: bool
    expected_reason: str


@dataclass(frozen=True)
class EvaluationReport:
    total_cases: int
    valid_cases: int
    invalid_cases: int
    valid_allowed: int
    invalid_allowed: int
    evidence_complete: int

    @property
    def valid_task_success_rate(self) -> float:
        return self.valid_allowed / self.valid_cases if self.valid_cases else 0.0

    @property
    def unauthorized_success_rate(self) -> float:
        return self.invalid_allowed / self.invalid_cases if self.invalid_cases else 0.0

    @property
    def invalid_block_rate(self) -> float:
        return 1.0 - self.unauthorized_success_rate if self.invalid_cases else 0.0

    @property
    def evidence_completeness_rate(self) -> float:
        return self.evidence_complete / self.total_cases if self.total_cases else 0.0

    def as_dict(self) -> dict[str, int | float]:
        return {
            "total_cases": self.total_cases,
            "valid_cases": self.valid_cases,
            "invalid_cases": self.invalid_cases,
            "valid_task_success_rate": self.valid_task_success_rate,
            "unauthorized_success_rate": self.unauthorized_success_rate,
            "invalid_block_rate": self.invalid_block_rate,
            "evidence_completeness_rate": self.evidence_completeness_rate,
        }


Registry = Mapping[str, Principal]
Evaluator = Callable[[Case, Registry, int], Decision]


def deny(
    case: Case,
    reason: str,
    checks: Iterable[str],
    *,
    workload: str | None = None,
    actor: str | None = None,
    requester: str | None = None,
) -> Decision:
    """Fail closed without promoting unchecked identity into trusted fields."""

    return Decision(
        False,
        reason,
        POLICY_VERSION,
        case.context.correlation_id,
        workload,
        actor,
        requester,
        case.evidence.evidence_id,
        case.binding.binding_id,
        case.grant.grant_id,
        tuple(checks),
    )


def declared_agent_baseline(case: Case, registry: Registry, now: int) -> Decision:
    """Intentionally unsafe: accepts a caller-declared logical agent name."""

    del registry, now
    allowed = case.context.actor_id == "agent:procurement"
    return Decision(
        allowed,
        "declared_agent_accepted" if allowed else "declared_agent_rejected",
        "unsafe-baseline-v0",
        case.context.correlation_id,
        case.context.workload_id if allowed else None,
        case.context.actor_id if allowed else None,
        case.context.requester_id if allowed else None,
        None,
        None,
        None,
        ("trusted caller-declared identity context",),
    )


def evidence_bound_gate(case: Case, registry: Registry, now: int = NOW) -> Decision:
    """Bind workload evidence, governed identities, resource, and delegation."""

    checks: list[str] = []
    evidence = case.evidence
    context = case.context
    proposal = case.proposal

    workload = registry.get(evidence.workload_id)
    if workload is None or workload.kind is not PrincipalKind.WORKLOAD:
        return deny(case, "unregistered_workload", checks)
    if not workload.active:
        return deny(case, "inactive_workload", checks)
    checks.append("workload_registered_and_active")

    if evidence.issuer != EXPECTED_ISSUER:
        return deny(case, "untrusted_issuer", checks)
    if evidence.trust_domain != TRUST_DOMAIN or workload.trust_domain != TRUST_DOMAIN:
        return deny(case, "untrusted_domain", checks)
    checks.append("issuer_and_trust_domain_valid")

    if evidence.authenticated_at > now:
        return deny(case, "evidence_not_yet_valid", checks)
    if evidence.expires_at <= now:
        return deny(case, "evidence_expired", checks)
    if evidence.audience != EXPECTED_AUDIENCE:
        return deny(case, "wrong_audience", checks)
    checks.append("evidence_current_and_audience_bound")

    if context.workload_id != evidence.workload_id:
        return deny(case, "context_workload_mismatch", checks, workload=workload.principal_id)
    checks.append("context_bound_to_authenticated_workload")

    actor = registry.get(context.actor_id)
    requester = registry.get(context.requester_id)
    if actor is None or actor.kind is not PrincipalKind.AGENT or not actor.active:
        return deny(case, "invalid_agent", checks, workload=workload.principal_id)
    if requester is None or requester.kind is not PrincipalKind.USER or not requester.active:
        return deny(case, "invalid_requester", checks, workload=workload.principal_id, actor=actor.principal_id)
    checks.append("agent_and_requester_registered")

    if not (
        evidence.tenant
        == workload.tenant
        == actor.tenant
        == requester.tenant
        == context.tenant
        == case.grant.tenant
        == case.resource.tenant
    ):
        return deny(case, "tenant_mismatch", checks, workload=workload.principal_id, actor=actor.principal_id)
    checks.append("tenant_bound_to_resource")

    binding = case.binding
    if not binding.active or binding.environment != "production":
        return deny(case, "inactive_or_nonproduction_binding", checks, workload=workload.principal_id, actor=actor.principal_id)
    if binding.agent_id != actor.principal_id or binding.workload_id != workload.principal_id:
        return deny(case, "agent_workload_binding_mismatch", checks, workload=workload.principal_id, actor=actor.principal_id)
    checks.append("logical_agent_bound_to_workload")

    grant = case.grant
    if grant.delegator_id != requester.principal_id:
        return deny(case, "grant_delegator_mismatch", checks, workload=workload.principal_id, actor=actor.principal_id)
    if grant.delegate_id != actor.principal_id:
        return deny(case, "grant_delegate_mismatch", checks, workload=workload.principal_id, actor=actor.principal_id)
    if grant.audience != EXPECTED_AUDIENCE:
        return deny(case, "grant_audience_mismatch", checks, workload=workload.principal_id, actor=actor.principal_id)
    if grant.issued_at > now or grant.expires_at <= now:
        return deny(case, "grant_not_current", checks, workload=workload.principal_id, actor=actor.principal_id)
    checks.append("delegator_delegate_and_lifetime_valid")

    if proposal.resource_id != case.resource.resource_id:
        return deny(case, "resource_record_mismatch", checks, workload=workload.principal_id, actor=actor.principal_id, requester=requester.principal_id)
    if proposal.action != grant.action or proposal.action not in case.resource.supported_actions:
        return deny(case, "action_not_granted", checks, workload=workload.principal_id, actor=actor.principal_id, requester=requester.principal_id)
    if not proposal.resource_id.startswith(grant.resource_prefix):
        return deny(case, "resource_not_granted", checks, workload=workload.principal_id, actor=actor.principal_id, requester=requester.principal_id)
    if proposal.amount_cad > grant.max_amount_cad:
        return deny(case, "amount_exceeds_grant", checks, workload=workload.principal_id, actor=actor.principal_id, requester=requester.principal_id)
    checks.append("action_resource_and_amount_granted")

    return Decision(
        True,
        "boundary_checks_passed",
        POLICY_VERSION,
        context.correlation_id,
        workload.principal_id,
        actor.principal_id,
        requester.principal_id,
        evidence.evidence_id,
        binding.binding_id,
        grant.grant_id,
        tuple(checks),
    )


def build_registry() -> dict[str, Principal]:
    principals = (
        Principal("user:alice", PrincipalKind.USER, "tenant:acme", TRUST_DOMAIN, "people-ops"),
        Principal("agent:procurement", PrincipalKind.AGENT, "tenant:acme", TRUST_DOMAIN, "procurement-platform"),
        Principal("agent:research", PrincipalKind.AGENT, "tenant:acme", TRUST_DOMAIN, "research-platform"),
        Principal("spiffe://example.com/prod/procurement", PrincipalKind.WORKLOAD, "tenant:acme", TRUST_DOMAIN, "platform-team"),
        Principal("spiffe://example.com/prod/research", PrincipalKind.WORKLOAD, "tenant:acme", TRUST_DOMAIN, "platform-team"),
        Principal("spiffe://example.com/dev/procurement", PrincipalKind.WORKLOAD, "tenant:acme", TRUST_DOMAIN, "platform-team"),
        Principal("spiffe://external.example/attacker", PrincipalKind.WORKLOAD, "tenant:external", "external.example", "red-team"),
    )
    return {principal.principal_id: principal for principal in principals}


def build_cases() -> tuple[Case, ...]:
    context = IdentityContext(
        "user:alice",
        "agent:procurement",
        "spiffe://example.com/prod/procurement",
        "tenant:acme",
        "task:atlas-supplies",
        "purchase approved Project Atlas supplies",
        "corr-valid",
    )
    proposal = PurchaseProposal("purchase:create", "project:atlas/purchase-order", "CHAIR-01", 180)
    evidence = IdentityEvidence(
        "evidence:prod-procurement",
        context.workload_id,
        EXPECTED_ISSUER,
        EXPECTED_AUDIENCE,
        "tenant:acme",
        TRUST_DOMAIN,
        10,
        90,
        "spiffe-x509-svid",
    )
    binding = AgentWorkloadBinding("binding:procurement-prod", context.actor_id, context.workload_id, "production")
    grant = DelegationGrant(
        "grant:alice-atlas",
        context.requester_id,
        context.actor_id,
        "tenant:acme",
        EXPECTED_AUDIENCE,
        "purchase:create",
        "project:atlas/",
        500,
        10,
        80,
    )
    resource = ResourceRecord("project:atlas/purchase-order", "tenant:acme", frozenset({"purchase:create"}))

    return (
        Case("valid_purchase", context, proposal, evidence, binding, grant, resource, True, "boundary_checks_passed"),
        Case(
            "forged_agent_label",
            replace(context, workload_id="spiffe://example.com/prod/research", correlation_id="corr-forged"),
            proposal,
            replace(evidence, evidence_id="evidence:research", workload_id="spiffe://example.com/prod/research"),
            binding,
            grant,
            resource,
            False,
            "agent_workload_binding_mismatch",
        ),
        Case(
            "development_workload",
            replace(context, workload_id="spiffe://example.com/dev/procurement", correlation_id="corr-dev"),
            proposal,
            replace(evidence, evidence_id="evidence:dev", workload_id="spiffe://example.com/dev/procurement"),
            replace(binding, binding_id="binding:procurement-dev", workload_id="spiffe://example.com/dev/procurement", environment="development"),
            grant,
            resource,
            False,
            "inactive_or_nonproduction_binding",
        ),
        Case("wrong_audience", replace(context, correlation_id="corr-aud"), proposal, replace(evidence, evidence_id="evidence:aud", audience="payroll-api"), binding, grant, resource, False, "wrong_audience"),
        Case("expired_evidence", replace(context, correlation_id="corr-expired"), proposal, replace(evidence, evidence_id="evidence:expired", expires_at=NOW), binding, grant, resource, False, "evidence_expired"),
        Case(
            "untrusted_domain",
            replace(context, workload_id="spiffe://external.example/attacker", correlation_id="corr-domain"),
            proposal,
            replace(evidence, evidence_id="evidence:external", workload_id="spiffe://external.example/attacker", tenant="tenant:external", trust_domain="external.example"),
            binding,
            grant,
            resource,
            False,
            "untrusted_domain",
        ),
        Case("cross_tenant_resource", replace(context, correlation_id="corr-tenant"), replace(proposal, resource_id="project:partner/purchase-order"), evidence, binding, grant, ResourceRecord("project:partner/purchase-order", "tenant:partner", frozenset({"purchase:create"})), False, "tenant_mismatch"),
        Case("amount_escalation", replace(context, correlation_id="corr-amount"), replace(proposal, amount_cad=5_000), evidence, binding, grant, resource, False, "amount_exceeds_grant"),
        Case("expired_grant", replace(context, correlation_id="corr-grant"), proposal, evidence, binding, replace(grant, grant_id="grant:expired", expires_at=NOW), resource, False, "grant_not_current"),
        Case("unknown_requester", replace(context, requester_id="user:mallory", correlation_id="corr-requester"), proposal, evidence, binding, grant, resource, False, "invalid_requester"),
    )


def evaluate(
    cases: Iterable[Case], evaluator: Evaluator, registry: Registry, now: int = NOW
) -> tuple[EvaluationReport, tuple[Decision, ...]]:
    case_list = tuple(cases)
    decisions = tuple(evaluator(case, registry, now) for case in case_list)
    valid_cases = sum(case.expected_allow for case in case_list)
    invalid_cases = len(case_list) - valid_cases
    valid_allowed = sum(case.expected_allow and decision.allowed for case, decision in zip(case_list, decisions))
    invalid_allowed = sum((not case.expected_allow) and decision.allowed for case, decision in zip(case_list, decisions))
    evidence_complete = sum(
        bool(
            decision.correlation_id
            and decision.policy_version
            and decision.reason_code
            and decision.evidence_id
            and decision.binding_id
            and decision.grant_id
        )
        for decision in decisions
    )
    return (
        EvaluationReport(len(case_list), valid_cases, invalid_cases, valid_allowed, invalid_allowed, evidence_complete),
        decisions,
    )


def decision_rows(cases: Iterable[Case], decisions: Iterable[Decision]) -> tuple[dict[str, str | bool], ...]:
    return tuple(
        {
            "case": case.case_id,
            "expected_allow": case.expected_allow,
            "allowed": decision.allowed,
            "reason": decision.reason_code,
            "workload": decision.authenticated_workload or "none",
        }
        for case, decision in zip(cases, decisions)
    )


def run_demo() -> dict[str, object]:
    registry = build_registry()
    cases = build_cases()
    baseline_report, baseline_decisions = evaluate(cases, declared_agent_baseline, registry)
    secure_report, secure_decisions = evaluate(cases, evidence_bound_gate, registry)

    assert baseline_report.unauthorized_success_rate == 1.0
    assert secure_report.valid_task_success_rate == 1.0
    assert secure_report.unauthorized_success_rate == 0.0
    assert secure_report.evidence_completeness_rate == 1.0
    for case, decision in zip(cases, secure_decisions):
        assert decision.allowed == case.expected_allow
        assert decision.reason_code == case.expected_reason

    return {
        "baseline": baseline_report.as_dict(),
        "secure": secure_report.as_dict(),
        "baseline_decisions": decision_rows(cases, baseline_decisions),
        "secure_decisions": decision_rows(cases, secure_decisions),
    }


if __name__ == "__main__":
    from pprint import pprint

    result = run_demo()
    print("Declared-agent baseline")
    pprint(result["baseline"])
    print("\nEvidence-bound gate")
    pprint(result["secure"])
    print("\nSecure decisions")
    pprint(result["secure_decisions"])
