"""Deterministic lab for Beginner 02: Humans, Workloads and Agents.

The lab models identity provenance for a multi-hop employee travel workflow.
It deliberately compares a platform-account baseline with a gate that preserves
the human requester, application, logical-agent chain, and runtime workload.
All records are synthetic and no external service is called.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from enum import Enum
from pprint import pprint
from typing import Callable, Iterable


NOW = datetime(2026, 9, 20, 12, 0, tzinfo=timezone.utc)
POLICY_VERSION = "identity-provenance/v1"
EXPECTED_AUDIENCE = "booking-api"
TRUSTED_ISSUER = "https://identity.corp.example"


class PrincipalKind(str, Enum):
    HUMAN = "human"
    APPLICATION = "application"
    AGENT = "agent"
    WORKLOAD = "workload"
    SERVICE = "service"
    RESOURCE = "resource"


@dataclass(frozen=True)
class Principal:
    principal_id: str
    kind: PrincipalKind
    tenant: str
    owner: str
    status: str = "active"
    environment: str | None = None


@dataclass(frozen=True)
class DeploymentBinding:
    binding_id: str
    application_id: str
    agent_id: str
    workload_id: str
    environment: str
    version: str
    status: str = "active"


@dataclass(frozen=True)
class DelegationEdge:
    delegation_id: str
    delegator_id: str
    delegate_id: str
    task_id: str
    actions: tuple[str, ...]
    resources: tuple[str, ...]
    tenant: str
    expires_at: datetime


@dataclass(frozen=True)
class IdentityEvidence:
    evidence_id: str
    authenticated_peer_id: str
    issuer: str
    audience: str
    tenant: str
    issued_at: datetime
    expires_at: datetime


@dataclass(frozen=True)
class ProvenanceEnvelope:
    correlation_id: str
    requester_id: str
    application_id: str
    current_actor_id: str
    parent_actor_id: str | None
    workload_id: str
    actor_chain: tuple[str, ...]
    task_id: str
    tenant: str


@dataclass(frozen=True)
class BookingRequest:
    action: str
    service_id: str
    resource_id: str


@dataclass(frozen=True)
class ResourceRecord:
    resource_id: str
    tenant: str
    status: str = "active"


@dataclass(frozen=True)
class Registry:
    principals: dict[str, Principal]
    deployments: tuple[DeploymentBinding, ...]
    delegations: tuple[DelegationEdge, ...]
    resources: dict[str, ResourceRecord]


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason_code: str
    correlation_id: str
    audit_principal: str
    evidence_id: str
    presented_requester: str
    presented_actor: str
    presented_workload: str
    validated_requester: str | None = None
    validated_application: str | None = None
    validated_actor: str | None = None
    validated_workload: str | None = None
    validated_service: str | None = None
    validated_resource: str | None = None
    validated_actor_chain: tuple[str, ...] = ()
    deployment_binding_id: str | None = None
    delegation_ids: tuple[str, ...] = ()
    policy_version: str = POLICY_VERSION

    @property
    def valid_provenance_complete(self) -> bool:
        return bool(
            self.allowed
            and self.correlation_id
            and self.evidence_id
            and self.validated_requester
            and self.validated_application
            and self.validated_actor
            and self.validated_workload
            and self.validated_service
            and self.validated_resource
            and self.validated_actor_chain
            and self.deployment_binding_id
            and self.delegation_ids
            and self.policy_version
        )


@dataclass(frozen=True)
class Case:
    case_id: str
    envelope: ProvenanceEnvelope
    evidence: IdentityEvidence
    request: BookingRequest
    expected_allow: bool


@dataclass(frozen=True)
class EvaluationReport:
    total_cases: int
    valid_cases: int
    invalid_cases: int
    valid_task_success_rate: float
    unauthorized_success_rate: float
    invalid_block_rate: float
    valid_provenance_completeness_rate: float
    invalid_identity_collision_rate: float

    def as_dict(self) -> dict[str, float | int]:
        return {
            "total_cases": self.total_cases,
            "valid_cases": self.valid_cases,
            "invalid_cases": self.invalid_cases,
            "valid_task_success_rate": self.valid_task_success_rate,
            "unauthorized_success_rate": self.unauthorized_success_rate,
            "invalid_block_rate": self.invalid_block_rate,
            "valid_provenance_completeness_rate": self.valid_provenance_completeness_rate,
            "invalid_identity_collision_rate": self.invalid_identity_collision_rate,
        }


def build_registry() -> Registry:
    principals = {
        principal.principal_id: principal
        for principal in (
            Principal("user:alice", PrincipalKind.HUMAN, "northwind", "people-ops"),
            Principal("client:travel-portal", PrincipalKind.APPLICATION, "northwind", "team:travel"),
            Principal("client:shared-agent-platform", PrincipalKind.APPLICATION, "northwind", "team:platform"),
            Principal("agent:travel-planner", PrincipalKind.AGENT, "northwind", "team:travel"),
            Principal("agent:booking-specialist", PrincipalKind.AGENT, "northwind", "team:travel"),
            Principal("agent:research-assistant", PrincipalKind.AGENT, "northwind", "team:research"),
            Principal(
                "spiffe://corp.example/prod/travel-planner",
                PrincipalKind.WORKLOAD,
                "northwind",
                "team:travel",
                environment="prod",
            ),
            Principal(
                "spiffe://corp.example/prod/booking-specialist",
                PrincipalKind.WORKLOAD,
                "northwind",
                "team:travel",
                environment="prod",
            ),
            Principal(
                "spiffe://corp.example/prod/research-assistant",
                PrincipalKind.WORKLOAD,
                "northwind",
                "team:research",
                environment="prod",
            ),
            Principal(
                "spiffe://corp.example/dev/booking-specialist",
                PrincipalKind.WORKLOAD,
                "northwind",
                "team:travel",
                environment="dev",
            ),
            Principal(
                "spiffe://corp.example/prod/booking-retired",
                PrincipalKind.WORKLOAD,
                "northwind",
                "team:travel",
                status="disabled",
                environment="prod",
            ),
            Principal("service:booking-api", PrincipalKind.SERVICE, "northwind", "team:travel"),
        )
    }
    deployments = (
        DeploymentBinding(
            "binding:travel-planner:v7",
            "client:travel-portal",
            "agent:travel-planner",
            "spiffe://corp.example/prod/travel-planner",
            "prod",
            "7.2.1",
        ),
        DeploymentBinding(
            "binding:booking-specialist:v4",
            "client:travel-portal",
            "agent:booking-specialist",
            "spiffe://corp.example/prod/booking-specialist",
            "prod",
            "4.8.0",
        ),
        DeploymentBinding(
            "binding:research-assistant:v2",
            "client:shared-agent-platform",
            "agent:research-assistant",
            "spiffe://corp.example/prod/research-assistant",
            "prod",
            "2.3.0",
        ),
        DeploymentBinding(
            "binding:booking-dev:v4",
            "client:travel-portal",
            "agent:booking-specialist",
            "spiffe://corp.example/dev/booking-specialist",
            "dev",
            "4.9.0-rc1",
        ),
    )
    delegations = (
        DelegationEdge(
            "delegation:alice-to-planner:trip-483",
            "user:alice",
            "agent:travel-planner",
            "trip:483",
            ("itinerary:read", "booking:create"),
            ("trip:483",),
            "northwind",
            NOW + timedelta(minutes=30),
        ),
        DelegationEdge(
            "delegation:planner-to-booking:trip-483",
            "agent:travel-planner",
            "agent:booking-specialist",
            "trip:483",
            ("booking:create",),
            ("trip:483",),
            "northwind",
            NOW + timedelta(minutes=10),
        ),
    )
    resources = {"trip:483": ResourceRecord("trip:483", "northwind")}
    return Registry(principals, deployments, delegations, resources)


def _decision(
    case: Case,
    *,
    allowed: bool,
    reason: str,
    audit_principal: str,
    requester: str | None = None,
    application: str | None = None,
    actor: str | None = None,
    workload: str | None = None,
    service: str | None = None,
    resource: str | None = None,
    actor_chain: tuple[str, ...] = (),
    binding_id: str | None = None,
    delegation_ids: tuple[str, ...] = (),
) -> Decision:
    return Decision(
        allowed=allowed,
        reason_code=reason,
        correlation_id=case.envelope.correlation_id,
        audit_principal=audit_principal,
        evidence_id=case.evidence.evidence_id,
        presented_requester=case.envelope.requester_id,
        presented_actor=case.envelope.current_actor_id,
        presented_workload=case.envelope.workload_id,
        validated_requester=requester,
        validated_application=application,
        validated_actor=actor,
        validated_workload=workload,
        validated_service=service,
        validated_resource=resource,
        validated_actor_chain=actor_chain,
        deployment_binding_id=binding_id,
        delegation_ids=delegation_ids,
    )


def collapsed_platform_baseline(case: Case, registry: Registry) -> Decision:
    """Unsafe baseline: every corporate workload becomes one platform identity."""
    del registry
    corporate_peer = case.evidence.authenticated_peer_id.startswith("spiffe://corp.example/")
    return _decision(
        case,
        allowed=corporate_peer,
        reason="trusted_shared_agent_platform" if corporate_peer else "unknown_platform",
        audit_principal="service-account:agents-prod",
    )


def provenance_bound_gate(case: Case, registry: Registry) -> Decision:
    """Validate each identity class and every edge in the delegation path."""

    def deny(reason: str, audit_principal: str = "unvalidated") -> Decision:
        return _decision(case, allowed=False, reason=reason, audit_principal=audit_principal)

    evidence = case.evidence
    envelope = case.envelope

    if evidence.issuer != TRUSTED_ISSUER:
        return deny("untrusted_issuer")
    if evidence.audience != EXPECTED_AUDIENCE:
        return deny("wrong_audience")
    if not (evidence.issued_at <= NOW < evidence.expires_at):
        return deny("evidence_not_current")

    peer = registry.principals.get(evidence.authenticated_peer_id)
    if not peer or peer.kind is not PrincipalKind.WORKLOAD or peer.status != "active":
        return deny("invalid_workload")
    if evidence.authenticated_peer_id != envelope.workload_id:
        return deny("peer_context_mismatch", peer.principal_id)
    if peer.environment != "prod":
        return deny("nonproduction_workload", peer.principal_id)

    requester = registry.principals.get(envelope.requester_id)
    if not requester or requester.kind is not PrincipalKind.HUMAN or requester.status != "active":
        return deny("invalid_requester", peer.principal_id)
    application = registry.principals.get(envelope.application_id)
    if not application or application.kind is not PrincipalKind.APPLICATION or application.status != "active":
        return deny("invalid_application", peer.principal_id)
    actor = registry.principals.get(envelope.current_actor_id)
    if not actor or actor.kind is not PrincipalKind.AGENT or actor.status != "active":
        return deny("invalid_actor", peer.principal_id)
    resource = registry.resources.get(case.request.resource_id)
    if not resource or resource.status != "active":
        return deny("invalid_resource", peer.principal_id)
    service = registry.principals.get(case.request.service_id)
    if not service or service.kind is not PrincipalKind.SERVICE or service.status != "active":
        return deny("invalid_service", peer.principal_id)

    tenants = {
        envelope.tenant,
        evidence.tenant,
        peer.tenant,
        requester.tenant,
        application.tenant,
        actor.tenant,
        service.tenant,
        resource.tenant,
    }
    if len(tenants) != 1:
        return deny("tenant_mismatch", peer.principal_id)

    binding = next(
        (
            item
            for item in registry.deployments
            if item.status == "active"
            and item.environment == "prod"
            and item.application_id == application.principal_id
            and item.agent_id == actor.principal_id
            and item.workload_id == peer.principal_id
        ),
        None,
    )
    if not binding:
        return deny("deployment_binding_mismatch", peer.principal_id)

    chain = envelope.actor_chain
    if not chain or chain[-1] != actor.principal_id:
        return deny("actor_chain_terminal_mismatch", peer.principal_id)
    if len(chain) > 2 or len(set(chain)) != len(chain):
        return deny("actor_chain_invalid", peer.principal_id)
    expected_parent = chain[-2] if len(chain) > 1 else None
    if envelope.parent_actor_id != expected_parent:
        return deny("parent_actor_mismatch", peer.principal_id)

    for principal_id in chain:
        principal = registry.principals.get(principal_id)
        if not principal or principal.kind is not PrincipalKind.AGENT or principal.status != "active":
            return deny("invalid_actor_chain_member", peer.principal_id)

    delegation_ids: list[str] = []
    path = (requester.principal_id,) + chain
    for delegator_id, delegate_id in zip(path, path[1:]):
        edge = next(
            (
                item
                for item in registry.delegations
                if item.delegator_id == delegator_id
                and item.delegate_id == delegate_id
                and item.task_id == envelope.task_id
                and item.tenant == envelope.tenant
                and NOW < item.expires_at
                and case.request.action in item.actions
                and case.request.resource_id in item.resources
            ),
            None,
        )
        if not edge:
            return deny("delegation_path_invalid", peer.principal_id)
        delegation_ids.append(edge.delegation_id)

    return _decision(
        case,
        allowed=True,
        reason="identity_provenance_valid",
        audit_principal=actor.principal_id,
        requester=requester.principal_id,
        application=application.principal_id,
        actor=actor.principal_id,
        workload=peer.principal_id,
        service=service.principal_id,
        resource=resource.resource_id,
        actor_chain=chain,
        binding_id=binding.binding_id,
        delegation_ids=tuple(delegation_ids),
    )


def build_cases() -> tuple[Case, ...]:
    envelope = ProvenanceEnvelope(
        correlation_id="corr-trip-483",
        requester_id="user:alice",
        application_id="client:travel-portal",
        current_actor_id="agent:booking-specialist",
        parent_actor_id="agent:travel-planner",
        workload_id="spiffe://corp.example/prod/booking-specialist",
        actor_chain=("agent:travel-planner", "agent:booking-specialist"),
        task_id="trip:483",
        tenant="northwind",
    )
    evidence = IdentityEvidence(
        evidence_id="evidence:booking-prod",
        authenticated_peer_id="spiffe://corp.example/prod/booking-specialist",
        issuer=TRUSTED_ISSUER,
        audience=EXPECTED_AUDIENCE,
        tenant="northwind",
        issued_at=NOW - timedelta(minutes=1),
        expires_at=NOW + timedelta(minutes=4),
    )
    request = BookingRequest("booking:create", "service:booking-api", "trip:483")
    valid = Case("valid_multihop_booking", envelope, evidence, request, True)

    def variant(
        case_id: str,
        *,
        envelope_value: ProvenanceEnvelope = envelope,
        evidence_value: IdentityEvidence = evidence,
        request_value: BookingRequest = request,
    ) -> Case:
        return Case(case_id, envelope_value, evidence_value, request_value, False)

    research_workload = "spiffe://corp.example/prod/research-assistant"
    dev_workload = "spiffe://corp.example/dev/booking-specialist"
    retired_workload = "spiffe://corp.example/prod/booking-retired"

    return (
        valid,
        variant(
            "spoofed_logical_agent",
            envelope_value=replace(envelope, workload_id=research_workload, correlation_id="corr-spoof"),
            evidence_value=replace(
                evidence,
                evidence_id="evidence:research-prod",
                authenticated_peer_id=research_workload,
            ),
        ),
        variant(
            "development_runtime",
            envelope_value=replace(envelope, workload_id=dev_workload, correlation_id="corr-dev"),
            evidence_value=replace(evidence, evidence_id="evidence:booking-dev", authenticated_peer_id=dev_workload),
        ),
        variant(
            "application_identity_collision",
            envelope_value=replace(
                envelope,
                application_id="client:shared-agent-platform",
                correlation_id="corr-client",
            ),
        ),
        variant(
            "unknown_requester",
            envelope_value=replace(envelope, requester_id="user:mallory", correlation_id="corr-requester"),
        ),
        variant(
            "cross_tenant_context",
            envelope_value=replace(envelope, tenant="contoso", correlation_id="corr-tenant"),
        ),
        variant(
            "missing_parent_actor",
            envelope_value=replace(envelope, parent_actor_id=None, correlation_id="corr-parent"),
        ),
        variant(
            "cyclic_actor_chain",
            envelope_value=replace(
                envelope,
                actor_chain=("agent:travel-planner", "agent:travel-planner", "agent:booking-specialist"),
                correlation_id="corr-cycle",
            ),
        ),
        variant(
            "task_substitution",
            envelope_value=replace(envelope, task_id="trip:999", correlation_id="corr-task"),
        ),
        variant(
            "disabled_workload",
            envelope_value=replace(envelope, workload_id=retired_workload, correlation_id="corr-disabled"),
            evidence_value=replace(evidence, evidence_id="evidence:retired", authenticated_peer_id=retired_workload),
        ),
    )


Gate = Callable[[Case, Registry], Decision]


def evaluate(cases: Iterable[Case], gate: Gate, registry: Registry) -> tuple[EvaluationReport, tuple[Decision, ...]]:
    case_list = tuple(cases)
    decisions = tuple(gate(case, registry) for case in case_list)
    valid_pairs = [(case, decision) for case, decision in zip(case_list, decisions) if case.expected_allow]
    invalid_pairs = [(case, decision) for case, decision in zip(case_list, decisions) if not case.expected_allow]

    valid_allowed = sum(decision.allowed for _, decision in valid_pairs)
    invalid_allowed = sum(decision.allowed for _, decision in invalid_pairs)
    invalid_blocked = sum(not decision.allowed for _, decision in invalid_pairs)
    complete_valid = sum(decision.valid_provenance_complete for _, decision in valid_pairs)
    valid_audit_principals = {decision.audit_principal for _, decision in valid_pairs if decision.allowed}
    invalid_collisions = sum(
        decision.allowed and decision.audit_principal in valid_audit_principals
        for _, decision in invalid_pairs
    )

    def rate(numerator: int, denominator: int) -> float:
        return numerator / denominator if denominator else 0.0

    report = EvaluationReport(
        total_cases=len(case_list),
        valid_cases=len(valid_pairs),
        invalid_cases=len(invalid_pairs),
        valid_task_success_rate=rate(valid_allowed, len(valid_pairs)),
        unauthorized_success_rate=rate(invalid_allowed, len(invalid_pairs)),
        invalid_block_rate=rate(invalid_blocked, len(invalid_pairs)),
        valid_provenance_completeness_rate=rate(complete_valid, len(valid_pairs)),
        invalid_identity_collision_rate=rate(invalid_collisions, len(invalid_pairs)),
    )
    return report, decisions


def decision_rows(cases: Iterable[Case], decisions: Iterable[Decision]) -> tuple[dict[str, object], ...]:
    return tuple(
        {
            "case": case.case_id,
            "expected_allow": case.expected_allow,
            "allowed": decision.allowed,
            "reason": decision.reason_code,
            "audit_principal": decision.audit_principal,
        }
        for case, decision in zip(cases, decisions)
    )


def run_demo() -> None:
    registry = build_registry()
    cases = build_cases()
    baseline_report, _ = evaluate(cases, collapsed_platform_baseline, registry)
    controlled_report, controlled_decisions = evaluate(cases, provenance_bound_gate, registry)

    print("Collapsed platform-identity baseline")
    pprint(baseline_report.as_dict())
    print("\nProvenance-bound gate")
    pprint(controlled_report.as_dict())
    print("\nControlled decisions")
    pprint(decision_rows(cases, controlled_decisions))

    assert baseline_report.unauthorized_success_rate == 1.0
    assert baseline_report.invalid_identity_collision_rate == 1.0
    assert controlled_report.valid_task_success_rate == 1.0
    assert controlled_report.unauthorized_success_rate == 0.0
    assert controlled_report.invalid_block_rate == 1.0
    assert controlled_report.valid_provenance_completeness_rate == 1.0
    assert controlled_report.invalid_identity_collision_rate == 0.0


if __name__ == "__main__":
    run_demo()
