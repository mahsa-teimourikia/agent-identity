"""Deterministic authorization lab for Beginner 04.

The lab compares a broad role check with a default-deny policy decision point
(PDP) and a policy enforcement point (PEP) for a refund agent.  All identities
and resource attributes supplied to the PDP are treated as trusted application
state, not model output.  The implementation is credential-free and has no
network side effects.

The in-memory approval store demonstrates exact binding and single-use
consumption.  A production service must make approval consumption and the
business effect atomic in durable storage.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from enum import Enum
import hashlib
import json
from threading import Lock
from typing import Callable, Iterable


NOW = datetime(2026, 9, 21, 12, 0, tzinfo=timezone.utc)
POLICY_VERSION = "refund-authorization/2026-09-21.1"
AUTO_REFUND_LIMIT = 200
MANAGER_REFUND_LIMIT = 1_000


class Outcome(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


@dataclass(frozen=True)
class VerifiedContext:
    """Identity context created by trusted authentication middleware."""

    requester_id: str
    actor_id: str
    workload_id: str
    tenant_id: str


@dataclass(frozen=True)
class RefundProposal:
    """Untrusted action proposed by an agent or other caller."""

    request_id: str
    task_id: str
    action: str
    resource_id: str
    amount_cents: int
    currency: str = "CAD"


@dataclass(frozen=True)
class PrincipalRecord:
    principal_id: str
    kind: str
    tenant_id: str
    active: bool = True


@dataclass(frozen=True)
class WorkloadBinding:
    workload_id: str
    actor_id: str
    tenant_id: str
    environment: str
    active: bool = True


@dataclass(frozen=True)
class OrderRecord:
    order_id: str
    tenant_id: str
    customer_id: str
    state: str
    refundable_cents: int


@dataclass(frozen=True)
class DelegationGrant:
    grant_id: str
    requester_id: str
    delegate_actor_id: str
    workload_id: str
    tenant_id: str
    task_id: str
    actions: frozenset[str]
    resources: frozenset[str]
    max_amount_cents: int
    issued_at: datetime
    expires_at: datetime
    redelegation_allowed: bool = False


@dataclass(frozen=True)
class ApprovalReceipt:
    approval_id: str
    approver_id: str
    approver_role: str
    tenant_id: str
    proposal_digest: str
    policy_version: str
    issued_at: datetime
    expires_at: datetime


@dataclass(frozen=True)
class AuthorizationDecision:
    outcome: Outcome
    reason_code: str
    decision_id: str
    request_id: str
    policy_version: str
    proposal_digest: str
    checks: tuple[str, ...]
    obligations: tuple[str, ...] = ()
    grant_id: str | None = None
    approval_id: str | None = None

    @property
    def allowed(self) -> bool:
        return self.outcome is Outcome.ALLOW

    @property
    def evidence_complete(self) -> bool:
        return bool(
            self.decision_id
            and self.request_id
            and self.policy_version
            and self.proposal_digest
            and self.reason_code
            and self.checks
        )


@dataclass(frozen=True)
class ExecutionReceipt:
    execution_id: str
    request_id: str
    resource_id: str
    amount_cents: int
    decision_id: str


@dataclass(frozen=True)
class GatewayResult:
    decision: AuthorizationDecision
    execution: ExecutionReceipt | None


@dataclass(frozen=True)
class ScenarioCase:
    case_id: str
    context: VerifiedContext
    proposal: RefundProposal
    expected_outcomes: tuple[Outcome, ...]
    approval: ApprovalReceipt | None = None
    pdp_available: bool = True


@dataclass(frozen=True)
class EvaluationReport:
    attempts: int
    expected_executable_attempts: int
    expected_blocked_attempts: int
    valid_execution_rate: float
    invalid_execution_rate: float
    invalid_block_rate: float
    approval_challenge_rate: float
    evidence_completeness_rate: float

    def as_dict(self) -> dict[str, float | int]:
        return {
            "attempts": self.attempts,
            "expected_executable_attempts": self.expected_executable_attempts,
            "expected_blocked_attempts": self.expected_blocked_attempts,
            "valid_execution_rate": self.valid_execution_rate,
            "invalid_execution_rate": self.invalid_execution_rate,
            "invalid_block_rate": self.invalid_block_rate,
            "approval_challenge_rate": self.approval_challenge_rate,
            "evidence_completeness_rate": self.evidence_completeness_rate,
        }


class PolicyUnavailable(RuntimeError):
    """Raised by the PDP adapter when policy evaluation is unavailable."""


class ApprovalStore:
    """Atomic-style, single-process stand-in for a durable approval store."""

    def __init__(self) -> None:
        self._consumed: set[str] = set()
        self._lock = Lock()

    def consume(self, approval_id: str) -> bool:
        with self._lock:
            if approval_id in self._consumed:
                return False
            self._consumed.add(approval_id)
            return True


def _stable_digest(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def proposal_digest(proposal: RefundProposal) -> str:
    return _stable_digest(
        {
            "request_id": proposal.request_id,
            "task_id": proposal.task_id,
            "action": proposal.action,
            "resource_id": proposal.resource_id,
            "amount_cents": proposal.amount_cents,
            "currency": proposal.currency,
        }
    )


def _decision_id(proposal: RefundProposal, attempt: int) -> str:
    seed = f"{proposal_digest(proposal)}:{attempt}:{POLICY_VERSION}"
    return f"decision:{hashlib.sha256(seed.encode()).hexdigest()[:16]}"


def _decision(
    proposal: RefundProposal,
    attempt: int,
    outcome: Outcome,
    reason: str,
    checks: list[str],
    *,
    obligations: tuple[str, ...] = (),
    grant_id: str | None = None,
    approval_id: str | None = None,
) -> AuthorizationDecision:
    return AuthorizationDecision(
        outcome=outcome,
        reason_code=reason,
        decision_id=_decision_id(proposal, attempt),
        request_id=proposal.request_id,
        policy_version=POLICY_VERSION,
        proposal_digest=proposal_digest(proposal),
        checks=tuple(checks),
        obligations=obligations,
        grant_id=grant_id,
        approval_id=approval_id,
    )


def build_policy_data() -> tuple[
    dict[str, PrincipalRecord],
    dict[str, WorkloadBinding],
    dict[str, OrderRecord],
    dict[str, DelegationGrant],
    dict[str, frozenset[str]],
]:
    principals = {
        "user:alice": PrincipalRecord("user:alice", "customer", "tenant:north"),
        "user:bob": PrincipalRecord("user:bob", "customer", "tenant:south"),
        "agent:refund": PrincipalRecord("agent:refund", "agent", "tenant:north"),
        "agent:refund-child": PrincipalRecord(
            "agent:refund-child", "agent", "tenant:north"
        ),
        "manager:mira": PrincipalRecord("manager:mira", "human", "tenant:north"),
    }
    workloads = {
        "spiffe://corp.example/ns/refunds/sa/refund-prod": WorkloadBinding(
            "spiffe://corp.example/ns/refunds/sa/refund-prod",
            "agent:refund",
            "tenant:north",
            "production",
        ),
        "spiffe://corp.example/ns/research/sa/research-prod": WorkloadBinding(
            "spiffe://corp.example/ns/research/sa/research-prod",
            "agent:refund-child",
            "tenant:north",
            "production",
        ),
    }
    orders = {
        "order:north:123": OrderRecord(
            "order:north:123", "tenant:north", "user:alice", "paid", 80_000
        ),
        "order:north:closed": OrderRecord(
            "order:north:closed", "tenant:north", "user:alice", "refunded", 0
        ),
        "order:south:999": OrderRecord(
            "order:south:999", "tenant:south", "user:bob", "paid", 90_000
        ),
    }
    grants = {
        "task:refund-928": DelegationGrant(
            grant_id="grant:refund-928",
            requester_id="user:alice",
            delegate_actor_id="agent:refund",
            workload_id="spiffe://corp.example/ns/refunds/sa/refund-prod",
            tenant_id="tenant:north",
            task_id="task:refund-928",
            actions=frozenset({"refund:create", "order:read"}),
            resources=frozenset({"order:north:123"}),
            max_amount_cents=60_000,
            issued_at=NOW - timedelta(minutes=5),
            expires_at=NOW + timedelta(minutes=10),
        ),
        "task:expired": DelegationGrant(
            grant_id="grant:expired",
            requester_id="user:alice",
            delegate_actor_id="agent:refund",
            workload_id="spiffe://corp.example/ns/refunds/sa/refund-prod",
            tenant_id="tenant:north",
            task_id="task:expired",
            actions=frozenset({"refund:create"}),
            resources=frozenset({"order:north:123"}),
            max_amount_cents=60_000,
            issued_at=NOW - timedelta(hours=1),
            expires_at=NOW - timedelta(minutes=1),
        ),
    }
    roles = {
        "agent:refund": frozenset({"refund_agent"}),
        "manager:mira": frozenset({"refund_manager"}),
    }
    return principals, workloads, orders, grants, roles


def issue_approval(
    proposal: RefundProposal,
    *,
    approval_id: str = "approval:928",
    approver_id: str = "manager:mira",
    approver_role: str = "refund_manager",
    tenant_id: str = "tenant:north",
    issued_at: datetime = NOW - timedelta(minutes=1),
    expires_at: datetime = NOW + timedelta(minutes=5),
    digest: str | None = None,
    policy_version: str = POLICY_VERSION,
) -> ApprovalReceipt:
    return ApprovalReceipt(
        approval_id=approval_id,
        approver_id=approver_id,
        approver_role=approver_role,
        tenant_id=tenant_id,
        proposal_digest=digest or proposal_digest(proposal),
        policy_version=policy_version,
        issued_at=issued_at,
        expires_at=expires_at,
    )


class BroadRolePDP:
    """Intentionally unsafe baseline: role + action, without resource scope."""

    def __init__(self, roles: dict[str, frozenset[str]]) -> None:
        self.roles = roles

    def decide(
        self,
        context: VerifiedContext,
        proposal: RefundProposal,
        approval: ApprovalReceipt | None,
        approval_store: ApprovalStore,
        attempt: int,
    ) -> AuthorizationDecision:
        del approval, approval_store
        checks = ["actor_role", "action_name"]
        allowed = (
            "refund_agent" in self.roles.get(context.actor_id, frozenset())
            and proposal.action == "refund:create"
        )
        return _decision(
            proposal,
            attempt,
            Outcome.ALLOW if allowed else Outcome.DENY,
            "broad_role_match" if allowed else "role_or_action_missing",
            checks,
        )


class RefundPDP:
    """Default-deny composed policy for one bounded refund workflow."""

    def __init__(
        self,
        *,
        available: bool = True,
        now: datetime = NOW,
    ) -> None:
        self.available = available
        self.now = now
        (
            self.principals,
            self.workloads,
            self.orders,
            self.grants,
            self.roles,
        ) = build_policy_data()

    def decide(
        self,
        context: VerifiedContext,
        proposal: RefundProposal,
        approval: ApprovalReceipt | None,
        approval_store: ApprovalStore,
        attempt: int,
    ) -> AuthorizationDecision:
        if not self.available:
            raise PolicyUnavailable("policy service unavailable")

        checks: list[str] = ["schema"]
        if (
            not proposal.request_id
            or not proposal.task_id
            or proposal.action != "refund:create"
            or not proposal.resource_id
            or not isinstance(proposal.amount_cents, int)
            or proposal.amount_cents <= 0
            or proposal.currency != "CAD"
        ):
            return _decision(proposal, attempt, Outcome.DENY, "invalid_request", checks)

        checks.append("principal_lifecycle")
        requester = self.principals.get(context.requester_id)
        actor = self.principals.get(context.actor_id)
        if not requester or not actor or not requester.active or not actor.active:
            return _decision(proposal, attempt, Outcome.DENY, "principal_invalid", checks)

        checks.append("workload_binding")
        binding = self.workloads.get(context.workload_id)
        if (
            not binding
            or not binding.active
            or binding.environment != "production"
            or binding.actor_id != context.actor_id
            or binding.tenant_id != context.tenant_id
        ):
            return _decision(proposal, attempt, Outcome.DENY, "workload_not_bound", checks)

        checks.append("resource_state")
        order = self.orders.get(proposal.resource_id)
        if not order:
            return _decision(proposal, attempt, Outcome.DENY, "resource_unknown", checks)
        if order.state != "paid" or proposal.amount_cents > order.refundable_cents:
            return _decision(proposal, attempt, Outcome.DENY, "resource_not_refundable", checks)

        checks.append("tenant_and_relationship")
        if not (
            requester.tenant_id
            == actor.tenant_id
            == order.tenant_id
            == context.tenant_id
        ):
            return _decision(proposal, attempt, Outcome.DENY, "tenant_mismatch", checks)
        if order.customer_id != context.requester_id:
            return _decision(proposal, attempt, Outcome.DENY, "requester_not_customer", checks)

        checks.append("task_delegation")
        grant = self.grants.get(proposal.task_id)
        if not grant:
            return _decision(proposal, attempt, Outcome.DENY, "delegation_missing", checks)
        if self.now < grant.issued_at or self.now >= grant.expires_at:
            return _decision(
                proposal,
                attempt,
                Outcome.DENY,
                "delegation_expired",
                checks,
                grant_id=grant.grant_id,
            )
        if (
            grant.requester_id != context.requester_id
            or grant.delegate_actor_id != context.actor_id
            or grant.workload_id != context.workload_id
            or grant.tenant_id != context.tenant_id
            or proposal.action not in grant.actions
            or proposal.resource_id not in grant.resources
        ):
            return _decision(
                proposal,
                attempt,
                Outcome.DENY,
                "delegation_scope_mismatch",
                checks,
                grant_id=grant.grant_id,
            )

        checks.append("amount_boundary")
        if (
            proposal.amount_cents > grant.max_amount_cents
            or proposal.amount_cents > MANAGER_REFUND_LIMIT * 100
        ):
            return _decision(
                proposal,
                attempt,
                Outcome.DENY,
                "amount_exceeds_authority",
                checks,
                grant_id=grant.grant_id,
            )

        if proposal.amount_cents <= AUTO_REFUND_LIMIT * 100:
            return _decision(
                proposal,
                attempt,
                Outcome.ALLOW,
                "bounded_refund_allowed",
                checks,
                grant_id=grant.grant_id,
            )

        checks.append("approval_binding")
        if approval is None:
            return _decision(
                proposal,
                attempt,
                Outcome.REQUIRE_APPROVAL,
                "manager_approval_required",
                checks,
                obligations=("obtain_bound_manager_approval",),
                grant_id=grant.grant_id,
            )
        if (
            approval.approver_role != "refund_manager"
            or "refund_manager"
            not in self.roles.get(approval.approver_id, frozenset())
            or approval.approver_id
            in {context.requester_id, context.actor_id}
            or approval.tenant_id != context.tenant_id
            or approval.proposal_digest != proposal_digest(proposal)
            or approval.policy_version != POLICY_VERSION
            or self.now < approval.issued_at
            or self.now >= approval.expires_at
        ):
            return _decision(
                proposal,
                attempt,
                Outcome.DENY,
                "approval_invalid",
                checks,
                grant_id=grant.grant_id,
                approval_id=approval.approval_id,
            )

        checks.append("approval_single_use")
        if not approval_store.consume(approval.approval_id):
            return _decision(
                proposal,
                attempt,
                Outcome.DENY,
                "approval_replayed",
                checks,
                grant_id=grant.grant_id,
                approval_id=approval.approval_id,
            )
        return _decision(
            proposal,
            attempt,
            Outcome.ALLOW,
            "approved_refund_allowed",
            checks,
            grant_id=grant.grant_id,
            approval_id=approval.approval_id,
        )


class RefundGateway:
    """PEP: obtain a decision, fail closed, then execute only an allow."""

    def __init__(self, pdp: BroadRolePDP | RefundPDP) -> None:
        self.pdp = pdp
        self.approval_store = ApprovalStore()
        self.audit_log: list[AuthorizationDecision] = []
        self.executions: list[ExecutionReceipt] = []

    def submit(
        self,
        context: VerifiedContext,
        proposal: RefundProposal,
        *,
        approval: ApprovalReceipt | None = None,
        attempt: int = 1,
    ) -> GatewayResult:
        try:
            decision = self.pdp.decide(
                context, proposal, approval, self.approval_store, attempt
            )
        except PolicyUnavailable:
            decision = _decision(
                proposal,
                attempt,
                Outcome.DENY,
                "pdp_unavailable",
                ["fail_closed"],
            )
        self.audit_log.append(decision)
        if not decision.allowed:
            return GatewayResult(decision, None)

        execution = ExecutionReceipt(
            execution_id=f"execution:{decision.decision_id.removeprefix('decision:')}",
            request_id=proposal.request_id,
            resource_id=proposal.resource_id,
            amount_cents=proposal.amount_cents,
            decision_id=decision.decision_id,
        )
        self.executions.append(execution)
        return GatewayResult(decision, execution)


def attenuate(
    parent: DelegationGrant,
    *,
    grant_id: str,
    delegate_actor_id: str,
    workload_id: str,
    actions: frozenset[str],
    resources: frozenset[str],
    max_amount_cents: int,
    expires_at: datetime,
) -> DelegationGrant:
    """Create a child grant only when every authority dimension narrows."""

    if not parent.redelegation_allowed:
        raise ValueError("parent_forbids_redelegation")
    if not actions.issubset(parent.actions):
        raise ValueError("action_scope_widened")
    if not resources.issubset(parent.resources):
        raise ValueError("resource_scope_widened")
    if max_amount_cents > parent.max_amount_cents:
        raise ValueError("amount_scope_widened")
    if expires_at > parent.expires_at:
        raise ValueError("expiry_scope_widened")
    return replace(
        parent,
        grant_id=grant_id,
        delegate_actor_id=delegate_actor_id,
        workload_id=workload_id,
        actions=actions,
        resources=resources,
        max_amount_cents=max_amount_cents,
        expires_at=expires_at,
        redelegation_allowed=False,
    )


def authorized_order_context(
    context: VerifiedContext,
    task_id: str,
    requested_order_ids: Iterable[str],
    *,
    now: datetime = NOW,
) -> list[OrderRecord]:
    """Authorize exact order IDs before returning protected retrieval context."""

    principals, workloads, orders, grants, _ = build_policy_data()
    requester = principals.get(context.requester_id)
    actor = principals.get(context.actor_id)
    binding = workloads.get(context.workload_id)
    grant = grants.get(task_id)
    if not requester or not actor or not binding or not grant:
        return []
    if not all((requester.active, actor.active, binding.active)):
        return []
    if now < grant.issued_at or now >= grant.expires_at:
        return []
    if (
        binding.actor_id != context.actor_id
        or binding.tenant_id != context.tenant_id
        or grant.requester_id != context.requester_id
        or grant.delegate_actor_id != context.actor_id
        or grant.workload_id != context.workload_id
        or "order:read" not in grant.actions
    ):
        return []
    result = []
    for order_id in requested_order_ids:
        order = orders.get(order_id)
        if (
            order
            and order_id in grant.resources
            and order.tenant_id == context.tenant_id
            and order.customer_id == context.requester_id
        ):
            result.append(order)
    return result


def policy_engine_inputs(
    context: VerifiedContext, proposal: RefundProposal
) -> dict[str, object]:
    """Show how the same trusted request maps to common policy engines."""

    return {
        "opa": {
            "input": {
                "principal": context.actor_id,
                "requester": context.requester_id,
                "workload": context.workload_id,
                "tenant": context.tenant_id,
                "action": proposal.action,
                "resource": proposal.resource_id,
                "context": {
                    "task_id": proposal.task_id,
                    "amount_cents": proposal.amount_cents,
                    "currency": proposal.currency,
                },
            }
        },
        "cedar": {
            "principal": context.actor_id,
            "action": proposal.action,
            "resource": proposal.resource_id,
            "context": {
                "requester": context.requester_id,
                "workload": context.workload_id,
                "tenant": context.tenant_id,
                "task_id": proposal.task_id,
                "amount_cents": proposal.amount_cents,
            },
        },
        "openfga": {
            "checks": [
                {
                    "user": proposal.task_id,
                    "relation": "can_call",
                    "object": "tool:refund_create",
                },
                {
                    "user": context.requester_id,
                    "relation": "customer",
                    "object": proposal.resource_id,
                },
            ],
            "context": {
                "calling_agent": context.actor_id,
                "amount_cents": proposal.amount_cents,
            },
        },
    }


def build_cases() -> list[ScenarioCase]:
    valid_context = VerifiedContext(
        requester_id="user:alice",
        actor_id="agent:refund",
        workload_id="spiffe://corp.example/ns/refunds/sa/refund-prod",
        tenant_id="tenant:north",
    )
    low = RefundProposal(
        "request:low", "task:refund-928", "refund:create", "order:north:123", 12_500
    )
    high = RefundProposal(
        "request:high", "task:refund-928", "refund:create", "order:north:123", 45_000
    )
    altered = replace(high, request_id="request:altered", amount_cents=46_000)
    return [
        ScenarioCase("valid_low_refund", valid_context, low, (Outcome.ALLOW,)),
        ScenarioCase(
            "valid_approved_refund",
            valid_context,
            high,
            (Outcome.ALLOW,),
            issue_approval(high),
        ),
        ScenarioCase(
            "approval_required",
            valid_context,
            replace(high, request_id="request:approval-required"),
            (Outcome.REQUIRE_APPROVAL,),
        ),
        ScenarioCase(
            "cross_tenant_resource",
            valid_context,
            replace(low, request_id="request:cross-tenant", resource_id="order:south:999"),
            (Outcome.DENY,),
        ),
        ScenarioCase(
            "presented_tenant_substitution",
            replace(valid_context, tenant_id="tenant:south"),
            replace(low, request_id="request:tenant-substitution"),
            (Outcome.DENY,),
        ),
        ScenarioCase(
            "wrong_workload",
            replace(
                valid_context,
                workload_id="spiffe://corp.example/ns/research/sa/research-prod",
            ),
            replace(low, request_id="request:wrong-workload"),
            (Outcome.DENY,),
        ),
        ScenarioCase(
            "wrong_actor",
            replace(valid_context, actor_id="agent:refund-child"),
            replace(low, request_id="request:wrong-actor"),
            (Outcome.DENY,),
        ),
        ScenarioCase(
            "expired_delegation",
            valid_context,
            replace(low, request_id="request:expired", task_id="task:expired"),
            (Outcome.DENY,),
        ),
        ScenarioCase(
            "missing_delegation",
            valid_context,
            replace(low, request_id="request:no-grant", task_id="task:unknown"),
            (Outcome.DENY,),
        ),
        ScenarioCase(
            "unauthorized_action",
            valid_context,
            replace(low, request_id="request:wrong-action", action="order:delete"),
            (Outcome.DENY,),
        ),
        ScenarioCase(
            "amount_escalation",
            valid_context,
            replace(low, request_id="request:amount", amount_cents=60_001),
            (Outcome.DENY,),
        ),
        ScenarioCase(
            "closed_order",
            valid_context,
            replace(low, request_id="request:closed", resource_id="order:north:closed"),
            (Outcome.DENY,),
        ),
        ScenarioCase(
            "altered_after_approval",
            valid_context,
            altered,
            (Outcome.DENY,),
            issue_approval(altered, digest=proposal_digest(high), approval_id="approval:altered"),
        ),
        ScenarioCase(
            "replayed_approval",
            valid_context,
            replace(high, request_id="request:replay"),
            (Outcome.ALLOW, Outcome.DENY),
            issue_approval(
                replace(high, request_id="request:replay"), approval_id="approval:replay"
            ),
        ),
        ScenarioCase(
            "pdp_outage",
            valid_context,
            replace(low, request_id="request:outage"),
            (Outcome.DENY,),
            pdp_available=False,
        ),
        ScenarioCase(
            "invalid_negative_amount",
            valid_context,
            replace(low, request_id="request:negative", amount_cents=-1),
            (Outcome.DENY,),
        ),
    ]


PDPFactory = Callable[[bool], BroadRolePDP | RefundPDP]


def baseline_factory(available: bool) -> BroadRolePDP:
    del available
    return BroadRolePDP(build_policy_data()[4])


def hardened_factory(available: bool) -> RefundPDP:
    return RefundPDP(available=available)


def evaluate(
    cases: Iterable[ScenarioCase], factory: PDPFactory
) -> tuple[EvaluationReport, list[tuple[str, Outcome, GatewayResult]]]:
    rows: list[tuple[str, Outcome, GatewayResult]] = []
    for case in cases:
        gateway = RefundGateway(factory(case.pdp_available))
        for attempt, expected in enumerate(case.expected_outcomes, start=1):
            result = gateway.submit(
                case.context,
                case.proposal,
                approval=case.approval,
                attempt=attempt,
            )
            rows.append((case.case_id, expected, result))

    valid = [row for row in rows if row[1] is Outcome.ALLOW]
    invalid = [row for row in rows if row[1] is not Outcome.ALLOW]
    executed_valid = sum(row[2].execution is not None for row in valid)
    executed_invalid = sum(row[2].execution is not None for row in invalid)
    challenged = sum(
        row[2].decision.outcome is Outcome.REQUIRE_APPROVAL for row in rows
    )
    evidence = sum(row[2].decision.evidence_complete for row in rows)
    report = EvaluationReport(
        attempts=len(rows),
        expected_executable_attempts=len(valid),
        expected_blocked_attempts=len(invalid),
        valid_execution_rate=executed_valid / len(valid),
        invalid_execution_rate=executed_invalid / len(invalid),
        invalid_block_rate=(len(invalid) - executed_invalid) / len(invalid),
        approval_challenge_rate=challenged / len(rows),
        evidence_completeness_rate=evidence / len(rows),
    )
    return report, rows


def release_gate(report: EvaluationReport) -> bool:
    return (
        report.valid_execution_rate == 1.0
        and report.invalid_execution_rate == 0.0
        and report.evidence_completeness_rate == 1.0
    )


if __name__ == "__main__":
    cases = build_cases()
    baseline, _ = evaluate(cases, baseline_factory)
    hardened, _ = evaluate(cases, hardened_factory)
    print(json.dumps({"baseline": baseline.as_dict()}, indent=2))
    print(json.dumps({"hardened": hardened.as_dict()}, indent=2))
    print("release_gate", release_gate(hardened))
