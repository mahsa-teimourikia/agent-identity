"""Credential-free hybrid authorization lab for autonomous claims agents.

The agent supplies only an action proposal. Trusted application code supplies
identity, relationship, task, resource, risk, policy-version, and approval
facts. The policy decision point (PDP) returns a structured decision; the policy
enforcement point (PEP) reauthorizes at commit, enforces constraints and
obligations, and records a privacy-safe receipt.

This is an intentionally small reference implementation, not a replacement for
OPA, Cedar, OpenFGA, an identity provider, or a durable transaction service.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterable, Mapping
from dataclasses import asdict, dataclass, field, replace
from hashlib import sha256
from pathlib import Path
from threading import Lock
from typing import Any

NOW = 1_800_000_000
TENANT = "tenant:northstar"
OTHER_TENANT = "tenant:contoso"
USER = "user:alice"
AGENT = "agent:claims"
SUBAGENT = "agent:research"
WORKLOAD = "spiffe://northstar.example/claims/agent"
TASK = "task:claim-483"
CLAIM = "claim:483"
TOOL = "tool:claims-update"
POLICY_VERSION = "advanced-authz-2026-10-07"
RELATION_VERSION = "relations:42"
ATTRIBUTE_VERSION = "attributes:17"
RESOURCE_VERSION = 9


def canonical(value: Any) -> str:
    """Stable JSON for bindings, cache keys, approvals, and evidence."""

    if hasattr(value, "__dataclass_fields__"):
        value = asdict(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=list)


def digest(value: Any) -> str:
    return sha256(canonical(value).encode()).hexdigest()


class EnforcementError(RuntimeError):
    """Public, stable failure from the PEP."""

    def __init__(self, reason_code: str):
        self.reason_code = reason_code
        super().__init__(reason_code)


@dataclass(frozen=True)
class VerifiedIdentity:
    subject_id: str
    agent_id: str
    workload_id: str
    tenant_id: str
    roles: frozenset[str]
    authenticated: bool = True
    workload_attested: bool = True


@dataclass(frozen=True)
class RelationshipSnapshot:
    """Versioned facts normally resolved by a ReBAC service such as OpenFGA."""

    version: str
    observed_at: int
    user_operates_agent: bool
    agent_assigned_to_task: bool
    task_contains_resource: bool
    task_permits_tool: bool
    available: bool = True


@dataclass(frozen=True)
class TaskGrant:
    task_id: str
    tenant_id: str
    subject_id: str
    agent_id: str
    resource_id: str
    tool_id: str
    actions: frozenset[str]
    purposes: frozenset[str]
    expires_at: int
    remaining_calls: int
    active: bool = True


@dataclass(frozen=True)
class ResourceRecord:
    resource_id: str
    tenant_id: str
    owner_id: str
    classification: str
    status: str
    version: int


@dataclass(frozen=True)
class RuntimeAttributes:
    """Trusted ABAC inputs; no value is accepted from model text."""

    version: str
    observed_at: int
    source: str
    risk_score: int
    device_managed: bool
    network_zone: str
    available: bool = True


@dataclass(frozen=True)
class ActionProposal:
    """Untrusted agent intent. It contains no identity or authority fields."""

    operation_id: str
    action: str
    resource_id: str
    tool_id: str
    purpose: str
    fields: tuple[str, ...] = ()
    amount_cents: int = 0


@dataclass(frozen=True)
class ApprovalReceipt:
    receipt_id: str
    tenant_id: str
    subject_id: str
    agent_id: str
    task_id: str
    proposal_digest: str
    policy_version: str
    resource_version: int
    approver_id: str
    approver_role: str
    issued_at: int
    expires_at: int


@dataclass(frozen=True)
class AuthorizationInput:
    identity: VerifiedIdentity
    relationships: RelationshipSnapshot
    task: TaskGrant
    resource: ResourceRecord
    attributes: RuntimeAttributes
    proposal: ActionProposal
    expected_policy_version: str = POLICY_VERSION
    approval: ApprovalReceipt | None = None


@dataclass(frozen=True)
class Obligation:
    obligation_id: str
    arguments: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Decision:
    """PDP output. Only the PEP turns an allow into an effect."""

    outcome: str  # allow | deny | step_up | retryable_error
    reason_codes: tuple[str, ...]
    constraints: Mapping[str, Any]
    obligations: tuple[Obligation, ...]
    policy_version: str
    relationship_version: str
    attribute_version: str
    resource_version: int
    decision_id: str
    input_digest: str
    cache_key: str
    cache_hit: bool = False


@dataclass(frozen=True)
class ExecutionReceipt:
    operation_id: str
    effect_id: str
    decision_id: str
    proposal_digest: str
    policy_version: str
    resource_version: int
    obligation_ids: tuple[str, ...]


def proposal_digest(proposal: ActionProposal) -> str:
    return digest(proposal)


def cache_key(authz: AuthorizationInput) -> str:
    """Bind every decision-relevant value, including all source versions."""

    return digest(
        {
            "identity": asdict(authz.identity),
            "relationships": asdict(authz.relationships),
            "task": asdict(authz.task),
            "resource": asdict(authz.resource),
            "attributes": asdict(authz.attributes),
            "proposal": asdict(authz.proposal),
            "policy_version": authz.expected_policy_version,
            "approval": asdict(authz.approval) if authz.approval else None,
        }
    )


def approval_failures(authz: AuthorizationInput, now: int = NOW) -> list[str]:
    receipt = authz.approval
    if receipt is None:
        return ["approval_required"]
    expected = {
        "tenant_id": authz.identity.tenant_id,
        "subject_id": authz.identity.subject_id,
        "agent_id": authz.identity.agent_id,
        "task_id": authz.task.task_id,
        "proposal_digest": proposal_digest(authz.proposal),
        "policy_version": POLICY_VERSION,
        "resource_version": authz.resource.version,
    }
    failures = [
        f"approval_{name}_mismatch"
        for name, expected_value in expected.items()
        if getattr(receipt, name) != expected_value
    ]
    if receipt.approver_role != "claims-supervisor":
        failures.append("approval_role_invalid")
    if not receipt.issued_at <= now < receipt.expires_at:
        failures.append("approval_expired")
    return failures


def common_failures(authz: AuthorizationInput, now: int = NOW) -> list[str]:
    i, rel, task, resource, attrs, proposal = (
        authz.identity,
        authz.relationships,
        authz.task,
        authz.resource,
        authz.attributes,
        authz.proposal,
    )
    failures: list[str] = []
    if authz.expected_policy_version != POLICY_VERSION:
        failures.append("policy_version_mismatch")
    if not i.authenticated:
        failures.append("identity_not_authenticated")
    if not i.workload_attested or i.workload_id != WORKLOAD:
        failures.append("workload_not_attested")
    if not rel.available:
        failures.append("relationship_dependency_unavailable")
    if not attrs.available:
        failures.append("attribute_dependency_unavailable")
    if rel.version != RELATION_VERSION:
        failures.append("relationship_version_stale")
    if attrs.version != ATTRIBUTE_VERSION:
        failures.append("attribute_version_stale")
    if rel.observed_at < now - 60:
        failures.append("relationships_stale")
    if attrs.observed_at < now - 60:
        failures.append("attributes_stale")
    if attrs.source != "risk-engine:v5" or not 0 <= attrs.risk_score <= 100:
        failures.append("attributes_untrusted_or_invalid")
    if len({i.tenant_id, task.tenant_id, resource.tenant_id}) != 1:
        failures.append("tenant_mismatch")
    if i.subject_id != task.subject_id:
        failures.append("subject_task_mismatch")
    if i.agent_id != task.agent_id:
        failures.append("agent_task_mismatch")
    relation_checks = {
        "operator_relationship_missing": rel.user_operates_agent,
        "task_assignment_missing": rel.agent_assigned_to_task,
        "resource_relationship_missing": rel.task_contains_resource,
        "tool_relationship_missing": rel.task_permits_tool,
    }
    failures.extend(code for code, passed in relation_checks.items() if not passed)
    if not task.active:
        failures.append("task_inactive")
    if task.expires_at <= now:
        failures.append("task_expired")
    if task.remaining_calls <= 0:
        failures.append("task_budget_exhausted")
    if proposal.action not in task.actions:
        failures.append("action_not_delegated")
    if proposal.purpose not in task.purposes:
        failures.append("purpose_not_delegated")
    if (
        proposal.resource_id != resource.resource_id
        or task.resource_id != resource.resource_id
    ):
        failures.append("resource_binding_mismatch")
    if proposal.tool_id != task.tool_id:
        failures.append("tool_binding_mismatch")
    if resource.owner_id != i.subject_id:
        failures.append("resource_owner_mismatch")
    return failures


class HybridPDP:
    """Compose role eligibility, ReBAC facts, ABAC context, and task bounds."""

    def __init__(self) -> None:
        self.evaluations = 0

    def evaluate(self, authz: AuthorizationInput, now: int = NOW) -> Decision:
        self.evaluations += 1
        failures = common_failures(authz, now)
        proposal, resource, attrs = authz.proposal, authz.resource, authz.attributes
        constraints: dict[str, Any] = {}
        obligations: list[Obligation] = []

        unavailable = {
            "relationship_dependency_unavailable",
            "attribute_dependency_unavailable",
        }.intersection(failures)
        if "claims-operator" not in authz.identity.roles:
            failures.append("role_ineligible")
        outcome = "deny"
        if unavailable:
            outcome = "retryable_error"
        elif failures:
            outcome = "deny"
        elif attrs.risk_score >= 80:
            failures.append("risk_critical")
        elif attrs.risk_score >= 50:
            failures.append("step_up_required")
            outcome = "step_up"
        elif proposal.action == "claim.read":
            constraints = {"max_classification": "restricted"}
            obligations = [
                Obligation("audit"),
                Obligation("redact", {"fields": ["ssn", "bank_account"]}),
            ]
        elif proposal.action == "claim.update":
            if resource.status != "open":
                failures.append("claim_not_open")
            if not attrs.device_managed or attrs.network_zone != "corporate":
                failures.append("update_context_not_trusted")
            constraints = {"allowed_fields": ["status", "notes"], "max_amount_cents": 0}
            obligations = [Obligation("audit"), Obligation("optimistic_lock")]
        elif proposal.action == "claim.settle":
            if resource.status != "settlement-approved":
                failures.append("claim_not_settlement_approved")
            if not 0 < proposal.amount_cents <= 50_000:
                failures.append("settlement_amount_out_of_bounds")
            failures.extend(approval_failures(authz, now))
            constraints = {"max_amount_cents": 50_000, "allowed_fields": []}
            obligations = [
                Obligation("audit"),
                Obligation("idempotency"),
                Obligation("consume_approval"),
                Obligation("optimistic_lock"),
            ]
        else:
            failures.append("action_unsupported")

        failures = list(dict.fromkeys(failures))
        if not failures:
            outcome = "allow"
        elif outcome not in {"step_up", "retryable_error"}:
            outcome = "deny"
        body_digest = digest(authz)
        key = cache_key(authz)
        return Decision(
            outcome=outcome,
            reason_codes=tuple(failures or ["policy_allow"]),
            constraints=constraints if outcome == "allow" else {},
            obligations=tuple(obligations if outcome == "allow" else ()),
            policy_version=POLICY_VERSION,
            relationship_version=authz.relationships.version,
            attribute_version=authz.attributes.version,
            resource_version=authz.resource.version,
            decision_id=f"decision:{body_digest[:20]}",
            input_digest=body_digest,
            cache_key=key,
        )


class DecisionCache:
    """Small TTL cache whose key contains the complete trusted decision state."""

    def __init__(self, ttl_seconds: int = 15) -> None:
        self.ttl_seconds = ttl_seconds
        self._entries: dict[str, tuple[int, Decision]] = {}

    def get(self, key: str, now: int) -> Decision | None:
        entry = self._entries.get(key)
        if not entry or entry[0] <= now:
            self._entries.pop(key, None)
            return None
        return replace(entry[1], cache_hit=True)

    def put(self, decision: Decision, now: int) -> None:
        if decision.outcome in {"allow", "deny", "step_up"}:
            self._entries[decision.cache_key] = (now + self.ttl_seconds, decision)

    def invalidate_all(self) -> None:
        self._entries.clear()


class CachedPDP:
    def __init__(self, pdp: HybridPDP, cache: DecisionCache) -> None:
        self.pdp = pdp
        self.cache = cache

    def evaluate(self, authz: AuthorizationInput, now: int = NOW) -> Decision:
        key = cache_key(authz)
        cached = self.cache.get(key, now)
        if cached:
            return cached
        decision = self.pdp.evaluate(authz, now)
        self.cache.put(decision, now)
        return decision


class ApprovalStore:
    def __init__(self) -> None:
        self._consumed: set[str] = set()
        self._lock = Lock()

    def consume(self, receipt: ApprovalReceipt | None) -> None:
        if receipt is None:
            raise EnforcementError("approval_required")
        with self._lock:
            if receipt.receipt_id in self._consumed:
                raise EnforcementError("approval_replayed")
            self._consumed.add(receipt.receipt_id)


class PolicyEnforcementPoint:
    """Fail-closed enforcement with commit-time reauthorization."""

    def __init__(
        self,
        pdp: Any,
        *,
        approvals: ApprovalStore | None = None,
        supported_obligations: Iterable[str] = (
            "audit",
            "redact",
            "idempotency",
            "consume_approval",
            "optimistic_lock",
        ),
    ) -> None:
        self.pdp = pdp
        self.approvals = approvals or ApprovalStore()
        self.supported_obligations = frozenset(supported_obligations)
        self._effects: dict[str, tuple[str, ExecutionReceipt]] = {}
        self._lock = Lock()
        self.evidence: list[dict[str, Any]] = []

    def execute(
        self,
        authz: AuthorizationInput,
        *,
        now: int = NOW,
        refresh: Callable[[], AuthorizationInput] | None = None,
    ) -> ExecutionReceipt:
        fingerprint = proposal_digest(authz.proposal)
        with self._lock:
            prior = self._effects.get(authz.proposal.operation_id)
            if prior:
                if prior[0] != fingerprint:
                    raise EnforcementError("operation_id_conflict")
                return prior[1]

        decision = self._evaluate(authz, now)
        if decision.outcome != "allow":
            self._record_non_allow(authz, decision, "not_executed")
        self._require_allow(decision)
        self._enforce_contract(authz, decision)

        commit_input = refresh() if refresh else authz
        commit_decision = self._evaluate(commit_input, now)
        if commit_decision.outcome != "allow":
            self._record_non_allow(commit_input, commit_decision, "commit_not_executed")
        self._require_allow(commit_decision, prefix="commit_")
        if proposal_digest(commit_input.proposal) != fingerprint:
            raise EnforcementError("commit_proposal_changed")
        if commit_input.resource.version != decision.resource_version:
            raise EnforcementError("commit_resource_version_changed")
        if commit_decision.policy_version != decision.policy_version:
            raise EnforcementError("commit_policy_version_changed")
        self._enforce_contract(commit_input, commit_decision)

        obligation_ids = {o.obligation_id for o in commit_decision.obligations}
        if "consume_approval" in obligation_ids:
            self.approvals.consume(commit_input.approval)
        receipt = ExecutionReceipt(
            operation_id=commit_input.proposal.operation_id,
            effect_id=f"effect:{fingerprint[:20]}",
            decision_id=commit_decision.decision_id,
            proposal_digest=fingerprint,
            policy_version=commit_decision.policy_version,
            resource_version=commit_input.resource.version,
            obligation_ids=tuple(sorted(obligation_ids)),
        )
        with self._lock:
            self._effects[commit_input.proposal.operation_id] = (fingerprint, receipt)
        self.evidence.append(
            {
                "operation_id": receipt.operation_id,
                "decision_id": receipt.decision_id,
                "proposal_digest": receipt.proposal_digest,
                "policy_version": receipt.policy_version,
                "relationship_version": commit_decision.relationship_version,
                "attribute_version": commit_decision.attribute_version,
                "resource_version": receipt.resource_version,
                "outcome": "executed",
                "reason_codes": list(commit_decision.reason_codes),
                "obligations": list(receipt.obligation_ids),
            }
        )
        return receipt

    def _record_non_allow(
        self, authz: AuthorizationInput, decision: Decision, outcome: str
    ) -> None:
        self.evidence.append(
            {
                "operation_id": authz.proposal.operation_id,
                "decision_id": decision.decision_id,
                "proposal_digest": proposal_digest(authz.proposal),
                "policy_version": decision.policy_version,
                "relationship_version": decision.relationship_version,
                "attribute_version": decision.attribute_version,
                "resource_version": decision.resource_version,
                "outcome": outcome,
                "decision_outcome": decision.outcome,
                "reason_codes": list(decision.reason_codes),
                "obligations": [],
            }
        )

    def _evaluate(self, authz: AuthorizationInput, now: int) -> Decision:
        try:
            return self.pdp.evaluate(authz, now)
        except Exception as exc:
            raise EnforcementError("pdp_unavailable") from exc

    @staticmethod
    def _require_allow(decision: Decision, prefix: str = "") -> None:
        if decision.outcome != "allow":
            reason = (
                decision.reason_codes[0] if decision.reason_codes else decision.outcome
            )
            raise EnforcementError(f"{prefix}{reason}")

    def _enforce_contract(self, authz: AuthorizationInput, decision: Decision) -> None:
        if decision.policy_version != POLICY_VERSION:
            raise EnforcementError("policy_version_unexpected")
        unknown = {
            o.obligation_id for o in decision.obligations
        } - self.supported_obligations
        if unknown:
            raise EnforcementError("obligation_unsupported")
        allowed_fields = set(
            decision.constraints.get("allowed_fields", authz.proposal.fields)
        )
        if not set(authz.proposal.fields).issubset(allowed_fields):
            raise EnforcementError("field_constraint_violated")
        maximum = decision.constraints.get("max_amount_cents")
        if maximum is not None and authz.proposal.amount_cents > maximum:
            raise EnforcementError("amount_constraint_violated")


@dataclass(frozen=True)
class DelegationGrant:
    grant_id: str
    tenant_id: str
    delegate_id: str
    actions: frozenset[str]
    resources: frozenset[str]
    tools: frozenset[str]
    purposes: frozenset[str]
    expires_at: int
    max_calls: int
    depth: int
    parent_digest: str | None = None


def delegation_violations(
    parent: DelegationGrant, child: DelegationGrant
) -> tuple[str, ...]:
    checks = {
        "tenant_widened": child.tenant_id != parent.tenant_id,
        "action_widened": not child.actions.issubset(parent.actions),
        "resource_widened": not child.resources.issubset(parent.resources),
        "tool_widened": not child.tools.issubset(parent.tools),
        "purpose_widened": not child.purposes.issubset(parent.purposes),
        "expiry_widened": child.expires_at > parent.expires_at,
        "budget_widened": child.max_calls > parent.max_calls,
        "depth_invalid": child.depth != parent.depth + 1 or child.depth > 2,
        "parent_binding_invalid": child.parent_digest != digest(parent),
    }
    return tuple(code for code, failed in checks.items() if failed)


def make_approval(authz: AuthorizationInput, **changes: Any) -> ApprovalReceipt:
    values = {
        "receipt_id": "approval:483:1",
        "tenant_id": authz.identity.tenant_id,
        "subject_id": authz.identity.subject_id,
        "agent_id": authz.identity.agent_id,
        "task_id": authz.task.task_id,
        "proposal_digest": proposal_digest(authz.proposal),
        "policy_version": POLICY_VERSION,
        "resource_version": authz.resource.version,
        "approver_id": "user:supervisor",
        "approver_role": "claims-supervisor",
        "issued_at": NOW - 10,
        "expires_at": NOW + 300,
    }
    values.update(changes)
    return ApprovalReceipt(**values)


def environment(action: str = "claim.read") -> AuthorizationInput:
    fields = ("status", "notes") if action == "claim.update" else ()
    status = "settlement-approved" if action == "claim.settle" else "open"
    proposal = ActionProposal(
        operation_id=f"operation:{action}:483",
        action=action,
        resource_id=CLAIM,
        tool_id=TOOL,
        purpose="settle-claim" if action == "claim.settle" else "claims-processing",
        fields=fields,
        amount_cents=25_000 if action == "claim.settle" else 0,
    )
    value = AuthorizationInput(
        identity=VerifiedIdentity(
            USER,
            AGENT,
            WORKLOAD,
            TENANT,
            frozenset({"claims-operator"}),
        ),
        relationships=RelationshipSnapshot(
            RELATION_VERSION,
            NOW - 5,
            True,
            True,
            True,
            True,
        ),
        task=TaskGrant(
            TASK,
            TENANT,
            USER,
            AGENT,
            CLAIM,
            TOOL,
            frozenset({"claim.read", "claim.update", "claim.settle"}),
            frozenset({"claims-processing", "settle-claim"}),
            NOW + 600,
            3,
        ),
        resource=ResourceRecord(
            CLAIM, TENANT, USER, "restricted", status, RESOURCE_VERSION
        ),
        attributes=RuntimeAttributes(
            ATTRIBUTE_VERSION,
            NOW - 5,
            "risk-engine:v5",
            20,
            True,
            "corporate",
        ),
        proposal=proposal,
    )
    return (
        replace(value, approval=make_approval(value))
        if action == "claim.settle"
        else value
    )


def role_only_baseline(authz: AuthorizationInput) -> bool:
    """Intentionally unsafe baseline used only for measured comparison."""

    return "claims-operator" in authz.identity.roles


@dataclass(frozen=True)
class Case:
    case_id: str
    category: str
    expected_outcome: str
    prepare: Callable[[], AuthorizationInput]


def build_cases() -> list[Case]:
    def case(
        case_id: str,
        category: str,
        expected: str,
        action: str = "claim.read",
        mutate: Callable[[AuthorizationInput], AuthorizationInput] | None = None,
    ) -> Case:
        def prepare() -> AuthorizationInput:
            value = environment(action)
            return mutate(value) if mutate else value

        return Case(case_id, category, expected, prepare)

    def identity(**changes: Any) -> Callable[[AuthorizationInput], AuthorizationInput]:
        return lambda x: replace(x, identity=replace(x.identity, **changes))

    def relationships(
        **changes: Any,
    ) -> Callable[[AuthorizationInput], AuthorizationInput]:
        return lambda x: replace(x, relationships=replace(x.relationships, **changes))

    def task(**changes: Any) -> Callable[[AuthorizationInput], AuthorizationInput]:
        return lambda x: replace(x, task=replace(x.task, **changes))

    def resource(**changes: Any) -> Callable[[AuthorizationInput], AuthorizationInput]:
        return lambda x: replace(x, resource=replace(x.resource, **changes))

    def attributes(
        **changes: Any,
    ) -> Callable[[AuthorizationInput], AuthorizationInput]:
        return lambda x: replace(x, attributes=replace(x.attributes, **changes))

    def proposal(**changes: Any) -> Callable[[AuthorizationInput], AuthorizationInput]:
        return lambda x: replace(x, proposal=replace(x.proposal, **changes))

    def approval(**changes: Any) -> Callable[[AuthorizationInput], AuthorizationInput]:
        return lambda x: replace(x, approval=replace(x.approval, **changes))  # type: ignore[arg-type]

    return [
        case("read_allowed", "valid", "allow"),
        case("update_allowed", "valid", "allow", "claim.update"),
        case("settle_allowed", "valid", "allow", "claim.settle"),
        case(
            "unauthenticated", "identity", "deny", mutate=identity(authenticated=False)
        ),
        case(
            "unattested_workload",
            "identity",
            "deny",
            mutate=identity(workload_attested=False),
        ),
        case(
            "wrong_workload",
            "identity",
            "deny",
            mutate=identity(workload_id="spiffe://evil/agent"),
        ),
        case("role_ineligible", "role", "deny", mutate=identity(roles=frozenset())),
        case(
            "cross_tenant", "isolation", "deny", mutate=resource(tenant_id=OTHER_TENANT)
        ),
        case(
            "wrong_subject", "binding", "deny", mutate=identity(subject_id="user:eve")
        ),
        case("wrong_agent", "binding", "deny", mutate=identity(agent_id="agent:rogue")),
        case(
            "operator_edge_missing",
            "relationship",
            "deny",
            mutate=relationships(user_operates_agent=False),
        ),
        case(
            "assignment_edge_missing",
            "relationship",
            "deny",
            mutate=relationships(agent_assigned_to_task=False),
        ),
        case(
            "resource_edge_missing",
            "relationship",
            "deny",
            mutate=relationships(task_contains_resource=False),
        ),
        case(
            "tool_edge_missing",
            "relationship",
            "deny",
            mutate=relationships(task_permits_tool=False),
        ),
        case(
            "relationships_stale",
            "freshness",
            "deny",
            mutate=relationships(observed_at=NOW - 61),
        ),
        case(
            "relation_version_stale",
            "version",
            "deny",
            mutate=relationships(version="relations:41"),
        ),
        case(
            "relationship_outage",
            "dependency",
            "retryable_error",
            mutate=relationships(available=False),
        ),
        case("task_inactive", "task", "deny", mutate=task(active=False)),
        case("task_expired", "task", "deny", mutate=task(expires_at=NOW)),
        case("task_budget_exhausted", "task", "deny", mutate=task(remaining_calls=0)),
        case(
            "action_widening",
            "task",
            "deny",
            "claim.update",
            task(actions=frozenset({"claim.read"})),
        ),
        case("purpose_widening", "task", "deny", mutate=proposal(purpose="marketing")),
        case(
            "resource_substitution",
            "binding",
            "deny",
            mutate=proposal(resource_id="claim:999"),
        ),
        case(
            "tool_substitution",
            "binding",
            "deny",
            mutate=proposal(tool_id="tool:wire-transfer"),
        ),
        case(
            "attribute_source_spoofed",
            "attribute",
            "deny",
            mutate=attributes(source="agent:self-report"),
        ),
        case(
            "attributes_stale",
            "freshness",
            "deny",
            mutate=attributes(observed_at=NOW - 61),
        ),
        case(
            "attribute_version_stale",
            "version",
            "deny",
            mutate=attributes(version="attributes:16"),
        ),
        case(
            "attribute_outage",
            "dependency",
            "retryable_error",
            mutate=attributes(available=False),
        ),
        case("elevated_risk", "risk", "step_up", mutate=attributes(risk_score=50)),
        case("critical_risk", "risk", "deny", mutate=attributes(risk_score=80)),
        case(
            "unmanaged_update",
            "context",
            "deny",
            "claim.update",
            attributes(device_managed=False),
        ),
        case(
            "external_network_update",
            "context",
            "deny",
            "claim.update",
            attributes(network_zone="external"),
        ),
        case(
            "closed_claim_update",
            "resource",
            "deny",
            "claim.update",
            resource(status="closed"),
        ),
        case(
            "settle_without_approval",
            "approval",
            "deny",
            "claim.settle",
            lambda x: replace(x, approval=None),
        ),
        case(
            "settle_approval_digest_changed",
            "approval",
            "deny",
            "claim.settle",
            approval(proposal_digest="wrong"),
        ),
        case(
            "settle_approval_expired",
            "approval",
            "deny",
            "claim.settle",
            approval(expires_at=NOW),
        ),
        case(
            "settle_too_large",
            "constraint",
            "deny",
            "claim.settle",
            proposal(amount_cents=50_001),
        ),
        case(
            "policy_version_stale",
            "version",
            "deny",
            mutate=lambda x: replace(x, expected_policy_version="old"),
        ),
    ]


@dataclass(frozen=True)
class Metrics:
    total: int
    expected_allow: int
    expected_non_allow: int
    exact_matches: int
    invalid_allows: int
    valid_work_blocked: int
    outcome_accuracy: float


def evaluate_cases(
    cases: Iterable[Case], *, hardened: bool
) -> tuple[Metrics, list[dict[str, Any]]]:
    rows: list[dict[str, Any]] = []
    pdp = HybridPDP()
    for item in cases:
        authz = item.prepare()
        actual = (
            pdp.evaluate(authz).outcome
            if hardened
            else ("allow" if role_only_baseline(authz) else "deny")
        )
        rows.append(
            {
                "case_id": item.case_id,
                "category": item.category,
                "expected": item.expected_outcome,
                "actual": actual,
                "match": actual == item.expected_outcome,
            }
        )
    total = len(rows)
    exact = sum(row["match"] for row in rows)
    metrics = Metrics(
        total=total,
        expected_allow=sum(row["expected"] == "allow" for row in rows),
        expected_non_allow=sum(row["expected"] != "allow" for row in rows),
        exact_matches=exact,
        invalid_allows=sum(
            row["actual"] == "allow" and row["expected"] != "allow" for row in rows
        ),
        valid_work_blocked=sum(
            row["actual"] != "allow" and row["expected"] == "allow" for row in rows
        ),
        outcome_accuracy=exact / total if total else 0.0,
    )
    return metrics, rows


def release_gate(metrics: Metrics) -> bool:
    return (
        metrics.total >= 35
        and metrics.invalid_allows == 0
        and metrics.valid_work_blocked == 0
        and metrics.outcome_accuracy == 1.0
    )


def opa_input(authz: AuthorizationInput) -> dict[str, Any]:
    """Map trusted state to the included Rego contract; no raw credentials."""

    return {
        "now": NOW,
        "policy_version": authz.expected_policy_version,
        "identity": {**asdict(authz.identity), "roles": sorted(authz.identity.roles)},
        "relationships": asdict(authz.relationships),
        "task": {
            **asdict(authz.task),
            "actions": sorted(authz.task.actions),
            "purposes": sorted(authz.task.purposes),
        },
        "resource": asdict(authz.resource),
        "attributes": asdict(authz.attributes),
        "proposal": asdict(authz.proposal),
        "approval_valid": not approval_failures(authz)
        if authz.proposal.action == "claim.settle"
        else False,
    }


def cedar_request(authz: AuthorizationInput) -> dict[str, Any]:
    action = {
        "claim.read": "ReadClaim",
        "claim.update": "UpdateClaim",
        "claim.settle": "SettleClaim",
    }.get(authz.proposal.action, "Unsupported")
    failures = common_failures(authz)
    return {
        "principal": {"type": "Agent", "id": authz.identity.agent_id},
        "action": {"type": "Action", "id": action},
        "resource": {"type": "Claim", "id": authz.resource.resource_id},
        "context": {
            "authenticated": authz.identity.authenticated,
            "workloadTrusted": authz.identity.workload_attested
            and authz.identity.workload_id == WORKLOAD,
            "roleEligible": "claims-operator" in authz.identity.roles,
            "policyVersionCurrent": "policy_version_mismatch" not in failures,
            "tenantMatch": "tenant_mismatch" not in failures,
            "relationshipBinding": not any(
                code in failures
                for code in (
                    "operator_relationship_missing",
                    "task_assignment_missing",
                    "resource_relationship_missing",
                    "tool_relationship_missing",
                )
            ),
            "taskValid": not any(
                code in failures
                for code in (
                    "task_inactive",
                    "task_expired",
                    "task_budget_exhausted",
                    "action_not_delegated",
                    "purpose_not_delegated",
                    "resource_binding_mismatch",
                    "tool_binding_mismatch",
                )
            ),
            "stateCurrent": not any(
                "stale" in code or "unavailable" in code or "untrusted" in code
                for code in failures
            ),
            "riskScore": authz.attributes.risk_score,
            "updateContextTrusted": authz.attributes.device_managed
            and authz.attributes.network_zone == "corporate",
            "claimOpen": authz.resource.status == "open",
            "settlementApproved": authz.resource.status == "settlement-approved",
            "amountValid": 0 < authz.proposal.amount_cents <= 50_000,
            "approvalValid": not approval_failures(authz)
            if authz.proposal.action == "claim.settle"
            else False,
        },
    }


def cedar_entities(authz: AuthorizationInput) -> list[dict[str, Any]]:
    return [
        {
            "uid": {"type": "Agent", "id": authz.identity.agent_id},
            "attrs": {"tenantId": authz.identity.tenant_id},
            "parents": [],
        },
        {
            "uid": {"type": "Claim", "id": authz.resource.resource_id},
            "attrs": {"tenantId": authz.resource.tenant_id},
            "parents": [],
        },
    ]


def evaluate_cedar(authz: AuthorizationInput, course_dir: Path | None = None) -> bool:
    import cedarpy

    root = course_dir or Path(__file__).parent
    policies = (root / "policies/cedar/agent_authz.cedar").read_text()
    schema = json.loads((root / "policies/cedar/schema.json").read_text())
    validation = cedarpy.validate_policies(policies, schema)
    if not validation.validation_passed:
        raise RuntimeError(f"Cedar validation failed: {validation}")
    result = cedarpy.is_authorized(
        cedar_request(authz), policies, cedar_entities(authz), schema
    )
    # Cedar skips a policy that errors. The application treats diagnostics as a
    # deny signal; schema validation reduces but does not replace this runtime check.
    if result.diagnostics.errors:
        return False
    return result.decision == cedarpy.Decision.Allow


def openfga_check(authz: AuthorizationInput) -> Any:
    """Build a real OpenFGA SDK request without requiring a live server."""

    from openfga_sdk.client.models import ClientCheckRequest, ClientTuple

    relation = {
        "claim.read": "can_read",
        "claim.update": "can_update",
        "claim.settle": "can_settle",
    }.get(authz.proposal.action, "unsupported")
    tuples = [
        ClientTuple(
            user=authz.identity.agent_id,
            relation="operator",
            object=authz.identity.subject_id,
        ),
        ClientTuple(
            user=authz.identity.agent_id, relation="assignee", object=authz.task.task_id
        ),
        ClientTuple(
            user=authz.task.task_id, relation="task", object=authz.resource.resource_id
        ),
        ClientTuple(
            user=authz.identity.agent_id,
            relation="invoker",
            object=authz.proposal.tool_id,
        ),
    ]
    return ClientCheckRequest(
        user=authz.identity.agent_id,
        relation=relation,
        object=authz.resource.resource_id,
        contextual_tuples=tuples,
    )


if __name__ == "__main__":
    baseline, _ = evaluate_cases(build_cases(), hardened=False)
    hardened, rows = evaluate_cases(build_cases(), hardened=True)
    print(
        json.dumps(
            {
                "baseline": asdict(baseline),
                "hardened": asdict(hardened),
                "release_gate": release_gate(hardened),
                "mismatches": [row for row in rows if not row["match"]],
            },
            indent=2,
        )
    )
