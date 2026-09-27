"""Deterministic fine-grained authorization lab for an insurance claims agent.

The model or agent proposes an action. Trusted application code derives identity,
task, resource, risk, and approval facts; asks a PDP; enforces every obligation;
and records a privacy-safe decision. No network service or credential is required.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field, replace
from hashlib import sha256
import json
from pathlib import Path
from threading import Lock
from typing import Any, Callable, Iterable, Mapping


NOW = 1_800_000_000
POLICY_VERSION = "claims-authz-2026-09-27"
TENANT = "tenant:northstar"
OTHER_TENANT = "tenant:contoso"
USER = "user:alice"
AGENT = "agent:claims-adjuster"
WORKLOAD = "spiffe://northstar.example/claims/adjuster"
TASK = "task:review-clm-100"
CLAIM = "claim:clm-100"
OTHER_CLAIM = "claim:clm-900"


class AuthorizationError(RuntimeError):
    """A stable, public failure suitable for tests and decision evidence."""

    def __init__(self, reason_code: str):
        self.reason_code = reason_code
        super().__init__(reason_code)


class DependencyUnavailable(RuntimeError):
    pass


def canonical(value: Any) -> str:
    if hasattr(value, "__dataclass_fields__"):
        value = asdict(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=list)


def digest(value: Any) -> str:
    return sha256(canonical(value).encode()).hexdigest()


@dataclass(frozen=True)
class VerifiedCaller:
    """Facts created by authentication, workload verification, and token validation."""

    subject_id: str
    agent_id: str
    workload_id: str
    tenant_id: str
    scopes: frozenset[str]
    authenticated: bool = True
    workload_attested: bool = True


@dataclass(frozen=True)
class TaskGrant:
    task_id: str
    tenant_id: str
    requester_id: str
    assignee_id: str
    resource_id: str
    allowed_actions: frozenset[str]
    expires_at: int
    active: bool = True


@dataclass(frozen=True)
class ResourceRecord:
    resource_id: str
    tenant_id: str
    owner_id: str
    status: str
    version: int


@dataclass(frozen=True)
class RiskSignal:
    resource_id: str
    tenant_id: str
    score: int
    source: str
    observed_at: int


@dataclass(frozen=True)
class ActionProposal:
    """Untrusted agent intent. Identity and authority are deliberately absent."""

    operation_id: str
    action: str
    resource_id: str
    purpose: str
    amount_cents: int = 0


def proposal_digest(proposal: ActionProposal) -> str:
    return digest(proposal)


@dataclass(frozen=True)
class ApprovalReceipt:
    receipt_id: str
    tenant_id: str
    subject_id: str
    agent_id: str
    task_id: str
    action: str
    resource_id: str
    proposal_digest: str
    policy_version: str
    approver_id: str
    approver_role: str
    issued_at: int
    expires_at: int


@dataclass(frozen=True)
class AuthorizationInput:
    caller: VerifiedCaller
    task: TaskGrant
    resource: ResourceRecord
    risk: RiskSignal
    proposal: ActionProposal
    approval: ApprovalReceipt | None = None


@dataclass(frozen=True)
class Obligation:
    obligation_id: str
    arguments: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason_codes: tuple[str, ...]
    obligations: tuple[Obligation, ...]
    decision_id: str
    policy_version: str
    input_digest: str
    engine: str = "reference"


@dataclass(frozen=True)
class ExecutionReceipt:
    operation_id: str
    result_id: str
    decision_id: str
    policy_version: str
    obligation_ids: tuple[str, ...]


def required_scope(action: str) -> str:
    return {
        "claim.read": "claims:read",
        "claim.update": "claims:update",
        "payment.create": "payments:create",
    }.get(action, "unsupported")


def common_failures(authz: AuthorizationInput, now: int = NOW) -> list[str]:
    c, t, r, risk, p = authz.caller, authz.task, authz.resource, authz.risk, authz.proposal
    failures: list[str] = []
    if not c.authenticated:
        failures.append("caller_not_authenticated")
    if not c.workload_attested:
        failures.append("workload_not_attested")
    if c.workload_id != WORKLOAD:
        failures.append("workload_not_allowed")
    if c.subject_id != t.requester_id:
        failures.append("subject_task_mismatch")
    if c.agent_id != t.assignee_id:
        failures.append("agent_task_mismatch")
    if not t.active:
        failures.append("task_inactive")
    if t.expires_at <= now:
        failures.append("task_expired")
    if p.resource_id != r.resource_id or t.resource_id != r.resource_id:
        failures.append("resource_task_mismatch")
    if r.owner_id != c.subject_id:
        failures.append("resource_owner_mismatch")
    if len({c.tenant_id, t.tenant_id, r.tenant_id, risk.tenant_id}) != 1:
        failures.append("tenant_mismatch")
    if (
        risk.resource_id != r.resource_id
        or risk.observed_at < now - 300
        or risk.source != "fraud-service:v4"
        or not 0 <= risk.score <= 100
    ):
        failures.append("risk_signal_stale_or_mismatched")
    if p.action not in t.allowed_actions:
        failures.append("action_not_delegated")
    if required_scope(p.action) not in c.scopes:
        failures.append("scope_missing")
    return failures


def approval_failures(authz: AuthorizationInput, now: int = NOW) -> list[str]:
    p, c, t, receipt = authz.proposal, authz.caller, authz.task, authz.approval
    if receipt is None:
        return ["approval_required"]
    expected = {
        "tenant_id": c.tenant_id,
        "subject_id": c.subject_id,
        "agent_id": c.agent_id,
        "task_id": t.task_id,
        "action": p.action,
        "resource_id": p.resource_id,
        "proposal_digest": proposal_digest(p),
        "policy_version": POLICY_VERSION,
    }
    failures = [f"approval_{name}_mismatch" for name, value in expected.items() if getattr(receipt, name) != value]
    if receipt.approver_role != "claims-supervisor":
        failures.append("approval_role_invalid")
    if not (receipt.issued_at <= now < receipt.expires_at):
        failures.append("approval_expired")
    return failures


class ReferencePDP:
    """Reference policy decision point; it decides but performs no side effect."""

    def evaluate(self, authz: AuthorizationInput, now: int = NOW) -> Decision:
        failures = common_failures(authz, now)
        p, r, risk = authz.proposal, authz.resource, authz.risk
        obligations: list[Obligation] = []

        if p.action == "claim.read":
            obligations.extend((Obligation("audit"), Obligation("redact_pii", {"fields": ["ssn"]})))
        elif p.action == "claim.update":
            if r.status != "open":
                failures.append("claim_not_open")
            if risk.score >= 50:
                failures.append("risk_too_high")
            obligations.append(Obligation("audit"))
        elif p.action == "payment.create":
            if r.status != "settlement-approved":
                failures.append("claim_not_settlement_approved")
            if p.amount_cents <= 0 or p.amount_cents > 50_000:
                failures.append("payment_amount_out_of_bounds")
            if p.purpose != f"settle:{r.resource_id}":
                failures.append("purpose_mismatch")
            failures.extend(approval_failures(authz, now))
            obligations.extend((Obligation("audit"), Obligation("idempotency", {"operation_id": p.operation_id})))
        else:
            failures.append("action_unsupported")

        failures = list(dict.fromkeys(failures))
        body = {
            "caller": asdict(authz.caller),
            "task": asdict(authz.task),
            "resource": asdict(authz.resource),
            "risk": asdict(authz.risk),
            "proposal": asdict(authz.proposal),
            "approval_digest": digest(authz.approval) if authz.approval else None,
        }
        input_hash = digest(body)
        return Decision(
            allowed=not failures,
            reason_codes=tuple(failures or ["policy_allow"]),
            obligations=tuple(obligations if not failures else ()),
            decision_id=f"decision:{input_hash[:20]}",
            policy_version=POLICY_VERSION,
            input_digest=input_hash,
        )


class ApprovalStore:
    """Atomically consumes exact receipts after an allow decision and before effect."""

    def __init__(self) -> None:
        self._consumed: set[str] = set()
        self._lock = Lock()

    def consume(self, receipt: ApprovalReceipt | None) -> None:
        if receipt is None:
            raise AuthorizationError("approval_required")
        with self._lock:
            if receipt.receipt_id in self._consumed:
                raise AuthorizationError("approval_replayed")
            self._consumed.add(receipt.receipt_id)


class PolicyEnforcementPoint:
    """Fail-closed PEP with obligation handling and exact idempotent reconciliation."""

    def __init__(
        self,
        pdp: ReferencePDP | Any,
        approvals: ApprovalStore | None = None,
        supported_obligations: Iterable[str] = ("audit", "redact_pii", "idempotency"),
    ) -> None:
        self.pdp = pdp
        self.approvals = approvals or ApprovalStore()
        self.supported_obligations = frozenset(supported_obligations)
        self._operations: dict[str, tuple[str, ExecutionReceipt]] = {}
        self._lock = Lock()
        self.evidence: list[dict[str, Any]] = []

    def execute(self, authz: AuthorizationInput, now: int = NOW) -> ExecutionReceipt:
        fingerprint = proposal_digest(authz.proposal)
        with self._lock:
            prior = self._operations.get(authz.proposal.operation_id)
            if prior:
                if prior[0] != fingerprint:
                    self._record_failure(authz, "operation_id_conflict")
                    raise AuthorizationError("operation_id_conflict")
                return prior[1]

        try:
            decision = self.pdp.evaluate(authz, now)
        except Exception as exc:
            self._record_failure(authz, "pdp_unavailable")
            raise AuthorizationError("pdp_unavailable") from exc
        if not decision.allowed:
            self._record(authz, decision, "denied")
            raise AuthorizationError(decision.reason_codes[0])
        if decision.policy_version != POLICY_VERSION:
            self._record_failure(authz, "policy_version_stale", decision.policy_version)
            raise AuthorizationError("policy_version_stale")

        unknown = [o.obligation_id for o in decision.obligations if o.obligation_id not in self.supported_obligations]
        if unknown:
            self._record_failure(authz, "obligation_unsupported", decision.policy_version)
            raise AuthorizationError("obligation_unsupported")
        if authz.proposal.action == "payment.create":
            try:
                self.approvals.consume(authz.approval)
            except AuthorizationError as exc:
                self._record_failure(authz, exc.reason_code, decision.policy_version)
                raise

        receipt = ExecutionReceipt(
            operation_id=authz.proposal.operation_id,
            result_id=f"result:{fingerprint[:20]}",
            decision_id=decision.decision_id,
            policy_version=decision.policy_version,
            obligation_ids=tuple(o.obligation_id for o in decision.obligations),
        )
        with self._lock:
            prior = self._operations.get(authz.proposal.operation_id)
            if prior and prior[0] != fingerprint:
                self._record_failure(authz, "operation_id_conflict", decision.policy_version)
                raise AuthorizationError("operation_id_conflict")
            self._operations[authz.proposal.operation_id] = (fingerprint, receipt)
        self._record(authz, decision, "executed")
        return receipt

    def _record(self, authz: AuthorizationInput, decision: Decision, outcome: str) -> None:
        self.evidence.append(
            {
                "decision_id": decision.decision_id,
                "operation_id": authz.proposal.operation_id,
                "input_digest": decision.input_digest,
                "policy_version": decision.policy_version,
                "allowed": decision.allowed,
                "reason_codes": list(decision.reason_codes),
                "obligations": [o.obligation_id for o in decision.obligations],
                "outcome": outcome,
            }
        )

    def _record_failure(self, authz: AuthorizationInput, reason: str, policy_version: str = POLICY_VERSION) -> None:
        input_hash = digest(authz)
        self.evidence.append(
            {
                "decision_id": f"failure:{input_hash[:20]}",
                "operation_id": authz.proposal.operation_id,
                "input_digest": input_hash,
                "policy_version": policy_version,
                "allowed": False,
                "reason_codes": [reason],
                "obligations": [],
                "outcome": "not_executed",
            }
        )


def make_approval(authz: AuthorizationInput, **changes: Any) -> ApprovalReceipt:
    values = dict(
        receipt_id="approval:clm-100:1",
        tenant_id=authz.caller.tenant_id,
        subject_id=authz.caller.subject_id,
        agent_id=authz.caller.agent_id,
        task_id=authz.task.task_id,
        action=authz.proposal.action,
        resource_id=authz.proposal.resource_id,
        proposal_digest=proposal_digest(authz.proposal),
        policy_version=POLICY_VERSION,
        approver_id="user:supervisor-bob",
        approver_role="claims-supervisor",
        issued_at=NOW - 30,
        expires_at=NOW + 300,
    )
    values.update(changes)
    return ApprovalReceipt(**values)


def environment(action: str = "claim.read") -> AuthorizationInput:
    status = "settlement-approved" if action == "payment.create" else "open"
    proposal = ActionProposal(
        operation_id=f"operation:{action}:clm-100",
        action=action,
        resource_id=CLAIM,
        purpose=f"settle:{CLAIM}" if action == "payment.create" else "adjust-claim",
        amount_cents=25_000 if action == "payment.create" else 0,
    )
    base = AuthorizationInput(
        caller=VerifiedCaller(USER, AGENT, WORKLOAD, TENANT, frozenset({"claims:read", "claims:update", "payments:create"})),
        task=TaskGrant(TASK, TENANT, USER, AGENT, CLAIM, frozenset({"claim.read", "claim.update", "payment.create"}), NOW + 600),
        resource=ResourceRecord(CLAIM, TENANT, USER, status, 7),
        risk=RiskSignal(CLAIM, TENANT, 20, "fraud-service:v4", NOW - 5),
        proposal=proposal,
    )
    return replace(base, approval=make_approval(base)) if action == "payment.create" else base


def scope_only_baseline(authz: AuthorizationInput) -> bool:
    """Intentionally unsafe comparison: possession of a matching scope is enough."""

    return required_scope(authz.proposal.action) in authz.caller.scopes


@dataclass(frozen=True)
class Case:
    case_id: str
    expected_allowed: bool
    category: str
    prepare: Callable[[], AuthorizationInput]
    mode: str = "normal"


def _case(case_id: str, expected: bool, category: str, action: str, mutate: Callable[[AuthorizationInput], AuthorizationInput] | None = None, mode: str = "normal") -> Case:
    def prepare() -> AuthorizationInput:
        value = environment(action)
        return mutate(value) if mutate else value

    return Case(case_id, expected, category, prepare, mode)


def build_cases() -> list[Case]:
    def caller(**changes: Any) -> Callable[[AuthorizationInput], AuthorizationInput]:
        return lambda x: replace(x, caller=replace(x.caller, **changes))

    def task(**changes: Any) -> Callable[[AuthorizationInput], AuthorizationInput]:
        return lambda x: replace(x, task=replace(x.task, **changes))

    def resource(**changes: Any) -> Callable[[AuthorizationInput], AuthorizationInput]:
        return lambda x: replace(x, resource=replace(x.resource, **changes))

    def risk(**changes: Any) -> Callable[[AuthorizationInput], AuthorizationInput]:
        return lambda x: replace(x, risk=replace(x.risk, **changes))

    def proposal(**changes: Any) -> Callable[[AuthorizationInput], AuthorizationInput]:
        return lambda x: replace(x, proposal=replace(x.proposal, **changes))

    def approval(**changes: Any) -> Callable[[AuthorizationInput], AuthorizationInput]:
        return lambda x: replace(x, approval=replace(x.approval, **changes))  # type: ignore[arg-type]

    return [
        _case("read_allowed", True, "valid", "claim.read"),
        _case("update_allowed", True, "valid", "claim.update"),
        _case("payment_allowed", True, "valid", "payment.create"),
        _case("read_high_risk_allowed", True, "valid", "claim.read", risk(score=90)),
        _case("unauthenticated", False, "identity", "claim.read", caller(authenticated=False)),
        _case("workload_unattested", False, "identity", "claim.read", caller(workload_attested=False)),
        _case("workload_substitution", False, "identity", "claim.read", caller(workload_id="spiffe://attacker/agent")),
        _case("subject_substitution", False, "identity", "claim.read", caller(subject_id="user:eve")),
        _case("agent_substitution", False, "identity", "claim.read", caller(agent_id="agent:rogue")),
        _case("caller_cross_tenant", False, "isolation", "claim.read", caller(tenant_id=OTHER_TENANT)),
        _case("resource_cross_tenant", False, "isolation", "claim.read", resource(tenant_id=OTHER_TENANT)),
        _case("risk_cross_tenant", False, "isolation", "claim.update", risk(tenant_id=OTHER_TENANT)),
        _case("task_inactive", False, "lifecycle", "claim.read", task(active=False)),
        _case("task_expired", False, "lifecycle", "claim.read", task(expires_at=NOW)),
        _case("task_wrong_resource", False, "authority", "claim.read", task(resource_id=OTHER_CLAIM)),
        _case("proposal_wrong_resource", False, "authority", "claim.read", proposal(resource_id=OTHER_CLAIM)),
        _case("resource_wrong_owner", False, "authority", "claim.read", resource(owner_id="user:eve")),
        _case("action_not_delegated", False, "authority", "claim.update", task(allowed_actions=frozenset({"claim.read"}))),
        _case("scope_missing", False, "authority", "claim.update", caller(scopes=frozenset({"claims:read"}))),
        _case("closed_claim_update", False, "state", "claim.update", resource(status="closed")),
        _case("high_risk_update", False, "risk", "claim.update", risk(score=50)),
        _case("stale_risk", False, "risk", "claim.update", risk(observed_at=NOW - 301)),
        _case("untrusted_risk_source", False, "risk", "claim.update", risk(source="caller:self-report")),
        _case("invalid_risk_score", False, "risk", "claim.update", risk(score=-1)),
        _case("payment_too_large", False, "approval", "payment.create", proposal(amount_cents=50_001)),
        _case("payment_wrong_purpose", False, "approval", "payment.create", proposal(purpose="export-data")),
        _case("approval_missing", False, "approval", "payment.create", lambda x: replace(x, approval=None)),
        _case("approval_wrong_digest", False, "approval", "payment.create", approval(proposal_digest="wrong")),
        _case("approval_wrong_role", False, "approval", "payment.create", approval(approver_role="claims-viewer")),
        _case("approval_expired", False, "approval", "payment.create", approval(expires_at=NOW)),
        _case("pdp_unavailable", False, "failure", "claim.read", mode="pdp_unavailable"),
        _case("stale_policy", False, "failure", "claim.read", mode="stale_policy"),
        _case("unsupported_obligation", False, "failure", "claim.read", mode="unsupported_obligation"),
    ]


class _UnavailablePDP:
    def evaluate(self, authz: AuthorizationInput, now: int = NOW) -> Decision:
        raise DependencyUnavailable("offline")


class _StalePDP:
    def evaluate(self, authz: AuthorizationInput, now: int = NOW) -> Decision:
        return replace(ReferencePDP().evaluate(authz, now), policy_version="stale")


class _UnknownObligationPDP:
    def evaluate(self, authz: AuthorizationInput, now: int = NOW) -> Decision:
        return replace(ReferencePDP().evaluate(authz, now), obligations=(Obligation("notify_unknown_system"),))


@dataclass(frozen=True)
class Metrics:
    total: int
    expected_allowed: int
    expected_blocked: int
    outcome_matches: int
    invalid_acceptances: int
    valid_work_blocked: int
    accuracy: float


def run_case(case: Case, hardened: bool = True) -> tuple[bool, str]:
    authz = case.prepare()
    if not hardened:
        allowed = scope_only_baseline(authz)
        return allowed, "scope_present" if allowed else "scope_missing"
    pdp: Any = ReferencePDP()
    if case.mode == "pdp_unavailable":
        pdp = _UnavailablePDP()
    elif case.mode == "stale_policy":
        pdp = _StalePDP()
    elif case.mode == "unsupported_obligation":
        pdp = _UnknownObligationPDP()
    try:
        PolicyEnforcementPoint(pdp).execute(authz)
        return True, "executed"
    except AuthorizationError as exc:
        return False, exc.reason_code


def evaluate(cases: Iterable[Case], hardened: bool = True) -> tuple[Metrics, list[dict[str, Any]]]:
    rows = []
    for case in cases:
        actual, reason = run_case(case, hardened)
        rows.append({"case_id": case.case_id, "category": case.category, "expected": case.expected_allowed, "actual": actual, "reason": reason, "match": actual == case.expected_allowed})
    total = len(rows)
    matches = sum(row["match"] for row in rows)
    metrics = Metrics(
        total=total,
        expected_allowed=sum(row["expected"] for row in rows),
        expected_blocked=sum(not row["expected"] for row in rows),
        outcome_matches=matches,
        invalid_acceptances=sum(row["actual"] and not row["expected"] for row in rows),
        valid_work_blocked=sum(not row["actual"] and row["expected"] for row in rows),
        accuracy=matches / total if total else 0.0,
    )
    return metrics, rows


def release_gate(metrics: Metrics) -> bool:
    return metrics.total >= 30 and metrics.invalid_acceptances == 0 and metrics.valid_work_blocked == 0 and metrics.accuracy == 1.0


def authzen_request(authz: AuthorizationInput) -> dict[str, Any]:
    """Create the AuthZEN SARC request from trusted application state."""

    return {
        "subject": {"type": "identity", "id": authz.caller.agent_id, "properties": {"subject_id": authz.caller.subject_id, "workload_id": authz.caller.workload_id, "tenant_id": authz.caller.tenant_id}},
        "action": {"name": authz.proposal.action},
        "resource": {"type": "claim", "id": authz.resource.resource_id, "properties": {"tenant_id": authz.resource.tenant_id, "status": authz.resource.status}},
        "context": {"task_id": authz.task.task_id, "operation_id": authz.proposal.operation_id, "risk_score": authz.risk.score, "amount_cents": authz.proposal.amount_cents, "approval_valid": not approval_failures(authz) if authz.proposal.action == "payment.create" else False},
    }


def opa_input(authz: AuthorizationInput) -> dict[str, Any]:
    """Input document for ``data.claims.authz.decision``; no raw credentials."""

    return {
        "now": NOW,
        "policy_version": POLICY_VERSION,
        "caller": {**asdict(authz.caller), "scopes": sorted(authz.caller.scopes)},
        "task": {**asdict(authz.task), "allowed_actions": sorted(authz.task.allowed_actions)},
        "resource": asdict(authz.resource),
        "risk": asdict(authz.risk),
        "proposal": asdict(authz.proposal),
        "approval_valid": not approval_failures(authz) if authz.proposal.action == "payment.create" else False,
    }


def cedar_request(authz: AuthorizationInput) -> dict[str, Any]:
    action = {"claim.read": "ReadClaim", "claim.update": "UpdateClaim", "payment.create": "CreatePayment"}.get(authz.proposal.action, "Unsupported")
    failures = common_failures(authz)
    return {
        "principal": {"type": "Agent", "id": authz.caller.agent_id},
        "action": {"type": "Action", "id": action},
        "resource": {"type": "Claim", "id": authz.resource.resource_id},
        "context": {
            "authenticated": authz.caller.authenticated,
            "workloadAttested": authz.caller.workload_attested and authz.caller.workload_id == WORKLOAD,
            "tenantMatch": "tenant_mismatch" not in failures,
            "taskBinding": not any(code in failures for code in ("subject_task_mismatch", "agent_task_mismatch", "task_inactive", "task_expired", "resource_task_mismatch", "resource_owner_mismatch", "action_not_delegated", "scope_missing")),
            "claimOpen": authz.resource.status == "open",
            "settlementApproved": authz.resource.status == "settlement-approved",
            "riskScore": authz.risk.score,
            "riskCurrent": "risk_signal_stale_or_mismatched" not in failures,
            "amountCents": authz.proposal.amount_cents,
            "amountValid": 0 < authz.proposal.amount_cents <= 50_000,
            "purposeMatches": authz.proposal.purpose == f"settle:{authz.resource.resource_id}",
            "approvalValid": not approval_failures(authz) if authz.proposal.action == "payment.create" else False,
        },
    }


def cedar_entities(authz: AuthorizationInput) -> list[dict[str, Any]]:
    return [
        {"uid": {"type": "Agent", "id": authz.caller.agent_id}, "attrs": {"tenantId": authz.caller.tenant_id}, "parents": []},
        {"uid": {"type": "Claim", "id": authz.resource.resource_id}, "attrs": {"tenantId": authz.resource.tenant_id, "ownerId": authz.resource.owner_id}, "parents": []},
    ]


def evaluate_cedar(authz: AuthorizationInput, course_dir: Path | None = None) -> bool:
    """Execute the real Cedar policy through cedarpy (optional course dependency)."""

    try:
        import cedarpy
    except ImportError as exc:  # pragma: no cover - dependency guidance path
        raise RuntimeError("Install cedarpy from requirements.txt") from exc
    root = course_dir or Path(__file__).parent
    policies = (root / "policies/cedar/claims.cedar").read_text()
    schema = json.loads((root / "policies/cedar/schema.json").read_text())
    validation = cedarpy.validate_policies(policies, schema)
    if not validation.validation_passed:
        raise RuntimeError(f"Cedar validation failed: {validation}")
    result = cedarpy.is_authorized(cedar_request(authz), policies, cedar_entities(authz), schema)
    return result.decision == cedarpy.Decision.Allow


def openfga_check(authz: AuthorizationInput) -> Any:
    """Build an OpenFGA SDK Check request; a live server remains an explicit exercise."""

    try:
        from openfga_sdk.client.models import ClientCheckRequest, ClientTuple
    except ImportError as exc:  # pragma: no cover - dependency guidance path
        raise RuntimeError("Install openfga-sdk from requirements.txt") from exc
    relation = {"claim.read": "can_read", "claim.update": "can_update", "payment.create": "can_pay"}.get(authz.proposal.action, "unsupported")
    tuples = [
        ClientTuple(user=authz.caller.agent_id, relation="assignee", object=authz.task.task_id),
        ClientTuple(user=authz.caller.agent_id, relation="delegated_agent", object=authz.task.task_id),
        ClientTuple(user=authz.task.task_id, relation="assigned_task", object=authz.resource.resource_id),
    ]
    return ClientCheckRequest(user=authz.caller.agent_id, relation=relation, object=authz.resource.resource_id, contextual_tuples=tuples)


def opa_client(url: str = "http://localhost:8181") -> Any:
    """Construct the maintained Python client without making a network request."""

    try:
        from opa_client.opa import OpaClient
    except ImportError as exc:  # pragma: no cover - dependency guidance path
        raise RuntimeError("Install opa-python-client from requirements.txt") from exc
    return OpaClient(host=url)


def parity_rows(cases: Iterable[Case]) -> list[dict[str, Any]]:
    """Compare the reference PDP with a real local Cedar evaluator."""

    rows = []
    for case in cases:
        if case.mode != "normal":
            continue
        authz = case.prepare()
        reference = ReferencePDP().evaluate(authz).allowed
        cedar = evaluate_cedar(authz)
        rows.append({"case_id": case.case_id, "expected": case.expected_allowed, "reference": reference, "cedar": cedar, "parity": reference == cedar == case.expected_allowed})
    return rows


if __name__ == "__main__":
    baseline, _ = evaluate(build_cases(), hardened=False)
    hardened, rows = evaluate(build_cases(), hardened=True)
    print(json.dumps({"baseline": asdict(baseline), "hardened": asdict(hardened), "release_gate": release_gate(hardened), "failures": [row for row in rows if not row["match"]]}, indent=2))
