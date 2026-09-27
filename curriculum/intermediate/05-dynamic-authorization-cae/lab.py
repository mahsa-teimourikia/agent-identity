"""Deterministic continuous-authorization lab for a long-running claims agent.

The lab separates a standards-shaped Shared Signals receiver from an asynchronous
projection and a policy enforcement point (PEP).  It is deliberately local and
credential-free, but preserves the production invariants: authenticate before
acknowledgement, persist before processing, scope every signal to its subject,
make restrictive changes monotonic, bind cached decisions to exact proposals and
trusted versions, and re-authorize immediately before a side effect.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field, replace
from hashlib import sha256
import json
from pathlib import Path
import sqlite3
from threading import Lock
from typing import Any, Callable, Mapping

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


NOW = 1_800_000_000
TENANT = "tenant:northstar"
SUBJECT = "user:alice"
OTHER_SUBJECT = "user:mallory"
AGENT = "agent:claims-adjuster"
WORKLOAD = "spiffe://northstar.example/claims/adjuster"
TASK = "task:review-clm-100"
CLAIM = "claim:clm-100"
POLICY_VERSION = 7
RESOURCE_VERSION = 4
RELATIONSHIP_VERSION = 9
APPROVAL_VERSION = 2
DELEGATION_VERSION = 3

CAEP_SESSION_REVOKED = "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
CAEP_TOKEN_CLAIMS_CHANGE = "https://schemas.openid.net/secevent/caep/event-type/token-claims-change"
CAEP_RISK_LEVEL_CHANGE = "https://schemas.openid.net/secevent/caep/event-type/risk-level-change"
CAEP_DEVICE_COMPLIANCE_CHANGE = "https://schemas.openid.net/secevent/caep/event-type/device-compliance-change"
INTERNAL_TASK_CHANGE = "https://signals.northstar.example/events/task-change"
INTERNAL_POLICY_CHANGE = "https://signals.northstar.example/events/policy-change"
INTERNAL_RESOURCE_CHANGE = "https://signals.northstar.example/events/resource-change"
INTERNAL_APPROVAL_CHANGE = "https://signals.northstar.example/events/approval-change"
INTERNAL_DELEGATION_CHANGE = "https://signals.northstar.example/events/delegation-change"
INTERNAL_WORKLOAD_CHANGE = "https://signals.northstar.example/events/workload-change"

EVENT_DOMAINS = {
    CAEP_SESSION_REVOKED: "session",
    CAEP_TOKEN_CLAIMS_CHANGE: "claims",
    CAEP_RISK_LEVEL_CHANGE: "risk",
    CAEP_DEVICE_COMPLIANCE_CHANGE: "device",
    INTERNAL_TASK_CHANGE: "task",
    INTERNAL_POLICY_CHANGE: "policy",
    INTERNAL_RESOURCE_CHANGE: "resource",
    INTERNAL_APPROVAL_CHANGE: "approval",
    INTERNAL_DELEGATION_CHANGE: "delegation",
    INTERNAL_WORKLOAD_CHANGE: "workload",
}


class LabError(RuntimeError):
    def __init__(self, reason_code: str):
        self.reason_code = reason_code
        super().__init__(reason_code)


def canonical(value: Any) -> str:
    if hasattr(value, "__dataclass_fields__"):
        value = asdict(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=list)


def digest(value: Any) -> str:
    return sha256(canonical(value).encode()).hexdigest()


@dataclass
class ManualClock:
    now: int = NOW
    logical_ms: int = 0

    def tick(self, milliseconds: int = 1) -> int:
        self.logical_ms += milliseconds
        return self.logical_ms


@dataclass(frozen=True)
class StreamConfig:
    issuer: str
    audience: str
    transmitter_id: str
    verification_keys: Mapping[str, Any]
    allowed_event_types: frozenset[str] = frozenset(EVENT_DOMAINS)
    enabled: bool = True


class SetTransmitter:
    """Fixture transmitter using a real Ed25519 signature, never a shared secret."""

    def __init__(self, issuer: str = "https://idp.northstar.example", kid: str = "set-2026-01"):
        self.issuer = issuer
        self.kid = kid
        self.private_key = Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()

    def issue(
        self,
        event_type: str,
        event_data: Mapping[str, Any],
        *,
        audience: str = "https://signals.northstar.example/ssf",
        subject: str = SUBJECT,
        jti: str = "set-001",
        txn: str = "txn-001",
        issued_at: int = NOW,
        typ: str = "secevent+jwt",
        issuer: str | None = None,
        extra_claims: Mapping[str, Any] | None = None,
        private_key: Any | None = None,
    ) -> str:
        claims: dict[str, Any] = {
            "iss": issuer or self.issuer,
            "aud": audience,
            "iat": issued_at,
            "jti": jti,
            "txn": txn,
            "sub_id": {"format": "iss_sub", "iss": self.issuer, "sub": subject},
            "events": {event_type: dict(event_data)},
        }
        claims.update(extra_claims or {})
        return jwt.encode(
            claims,
            private_key or self.private_key,
            algorithm="EdDSA",
            headers={"kid": self.kid, "typ": typ},
        )


@dataclass(frozen=True)
class ReceiveResult:
    http_status: int
    outcome: str
    jti: str


class SecurityEventInbox:
    """Durable SET inbox: validate, persist, then acknowledge with HTTP 202 semantics."""

    def __init__(self, config: StreamConfig, database: str | Path = ":memory:", clock: ManualClock | None = None):
        self.config = config
        self.clock = clock or ManualClock()
        self.connection = sqlite3.connect(str(database), check_same_thread=False)
        self.connection.row_factory = sqlite3.Row
        self._lock = Lock()
        self.connection.execute(
            """CREATE TABLE IF NOT EXISTS inbox (
                jti TEXT PRIMARY KEY, txn TEXT NOT NULL, subject_key TEXT NOT NULL,
                event_type TEXT NOT NULL, domain TEXT NOT NULL, sequence INTEGER NOT NULL,
                issued_at INTEGER NOT NULL, event_json TEXT NOT NULL,
                received_ms INTEGER NOT NULL, validated_ms INTEGER NOT NULL,
                persisted_ms INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'pending'
            )"""
        )
        self.connection.commit()

    def receive(self, compact_set: str) -> ReceiveResult:
        if not self.config.enabled:
            raise LabError("stream_disabled")
        try:
            header = jwt.get_unverified_header(compact_set)
        except jwt.PyJWTError as exc:
            raise LabError("set_malformed") from exc
        if header.get("typ") != "secevent+jwt":
            raise LabError("set_typ_invalid")
        if header.get("alg") != "EdDSA":
            raise LabError("set_algorithm_invalid")
        key = self.config.verification_keys.get(str(header.get("kid")))
        if key is None:
            raise LabError("set_key_unknown")
        try:
            claims = jwt.decode(
                compact_set,
                key,
                algorithms=["EdDSA"],
                issuer=self.config.issuer,
                audience=self.config.audience,
                options={
                    "require": ["iss", "aud", "iat", "jti", "sub_id", "events"],
                    # The lab uses a deterministic clock; freshness is checked
                    # below against that clock rather than wall time.
                    "verify_iat": False,
                },
            )
        except jwt.InvalidIssuerError as exc:
            raise LabError("set_issuer_invalid") from exc
        except jwt.InvalidAudienceError as exc:
            raise LabError("set_audience_invalid") from exc
        except jwt.InvalidSignatureError as exc:
            raise LabError("set_signature_invalid") from exc
        except jwt.PyJWTError as exc:
            raise LabError("set_claims_invalid") from exc
        if "sub" in claims or "exp" in claims:
            raise LabError("set_profile_invalid")
        if not isinstance(claims.get("iat"), int) or abs(int(claims["iat"]) - self.clock.now) > 300:
            raise LabError("set_iat_out_of_window")
        events = claims.get("events")
        if not isinstance(events, dict) or len(events) != 1:
            raise LabError("set_event_count_invalid")
        event_type, event_data = next(iter(events.items()))
        if event_type not in self.config.allowed_event_types or event_type not in EVENT_DOMAINS:
            raise LabError("event_type_not_allowed")
        if not isinstance(event_data, dict):
            raise LabError("event_payload_invalid")
        subject = claims.get("sub_id")
        if not isinstance(subject, dict) or subject.get("format") != "iss_sub":
            raise LabError("subject_identifier_invalid")
        if subject.get("iss") != self.config.issuer or not isinstance(subject.get("sub"), str):
            raise LabError("subject_identifier_invalid")
        sequence = event_data.get("sequence")
        if not isinstance(sequence, int) or sequence < 1:
            raise LabError("event_sequence_invalid")
        jti = str(claims["jti"])
        row = (
            jti,
            str(claims.get("txn", jti)),
            canonical(subject),
            event_type,
            EVENT_DOMAINS[event_type],
            sequence,
            int(claims["iat"]),
            canonical(event_data),
            self.clock.tick(),
            self.clock.tick(),
            self.clock.tick(),
        )
        with self._lock:
            try:
                self.connection.execute(
                    """INSERT INTO inbox
                    (jti, txn, subject_key, event_type, domain, sequence, issued_at,
                     event_json, received_ms, validated_ms, persisted_ms)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    row,
                )
                self.connection.commit()
                return ReceiveResult(202, "persisted", jti)
            except sqlite3.IntegrityError:
                return ReceiveResult(202, "duplicate", jti)

    def pending(self) -> list[sqlite3.Row]:
        return list(self.connection.execute("SELECT * FROM inbox WHERE status='pending' ORDER BY persisted_ms, jti"))

    def mark(self, jti: str, status: str) -> None:
        with self.connection:
            self.connection.execute("UPDATE inbox SET status=? WHERE jti=?", (status, jti))


@dataclass(frozen=True)
class AuthorizationProjection:
    subject_id: str = SUBJECT
    session_active: bool = True
    claims_active: bool = True
    risk_level: str = "low"
    device_compliant: bool = True
    task_active: bool = True
    task_expires_at: int = NOW + 3600
    policy_version: int = POLICY_VERSION
    resource_version: int = RESOURCE_VERSION
    relationship_version: int = RELATIONSHIP_VERSION
    relationship_active: bool = True
    approval_version: int = APPROVAL_VERSION
    approval_active: bool = True
    delegation_version: int = DELEGATION_VERSION
    delegation_active: bool = True
    workload_quarantined: bool = False
    stream_fresh: bool = True
    cursors: Mapping[str, int] = field(default_factory=dict)
    projected_ms: int = 0

    def fingerprint(self) -> str:
        return digest(asdict(self))


def _is_restrictive(event_type: str, data: Mapping[str, Any]) -> bool:
    if event_type == CAEP_SESSION_REVOKED:
        return True
    if event_type == CAEP_TOKEN_CLAIMS_CHANGE:
        return data.get("claims_active") is False
    if event_type == CAEP_RISK_LEVEL_CHANGE:
        return data.get("risk_level") in {"high", "critical"}
    if event_type == CAEP_DEVICE_COMPLIANCE_CHANGE:
        return data.get("device_compliant") is False
    return any(
        data.get(name) is False
        for name in ("active", "task_active", "relationship_active", "approval_active", "delegation_active")
    ) or data.get("quarantined") is True


class ProjectionStore:
    """Materialized authorization state with per-domain ordering and sticky restrictions."""

    def __init__(self, initial: AuthorizationProjection | None = None):
        self._states = {SUBJECT: initial or AuthorizationProjection()}
        self._lock = Lock()

    def get(self, subject_id: str = SUBJECT) -> AuthorizationProjection:
        return self._states.get(
            subject_id,
            AuthorizationProjection(
                subject_id=subject_id,
                session_active=False,
                claims_active=False,
                device_compliant=False,
                task_active=False,
                relationship_active=False,
                approval_active=False,
                delegation_active=False,
                stream_fresh=False,
            ),
        )

    def apply_pending(self, inbox: SecurityEventInbox) -> list[dict[str, Any]]:
        evidence = []
        for row in inbox.pending():
            subject = json.loads(row["subject_key"])["sub"]
            data = json.loads(row["event_json"])
            event_type, domain, sequence = row["event_type"], row["domain"], row["sequence"]
            with self._lock:
                current = self.get(subject)
                cursor = int(current.cursors.get(domain, 0))
                restrictive = _is_restrictive(event_type, data)
                if sequence <= cursor and not restrictive:
                    outcome = "stale_relaxation_ignored"
                    next_state = current
                else:
                    gap = sequence > cursor + 1
                    next_state = self._apply(current, event_type, data)
                    cursors = dict(next_state.cursors)
                    cursors[domain] = max(cursor, sequence)
                    next_state = replace(
                        next_state,
                        cursors=cursors,
                        stream_fresh=next_state.stream_fresh and not gap,
                        projected_ms=inbox.clock.tick(),
                    )
                    self._states[subject] = next_state
                    outcome = "restriction_applied" if restrictive else "state_updated"
                    if gap:
                        outcome = "gap_detected_" + outcome
            inbox.mark(row["jti"], outcome)
            evidence.append({
                "jti": row["jti"], "subject": subject, "domain": domain,
                "sequence": sequence, "outcome": outcome,
                "received_ms": row["received_ms"], "validated_ms": row["validated_ms"],
                "persisted_ms": row["persisted_ms"], "projected_ms": next_state.projected_ms,
            })
        return evidence

    @staticmethod
    def _apply(state: AuthorizationProjection, event_type: str, data: Mapping[str, Any]) -> AuthorizationProjection:
        if event_type == CAEP_SESSION_REVOKED:
            return replace(state, session_active=False)
        if event_type == CAEP_TOKEN_CLAIMS_CHANGE:
            return replace(state, claims_active=bool(data["claims_active"]))
        if event_type == CAEP_RISK_LEVEL_CHANGE:
            return replace(state, risk_level=str(data["risk_level"]))
        if event_type == CAEP_DEVICE_COMPLIANCE_CHANGE:
            return replace(state, device_compliant=bool(data["device_compliant"]))
        if event_type == INTERNAL_TASK_CHANGE:
            return replace(state, task_active=bool(data["task_active"]), task_expires_at=int(data.get("expires_at", state.task_expires_at)))
        if event_type == INTERNAL_POLICY_CHANGE:
            return replace(state, policy_version=max(state.policy_version, int(data["version"])))
        if event_type == INTERNAL_RESOURCE_CHANGE:
            return replace(state, resource_version=max(state.resource_version, int(data["version"])))
        if event_type == INTERNAL_APPROVAL_CHANGE:
            return replace(state, approval_active=bool(data["active"]), approval_version=max(state.approval_version, int(data["version"])))
        if event_type == INTERNAL_DELEGATION_CHANGE:
            return replace(state, delegation_active=bool(data["active"]), delegation_version=max(state.delegation_version, int(data["version"])))
        if event_type == INTERNAL_WORKLOAD_CHANGE:
            return replace(state, workload_quarantined=bool(data["quarantined"]))
        raise LabError("event_type_not_supported")


@dataclass(frozen=True)
class VerifiedCaller:
    subject_id: str = SUBJECT
    agent_id: str = AGENT
    workload_id: str = WORKLOAD
    tenant_id: str = TENANT
    scopes: frozenset[str] = frozenset({"claims:read", "claims:update", "payments:create"})
    token_expires_at: int = NOW + 900


@dataclass(frozen=True)
class ActionProposal:
    operation_id: str
    action: str
    resource_id: str = CLAIM
    tenant_id: str = TENANT
    purpose: str = "review:claim:clm-100"
    amount_cents: int = 0


@dataclass(frozen=True)
class ApprovalReceipt:
    receipt_id: str
    proposal_digest: str
    subject_id: str = SUBJECT
    agent_id: str = AGENT
    task_id: str = TASK
    tenant_id: str = TENANT
    action: str = "payment.create"
    resource_id: str = CLAIM
    policy_version: int = POLICY_VERSION
    approval_version: int = APPROVAL_VERSION
    approver_id: str = "user:claims-supervisor"
    approver_role: str = "claims-supervisor"
    issued_at: int = NOW - 30
    expires_at: int = NOW + 300


@dataclass(frozen=True)
class DecisionLease:
    allowed: bool
    reason_codes: tuple[str, ...]
    proposal_digest: str
    projection_fingerprint: str
    policy_version: int
    resource_version: int
    relationship_version: int
    approval_version: int
    delegation_version: int
    valid_until: int
    decision_id: str


def required_scope(action: str) -> str:
    return {"claim.read": "claims:read", "claim.update": "claims:update", "payment.create": "payments:create"}.get(action, "unsupported")


def proposal_digest(proposal: ActionProposal) -> str:
    return digest(proposal)


def make_approval(proposal: ActionProposal, projection: AuthorizationProjection | None = None) -> ApprovalReceipt:
    state = projection or AuthorizationProjection()
    return ApprovalReceipt(
        receipt_id="approval-001",
        proposal_digest=proposal_digest(proposal),
        tenant_id=proposal.tenant_id,
        action=proposal.action,
        resource_id=proposal.resource_id,
        policy_version=state.policy_version,
        approval_version=state.approval_version,
    )


class ReferencePDP:
    def evaluate(
        self,
        caller: VerifiedCaller,
        proposal: ActionProposal,
        state: AuthorizationProjection,
        approval: ApprovalReceipt | None = None,
        now: int = NOW,
    ) -> DecisionLease:
        failures: list[str] = []
        if caller.subject_id != SUBJECT:
            failures.append("subject_not_authorized_for_resource")
        if caller.subject_id != state.subject_id:
            failures.append("subject_mismatch")
        if caller.agent_id != AGENT or caller.workload_id != WORKLOAD:
            failures.append("actor_or_workload_invalid")
        if caller.tenant_id != TENANT or proposal.tenant_id != TENANT:
            failures.append("tenant_mismatch")
        if caller.token_expires_at <= now:
            failures.append("token_expired")
        if required_scope(proposal.action) not in caller.scopes:
            failures.append("scope_missing")
        if proposal.resource_id != CLAIM:
            failures.append("resource_not_assigned")
        if not state.session_active:
            failures.append("session_revoked")
        if not state.claims_active:
            failures.append("claims_inactive")
        if not state.device_compliant:
            failures.append("device_noncompliant")
        if not state.task_active or state.task_expires_at <= now:
            failures.append("task_inactive_or_expired")
        if not state.relationship_active:
            failures.append("relationship_revoked")
        if not state.delegation_active:
            failures.append("delegation_revoked")
        if state.workload_quarantined:
            failures.append("workload_quarantined")
        if state.risk_level in {"high", "critical"}:
            failures.append("risk_too_high")
        if not state.stream_fresh and proposal.action != "claim.read":
            failures.append("signal_stream_not_fresh")
        if proposal.action == "claim.update" and proposal.purpose != f"review:{CLAIM}":
            failures.append("purpose_invalid")
        if proposal.action == "payment.create":
            if proposal.amount_cents <= 0 or proposal.amount_cents > 50_000:
                failures.append("amount_out_of_bounds")
            if proposal.purpose != f"settle:{CLAIM}":
                failures.append("purpose_invalid")
            if approval is None:
                failures.append("approval_required")
            else:
                expected = {
                    "proposal_digest": proposal_digest(proposal),
                    "subject_id": caller.subject_id,
                    "agent_id": caller.agent_id,
                    "task_id": TASK,
                    "tenant_id": proposal.tenant_id,
                    "action": proposal.action,
                    "resource_id": proposal.resource_id,
                    "policy_version": state.policy_version,
                    "approval_version": state.approval_version,
                }
                failures.extend(
                    f"approval_{name}_mismatch"
                    for name, value in expected.items()
                    if getattr(approval, name) != value
                )
                if approval.approver_role != "claims-supervisor":
                    failures.append("approval_role_invalid")
                if not (approval.issued_at <= now < approval.expires_at) or not state.approval_active:
                    failures.append("approval_expired_or_revoked")
        if proposal.action not in {"claim.read", "claim.update", "payment.create"}:
            failures.append("action_unsupported")
        failures = list(dict.fromkeys(failures))
        body = {
            "proposal": proposal_digest(proposal), "projection": state.fingerprint(),
            "policy": state.policy_version, "failures": failures,
        }
        return DecisionLease(
            allowed=not failures,
            reason_codes=tuple(failures or ["all_current_conditions_satisfied"]),
            proposal_digest=proposal_digest(proposal),
            projection_fingerprint=state.fingerprint(),
            policy_version=state.policy_version,
            resource_version=state.resource_version,
            relationship_version=state.relationship_version,
            approval_version=state.approval_version,
            delegation_version=state.delegation_version,
            valid_until=min(now + 30, caller.token_expires_at, state.task_expires_at),
            decision_id="decision-" + digest(body)[:16],
        )


class DecisionCache:
    def __init__(self):
        self._items: dict[str, DecisionLease] = {}

    @staticmethod
    def key(
        caller: VerifiedCaller,
        proposal: ActionProposal,
        state: AuthorizationProjection,
        approval: ApprovalReceipt | None = None,
    ) -> str:
        return digest({
            "subject": caller.subject_id, "agent": caller.agent_id, "workload": caller.workload_id,
            "tenant": caller.tenant_id, "proposal": asdict(proposal), "state": state.fingerprint(),
            "approval": None if approval is None else digest(approval),
        })

    def get(
        self,
        caller: VerifiedCaller,
        proposal: ActionProposal,
        state: AuthorizationProjection,
        approval: ApprovalReceipt | None,
        now: int,
    ) -> DecisionLease | None:
        item = self._items.get(self.key(caller, proposal, state, approval))
        return item if item and item.valid_until > now else None

    def put(
        self,
        caller: VerifiedCaller,
        proposal: ActionProposal,
        state: AuthorizationProjection,
        approval: ApprovalReceipt | None,
        decision: DecisionLease,
    ) -> None:
        self._items[self.key(caller, proposal, state, approval)] = decision


class ApprovalStore:
    def __init__(self):
        self._used: set[str] = set()
        self._lock = Lock()

    def consume(self, approval: ApprovalReceipt) -> None:
        with self._lock:
            if approval.receipt_id in self._used:
                raise LabError("approval_replayed")
            self._used.add(approval.receipt_id)


class PolicyEnforcementPoint:
    """Authorizes proposals and repeats the decision at the commit boundary."""

    def __init__(self, projection: ProjectionStore, pdp: ReferencePDP | None = None):
        self.projection = projection
        self.pdp = pdp or ReferencePDP()
        self.cache = DecisionCache()
        self.approvals = ApprovalStore()
        self.effects: dict[str, str] = {}
        self.operation_digests: dict[str, str] = {}
        self.evidence: list[dict[str, Any]] = []

    def authorize(self, caller: VerifiedCaller, proposal: ActionProposal, approval: ApprovalReceipt | None = None, now: int = NOW) -> DecisionLease:
        state = self.projection.get(caller.subject_id)
        cached = self.cache.get(caller, proposal, state, approval, now)
        if cached:
            return cached
        try:
            decision = self.pdp.evaluate(caller, proposal, state, approval, now)
        except ConnectionError as exc:
            raise LabError("pdp_unavailable") from exc
        self.cache.put(caller, proposal, state, approval, decision)
        return decision

    def execute(
        self,
        caller: VerifiedCaller,
        proposal: ActionProposal,
        approval: ApprovalReceipt | None = None,
        *,
        now: int = NOW,
        before_commit: Callable[[], None] | None = None,
    ) -> str:
        request_digest = proposal_digest(proposal)
        prior = self.operation_digests.get(proposal.operation_id)
        if prior is not None:
            if prior != request_digest:
                raise LabError("operation_id_conflict")
            return self.effects[proposal.operation_id]
        try:
            first = self.authorize(caller, proposal, approval, now)
        except LabError as exc:
            if exc.reason_code == "pdp_unavailable":
                denial = self._dependency_denial(proposal, self.projection.get(caller.subject_id), now)
                self._record(proposal, denial, "not_executed")
            raise
        if not first.allowed:
            self._record(proposal, first, "not_executed")
            raise LabError(first.reason_codes[0])
        if before_commit:
            before_commit()
        # Never execute from the earlier lease: read current state and decide again.
        current = self.projection.get(caller.subject_id)
        try:
            final = self.pdp.evaluate(caller, proposal, current, approval, now)
        except ConnectionError as exc:
            denial = self._dependency_denial(proposal, current, now)
            self._record(proposal, denial, "not_executed")
            raise LabError("pdp_unavailable") from exc
        if not final.allowed:
            self._record(proposal, final, "not_executed")
            raise LabError(final.reason_codes[0])
        if approval and proposal.action == "payment.create":
            self.approvals.consume(approval)
        result = "effect-" + digest({"operation": proposal.operation_id, "decision": final.decision_id})[:12]
        self.operation_digests[proposal.operation_id] = request_digest
        self.effects[proposal.operation_id] = result
        self._record(proposal, final, "executed")
        return result

    def _record(self, proposal: ActionProposal, decision: DecisionLease, outcome: str) -> None:
        self.evidence.append({
            "operation_id": proposal.operation_id,
            "proposal_digest": proposal_digest(proposal),
            "decision_id": decision.decision_id,
            "policy_version": decision.policy_version,
            "projection_fingerprint": decision.projection_fingerprint,
            "reason_codes": list(decision.reason_codes),
            "outcome": outcome,
        })

    @staticmethod
    def _dependency_denial(proposal: ActionProposal, state: AuthorizationProjection, now: int) -> DecisionLease:
        return DecisionLease(
            allowed=False,
            reason_codes=("pdp_unavailable",),
            proposal_digest=proposal_digest(proposal),
            projection_fingerprint=state.fingerprint(),
            policy_version=state.policy_version,
            resource_version=state.resource_version,
            relationship_version=state.relationship_version,
            approval_version=state.approval_version,
            delegation_version=state.delegation_version,
            valid_until=now,
            decision_id="decision-dependency-unavailable",
        )


def stream_fixture(database: str | Path = ":memory:") -> tuple[SetTransmitter, SecurityEventInbox, ProjectionStore]:
    transmitter = SetTransmitter()
    config = StreamConfig(
        issuer=transmitter.issuer,
        audience="https://signals.northstar.example/ssf",
        transmitter_id="transmitter:northstar-idp",
        verification_keys={transmitter.kid: transmitter.public_key},
    )
    return transmitter, SecurityEventInbox(config, database), ProjectionStore()


def apply_event(
    transmitter: SetTransmitter,
    inbox: SecurityEventInbox,
    projection: ProjectionStore,
    event_type: str,
    data: Mapping[str, Any],
    *,
    subject: str = SUBJECT,
    jti: str = "set-001",
) -> list[dict[str, Any]]:
    token = transmitter.issue(event_type, data, subject=subject, jti=jti, txn="txn-" + jti)
    inbox.receive(token)
    return projection.apply_pending(inbox)


def proposal(action: str = "claim.update", operation_id: str = "op-001") -> ActionProposal:
    if action == "payment.create":
        return ActionProposal(operation_id, action, purpose=f"settle:{CLAIM}", amount_cents=25_000)
    return ActionProposal(operation_id, action)


@dataclass(frozen=True)
class Scenario:
    case_id: str
    mutation: str
    expected_allowed: bool


def build_cases() -> list[Scenario]:
    return [
        Scenario("valid-read", "none_read", True),
        Scenario("valid-update", "none_update", True),
        Scenario("valid-payment", "none_payment", True),
        Scenario("expired-token", "expired_token", False),
        Scenario("wrong-subject", "wrong_subject", False),
        Scenario("wrong-agent", "wrong_agent", False),
        Scenario("wrong-workload", "wrong_workload", False),
        Scenario("wrong-tenant", "wrong_tenant", False),
        Scenario("missing-scope", "missing_scope", False),
        Scenario("wrong-resource", "wrong_resource", False),
        Scenario("session-revoked", "session_revoked", False),
        Scenario("claims-removed", "claims_removed", False),
        Scenario("risk-high", "risk_high", False),
        Scenario("risk-critical", "risk_critical", False),
        Scenario("device-noncompliant", "device_noncompliant", False),
        Scenario("task-inactive", "task_inactive", False),
        Scenario("task-expired", "task_expired", False),
        Scenario("relationship-revoked", "relationship_revoked", False),
        Scenario("delegation-revoked", "delegation_revoked", False),
        Scenario("workload-quarantined", "workload_quarantined", False),
        Scenario("stale-stream-write", "stale_stream_update", False),
        Scenario("stale-stream-read", "stale_stream_read", True),
        Scenario("bad-purpose", "bad_purpose", False),
        Scenario("unsupported-action", "unsupported_action", False),
        Scenario("payment-no-approval", "payment_no_approval", False),
        Scenario("payment-changed-amount", "payment_changed_amount", False),
        Scenario("payment-revoked-approval", "payment_revoked_approval", False),
        Scenario("payment-policy-changed", "payment_policy_changed", False),
        Scenario("payment-too-large", "payment_too_large", False),
        Scenario("cross-tenant-payment", "cross_tenant_payment", False),
        Scenario("public-read-degraded", "public_read_degraded", True),
        Scenario("late-revocation", "late_revocation", False),
    ]


def run_case(case: Scenario, hardened: bool = True) -> bool:
    caller = VerifiedCaller()
    state = AuthorizationProjection()
    action = "claim.read" if "read" in case.mutation else "payment.create" if "payment" in case.mutation else "claim.update"
    p = proposal(action, "op-" + case.case_id)
    approval = make_approval(p, state) if action == "payment.create" else None
    mutation = case.mutation
    if mutation == "expired_token": caller = replace(caller, token_expires_at=NOW)
    if mutation == "wrong_subject": caller = replace(caller, subject_id=OTHER_SUBJECT)
    if mutation == "wrong_agent": caller = replace(caller, agent_id="agent:other")
    if mutation == "wrong_workload": caller = replace(caller, workload_id="spiffe://evil.example/agent")
    if mutation in {"wrong_tenant", "cross_tenant_payment"}: p = replace(p, tenant_id="tenant:other")
    if mutation == "missing_scope": caller = replace(caller, scopes=frozenset())
    if mutation == "wrong_resource": p = replace(p, resource_id="claim:other")
    if mutation == "session_revoked" or mutation == "late_revocation": state = replace(state, session_active=False)
    if mutation == "claims_removed": state = replace(state, claims_active=False)
    if mutation == "risk_high": state = replace(state, risk_level="high")
    if mutation == "risk_critical": state = replace(state, risk_level="critical")
    if mutation == "device_noncompliant": state = replace(state, device_compliant=False)
    if mutation == "task_inactive": state = replace(state, task_active=False)
    if mutation == "task_expired": state = replace(state, task_expires_at=NOW)
    if mutation == "relationship_revoked": state = replace(state, relationship_active=False)
    if mutation == "delegation_revoked": state = replace(state, delegation_active=False)
    if mutation == "workload_quarantined": state = replace(state, workload_quarantined=True)
    if mutation in {"stale_stream_update", "stale_stream_read", "public_read_degraded"}: state = replace(state, stream_fresh=False)
    if mutation == "bad_purpose": p = replace(p, purpose="unrelated")
    if mutation == "unsupported_action": p = replace(p, action="claim.delete")
    if mutation == "payment_no_approval": approval = None
    if mutation == "payment_changed_amount": p = replace(p, amount_cents=30_000)
    if mutation == "payment_revoked_approval": state = replace(state, approval_active=False)
    if mutation == "payment_policy_changed": state = replace(state, policy_version=POLICY_VERSION + 1)
    if mutation == "payment_too_large":
        p = replace(p, amount_cents=90_000)
        approval = make_approval(p, state)
    if not hardened:
        return caller.token_expires_at > NOW and required_scope(p.action) in caller.scopes
    return ReferencePDP().evaluate(caller, p, state, approval).allowed


@dataclass(frozen=True)
class Metrics:
    total: int
    expected_allowed: int
    expected_blocked: int
    invalid_acceptances: int
    valid_work_blocked: int
    outcome_matches: int


def evaluate(cases: list[Scenario], hardened: bool = True) -> tuple[Metrics, list[dict[str, Any]]]:
    rows = []
    for case in cases:
        actual = run_case(case, hardened)
        rows.append({"case_id": case.case_id, "expected_allowed": case.expected_allowed, "actual_allowed": actual, "match": actual == case.expected_allowed})
    metrics = Metrics(
        total=len(rows),
        expected_allowed=sum(row["expected_allowed"] for row in rows),
        expected_blocked=sum(not row["expected_allowed"] for row in rows),
        invalid_acceptances=sum(row["actual_allowed"] and not row["expected_allowed"] for row in rows),
        valid_work_blocked=sum(not row["actual_allowed"] and row["expected_allowed"] for row in rows),
        outcome_matches=sum(row["match"] for row in rows),
    )
    return metrics, rows


def release_gate(metrics: Metrics, max_projection_latency_ms: int = 25, observed_latency_ms: int = 4) -> bool:
    return (
        metrics.invalid_acceptances == 0
        and metrics.valid_work_blocked == 0
        and metrics.outcome_matches == metrics.total
        and observed_latency_ms <= max_projection_latency_ms
    )


def opa_input(caller: VerifiedCaller, p: ActionProposal, state: AuthorizationProjection, approval: ApprovalReceipt | None = None) -> dict[str, Any]:
    proposal_document = asdict(p)
    proposal_document["digest"] = proposal_digest(p)
    return {
        "caller": {**asdict(caller), "scopes": sorted(caller.scopes)},
        "proposal": proposal_document,
        "projection": {**asdict(state), "cursors": dict(state.cursors)},
        "approval": None if approval is None else asdict(approval),
        "now": NOW,
    }


def openfga_check(caller: VerifiedCaller | None = None):
    """Construct a real OpenFGA SDK request without making a network call."""
    from openfga_sdk.client.models import ClientCheckRequest, ClientTuple

    current = caller or VerifiedCaller()
    tuples = [
        ClientTuple(user=current.agent_id, relation="assignee", object=TASK),
        ClientTuple(user=current.agent_id, relation="delegated_agent", object=TASK),
        ClientTuple(user=TASK, relation="assigned_task", object=CLAIM),
    ]
    return ClientCheckRequest(
        user=current.agent_id,
        relation="can_update",
        object=CLAIM,
        contextual_tuples=tuples,
    )


def propagation_metrics(evidence: list[dict[str, Any]], enforced_ms: int) -> dict[str, int]:
    last = evidence[-1]
    return {
        "receive_to_persist_ms": last["persisted_ms"] - last["received_ms"],
        "persist_to_project_ms": last["projected_ms"] - last["persisted_ms"],
        "project_to_enforce_ms": enforced_ms - last["projected_ms"],
        "receive_to_enforce_ms": enforced_ms - last["received_ms"],
    }


def vulnerable_cache_key(proposal: ActionProposal) -> str:
    """Intentional anti-pattern: omits purpose, amount, tenant, and state versions."""
    return f"{proposal.action}:{proposal.resource_id}"
