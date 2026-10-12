"""Deterministic continuous and adaptive trust lab for an autonomous agent.

The lab uses real Ed25519 Security Event Tokens (SETs), a durable SQLite inbox,
tenant-scoped subject correlation, ordered state projection, multidimensional
risk, hysteresis, short decision leases, and commit-time reauthorization.  It
is an offline teaching implementation, not an SSF conformance implementation.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass, field, replace
from hashlib import sha256
from pathlib import Path
from threading import Lock, RLock
from typing import Any

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

NOW = 1_800_000_000
TENANT = "tenant:northstar"
AGENT = "agent:claims-adjuster"
WORKLOAD = "spiffe://northstar.example/claims/adjuster"
SESSION = "session:claims:483"
RESOURCE = "claim:483"
AUDIENCE = "https://signals.northstar.example/ssf"
POLICY_VERSION = "adaptive-policy-2026-10-12"

CAEP = "https://schemas.openid.net/secevent/caep/event-type/"
SESSION_REVOKED = CAEP + "session-revoked"
TOKEN_CLAIMS_CHANGE = CAEP + "token-claims-change"
CREDENTIAL_CHANGE = CAEP + "credential-change"
ASSURANCE_LEVEL_CHANGE = CAEP + "assurance-level-change"
DEVICE_COMPLIANCE_CHANGE = CAEP + "device-compliance-change"
RISK_LEVEL_CHANGE = CAEP + "risk-level-change"

PRIVATE = "https://signals.northstar.example/events/"
WORKLOAD_POSTURE_CHANGE = PRIVATE + "workload-posture-change"
AGENT_BEHAVIOR_CHANGE = PRIVATE + "agent-behavior-change"
THREAT_INTELLIGENCE_CHANGE = PRIVATE + "threat-intelligence-change"
TRANSACTION_RISK_CHANGE = PRIVATE + "transaction-risk-change"
TASK_CHANGE = PRIVATE + "task-change"
RELATIONSHIP_CHANGE = PRIVATE + "relationship-change"
POLICY_CHANGE = PRIVATE + "policy-change"
QUARANTINE_CHANGE = PRIVATE + "quarantine-change"

RISK_LEVELS = {"low": 10, "medium": 50, "high": 75, "critical": 95}
RISK_DIMENSIONS = frozenset(
    {"identity", "workload", "behavior", "threat", "transaction"}
)

EVENT_DOMAINS = {
    SESSION_REVOKED: "session",
    TOKEN_CLAIMS_CHANGE: "identity",
    CREDENTIAL_CHANGE: "credential",
    ASSURANCE_LEVEL_CHANGE: "identity",
    DEVICE_COMPLIANCE_CHANGE: "workload",
    RISK_LEVEL_CHANGE: "identity",
    WORKLOAD_POSTURE_CHANGE: "workload",
    AGENT_BEHAVIOR_CHANGE: "behavior",
    THREAT_INTELLIGENCE_CHANGE: "threat",
    TRANSACTION_RISK_CHANGE: "transaction",
    TASK_CHANGE: "task",
    RELATIONSHIP_CHANGE: "relationship",
    POLICY_CHANGE: "policy",
    QUARANTINE_CHANGE: "quarantine",
}

EVENT_REQUIRED_FIELDS: Mapping[str, Mapping[str, type]] = {
    SESSION_REVOKED: {},
    TOKEN_CLAIMS_CHANGE: {"claims": dict},
    CREDENTIAL_CHANGE: {"credential_type": str, "change_type": str},
    ASSURANCE_LEVEL_CHANGE: {"namespace": str, "current_level": str},
    DEVICE_COMPLIANCE_CHANGE: {
        "previous_status": str,
        "current_status": str,
    },
    RISK_LEVEL_CHANGE: {"current_level": str},
    WORKLOAD_POSTURE_CHANGE: {"trusted": bool, "current_level": str},
    AGENT_BEHAVIOR_CHANGE: {"current_level": str},
    THREAT_INTELLIGENCE_CHANGE: {"current_level": str},
    TRANSACTION_RISK_CHANGE: {"current_level": str},
    TASK_CHANGE: {"active": bool, "task_version": int},
    RELATIONSHIP_CHANGE: {"active": bool, "relationship_version": int},
    POLICY_CHANGE: {"policy_version": str},
    QUARANTINE_CHANGE: {"action": str},
}


def canonical(value: Any) -> str:
    if hasattr(value, "__dataclass_fields__"):
        value = asdict(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=list)


def digest(value: Any) -> str:
    return sha256(canonical(value).encode()).hexdigest()


def deterministic_private_key(label: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(sha256(label.encode()).digest())


@dataclass
class ManualClock:
    now: int = NOW
    logical_ms: int = 0

    def advance(self, seconds: int) -> int:
        self.now += seconds
        return self.now

    def tick(self, milliseconds: int = 1) -> int:
        self.logical_ms += milliseconds
        return self.logical_ms


@dataclass(frozen=True)
class SubjectRef:
    tenant_id: str
    agent_id: str
    workload_id: str
    session_id: str

    @property
    def key(self) -> str:
        return digest(asdict(self))

    def as_sub_id(self) -> dict[str, Any]:
        return {
            "format": "complex",
            "tenant": {"format": "opaque", "id": self.tenant_id},
            "agent": {"format": "opaque", "id": self.agent_id},
            "workload": {"format": "uri", "uri": self.workload_id},
            "session": {"format": "opaque", "id": self.session_id},
        }


SUBJECT = SubjectRef(TENANT, AGENT, WORKLOAD, SESSION)


def parse_subject(value: Any) -> SubjectRef | None:
    if not isinstance(value, dict) or set(value) != {
        "format",
        "tenant",
        "agent",
        "workload",
        "session",
    }:
        return None
    if value.get("format") != "complex":
        return None
    tenant = value.get("tenant")
    agent = value.get("agent")
    workload = value.get("workload")
    session = value.get("session")
    if not all(isinstance(item, dict) for item in (tenant, agent, workload, session)):
        return None
    if set(tenant) != {"format", "id"} or tenant.get("format") != "opaque":
        return None
    if set(agent) != {"format", "id"} or agent.get("format") != "opaque":
        return None
    if set(workload) != {"format", "uri"} or workload.get("format") != "uri":
        return None
    if set(session) != {"format", "id"} or session.get("format") != "opaque":
        return None
    values = (tenant.get("id"), agent.get("id"), workload.get("uri"), session.get("id"))
    if not all(isinstance(item, str) and item for item in values):
        return None
    return SubjectRef(*values)


@dataclass(frozen=True)
class TransmitterPolicy:
    issuer: str
    audience: str
    keys: Mapping[str, Any]
    allowed_event_types: frozenset[str]
    tenant_id: str = TENANT
    max_age_seconds: int = 300
    max_event_age_seconds: int = 3600
    future_skew_seconds: int = 30
    enabled: bool = True


class SetTransmitter:
    """Issue standards-shaped signed SET fixtures for one governed source."""

    def __init__(self, issuer: str, kid: str):
        self.issuer = issuer
        self.kid = kid
        self.private_key = deterministic_private_key(issuer)
        self.public_key = self.private_key.public_key()

    def issue(
        self,
        event_type: str,
        event_data: Mapping[str, Any],
        *,
        subject: SubjectRef = SUBJECT,
        audience: str = AUDIENCE,
        issued_at: int = NOW,
        event_timestamp: int | None = None,
        jti: str = "set:001",
        txn: str = "txn:claims:483",
        issuer: str | None = None,
        kid: str | None = None,
        typ: str = "secevent+jwt",
        private_key: Ed25519PrivateKey | None = None,
        extra_claims: Mapping[str, Any] | None = None,
        extra_events: Mapping[str, Mapping[str, Any]] | None = None,
    ) -> str:
        payload = dict(event_data)
        payload.setdefault("event_timestamp", event_timestamp or issued_at)
        events: dict[str, Mapping[str, Any]] = {event_type: payload}
        events.update(extra_events or {})
        claims: dict[str, Any] = {
            "iss": issuer or self.issuer,
            "aud": audience,
            "iat": issued_at,
            "jti": jti,
            "txn": txn,
            "sub_id": subject.as_sub_id(),
            "events": events,
        }
        claims.update(extra_claims or {})
        return jwt.encode(
            claims,
            private_key or self.private_key,
            algorithm="EdDSA",
            headers={"typ": typ, "kid": kid or self.kid},
        )


@dataclass(frozen=True)
class ReceiveResult:
    http_status: int
    outcome: str
    jti: str | None = None

    @property
    def accepted(self) -> bool:
        return self.http_status == 202


class DurableSignalReceiver:
    """Authenticate, validate, durably persist, then acknowledge an SSF push."""

    def __init__(
        self,
        policies: Mapping[str, TransmitterPolicy],
        *,
        database: str | Path = ":memory:",
        clock: ManualClock | None = None,
        capacity: int = 100,
    ):
        self.policies = dict(policies)
        self.clock = clock or ManualClock()
        self.capacity = capacity
        self.stream_available = True
        self.last_success_at = self.clock.now
        self.stream_epoch = 1
        self._lock = RLock()
        self.connection = sqlite3.connect(str(database), check_same_thread=False)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute(
            """CREATE TABLE IF NOT EXISTS inbox (
                jti TEXT PRIMARY KEY,
                issuer TEXT NOT NULL,
                txn TEXT NOT NULL,
                subject_key TEXT NOT NULL,
                subject_json TEXT NOT NULL,
                event_type TEXT NOT NULL,
                event_timestamp INTEGER NOT NULL,
                event_json TEXT NOT NULL,
                received_ms INTEGER NOT NULL,
                state TEXT NOT NULL
            )"""
        )
        self.connection.commit()

    @property
    def pending_count(self) -> int:
        with self._lock:
            row = self.connection.execute(
                "SELECT COUNT(*) AS count FROM inbox WHERE state = 'pending'"
            ).fetchone()
        return int(row["count"])

    def set_stream_available(self, available: bool) -> None:
        if self.stream_available != available:
            self.stream_epoch += 1
        self.stream_available = available

    def receive(self, token: str, *, now: int | None = None) -> ReceiveResult:
        current = self.clock.now if now is None else now
        if not self.stream_available:
            return ReceiveResult(503, "stream_unavailable")
        if self.pending_count >= self.capacity:
            return ReceiveResult(429, "receiver_backpressure")
        if not isinstance(token, str):
            return ReceiveResult(400, "set_not_compact_jwt")
        try:
            header = jwt.get_unverified_header(token)
            unverified = jwt.decode(token, options={"verify_signature": False})
        except jwt.PyJWTError:
            return ReceiveResult(400, "set_malformed")
        if header.get("typ") != "secevent+jwt" or header.get("alg") != "EdDSA":
            return ReceiveResult(400, "set_profile_invalid")
        issuer = unverified.get("iss")
        policy = self.policies.get(issuer) if isinstance(issuer, str) else None
        if policy is None or not policy.enabled:
            return ReceiveResult(400, "transmitter_untrusted")
        kid = header.get("kid")
        key = policy.keys.get(kid) if isinstance(kid, str) else None
        if key is None:
            return ReceiveResult(400, "set_key_untrusted")
        try:
            claims = jwt.decode(
                token,
                key,
                algorithms=["EdDSA"],
                audience=policy.audience,
                issuer=policy.issuer,
                options={
                    "require": ["iss", "aud", "iat", "jti", "events", "sub_id"],
                    "verify_iat": False,
                },
            )
        except jwt.InvalidAudienceError:
            return ReceiveResult(400, "set_audience_mismatch")
        except jwt.PyJWTError:
            return ReceiveResult(400, "set_signature_or_claims_invalid")
        jti = claims.get("jti")
        txn = claims.get("txn", "")
        issued_at = claims.get("iat")
        if not isinstance(jti, str) or not jti or not isinstance(txn, str):
            return ReceiveResult(400, "set_identifier_invalid")
        if not isinstance(issued_at, int):
            return ReceiveResult(400, "set_time_invalid", jti)
        if issued_at > current + policy.future_skew_seconds:
            return ReceiveResult(400, "set_from_future", jti)
        if current - issued_at > policy.max_age_seconds:
            return ReceiveResult(400, "set_too_old", jti)
        subject = parse_subject(claims.get("sub_id"))
        if subject is None:
            return ReceiveResult(400, "subject_identifier_invalid", jti)
        if subject.tenant_id != policy.tenant_id:
            return ReceiveResult(400, "subject_tenant_mismatch", jti)
        events = claims.get("events")
        if not isinstance(events, dict) or len(events) != 1:
            return ReceiveResult(400, "set_event_count_invalid", jti)
        event_type, event_data = next(iter(events.items()))
        if event_type not in policy.allowed_event_types:
            return ReceiveResult(400, "event_type_not_authorized", jti)
        error = validate_event(event_type, event_data)
        if error:
            return ReceiveResult(400, error, jti)
        event_timestamp = event_data["event_timestamp"]
        if event_timestamp > current + policy.future_skew_seconds:
            return ReceiveResult(400, "event_from_future", jti)
        if current - event_timestamp > policy.max_event_age_seconds:
            return ReceiveResult(400, "event_too_old", jti)
        with self._lock:
            queued = self.connection.execute(
                "SELECT COUNT(*) AS count FROM inbox WHERE state = 'pending'"
            ).fetchone()
            if int(queued["count"]) >= self.capacity:
                return ReceiveResult(429, "receiver_backpressure", jti)
            try:
                self.connection.execute("BEGIN IMMEDIATE")
                self.connection.execute(
                    """INSERT INTO inbox VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')""",
                    (
                        jti,
                        issuer,
                        txn,
                        subject.key,
                        canonical(subject),
                        event_type,
                        event_timestamp,
                        canonical(event_data),
                        self.clock.tick(),
                    ),
                )
                self.connection.commit()
            except sqlite3.IntegrityError:
                self.connection.rollback()
                return ReceiveResult(202, "duplicate", jti)
        self.last_success_at = current
        return ReceiveResult(202, "persisted", jti)

    def pending(self) -> list[sqlite3.Row]:
        with self._lock:
            return list(
                self.connection.execute(
                    "SELECT * FROM inbox WHERE state = 'pending' ORDER BY received_ms, jti"
                )
            )

    def mark_applied(self, jti: str) -> None:
        with self._lock:
            self.connection.execute(
                "UPDATE inbox SET state = 'applied' WHERE jti = ?", (jti,)
            )
            self.connection.commit()


def validate_event(event_type: str, event_data: Any) -> str | None:
    if not isinstance(event_data, dict):
        return "event_payload_invalid"
    timestamp = event_data.get("event_timestamp")
    if not isinstance(timestamp, int):
        return "event_timestamp_invalid"
    required = EVENT_REQUIRED_FIELDS.get(event_type)
    if required is None:
        return "event_type_unknown"
    for name, expected_type in required.items():
        value = event_data.get(name)
        if expected_type is int and isinstance(value, bool):
            return "event_payload_invalid"
        if not isinstance(value, expected_type):
            return "event_payload_invalid"
    level = event_data.get("current_level")
    if (
        level is not None
        and event_type not in {ASSURANCE_LEVEL_CHANGE}
        and level not in RISK_LEVELS
    ):
        return "event_risk_level_invalid"
    if event_type == CREDENTIAL_CHANGE and event_data["change_type"] not in {
        "create",
        "update",
        "revoke",
        "delete",
    }:
        return "credential_change_invalid"
    if event_type == DEVICE_COMPLIANCE_CHANGE and (
        event_data["previous_status"] not in {"compliant", "not-compliant"}
        or event_data["current_status"] not in {"compliant", "not-compliant"}
    ):
        return "device_status_invalid"
    if event_type == QUARANTINE_CHANGE and event_data["action"] not in {
        "quarantine",
        "release",
    }:
        return "quarantine_action_invalid"
    return None


def is_restrictive(event_type: str, data: Mapping[str, Any]) -> bool:
    if event_type == SESSION_REVOKED:
        return True
    if event_type == CREDENTIAL_CHANGE:
        return data.get("change_type") in {"revoke", "delete"}
    if event_type == DEVICE_COMPLIANCE_CHANGE:
        return data.get("current_status") == "not-compliant"
    if event_type in {
        RISK_LEVEL_CHANGE,
        WORKLOAD_POSTURE_CHANGE,
        AGENT_BEHAVIOR_CHANGE,
        THREAT_INTELLIGENCE_CHANGE,
        TRANSACTION_RISK_CHANGE,
    }:
        return data.get("current_level") in {"high", "critical"} or data.get(
            "trusted"
        ) is False
    if event_type in {TASK_CHANGE, RELATIONSHIP_CHANGE}:
        return data.get("active") is False
    if event_type == QUARANTINE_CHANGE:
        return data.get("action") == "quarantine"
    return False


@dataclass
class TrustState:
    subject: SubjectRef = SUBJECT
    risk: dict[str, int] = field(
        default_factory=lambda: {dimension: 10 for dimension in RISK_DIMENSIONS}
    )
    risk_updated_at: dict[str, int] = field(
        default_factory=lambda: {dimension: NOW for dimension in RISK_DIMENSIONS}
    )
    session_active: bool = True
    credential_active: bool = True
    workload_trusted: bool = True
    task_active: bool = True
    relationship_active: bool = True
    quarantined: bool = False
    claims_current: bool = True
    policy_version: str = POLICY_VERSION
    task_version: int = 4
    relationship_version: int = 7
    last_by_domain: dict[str, int] = field(default_factory=dict)
    state_version: int = 1
    recovery_ready: bool = False
    recovery_since: int | None = None
    applied_events: list[str] = field(default_factory=list)
    ignored_events: list[str] = field(default_factory=list)

    @property
    def max_risk(self) -> int:
        return max(self.risk.values()) if self.risk else 100

    @property
    def top_dimensions(self) -> tuple[str, ...]:
        maximum = self.max_risk
        return tuple(sorted(name for name, value in self.risk.items() if value == maximum))


class SignalProjector:
    """Project persisted events; stale relaxations lose and late restrictions win."""

    def __init__(self, states: Mapping[str, TrustState] | None = None):
        self.states = dict(states or {SUBJECT.key: TrustState()})

    def state_for(self, subject: SubjectRef = SUBJECT) -> TrustState | None:
        return self.states.get(subject.key)

    def project(self, receiver: DurableSignalReceiver) -> int:
        count = 0
        for row in receiver.pending():
            subject_data = json.loads(row["subject_json"])
            subject = SubjectRef(**subject_data)
            state = self.states.get(subject.key)
            if state is None:
                receiver.mark_applied(row["jti"])
                count += 1
                continue
            data = json.loads(row["event_json"])
            self._apply(
                state,
                row["issuer"],
                row["event_type"],
                data,
                row["event_timestamp"],
                row["jti"],
            )
            receiver.mark_applied(row["jti"])
            count += 1
        return count

    def _apply(
        self,
        state: TrustState,
        issuer: str,
        event_type: str,
        data: Mapping[str, Any],
        timestamp: int,
        jti: str,
    ) -> None:
        domain = EVENT_DOMAINS[event_type]
        previous = state.last_by_domain.get(domain, -1)
        restrictive = is_restrictive(event_type, data)
        if timestamp < previous and not restrictive:
            state.ignored_events.append(jti)
            return
        changed = self._apply_semantics(state, issuer, event_type, data, timestamp)
        if not changed:
            state.ignored_events.append(jti)
            return
        state.last_by_domain[domain] = max(previous, timestamp)
        state.applied_events.append(jti)
        state.state_version += 1

    def _apply_semantics(
        self,
        state: TrustState,
        issuer: str,
        event_type: str,
        data: Mapping[str, Any],
        timestamp: int,
    ) -> bool:
        if event_type == SESSION_REVOKED:
            state.session_active = False
        elif event_type == TOKEN_CLAIMS_CHANGE:
            state.claims_current = data["claims"].get("claims_current", False)
        elif event_type == CREDENTIAL_CHANGE:
            state.credential_active = data["change_type"] not in {"revoke", "delete"}
        elif event_type == ASSURANCE_LEVEL_CHANGE:
            level = data["current_level"].lower()
            state.risk["identity"] = 10 if level.endswith(("2", "3")) else 75
            state.risk_updated_at["identity"] = timestamp
        elif event_type == DEVICE_COMPLIANCE_CHANGE:
            trusted = data["current_status"] == "compliant"
            state.workload_trusted = trusted
            state.risk["workload"] = 10 if trusted else 75
            state.risk_updated_at["workload"] = timestamp
        elif event_type == RISK_LEVEL_CHANGE:
            state.risk["identity"] = RISK_LEVELS[data["current_level"]]
            state.risk_updated_at["identity"] = timestamp
        elif event_type == WORKLOAD_POSTURE_CHANGE:
            state.workload_trusted = data["trusted"]
            state.risk["workload"] = RISK_LEVELS[data["current_level"]]
            state.risk_updated_at["workload"] = timestamp
        elif event_type == AGENT_BEHAVIOR_CHANGE:
            state.risk["behavior"] = RISK_LEVELS[data["current_level"]]
            state.risk_updated_at["behavior"] = timestamp
        elif event_type == THREAT_INTELLIGENCE_CHANGE:
            state.risk["threat"] = RISK_LEVELS[data["current_level"]]
            state.risk_updated_at["threat"] = timestamp
        elif event_type == TRANSACTION_RISK_CHANGE:
            state.risk["transaction"] = RISK_LEVELS[data["current_level"]]
            state.risk_updated_at["transaction"] = timestamp
        elif event_type == TASK_CHANGE:
            state.task_active = data["active"]
            state.task_version = data["task_version"]
        elif event_type == RELATIONSHIP_CHANGE:
            state.relationship_active = data["active"]
            state.relationship_version = data["relationship_version"]
        elif event_type == POLICY_CHANGE:
            state.policy_version = data["policy_version"]
        elif event_type == QUARANTINE_CHANGE:
            if data["action"] == "quarantine":
                state.quarantined = True
                state.recovery_ready = False
                state.recovery_since = None
            else:
                authorized = (
                    issuer == "https://governance.northstar.example"
                    and data.get("human_approved") is True
                    and data.get("incident_cleared") is True
                    and data.get("fresh_attestation") is True
                )
                if not authorized:
                    return False
                state.quarantined = False
                state.recovery_ready = True
                state.recovery_since = timestamp
        return True


@dataclass(frozen=True)
class AccessRequest:
    operation_id: str
    tenant_id: str
    agent_id: str
    workload_id: str
    session_id: str
    action: str
    resource: str
    policy_version: str
    task_version: int
    relationship_version: int


def default_request(action: str = "claim.update") -> AccessRequest:
    return AccessRequest(
        "operation:claim:483",
        TENANT,
        AGENT,
        WORKLOAD,
        SESSION,
        action,
        RESOURCE,
        POLICY_VERSION,
        4,
        7,
    )


@dataclass(frozen=True)
class Decision:
    allowed: bool
    mode: str
    reason_code: str
    obligations: tuple[str, ...]
    state_version: int
    risk: Mapping[str, int]


MODE_RANK = {
    "ALLOW": 0,
    "OBSERVE": 1,
    "REDUCE": 2,
    "STEP_UP": 3,
    "PAUSE": 4,
    "REVOKE": 5,
    "QUARANTINE": 6,
    "DENY": 7,
}


class AdaptiveController:
    """Return an action, not a magic trust score; recovery is deliberately slow."""

    def __init__(self, *, cooldown_seconds: int = 300, signal_ttl_seconds: int = 600):
        self.cooldown_seconds = cooldown_seconds
        self.signal_ttl_seconds = signal_ttl_seconds
        self.previous: dict[str, tuple[str, int]] = {}

    def decide(
        self,
        state: TrustState | None,
        request: AccessRequest,
        receiver: DurableSignalReceiver,
        *,
        now: int = NOW,
    ) -> Decision:
        candidate = self._candidate(state, request, receiver, now=now)
        if state is None:
            return candidate
        prior = self.previous.get(state.subject.key)
        if prior and MODE_RANK[candidate.mode] < MODE_RANK[prior[0]]:
            recovery_age = now - (state.recovery_since or now)
            if not state.recovery_ready or recovery_age < self.cooldown_seconds:
                candidate = Decision(
                    False,
                    prior[0],
                    "recovery_cooldown",
                    ("retain_more_restrictive_mode",),
                    state.state_version,
                    dict(state.risk),
                )
        if prior is None or prior[0] != candidate.mode:
            self.previous[state.subject.key] = (candidate.mode, now)
        return candidate

    def _candidate(
        self,
        state: TrustState | None,
        request: AccessRequest,
        receiver: DurableSignalReceiver,
        *,
        now: int,
    ) -> Decision:
        risk = dict(state.risk) if state else {}

        def decision(
            allowed: bool, mode: str, reason: str, *obligations: str
        ) -> Decision:
            return Decision(
                allowed,
                mode,
                reason,
                tuple(obligations),
                state.state_version if state else 0,
                risk,
            )

        if state is None:
            return decision(False, "DENY", "subject_unresolved")
        expected = state.subject
        bindings = {
            "tenant_mismatch": request.tenant_id != expected.tenant_id,
            "agent_mismatch": request.agent_id != expected.agent_id,
            "workload_mismatch": request.workload_id != expected.workload_id,
            "session_mismatch": request.session_id != expected.session_id,
            "resource_not_allowed": request.resource != RESOURCE,
            "action_not_allowed": request.action not in {"claim.read", "claim.update"},
            "policy_version_mismatch": request.policy_version != state.policy_version,
            "task_version_mismatch": request.task_version != state.task_version,
            "relationship_version_mismatch": request.relationship_version
            != state.relationship_version,
        }
        for reason, failed in bindings.items():
            if failed:
                return decision(False, "DENY", reason)
        if state.quarantined:
            return decision(False, "QUARANTINE", "agent_quarantined", "isolate_agent")
        if not state.session_active:
            return decision(False, "REVOKE", "session_revoked", "end_session")
        if not state.credential_active:
            return decision(False, "REVOKE", "credential_revoked", "revoke_tokens")
        if not state.workload_trusted:
            return decision(False, "QUARANTINE", "workload_untrusted", "isolate_workload")
        if not state.task_active:
            return decision(False, "REVOKE", "task_inactive", "end_delegation")
        if not state.relationship_active:
            return decision(False, "REVOKE", "relationship_inactive", "end_delegation")
        if not state.claims_current:
            return decision(False, "STEP_UP", "token_claims_changed", "refresh_token")
        if not receiver.stream_available:
            return decision(False, "PAUSE", "signal_stream_unavailable", "fail_closed")
        if now - receiver.last_success_at > self.signal_ttl_seconds:
            return decision(False, "PAUSE", "signal_stream_stale", "refresh_state")
        if receiver.pending_count:
            return decision(False, "PAUSE", "restrictive_signal_backlog", "drain_inbox")
        if set(state.risk) != RISK_DIMENSIONS:
            return decision(False, "PAUSE", "risk_dimensions_incomplete", "refresh_state")
        stale = [
            name
            for name, timestamp in state.risk_updated_at.items()
            if now - timestamp > self.signal_ttl_seconds
        ]
        if stale:
            return decision(False, "PAUSE", "risk_signal_stale", *sorted(stale))
        if state.max_risk >= 90:
            return decision(
                False,
                "QUARANTINE",
                "critical_risk",
                *state.top_dimensions,
            )
        if state.max_risk >= 70:
            return decision(
                False,
                "STEP_UP",
                "high_risk",
                "fresh_attestation",
                *state.top_dimensions,
            )
        if state.max_risk >= 45:
            if request.action == "claim.read":
                return decision(
                    True,
                    "OBSERVE",
                    "moderate_risk_read",
                    "enhanced_logging",
                    *state.top_dimensions,
                )
            return decision(
                False,
                "REDUCE",
                "moderate_risk_write",
                "read_only",
                *state.top_dimensions,
            )
        return decision(True, "ALLOW", "authorized", "record_evidence")


@dataclass(frozen=True)
class DecisionLease:
    request_digest: str
    state_version: int
    stream_epoch: int
    expires_at: int
    decision: Decision


class DecisionCache:
    def __init__(self):
        self._leases: dict[str, DecisionLease] = {}

    def put(
        self,
        request: AccessRequest,
        state: TrustState,
        receiver: DurableSignalReceiver,
        decision: Decision,
        *,
        now: int = NOW,
        ttl_seconds: int = 30,
    ) -> DecisionLease:
        request_digest = digest(request)
        lease = DecisionLease(
            request_digest,
            state.state_version,
            receiver.stream_epoch,
            now + ttl_seconds,
            decision,
        )
        self._leases[request_digest] = lease
        return lease

    def get(
        self,
        request: AccessRequest,
        state: TrustState,
        receiver: DurableSignalReceiver,
        *,
        now: int = NOW,
    ) -> Decision | None:
        lease = self._leases.get(digest(request))
        if (
            lease is None
            or lease.request_digest != digest(request)
            or lease.state_version != state.state_version
            or lease.stream_epoch != receiver.stream_epoch
            or now >= lease.expires_at
        ):
            return None
        return lease.decision


class EvidenceLog:
    def __init__(self):
        self.records: list[dict[str, Any]] = []

    def append(self, request: AccessRequest, decision: Decision) -> None:
        self.records.append(
            {
                "operation_id": request.operation_id,
                "subject_hash": digest(
                    {
                        "tenant": request.tenant_id,
                        "agent": request.agent_id,
                        "workload": request.workload_id,
                    }
                ),
                "action": request.action,
                "resource": request.resource,
                "allowed": decision.allowed,
                "mode": decision.mode,
                "reason_code": decision.reason_code,
                "obligations": list(decision.obligations),
                "state_version": decision.state_version,
                "risk": dict(decision.risk),
                "policy_version": request.policy_version,
            }
        )


class CommitGate:
    """Re-authorize at the side-effect boundary and make retries exact."""

    def __init__(self, controller: AdaptiveController, evidence: EvidenceLog):
        self.controller = controller
        self.evidence = evidence
        self.ledger: dict[str, tuple[str, Decision]] = {}
        self.effects: list[str] = []
        self._lock = Lock()

    def execute(
        self,
        request: AccessRequest,
        state: TrustState,
        receiver: DurableSignalReceiver,
        *,
        now: int = NOW,
        before_commit: Callable[[], None] | None = None,
    ) -> Decision:
        operation_digest = digest(request)
        with self._lock:
            existing = self.ledger.get(request.operation_id)
            if existing:
                if existing[0] != operation_digest:
                    return Decision(
                        False,
                        "DENY",
                        "operation_conflict",
                        (),
                        state.state_version,
                        dict(state.risk),
                    )
                return existing[1]
            if before_commit:
                before_commit()
            decision = self.controller.decide(state, request, receiver, now=now)
            self.evidence.append(request, decision)
            self.ledger[request.operation_id] = (operation_digest, decision)
            if decision.allowed:
                self.effects.append(request.operation_id)
            return decision


def transmitter_fixture() -> tuple[dict[str, SetTransmitter], dict[str, TransmitterPolicy]]:
    transmitters = {
        "identity": SetTransmitter("https://id.northstar.example", "id-2026"),
        "security": SetTransmitter(
            "https://security.northstar.example", "security-2026"
        ),
        "workload": SetTransmitter(
            "https://workload.northstar.example", "workload-2026"
        ),
        "governance": SetTransmitter(
            "https://governance.northstar.example", "governance-2026"
        ),
    }
    allowed = {
        "identity": frozenset(
            {
                SESSION_REVOKED,
                TOKEN_CLAIMS_CHANGE,
                CREDENTIAL_CHANGE,
                ASSURANCE_LEVEL_CHANGE,
                DEVICE_COMPLIANCE_CHANGE,
                RISK_LEVEL_CHANGE,
            }
        ),
        "security": frozenset(
            {
                AGENT_BEHAVIOR_CHANGE,
                THREAT_INTELLIGENCE_CHANGE,
                TRANSACTION_RISK_CHANGE,
                QUARANTINE_CHANGE,
            }
        ),
        "workload": frozenset({WORKLOAD_POSTURE_CHANGE}),
        "governance": frozenset(
            {TASK_CHANGE, RELATIONSHIP_CHANGE, POLICY_CHANGE, QUARANTINE_CHANGE}
        ),
    }
    policies = {
        transmitter.issuer: TransmitterPolicy(
            transmitter.issuer,
            AUDIENCE,
            {transmitter.kid: transmitter.public_key},
            allowed[name],
        )
        for name, transmitter in transmitters.items()
    }
    return transmitters, policies


def scenario(*, database: str | Path = ":memory:") -> dict[str, Any]:
    clock = ManualClock()
    transmitters, policies = transmitter_fixture()
    receiver = DurableSignalReceiver(policies, database=database, clock=clock)
    projector = SignalProjector()
    state = projector.state_for()
    assert state is not None
    evidence = EvidenceLog()
    controller = AdaptiveController()
    return {
        "clock": clock,
        "transmitters": transmitters,
        "policies": policies,
        "receiver": receiver,
        "projector": projector,
        "state": state,
        "request": default_request(),
        "controller": controller,
        "cache": DecisionCache(),
        "evidence": evidence,
        "gate": CommitGate(controller, evidence),
    }


def emit(
    value: Mapping[str, Any],
    source: str,
    event_type: str,
    data: Mapping[str, Any],
    *,
    jti: str,
    timestamp: int = NOW,
    project: bool = True,
) -> ReceiveResult:
    transmitter = value["transmitters"][source]
    token = transmitter.issue(
        event_type,
        data,
        event_timestamp=timestamp,
        issued_at=value["clock"].now,
        jti=jti,
    )
    result = value["receiver"].receive(token)
    if result.accepted and result.outcome == "persisted" and project:
        value["projector"].project(value["receiver"])
    return result


@dataclass(frozen=True)
class DecisionCase:
    case_id: str
    category: str
    expected_allowed: bool
    mutate: Callable[[dict[str, Any]], None]

    def run(self) -> bool:
        value = scenario()
        self.mutate(value)
        decision = value["controller"].decide(
            value["state"],
            value["request"],
            value["receiver"],
            now=value["clock"].now,
        )
        return decision.allowed

    def baseline_run(self) -> bool:
        value = scenario()
        self.mutate(value)
        request = value["request"]
        return request.action in {"claim.read", "claim.update"} and request.resource == RESOURCE


def _nothing(_: dict[str, Any]) -> None:
    return None


def _request(**changes: Any) -> Callable[[dict[str, Any]], None]:
    def mutate(value: dict[str, Any]) -> None:
        value["request"] = replace(value["request"], **changes)

    return mutate


def _state(**changes: Any) -> Callable[[dict[str, Any]], None]:
    def mutate(value: dict[str, Any]) -> None:
        for name, item in changes.items():
            setattr(value["state"], name, item)

    return mutate


def _signal(
    source: str,
    event_type: str,
    data: Mapping[str, Any],
    case_id: str,
    *,
    timestamp: int = NOW,
    project: bool = True,
) -> Callable[[dict[str, Any]], None]:
    def mutate(value: dict[str, Any]) -> None:
        emit(
            value,
            source,
            event_type,
            data,
            jti=f"set:{case_id}",
            timestamp=timestamp,
            project=project,
        )

    return mutate


def _moderate_read(value: dict[str, Any]) -> None:
    value["request"] = replace(value["request"], action="claim.read")
    emit(
        value,
        "security",
        AGENT_BEHAVIOR_CHANGE,
        {"current_level": "medium"},
        jti="set:moderate-read",
    )


def _duplicate_low(value: dict[str, Any]) -> None:
    transmitter = value["transmitters"]["security"]
    token = transmitter.issue(
        AGENT_BEHAVIOR_CHANGE,
        {"current_level": "low", "event_timestamp": NOW},
        jti="set:duplicate-low",
    )
    value["receiver"].receive(token)
    value["receiver"].receive(token)
    value["projector"].project(value["receiver"])


def _stale_relaxation(value: dict[str, Any]) -> None:
    emit(
        value,
        "security",
        AGENT_BEHAVIOR_CHANGE,
        {"current_level": "high"},
        jti="set:new-high",
        timestamp=NOW,
    )
    emit(
        value,
        "security",
        AGENT_BEHAVIOR_CHANGE,
        {"current_level": "low"},
        jti="set:old-low",
        timestamp=NOW - 30,
    )


def _late_restriction(value: dict[str, Any]) -> None:
    emit(
        value,
        "identity",
        RISK_LEVEL_CHANGE,
        {"current_level": "low"},
        jti="set:new-low",
        timestamp=NOW,
    )
    emit(
        value,
        "identity",
        RISK_LEVEL_CHANGE,
        {"current_level": "high"},
        jti="set:late-high",
        timestamp=NOW - 30,
    )


def _fake_recovery(value: dict[str, Any]) -> None:
    emit(
        value,
        "security",
        QUARANTINE_CHANGE,
        {"action": "quarantine"},
        jti="set:quarantine",
    )
    emit(
        value,
        "security",
        QUARANTINE_CHANGE,
        {
            "action": "release",
            "human_approved": True,
            "incident_cleared": True,
            "fresh_attestation": True,
        },
        jti="set:fake-release",
        timestamp=NOW + 1,
    )


def _incomplete_recovery(missing: str) -> Callable[[dict[str, Any]], None]:
    def mutate(value: dict[str, Any]) -> None:
        emit(
            value,
            "security",
            QUARANTINE_CHANGE,
            {"action": "quarantine"},
            jti=f"set:quarantine:{missing}",
        )
        release = {
            "action": "release",
            "human_approved": True,
            "incident_cleared": True,
            "fresh_attestation": True,
        }
        release[missing] = False
        emit(
            value,
            "governance",
            QUARANTINE_CHANGE,
            release,
            jti=f"set:release:{missing}",
            timestamp=NOW + 1,
        )

    return mutate


def _cooldown(value: dict[str, Any]) -> None:
    controller = value["controller"]
    emit(
        value,
        "security",
        AGENT_BEHAVIOR_CHANGE,
        {"current_level": "high"},
        jti="set:cooldown-high",
    )
    controller.decide(value["state"], value["request"], value["receiver"], now=NOW)
    emit(
        value,
        "security",
        AGENT_BEHAVIOR_CHANGE,
        {"current_level": "low"},
        jti="set:cooldown-low",
        timestamp=NOW + 1,
    )
    value["state"].recovery_ready = True
    value["state"].recovery_since = NOW + 1


def _stream_stale(value: dict[str, Any]) -> None:
    value["clock"].advance(601)


def _risk_stale(value: dict[str, Any]) -> None:
    value["receiver"].last_success_at = NOW + 601
    value["clock"].advance(601)


def _missing_risk(value: dict[str, Any]) -> None:
    value["state"].risk.pop("threat")
    value["state"].risk_updated_at.pop("threat")


def _unresolved_subject(value: dict[str, Any]) -> None:
    value["state"] = None


def build_cases() -> list[DecisionCase]:
    cases = [
        DecisionCase("valid_update", "valid", True, _nothing),
        DecisionCase("valid_moderate_read", "valid", True, _moderate_read),
        DecisionCase("valid_duplicate_delivery", "valid", True, _duplicate_low),
        DecisionCase("session_revoked", "lifecycle", False, _signal("identity", SESSION_REVOKED, {}, "session-revoked")),
        DecisionCase("credential_revoked", "lifecycle", False, _signal("identity", CREDENTIAL_CHANGE, {"credential_type": "verifiable-credential", "change_type": "revoke"}, "credential-revoked")),
        DecisionCase("workload_untrusted", "workload", False, _signal("workload", WORKLOAD_POSTURE_CHANGE, {"trusted": False, "current_level": "high"}, "workload-untrusted")),
        DecisionCase("task_inactive", "governance", False, _signal("governance", TASK_CHANGE, {"active": False, "task_version": 5}, "task-inactive")),
        DecisionCase("relationship_inactive", "governance", False, _signal("governance", RELATIONSHIP_CHANGE, {"active": False, "relationship_version": 8}, "relationship-inactive")),
        DecisionCase("agent_quarantined", "negative-evidence", False, _signal("security", QUARANTINE_CHANGE, {"action": "quarantine"}, "agent-quarantined")),
        DecisionCase("critical_threat", "risk", False, _signal("security", THREAT_INTELLIGENCE_CHANGE, {"current_level": "critical"}, "critical-threat")),
        DecisionCase("high_behavior", "risk", False, _signal("security", AGENT_BEHAVIOR_CHANGE, {"current_level": "high"}, "high-behavior")),
        DecisionCase("high_identity", "risk", False, _signal("identity", RISK_LEVEL_CHANGE, {"current_level": "high"}, "high-identity")),
        DecisionCase("high_workload", "risk", False, _signal("workload", WORKLOAD_POSTURE_CHANGE, {"trusted": True, "current_level": "high"}, "high-workload")),
        DecisionCase("high_transaction", "risk", False, _signal("security", TRANSACTION_RISK_CHANGE, {"current_level": "high"}, "high-transaction")),
        DecisionCase("device_noncompliant", "workload", False, _signal("identity", DEVICE_COMPLIANCE_CHANGE, {"previous_status": "compliant", "current_status": "not-compliant"}, "device-noncompliant")),
        DecisionCase("wrong_tenant", "binding", False, _request(tenant_id="tenant:attacker")),
        DecisionCase("wrong_agent", "binding", False, _request(agent_id="agent:attacker")),
        DecisionCase("wrong_workload", "binding", False, _request(workload_id="spiffe://attacker.example/agent")),
        DecisionCase("wrong_session", "binding", False, _request(session_id="session:other")),
        DecisionCase("wrong_action", "authority", False, _request(action="claim.delete")),
        DecisionCase("wrong_resource", "authority", False, _request(resource="claim:999")),
        DecisionCase("policy_version_stale", "governance", False, _signal("governance", POLICY_CHANGE, {"policy_version": "adaptive-policy-2026-10-13"}, "policy-stale")),
        DecisionCase("task_version_stale", "governance", False, _signal("governance", TASK_CHANGE, {"active": True, "task_version": 5}, "task-version")),
        DecisionCase("relationship_version_stale", "governance", False, _signal("governance", RELATIONSHIP_CHANGE, {"active": True, "relationship_version": 8}, "relationship-version")),
        DecisionCase("token_claims_changed", "identity", False, _signal("identity", TOKEN_CLAIMS_CHANGE, {"claims": {"claims_current": False}}, "claims-changed")),
        DecisionCase("stream_unavailable", "resilience", False, lambda value: value["receiver"].set_stream_available(False)),
        DecisionCase("stream_stale", "resilience", False, _stream_stale),
        DecisionCase("restrictive_backlog", "resilience", False, _signal("identity", SESSION_REVOKED, {}, "backlog", project=False)),
        DecisionCase("stale_relaxation", "ordering", False, _stale_relaxation),
        DecisionCase("late_restriction", "ordering", False, _late_restriction),
        DecisionCase("fake_recovery_source", "recovery", False, _fake_recovery),
        DecisionCase("recovery_without_human", "recovery", False, _incomplete_recovery("human_approved")),
        DecisionCase("recovery_without_incident_clearance", "recovery", False, _incomplete_recovery("incident_cleared")),
        DecisionCase("recovery_without_attestation", "recovery", False, _incomplete_recovery("fresh_attestation")),
        DecisionCase("recovery_cooldown", "recovery", False, _cooldown),
        DecisionCase("moderate_write_reduced", "risk", False, _signal("security", AGENT_BEHAVIOR_CHANGE, {"current_level": "medium"}, "moderate-write")),
        DecisionCase("risk_signal_stale", "freshness", False, _risk_stale),
        DecisionCase("risk_dimensions_incomplete", "freshness", False, _missing_risk),
        DecisionCase("claims_state_inactive", "identity", False, _state(claims_current=False)),
        DecisionCase("subject_unresolved", "correlation", False, _unresolved_subject),
    ]
    assert len(cases) == 40
    return cases


@dataclass(frozen=True)
class Metrics:
    total: int
    expected_allowed: int
    expected_blocked: int
    matches: int
    invalid_allows: int
    valid_blocked: int

    @property
    def accuracy(self) -> float:
        return self.matches / self.total if self.total else 0.0


def evaluate(
    cases: list[DecisionCase], *, baseline: bool = False
) -> tuple[Metrics, list[dict[str, Any]]]:
    rows = []
    invalid_allows = valid_blocked = matches = 0
    for case in cases:
        allowed = case.baseline_run() if baseline else case.run()
        match = allowed is case.expected_allowed
        matches += int(match)
        invalid_allows += int(allowed and not case.expected_allowed)
        valid_blocked += int(not allowed and case.expected_allowed)
        rows.append(
            {
                "case_id": case.case_id,
                "category": case.category,
                "expected_allowed": case.expected_allowed,
                "actual_allowed": allowed,
                "match": match,
            }
        )
    metrics = Metrics(
        len(cases),
        sum(case.expected_allowed for case in cases),
        sum(not case.expected_allowed for case in cases),
        matches,
        invalid_allows,
        valid_blocked,
    )
    return metrics, rows


def release_gate(metrics: Metrics) -> bool:
    return (
        metrics.total >= 40
        and metrics.invalid_allows == 0
        and metrics.valid_blocked == 0
        and metrics.accuracy == 1.0
    )


def main() -> None:
    cases = build_cases()
    metrics, rows = evaluate(cases)
    baseline, _ = evaluate(cases, baseline=True)
    print(
        json.dumps(
            {
                "metrics": asdict(metrics) | {"accuracy": metrics.accuracy},
                "point_in_time_baseline": asdict(baseline)
                | {"accuracy": baseline.accuracy},
                "release_gate": release_gate(metrics),
                "mismatches": [row for row in rows if not row["match"]],
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
