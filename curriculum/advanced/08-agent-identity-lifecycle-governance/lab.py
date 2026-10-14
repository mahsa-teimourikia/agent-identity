"""Executable agent-identity lifecycle governance lab.

The lab is deterministic, credential-free, and deliberately small enough to inspect.
It models the controls around a high-risk insurance claims agent rather than an AI
model: schema validation, cryptographically bound approvals, segregation of duties,
optimistic concurrency, recertification, emergency response, retirement, and a
tamper-evident event trail.
"""

from __future__ import annotations

import base64
import json
import sqlite3
from collections.abc import Callable
from dataclasses import asdict, dataclass, replace
from hashlib import sha256
from pathlib import Path
from threading import RLock
from typing import Any

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jsonschema import Draft202012Validator

NOW = 1_800_000_000
TENANT = "tenant:northstar"
AGENT_ID = "agent:claims-investigator:v3"
WORKLOAD_ID = "spiffe://northstar.example/prod/claims-investigator"
POLICY_VERSION = "governance-2026-10"
AUDIENCE = "urn:northstar:agent-governance"
COURSE = Path(__file__).parent


class GovernanceError(ValueError):
    """A stable, testable governance failure."""


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def digest(value: Any) -> str:
    raw = value if isinstance(value, bytes) else canonical(value).encode()
    return base64.urlsafe_b64encode(sha256(raw).digest()).rstrip(b"=").decode()


def deterministic_key(label: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(sha256(label.encode()).digest())


@dataclass(frozen=True)
class AgentProposal:
    agent_id: str = AGENT_ID
    tenant_id: str = TENANT
    owner: str = "team:claims-ai"
    sponsor: str = "user:claims-vp"
    requester: str = "user:product-owner"
    purpose: str = "Investigate a claim and draft a non-binding adjuster note"
    risk_tier: str = "high"
    data_classification: str = "restricted"
    requested_actions: tuple[str, ...] = ("claim.read", "claim.note.create")
    resource_prefixes: tuple[str, ...] = ("/claims/",)
    environment: str = "prod"
    workload_id: str = WORKLOAD_ID
    artifact_digest: str = "sha256:claims-agent-v3"
    model_id: str = "approved-model:2026-09"
    policy_version: str = POLICY_VERSION
    monitoring_enabled: bool = True
    evals_passed: bool = True
    short_lived_credentials: bool = True
    credential_ttl_seconds: int = 300
    review_interval_days: int = 30

    def record(self) -> dict[str, Any]:
        value = asdict(self)
        value["requested_actions"] = list(self.requested_actions)
        value["resource_prefixes"] = list(self.resource_prefixes)
        return value

    @property
    def fingerprint(self) -> str:
        return digest(self.record())


@dataclass(frozen=True)
class Approver:
    subject: str
    role: str
    key: Ed25519PrivateKey


@dataclass(frozen=True)
class RequestContext:
    tenant_id: str = TENANT
    workload_id: str = WORKLOAD_ID
    action: str = "claim.read"
    resource: str = "/claims/483"
    purpose: str = "Investigate a claim and draft a non-binding adjuster note"
    policy_version: str = POLICY_VERSION
    now: int = NOW + 60


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    agent_id: str
    lifecycle_version: int


@dataclass(frozen=True)
class Case:
    case_id: str
    expected: bool
    description: str
    run: Callable[[bool], bool]


def required_roles(risk_tier: str) -> set[str]:
    try:
        return {
            "low": {"owner"},
            "medium": {"owner", "platform"},
            "high": {"owner", "security"},
            "critical": {"owner", "security", "risk", "business_authority"},
        }[risk_tier]
    except KeyError as exc:
        raise GovernanceError("risk_tier_unknown") from exc


class ApprovalAuthority:
    """Issues and verifies EdDSA approval receipts for registered approvers."""

    def __init__(self) -> None:
        roles = {
            "user:owner-approver": "owner",
            "user:security-approver": "security",
            "user:platform-approver": "platform",
            "user:risk-approver": "risk",
            "user:business-approver": "business_authority",
        }
        self.approvers = {
            subject: Approver(subject, role, deterministic_key(subject))
            for subject, role in roles.items()
        }

    def issue(
        self,
        subject: str,
        proposal: AgentProposal,
        *,
        now: int = NOW,
        lifetime: int = 900,
        jti: str | None = None,
        decision: str = "approve",
        digest_override: str | None = None,
        tenant_override: str | None = None,
        policy_override: str | None = None,
    ) -> str:
        approver = self.approvers[subject]
        claims = {
            "iss": "https://governance.northstar.example",
            "sub": subject,
            "role": approver.role,
            "aud": AUDIENCE,
            "tenant": tenant_override or proposal.tenant_id,
            "proposal_digest": digest_override or proposal.fingerprint,
            "policy_version": policy_override or proposal.policy_version,
            "decision": decision,
            "iat": now,
            "nbf": now,
            "exp": now + lifetime,
            "jti": jti or f"approval:{subject}:{proposal.fingerprint[:12]}",
        }
        return jwt.encode(
            claims,
            approver.key,
            algorithm="EdDSA",
            headers={"kid": subject, "typ": "governance-approval+jwt"},
        )

    def verify(
        self, token: str, proposal: AgentProposal, *, now: int = NOW
    ) -> dict[str, Any]:
        try:
            header = jwt.get_unverified_header(token)
            subject = header["kid"]
            approver = self.approvers[subject]
            claims = jwt.decode(
                token,
                approver.key.public_key(),
                algorithms=["EdDSA"],
                audience=AUDIENCE,
                issuer="https://governance.northstar.example",
                options={
                    "require": ["exp", "iat", "nbf", "jti", "sub"],
                    "verify_exp": False,
                    "verify_iat": False,
                    "verify_nbf": False,
                },
                leeway=0,
            )
        except Exception as exc:
            raise GovernanceError("approval_invalid") from exc
        expected = {
            "sub": subject,
            "role": approver.role,
            "tenant": proposal.tenant_id,
            "proposal_digest": proposal.fingerprint,
            "policy_version": proposal.policy_version,
            "decision": "approve",
        }
        if any(claims.get(key) != value for key, value in expected.items()):
            raise GovernanceError("approval_binding_invalid")
        if not (claims["nbf"] <= now < claims["exp"]):
            raise GovernanceError("approval_time_invalid")
        return claims


class GovernanceStore:
    """SQLite-backed lifecycle registry with atomic commands and hash-chained events."""

    def __init__(self, path: str = ":memory:") -> None:
        self.db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.lock = RLock()
        self.db.executescript(
            """
            PRAGMA foreign_keys = ON;
            CREATE TABLE agents (
              agent_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, state TEXT NOT NULL,
              version INTEGER NOT NULL, proposal_json TEXT NOT NULL,
              proposal_digest TEXT NOT NULL, review_due INTEGER,
              credential_active INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE events (
              agent_id TEXT NOT NULL, sequence INTEGER NOT NULL, event_type TEXT NOT NULL,
              actor TEXT NOT NULL, occurred_at INTEGER NOT NULL, payload_json TEXT NOT NULL,
              previous_hash TEXT NOT NULL, event_hash TEXT NOT NULL,
              PRIMARY KEY(agent_id, sequence),
              FOREIGN KEY(agent_id) REFERENCES agents(agent_id)
            );
            CREATE TABLE consumed_receipts (jti TEXT PRIMARY KEY, consumed_at INTEGER NOT NULL);
            CREATE TABLE commands (
              idempotency_key TEXT PRIMARY KEY, request_digest TEXT NOT NULL,
              result_json TEXT NOT NULL
            );
            """
        )
        schema = json.loads((COURSE / "schemas/agent_identity.schema.json").read_text())
        self.validator = Draft202012Validator(schema)

    def close(self) -> None:
        self.db.close()

    def _event(
        self,
        agent_id: str,
        event_type: str,
        actor: str,
        now: int,
        payload: dict[str, Any],
    ) -> str:
        prior = self.db.execute(
            "SELECT sequence,event_hash FROM events WHERE agent_id=? ORDER BY sequence DESC LIMIT 1",
            (agent_id,),
        ).fetchone()
        sequence = 1 if prior is None else prior["sequence"] + 1
        previous = "GENESIS" if prior is None else prior["event_hash"]
        body = {
            "agent_id": agent_id,
            "sequence": sequence,
            "event_type": event_type,
            "actor": actor,
            "occurred_at": now,
            "payload": payload,
            "previous_hash": previous,
        }
        event_hash = digest(body)
        self.db.execute(
            "INSERT INTO events VALUES (?,?,?,?,?,?,?,?)",
            (
                agent_id,
                sequence,
                event_type,
                actor,
                now,
                canonical(payload),
                previous,
                event_hash,
            ),
        )
        return event_hash

    def _cached(self, key: str, request_digest: str) -> dict[str, Any] | None:
        row = self.db.execute(
            "SELECT request_digest,result_json FROM commands WHERE idempotency_key=?",
            (key,),
        ).fetchone()
        if row is None:
            return None
        if row["request_digest"] != request_digest:
            raise GovernanceError("idempotency_conflict")
        return json.loads(row["result_json"])

    def _cache(self, key: str, request_digest: str, value: dict[str, Any]) -> None:
        self.db.execute(
            "INSERT INTO commands VALUES (?,?,?)",
            (key, request_digest, canonical(value)),
        )

    def register(
        self,
        proposal: AgentProposal,
        *,
        actor: str | None = None,
        command_id: str = "register:1",
        now: int = NOW,
    ) -> dict[str, Any]:
        actor = actor or proposal.requester
        errors = sorted(
            self.validator.iter_errors(proposal.record()), key=lambda x: list(x.path)
        )
        if errors:
            raise GovernanceError(f"schema_invalid:{errors[0].message}")
        self._onboarding_gates(proposal)
        request_digest = digest(
            {
                "operation": "register",
                "proposal": proposal.record(),
                "actor": actor,
            }
        )
        with self.lock:
            cached = self._cached(command_id, request_digest)
            if cached is not None:
                return cached
            try:
                self.db.execute("BEGIN IMMEDIATE")
                self.db.execute(
                    "INSERT INTO agents VALUES (?,?,?,?,?,?,?,?)",
                    (
                        proposal.agent_id,
                        proposal.tenant_id,
                        "pending_approval",
                        1,
                        canonical(proposal.record()),
                        proposal.fingerprint,
                        None,
                        0,
                    ),
                )
                self._event(
                    proposal.agent_id,
                    "registration_submitted",
                    actor,
                    now,
                    {"proposal_digest": proposal.fingerprint},
                )
                result = {
                    "agent_id": proposal.agent_id,
                    "state": "pending_approval",
                    "version": 1,
                }
                self._cache(command_id, request_digest, result)
                self.db.execute("COMMIT")
                return result
            except Exception:
                self.db.execute("ROLLBACK")
                raise

    @staticmethod
    def _onboarding_gates(proposal: AgentProposal) -> None:
        if proposal.environment == "prod" and not proposal.short_lived_credentials:
            raise GovernanceError("static_credential_forbidden")
        if not proposal.monitoring_enabled:
            raise GovernanceError("monitoring_required")
        if not proposal.evals_passed:
            raise GovernanceError("evals_required")
        if not proposal.workload_id.startswith("spiffe://northstar.example/"):
            raise GovernanceError("workload_binding_invalid")
        if proposal.credential_ttl_seconds > 900:
            raise GovernanceError("credential_ttl_too_long")
        if "payment.approve" in proposal.requested_actions:
            raise GovernanceError("toxic_authority_requested")
        if not proposal.owner or not proposal.sponsor:
            raise GovernanceError("accountability_missing")

    def get(self, agent_id: str = AGENT_ID) -> dict[str, Any]:
        row = self.db.execute(
            "SELECT * FROM agents WHERE agent_id=?", (agent_id,)
        ).fetchone()
        if row is None:
            raise GovernanceError("identity_unknown")
        value = dict(row)
        value["proposal"] = json.loads(value.pop("proposal_json"))
        value["credential_active"] = bool(value["credential_active"])
        return value

    def activate(
        self,
        agent_id: str,
        receipts: list[str],
        authority: ApprovalAuthority,
        *,
        expected_version: int = 1,
        actor: str = "service:identity-controller",
        command_id: str = "activate:1",
        now: int = NOW,
    ) -> dict[str, Any]:
        request_digest = digest(
            {
                "operation": "activate",
                "agent_id": agent_id,
                "receipts": receipts,
                "expected_version": expected_version,
                "actor": actor,
            }
        )
        with self.lock:
            cached = self._cached(command_id, request_digest)
            if cached is not None:
                return cached
            try:
                self.db.execute("BEGIN IMMEDIATE")
                record = self.get(agent_id)
                if record["state"] != "pending_approval":
                    raise GovernanceError("state_not_approvable")
                if record["version"] != expected_version:
                    raise GovernanceError("stale_version")
                proposal = AgentProposal(
                    **{
                        **record["proposal"],
                        "requested_actions": tuple(
                            record["proposal"]["requested_actions"]
                        ),
                        "resource_prefixes": tuple(
                            record["proposal"]["resource_prefixes"]
                        ),
                    }
                )
                claims = [
                    authority.verify(token, proposal, now=now) for token in receipts
                ]
                subjects = {claim["sub"] for claim in claims}
                roles = {claim["role"] for claim in claims}
                if proposal.requester in subjects:
                    raise GovernanceError("segregation_of_duties_failed")
                if len(subjects) != len(claims):
                    raise GovernanceError("distinct_approvers_required")
                if not required_roles(proposal.risk_tier).issubset(roles):
                    raise GovernanceError("approvals_incomplete")
                for claim in claims:
                    try:
                        self.db.execute(
                            "INSERT INTO consumed_receipts VALUES (?,?)",
                            (claim["jti"], now),
                        )
                    except sqlite3.IntegrityError as exc:
                        raise GovernanceError("approval_replayed") from exc
                due = now + proposal.review_interval_days * 86_400
                self.db.execute(
                    "UPDATE agents SET state='active',version=2,review_due=?,credential_active=1 WHERE agent_id=?",
                    (due, agent_id),
                )
                self._event(
                    agent_id,
                    "approvals_verified",
                    actor,
                    now,
                    {"approvers": sorted(subjects), "roles": sorted(roles)},
                )
                self._event(
                    agent_id,
                    "identity_provisioned",
                    actor,
                    now,
                    {
                        "workload_id": proposal.workload_id,
                        "credential_ttl_seconds": proposal.credential_ttl_seconds,
                    },
                )
                self._event(
                    agent_id, "identity_activated", actor, now, {"review_due": due}
                )
                result = {
                    "agent_id": agent_id,
                    "state": "active",
                    "version": 2,
                    "review_due": due,
                }
                self._cache(command_id, request_digest, result)
                self.db.execute("COMMIT")
                return result
            except Exception:
                self.db.execute("ROLLBACK")
                raise

    def transition(
        self,
        target: str,
        *,
        agent_id: str = AGENT_ID,
        expected_version: int,
        actor: str,
        reason: str,
        command_id: str,
        now: int = NOW + 120,
    ) -> dict[str, Any]:
        allowed = {
            "active": {"suspended", "quarantined", "retired"},
            # Recovery creates a newly reviewed identity version; this generic
            # transition API cannot silently restore runtime authority.
            "suspended": {"quarantined", "retired"},
            "quarantined": {"suspended", "retired"},
            "retired": set(),
        }
        request_digest = digest(
            {
                "operation": "transition",
                "agent_id": agent_id,
                "target": target,
                "expected_version": expected_version,
                "actor": actor,
                "reason": reason,
            }
        )
        with self.lock:
            cached = self._cached(command_id, request_digest)
            if cached is not None:
                return cached
            try:
                self.db.execute("BEGIN IMMEDIATE")
                record = self.get(agent_id)
                if record["version"] != expected_version:
                    raise GovernanceError("stale_version")
                if target not in allowed.get(record["state"], set()):
                    raise GovernanceError("transition_invalid")
                version = record["version"] + 1
                credential = 1 if target == "active" else 0
                self.db.execute(
                    "UPDATE agents SET state=?,version=?,credential_active=? WHERE agent_id=?",
                    (target, version, credential, agent_id),
                )
                self._event(
                    agent_id, f"identity_{target}", actor, now, {"reason": reason}
                )
                result = {"agent_id": agent_id, "state": target, "version": version}
                self._cache(command_id, request_digest, result)
                self.db.execute("COMMIT")
                return result
            except Exception:
                self.db.execute("ROLLBACK")
                raise

    def handle_signal(
        self, signal: str, *, expected_version: int = 2
    ) -> dict[str, Any]:
        mapping = {
            "owner_departed": ("suspended", "ownership_lost"),
            "credential_compromised": ("quarantined", "credential_compromised"),
            "new_write_tool": ("suspended", "material_change_review_required"),
            "monitoring_disabled": ("quarantined", "monitoring_control_failed"),
        }
        if signal not in mapping:
            raise GovernanceError("signal_unknown")
        target, reason = mapping[signal]
        return self.transition(
            target,
            expected_version=expected_version,
            actor="service:signal-controller",
            reason=reason,
            command_id=f"signal:{signal}:{expected_version}",
        )

    def recertify(
        self,
        receipts: list[str],
        authority: ApprovalAuthority,
        *,
        expected_version: int,
        now: int,
        command_id: str = "recertify:1",
    ) -> dict[str, Any]:
        request_digest = digest(
            {
                "operation": "recertify",
                "agent_id": AGENT_ID,
                "receipts": receipts,
                "expected_version": expected_version,
            }
        )
        with self.lock:
            cached = self._cached(command_id, request_digest)
            if cached is not None:
                return cached
            record = self.get()
            proposal = AgentProposal(
                **{
                    **record["proposal"],
                    "requested_actions": tuple(record["proposal"]["requested_actions"]),
                    "resource_prefixes": tuple(record["proposal"]["resource_prefixes"]),
                }
            )
            claims = [authority.verify(token, proposal, now=now) for token in receipts]
            subjects = {claim["sub"] for claim in claims}
            roles = {claim["role"] for claim in claims}
            if record["version"] != expected_version:
                raise GovernanceError("stale_version")
            if record["state"] != "active":
                raise GovernanceError("state_not_recertifiable")
            if proposal.requester in subjects:
                raise GovernanceError("segregation_of_duties_failed")
            if len(subjects) != len(claims):
                raise GovernanceError("distinct_approvers_required")
            if not required_roles(proposal.risk_tier).issubset(roles):
                raise GovernanceError("approvals_incomplete")
            due = now + proposal.review_interval_days * 86_400
            version = expected_version + 1
            self.db.execute("BEGIN IMMEDIATE")
            try:
                for claim in claims:
                    try:
                        self.db.execute(
                            "INSERT INTO consumed_receipts VALUES (?,?)",
                            (claim["jti"], now),
                        )
                    except sqlite3.IntegrityError as exc:
                        raise GovernanceError("approval_replayed") from exc
                self.db.execute(
                    "UPDATE agents SET version=?,review_due=? WHERE agent_id=?",
                    (version, due, AGENT_ID),
                )
                self._event(
                    AGENT_ID,
                    "access_recertified",
                    "service:review-controller",
                    now,
                    {"review_due": due},
                )
                result = {
                    "agent_id": AGENT_ID,
                    "state": record["state"],
                    "version": version,
                    "review_due": due,
                }
                self._cache(command_id, request_digest, result)
                self.db.execute("COMMIT")
                return result
            except Exception:
                self.db.execute("ROLLBACK")
                raise

    def authorize(
        self, context: RequestContext, *, agent_id: str = AGENT_ID
    ) -> Decision:
        record = self.get(agent_id)
        proposal = record["proposal"]
        checks = [
            (record["state"] == "active", "lifecycle_not_active"),
            (record["credential_active"], "credential_inactive"),
            (
                record["review_due"] is not None and context.now < record["review_due"],
                "review_overdue",
            ),
            (context.tenant_id == record["tenant_id"], "tenant_mismatch"),
            (context.workload_id == proposal["workload_id"], "workload_mismatch"),
            (context.action in proposal["requested_actions"], "action_not_approved"),
            (
                any(
                    context.resource.startswith(prefix)
                    for prefix in proposal["resource_prefixes"]
                ),
                "resource_not_approved",
            ),
            (context.purpose == proposal["purpose"], "purpose_mismatch"),
            (
                context.policy_version == proposal["policy_version"] == POLICY_VERSION,
                "policy_version_stale",
            ),
        ]
        for passed, reason in checks:
            if not passed:
                return Decision(False, reason, agent_id, record["version"])
        return Decision(True, "all_controls_satisfied", agent_id, record["version"])

    def baseline_authorize(
        self, context: RequestContext, *, agent_id: str = AGENT_ID
    ) -> Decision:
        record = self.get(agent_id)
        return Decision(
            record["state"] == "active",
            "state_only_baseline",
            agent_id,
            record["version"],
        )

    def events(self, agent_id: str = AGENT_ID) -> list[dict[str, Any]]:
        rows = self.db.execute(
            "SELECT * FROM events WHERE agent_id=? ORDER BY sequence", (agent_id,)
        ).fetchall()
        return [dict(row) for row in rows]

    def verify_event_chain(self, agent_id: str = AGENT_ID) -> bool:
        previous = "GENESIS"
        for row in self.events(agent_id):
            payload = json.loads(row["payload_json"])
            body = {
                "agent_id": row["agent_id"],
                "sequence": row["sequence"],
                "event_type": row["event_type"],
                "actor": row["actor"],
                "occurred_at": row["occurred_at"],
                "payload": payload,
                "previous_hash": row["previous_hash"],
            }
            if row["previous_hash"] != previous or row["event_hash"] != digest(body):
                return False
            previous = row["event_hash"]
        return True

    def metrics(self, *, now: int = NOW + 60) -> dict[str, int]:
        rows = self.db.execute("SELECT * FROM agents").fetchall()
        return {
            "total": len(rows),
            "active": sum(row["state"] == "active" for row in rows),
            "non_active": sum(row["state"] != "active" for row in rows),
            "overdue_reviews": sum(
                row["review_due"] is not None and row["review_due"] <= now
                for row in rows
            ),
            "active_without_credentials": sum(
                row["state"] == "active" and not row["credential_active"]
                for row in rows
            ),
        }


def approvals(
    authority: ApprovalAuthority, proposal: AgentProposal, *, now: int = NOW
) -> list[str]:
    return [
        authority.issue("user:owner-approver", proposal, now=now, jti=f"owner:{now}"),
        authority.issue(
            "user:security-approver", proposal, now=now, jti=f"security:{now}"
        ),
    ]


def active_scenario(
    proposal: AgentProposal | None = None,
) -> tuple[GovernanceStore, ApprovalAuthority, AgentProposal]:
    proposal = proposal or AgentProposal()
    store, authority = GovernanceStore(), ApprovalAuthority()
    store.register(proposal)
    store.activate(proposal.agent_id, approvals(authority, proposal), authority)
    return store, authority, proposal


def _decision_case(
    case_id: str, expected: bool, description: str, **changes: Any
) -> Case:
    def run(baseline: bool = False) -> bool:
        store, _, _ = active_scenario()
        context = replace(RequestContext(), **changes)
        method = store.baseline_authorize if baseline else store.authorize
        return method(context).allowed

    return Case(case_id, expected, description, run)


def cases() -> list[Case]:
    values = [
        _decision_case("valid-read", True, "Exact approved read request"),
        _decision_case(
            "valid-note", True, "Approved note creation", action="claim.note.create"
        ),
        _decision_case(
            "wrong-tenant", False, "Cross-tenant request", tenant_id="tenant:attacker"
        ),
        _decision_case(
            "wrong-workload",
            False,
            "Unbound workload",
            workload_id="spiffe://northstar.example/prod/unknown",
        ),
        _decision_case(
            "unapproved-action",
            False,
            "Payout approval was never granted",
            action="payment.approve",
        ),
        _decision_case(
            "unapproved-resource",
            False,
            "Resource falls outside claim prefix",
            resource="/customers/483",
        ),
        _decision_case(
            "purpose-drift",
            False,
            "Runtime purpose differs from approval",
            purpose="Train a marketing model",
        ),
        _decision_case(
            "stale-policy",
            False,
            "Runtime uses a stale policy",
            policy_version="governance-2025-01",
        ),
        _decision_case(
            "review-expired",
            False,
            "Recertification deadline elapsed",
            now=NOW + 31 * 86_400,
        ),
    ]

    for signal, case_id in [
        ("owner_departed", "owner-departure"),
        ("credential_compromised", "credential-compromise"),
        ("new_write_tool", "material-change"),
        ("monitoring_disabled", "monitoring-loss"),
    ]:

        def run(baseline: bool = False, signal: str = signal) -> bool:
            store, _, _ = active_scenario()
            store.handle_signal(signal)
            method = store.baseline_authorize if baseline else store.authorize
            return method(RequestContext()).allowed

        values.append(Case(case_id, False, f"Signal {signal} removes authority", run))

    def retired(baseline: bool = False) -> bool:
        store, _, _ = active_scenario()
        store.transition(
            "retired",
            expected_version=2,
            actor="user:owner-approver",
            reason="service ended",
            command_id="retire:case",
        )
        method = store.baseline_authorize if baseline else store.authorize
        return method(RequestContext()).allowed

    values.append(
        Case("retired-agent", False, "Retirement revokes runtime authority", retired)
    )

    def activation_case(
        case_id: str,
        description: str,
        attempt: Callable[[GovernanceStore, ApprovalAuthority, AgentProposal], None],
    ) -> None:
        def run(baseline: bool = False) -> bool:
            if baseline:
                return True  # the deliberately weak workflow trusts request presence
            store, authority, proposal = (
                GovernanceStore(),
                ApprovalAuthority(),
                AgentProposal(),
            )
            try:
                store.register(proposal)
                attempt(store, authority, proposal)
                return True
            except GovernanceError:
                return False

        values.append(Case(case_id, False, description, run))

    activation_case(
        "missing-security-approval",
        "High-risk activation has only the owner approval",
        lambda store, authority, proposal: store.activate(
            proposal.agent_id,
            [authority.issue("user:owner-approver", proposal)],
            authority,
        ),
    )
    activation_case(
        "expired-approval",
        "Approval receipt is outside its validity window",
        lambda store, authority, proposal: store.activate(
            proposal.agent_id,
            [
                authority.issue(
                    "user:owner-approver", proposal, now=NOW - 1_000, lifetime=60
                ),
                authority.issue(
                    "user:security-approver", proposal, now=NOW - 1_000, lifetime=60
                ),
            ],
            authority,
        ),
    )
    activation_case(
        "wrong-proposal-digest",
        "Approvals are bound to a different proposal",
        lambda store, authority, proposal: store.activate(
            proposal.agent_id,
            [
                authority.issue(
                    "user:owner-approver", proposal, digest_override="wrong"
                ),
                authority.issue(
                    "user:security-approver", proposal, digest_override="wrong"
                ),
            ],
            authority,
        ),
    )
    activation_case(
        "wrong-approval-tenant",
        "Approvals are bound to another tenant",
        lambda store, authority, proposal: store.activate(
            proposal.agent_id,
            [
                authority.issue(
                    "user:owner-approver", proposal, tenant_override="tenant:other"
                ),
                authority.issue(
                    "user:security-approver", proposal, tenant_override="tenant:other"
                ),
            ],
            authority,
        ),
    )
    activation_case(
        "wrong-approval-policy",
        "Approvals reference a superseded governance policy",
        lambda store, authority, proposal: store.activate(
            proposal.agent_id,
            [
                authority.issue("user:owner-approver", proposal, policy_override="old"),
                authority.issue(
                    "user:security-approver", proposal, policy_override="old"
                ),
            ],
            authority,
        ),
    )
    activation_case(
        "duplicate-approver",
        "One person cannot satisfy two approval slots",
        lambda store, authority, proposal: store.activate(
            proposal.agent_id,
            [
                authority.issue("user:owner-approver", proposal, jti="duplicate:1"),
                authority.issue("user:owner-approver", proposal, jti="duplicate:2"),
            ],
            authority,
        ),
    )
    activation_case(
        "stale-lifecycle-version",
        "A stale command cannot race the current record",
        lambda store, authority, proposal: store.activate(
            proposal.agent_id,
            approvals(authority, proposal),
            authority,
            expected_version=0,
        ),
    )

    def self_approval(baseline: bool = False) -> bool:
        if baseline:
            return True
        proposal = AgentProposal(requester="user:owner-approver")
        store, authority = GovernanceStore(), ApprovalAuthority()
        try:
            store.register(proposal)
            store.activate(proposal.agent_id, approvals(authority, proposal), authority)
            return True
        except GovernanceError:
            return False

    values.append(
        Case("self-approval", False, "Requester appears among approvers", self_approval)
    )

    def forbidden_registration(field: str, value: Any) -> Callable[[bool], bool]:
        def run(baseline: bool = False) -> bool:
            if baseline:
                return True
            store = GovernanceStore()
            try:
                store.register(replace(AgentProposal(), **{field: value}))
                return True
            except GovernanceError:
                return False

        return run

    values.extend(
        [
            Case(
                "static-production-secret",
                False,
                "Production credential is not short lived",
                forbidden_registration("short_lived_credentials", False),
            ),
            Case(
                "monitoring-not-enrolled",
                False,
                "Monitoring is mandatory before activation",
                forbidden_registration("monitoring_enabled", False),
            ),
            Case(
                "evaluation-gate-failed",
                False,
                "Required evaluations did not pass",
                forbidden_registration("evals_passed", False),
            ),
            Case(
                "toxic-payment-authority",
                False,
                "Claims investigator cannot approve payouts",
                forbidden_registration(
                    "requested_actions", ("claim.read", "payment.approve")
                ),
            ),
            Case(
                "foreign-trust-domain",
                False,
                "Workload binding is outside the governed trust domain",
                forbidden_registration(
                    "workload_id", "spiffe://attacker.example/agent"
                ),
            ),
        ]
    )
    return values


@dataclass(frozen=True)
class Evaluation:
    total: int
    correct: int
    invalid_allows: int
    valid_blocks: int


def evaluate(use_baseline: bool = False) -> tuple[Evaluation, list[dict[str, Any]]]:
    rows = []
    for case in cases():
        actual = case.run(use_baseline)
        rows.append(
            {
                "case_id": case.case_id,
                "description": case.description,
                "expected_allowed": case.expected,
                "actual_allowed": actual,
                "correct": actual is case.expected,
            }
        )
    return Evaluation(
        total=len(rows),
        correct=sum(row["correct"] for row in rows),
        invalid_allows=sum(
            not row["expected_allowed"] and row["actual_allowed"] for row in rows
        ),
        valid_blocks=sum(
            row["expected_allowed"] and not row["actual_allowed"] for row in rows
        ),
    ), rows


if __name__ == "__main__":
    secure, rows = evaluate()
    baseline, _ = evaluate(True)
    print(
        canonical({"hardened": asdict(secure), "state_only_baseline": asdict(baseline)})
    )
    if secure.correct != secure.total:
        raise SystemExit(1)
