"""Deterministic agent-identity lifecycle lab for Beginner 06.

The Northstar Travel scenario compares a state-field updater with a governed
lifecycle controller.  A caller may propose a lifecycle operation, but trusted
application code supplies administrator identity and roles, validates manifests,
enforces legal state transitions and separation of duties, binds provisioned
assets to attested workloads, checks review freshness, propagates revocation,
verifies retirement cleanup, and records a hash-chained public audit trail.

The default lab is credential-free and has no network, directory, token,
provisioning, or destructive side effects.  Credential records contain metadata
only; cleanup adapters simulate downstream systems deterministically.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from enum import Enum
import hashlib
import json
from threading import Lock, RLock
from typing import Any, Callable, Iterable, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError


NOW = datetime(2026, 9, 27, 16, 0, tzinfo=timezone.utc)
POLICY_VERSION = "agent-lifecycle/2026-09-27.1"
AGENT_ID = "agent:northstar:travel-booking"
TENANT_ID = "tenant:northstar"


class Outcome(str, Enum):
    APPLIED = "applied"
    DENIED = "denied"
    APPROVAL_REQUIRED = "approval_required"
    PARTIAL = "partial"


class LifecycleState(str, Enum):
    DRAFT = "draft"
    REGISTERED = "registered"
    UNDER_REVIEW = "under_review"
    APPROVED = "approved"
    PROVISIONED = "provisioned"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    REVOKED = "revoked"
    RETIRING = "retiring"
    RETIRED = "retired"
    REJECTED = "rejected"  # Reserved for the learner extension exercise.


class Action(str, Enum):
    REGISTER = "register"
    SUBMIT = "submit_for_review"
    APPROVE = "approve"
    PROVISION = "provision"
    ACTIVATE = "activate"
    RECERTIFY = "recertify"
    TRANSFER_SPONSOR = "transfer_sponsor"
    MATERIAL_CHANGE = "material_change"
    SUSPEND = "suspend"
    REACTIVATE = "reactivate"
    REVOKE = "revoke"
    RETIRE = "retire"


class Role(str, Enum):
    OWNER = "owner"
    SPONSOR = "sponsor"
    IAM_ADMIN = "iam_admin"
    RISK_APPROVER = "risk_approver"
    PROVISIONER = "provisioner"
    PLATFORM = "platform"
    SECURITY = "security"


class RiskTier(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ReviewVerdict(str, Enum):
    CONTINUE = "continue"
    MODIFY = "modify"
    REVOKE = "revoke"


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class AgentManifest(StrictModel):
    display_name: str = Field(min_length=3, max_length=100)
    purpose: str = Field(min_length=20, max_length=300)
    sponsor_id: str = Field(pattern=r"^user:[a-z0-9-]+$")
    technical_owner_id: str = Field(pattern=r"^(user|team):[a-z0-9-]+$")
    environment: Literal["development", "staging", "production"]
    risk_tier: RiskTier
    autonomy: Literal["assistive", "bounded", "high"]
    data_classes: tuple[str, ...] = Field(min_length=1)
    requested_capabilities: tuple[str, ...] = Field(min_length=1)
    blueprint_id: str = Field(pattern=r"^blueprint:[a-z0-9-]+$")
    blueprint_version: str = Field(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")


class EmptyPayload(StrictModel):
    pass


class ApprovalPayload(StrictModel):
    manifest_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")


class ProvisionPayload(StrictModel):
    workload_id: str = Field(pattern=r"^spiffe://[a-z0-9.-]+/[a-z0-9/_-]+$")
    capabilities: tuple[str, ...] = Field(min_length=1)
    credential_profiles: tuple[str, ...] = Field(min_length=1)


class RecertifyPayload(StrictModel):
    verdict: ReviewVerdict
    justification: str = Field(min_length=12, max_length=300)


class SponsorTransferPayload(StrictModel):
    expected_old_sponsor_id: str
    new_sponsor_id: str


class MaterialChangePayload(StrictModel):
    manifest: AgentManifest
    reason: str = Field(min_length=12, max_length=300)


class ReasonPayload(StrictModel):
    reason: str = Field(min_length=12, max_length=300)


class ReactivatePayload(StrictModel):
    incident_id: str = Field(pattern=r"^incident:[a-z0-9-]+$")
    credential_generation: int = Field(gt=0)


PAYLOAD_MODELS: dict[Action, type[StrictModel]] = {
    Action.REGISTER: EmptyPayload,
    Action.SUBMIT: EmptyPayload,
    Action.APPROVE: ApprovalPayload,
    Action.PROVISION: ProvisionPayload,
    Action.ACTIVATE: EmptyPayload,
    Action.RECERTIFY: RecertifyPayload,
    Action.TRANSFER_SPONSOR: SponsorTransferPayload,
    Action.MATERIAL_CHANGE: MaterialChangePayload,
    Action.SUSPEND: ReasonPayload,
    Action.REACTIVATE: ReactivatePayload,
    Action.REVOKE: ReasonPayload,
    Action.RETIRE: ReasonPayload,
}


@dataclass(frozen=True)
class VerifiedAdminContext:
    """Trusted identity context created by authentication middleware."""

    actor_id: str
    tenant_id: str
    roles: frozenset[Role]


@dataclass(frozen=True)
class LifecycleRequest:
    """Untrusted lifecycle operation proposed by a UI, workflow, or agent."""

    operation_id: str
    agent_id: str
    action: Action
    expected_version: int
    payload: dict[str, Any]


@dataclass(frozen=True)
class DirectoryIdentity:
    identity_id: str
    tenant_id: str
    active: bool
    manager_id: str | None = None
    roles: frozenset[Role] = frozenset()


@dataclass(frozen=True)
class AgentBlueprint:
    blueprint_id: str
    version: str
    tenant_id: str
    active: bool
    allowed_capabilities: frozenset[str]
    allowed_credential_profiles: frozenset[str]
    workload_trust_domain: str


@dataclass(frozen=True)
class WorkloadAttestation:
    workload_id: str
    agent_id: str
    tenant_id: str
    environment: str
    active: bool
    evidence_id: str


@dataclass(frozen=True)
class WorkloadBinding:
    workload_id: str
    evidence_id: str
    status: Literal["active", "suspended", "revoked", "removed"]


@dataclass(frozen=True)
class AccessGrant:
    grant_id: str
    capability: str
    expires_at: datetime
    status: Literal["active", "suspended", "revoked", "removed"]


@dataclass(frozen=True)
class CredentialProfile:
    """Credential configuration metadata; never a token or private key."""

    profile_id: str
    audience: str
    generation: int
    status: Literal["configured", "active", "suspended", "revoked", "removed"]


@dataclass(frozen=True)
class RuntimeSession:
    session_id: str
    status: Literal["active", "revoked", "removed"]


@dataclass(frozen=True)
class ReviewRecord:
    review_id: str
    reviewer_id: str
    verdict: ReviewVerdict
    reviewed_at: datetime
    next_review_at: datetime | None
    manifest_digest: str


@dataclass(frozen=True)
class LifecycleApproval:
    approval_id: str
    approver_id: str
    approver_role: Role
    tenant_id: str
    agent_id: str
    action: Action
    operation_id: str
    request_digest: str
    policy_version: str
    issued_at: datetime
    expires_at: datetime


@dataclass(frozen=True)
class LifecycleEvent:
    event_id: str
    sequence: int
    timestamp: datetime
    tenant_id: str
    agent_id: str
    actor_id: str
    action: str
    outcome: str
    reason_code: str
    operation_id: str
    request_digest: str
    policy_version: str
    record_version: int | None
    previous_hash: str
    event_hash: str


@dataclass(frozen=True)
class AgentRecord:
    agent_id: str
    tenant_id: str
    manifest: AgentManifest
    manifest_digest: str
    state: LifecycleState = LifecycleState.DRAFT
    version: int = 0
    workload_bindings: tuple[WorkloadBinding, ...] = ()
    access_grants: tuple[AccessGrant, ...] = ()
    credential_profiles: tuple[CredentialProfile, ...] = ()
    sessions: tuple[RuntimeSession, ...] = ()
    reviews: tuple[ReviewRecord, ...] = ()
    next_review_at: datetime | None = None
    cleanup_receipts: tuple[str, ...] = ()
    created_at: datetime = NOW
    updated_at: datetime = NOW


@dataclass(frozen=True)
class LifecycleDecision:
    outcome: Outcome
    reason_code: str
    decision_id: str
    operation_id: str
    agent_id: str
    action: Action
    actor_id: str
    request_digest: str
    policy_version: str
    state_before: LifecycleState | None
    state_after: LifecycleState | None
    record_version: int | None
    audit_event_id: str
    audit_hash: str
    obligations: tuple[str, ...] = ()
    reconciled: bool = False

    @property
    def evidence_complete(self) -> bool:
        return bool(
            self.decision_id
            and self.actor_id
            and self.request_digest.startswith("sha256:")
            and self.policy_version
            and self.audit_event_id
            and self.audit_hash.startswith("sha256:")
        )


@dataclass(frozen=True)
class LifecycleResult:
    decision: LifecycleDecision
    effect_committed: bool
    cleanup_verified: bool = False


@dataclass(frozen=True)
class EvaluationMetrics:
    attempts: int
    expected_applied: int
    expected_blocked: int
    expected_partial: int
    outcome_matches: int
    valid_applied: int
    forbidden_effects: int
    partial_detected: int
    duplicate_effects: int
    complete_evidence: int

    @property
    def outcome_match_rate(self) -> float:
        return self.outcome_matches / self.attempts

    @property
    def valid_apply_rate(self) -> float:
        return self.valid_applied / self.expected_applied

    @property
    def forbidden_effect_rate(self) -> float:
        return self.forbidden_effects / self.expected_blocked

    @property
    def partial_detection_rate(self) -> float:
        return self.partial_detected / self.expected_partial

    @property
    def duplicate_effect_rate(self) -> float:
        return self.duplicate_effects / self.attempts

    @property
    def evidence_completeness_rate(self) -> float:
        return self.complete_evidence / self.attempts


def _jsonable(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in sorted(value.items())}
    if isinstance(value, (tuple, list, set, frozenset)):
        return [_jsonable(item) for item in value]
    return value


def digest(value: Any) -> str:
    rendered = json.dumps(_jsonable(value), sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(rendered.encode()).hexdigest()


def stable_id(prefix: str, *parts: Any) -> str:
    suffix = digest(parts).split(":", 1)[1][:16]
    return f"{prefix}:{suffix}"


def manifest_digest(manifest: AgentManifest) -> str:
    return digest(manifest)


def request_digest(request: LifecycleRequest) -> str:
    return digest(
        {
            "operation_id": request.operation_id,
            "agent_id": request.agent_id,
            "action": request.action,
            "expected_version": request.expected_version,
            "payload": request.payload,
        }
    )


class AuditLog:
    """Append-only view with a hash chain suitable for public decision evidence."""

    def __init__(self) -> None:
        self._events: tuple[LifecycleEvent, ...] = ()

    @property
    def events(self) -> tuple[LifecycleEvent, ...]:
        return self._events

    def append(
        self,
        *,
        context: VerifiedAdminContext,
        request: LifecycleRequest,
        outcome: Outcome,
        reason_code: str,
        record_version: int | None,
    ) -> LifecycleEvent:
        sequence = len(self._events) + 1
        previous_hash = self._events[-1].event_hash if self._events else "GENESIS"
        body = {
            "sequence": sequence,
            "timestamp": NOW,
            "tenant_id": context.tenant_id,
            "agent_id": request.agent_id,
            "actor_id": context.actor_id,
            "action": request.action,
            "outcome": outcome,
            "reason_code": reason_code,
            "operation_id": request.operation_id,
            "request_digest": request_digest(request),
            "policy_version": POLICY_VERSION,
            "record_version": record_version,
            "previous_hash": previous_hash,
        }
        event_hash = digest(body)
        event = LifecycleEvent(
            event_id=stable_id("event", sequence, event_hash),
            sequence=sequence,
            timestamp=NOW,
            tenant_id=context.tenant_id,
            agent_id=request.agent_id,
            actor_id=context.actor_id,
            action=request.action.value,
            outcome=outcome.value,
            reason_code=reason_code,
            operation_id=request.operation_id,
            request_digest=request_digest(request),
            policy_version=POLICY_VERSION,
            record_version=record_version,
            previous_hash=previous_hash,
            event_hash=event_hash,
        )
        self._events = (*self._events, event)
        return event

    def verify(self) -> bool:
        previous = "GENESIS"
        for event in self._events:
            body = {
                "sequence": event.sequence,
                "timestamp": event.timestamp,
                "tenant_id": event.tenant_id,
                "agent_id": event.agent_id,
                "actor_id": event.actor_id,
                "action": Action(event.action),
                "outcome": Outcome(event.outcome),
                "reason_code": event.reason_code,
                "operation_id": event.operation_id,
                "request_digest": event.request_digest,
                "policy_version": event.policy_version,
                "record_version": event.record_version,
                "previous_hash": previous,
            }
            if event.previous_hash != previous or event.event_hash != digest(body):
                return False
            previous = event.event_hash
        return True


class ApprovalStore:
    def __init__(self) -> None:
        self._consumed: set[str] = set()
        self._lock = Lock()

    def consume(self, approval_id: str) -> bool:
        with self._lock:
            if approval_id in self._consumed:
                return False
            self._consumed.add(approval_id)
            return True

    def was_consumed(self, approval_id: str) -> bool:
        return approval_id in self._consumed


class CleanupAdapter:
    """Idempotent local simulator for downstream deprovisioning."""

    def __init__(self, fail_once_on: str | None = None) -> None:
        self.fail_once_on = fail_once_on
        self.failed = False
        self.completed: set[str] = set()
        self.effect_count = 0

    def remove(self, resource_id: str) -> bool:
        if resource_id in self.completed:
            return True
        if resource_id == self.fail_once_on and not self.failed:
            self.failed = True
            return False
        self.completed.add(resource_id)
        self.effect_count += 1
        return True


REVIEW_DAYS = {
    RiskTier.LOW: 365,
    RiskTier.MEDIUM: 180,
    RiskTier.HIGH: 90,
    RiskTier.CRITICAL: 30,
}


ROLE_FOR_ACTION: dict[Action, frozenset[Role]] = {
    Action.REGISTER: frozenset({Role.OWNER, Role.IAM_ADMIN}),
    Action.SUBMIT: frozenset({Role.OWNER, Role.IAM_ADMIN}),
    Action.APPROVE: frozenset({Role.IAM_ADMIN}),
    Action.PROVISION: frozenset({Role.PROVISIONER}),
    Action.ACTIVATE: frozenset({Role.PLATFORM}),
    Action.RECERTIFY: frozenset({Role.SPONSOR}),
    Action.TRANSFER_SPONSOR: frozenset({Role.IAM_ADMIN}),
    Action.MATERIAL_CHANGE: frozenset({Role.OWNER}),
    Action.SUSPEND: frozenset({Role.SECURITY}),
    Action.REACTIVATE: frozenset({Role.SECURITY}),
    Action.REVOKE: frozenset({Role.SECURITY}),
    Action.RETIRE: frozenset({Role.SPONSOR, Role.IAM_ADMIN}),
}


ALLOWED_STATES: dict[Action, frozenset[LifecycleState]] = {
    Action.REGISTER: frozenset({LifecycleState.DRAFT}),
    Action.SUBMIT: frozenset({LifecycleState.REGISTERED}),
    Action.APPROVE: frozenset({LifecycleState.UNDER_REVIEW}),
    Action.PROVISION: frozenset({LifecycleState.APPROVED}),
    Action.ACTIVATE: frozenset({LifecycleState.PROVISIONED}),
    Action.RECERTIFY: frozenset({LifecycleState.ACTIVE}),
    Action.TRANSFER_SPONSOR: frozenset(
        {LifecycleState.ACTIVE, LifecycleState.SUSPENDED, LifecycleState.APPROVED}
    ),
    Action.MATERIAL_CHANGE: frozenset({LifecycleState.ACTIVE}),
    Action.SUSPEND: frozenset({LifecycleState.ACTIVE}),
    Action.REACTIVATE: frozenset({LifecycleState.SUSPENDED}),
    Action.REVOKE: frozenset({LifecycleState.ACTIVE, LifecycleState.SUSPENDED}),
    Action.RETIRE: frozenset({LifecycleState.REVOKED, LifecycleState.RETIRING}),
}


def default_manifest() -> AgentManifest:
    return AgentManifest(
        display_name="Northstar Travel Booking Agent",
        purpose="Book policy-compliant employee travel within approved limits.",
        sponsor_id="user:alice",
        technical_owner_id="team:travel-platform",
        environment="production",
        risk_tier=RiskTier.HIGH,
        autonomy="bounded",
        data_classes=("employee-confidential", "travel-financial"),
        requested_capabilities=("flight.search", "flight.book_limited"),
        blueprint_id="blueprint:travel-agent",
        blueprint_version="2.1.0",
    )


def build_control_plane_data() -> tuple[
    dict[str, DirectoryIdentity],
    dict[str, AgentBlueprint],
    dict[str, WorkloadAttestation],
]:
    directory = {
        "user:alice": DirectoryIdentity(
            "user:alice", TENANT_ID, True, "user:director-travel", frozenset({Role.SPONSOR})
        ),
        "user:director-travel": DirectoryIdentity(
            "user:director-travel", TENANT_ID, True, "user:vp-operations", frozenset({Role.SPONSOR})
        ),
        "user:bob": DirectoryIdentity(
            "user:bob", TENANT_ID, True, "user:director-travel", frozenset({Role.SPONSOR})
        ),
        "team:travel-platform": DirectoryIdentity(
            "team:travel-platform", TENANT_ID, True, roles=frozenset({Role.OWNER})
        ),
        "user:owner": DirectoryIdentity("user:owner", TENANT_ID, True, roles=frozenset({Role.OWNER})),
        "user:iam": DirectoryIdentity("user:iam", TENANT_ID, True, roles=frozenset({Role.IAM_ADMIN})),
        "user:risk": DirectoryIdentity("user:risk", TENANT_ID, True, roles=frozenset({Role.RISK_APPROVER, Role.IAM_ADMIN})),
        "user:provisioner": DirectoryIdentity("user:provisioner", TENANT_ID, True, roles=frozenset({Role.PROVISIONER})),
        "workload:platform": DirectoryIdentity("workload:platform", TENANT_ID, True, roles=frozenset({Role.PLATFORM})),
        "service:soc": DirectoryIdentity("service:soc", TENANT_ID, True, roles=frozenset({Role.SECURITY})),
        "user:outsider": DirectoryIdentity("user:outsider", "tenant:other", True, roles=frozenset({Role.IAM_ADMIN})),
    }
    blueprints = {
        "blueprint:travel-agent": AgentBlueprint(
            blueprint_id="blueprint:travel-agent",
            version="2.1.0",
            tenant_id=TENANT_ID,
            active=True,
            allowed_capabilities=frozenset(
                {"flight.search", "flight.book_limited", "itinerary.send_internal"}
            ),
            allowed_credential_profiles=frozenset(
                {"travel-search", "travel-book-limited", "mail-internal"}
            ),
            workload_trust_domain="corp.example",
        )
    }
    workload_id = "spiffe://corp.example/prod/travel-booking"
    attestations = {
        workload_id: WorkloadAttestation(
            workload_id=workload_id,
            agent_id=AGENT_ID,
            tenant_id=TENANT_ID,
            environment="production",
            active=True,
            evidence_id="attestation:travel-prod-20260927",
        )
    }
    return directory, blueprints, attestations


def build_record(
    state: LifecycleState = LifecycleState.DRAFT,
    *,
    manifest: AgentManifest | None = None,
    overdue_review: bool = False,
) -> AgentRecord:
    manifest = manifest or default_manifest()
    record = AgentRecord(
        agent_id=AGENT_ID,
        tenant_id=TENANT_ID,
        manifest=manifest,
        manifest_digest=manifest_digest(manifest),
        state=state,
    )
    reviewed_states = {
        LifecycleState.APPROVED,
        LifecycleState.PROVISIONED,
        LifecycleState.ACTIVE,
        LifecycleState.SUSPENDED,
        LifecycleState.REVOKED,
        LifecycleState.RETIRING,
        LifecycleState.RETIRED,
    }
    provisioned_states = {
        LifecycleState.PROVISIONED,
        LifecycleState.ACTIVE,
        LifecycleState.SUSPENDED,
        LifecycleState.REVOKED,
        LifecycleState.RETIRING,
        LifecycleState.RETIRED,
    }
    runtime_states = {
        LifecycleState.ACTIVE,
        LifecycleState.SUSPENDED,
        LifecycleState.REVOKED,
        LifecycleState.RETIRING,
        LifecycleState.RETIRED,
    }
    if state in reviewed_states:
        next_review = NOW - timedelta(days=1) if overdue_review else NOW + timedelta(days=90)
        review = ReviewRecord(
            review_id="review:initial",
            reviewer_id="user:risk",
            verdict=ReviewVerdict.CONTINUE,
            reviewed_at=NOW - timedelta(days=1),
            next_review_at=next_review,
            manifest_digest=record.manifest_digest,
        )
        record = replace(record, reviews=(review,), next_review_at=next_review)
    if state in provisioned_states:
        final_status: Literal["active", "suspended", "revoked", "removed"] = "active"
        credential_status: Literal[
            "configured", "active", "suspended", "revoked", "removed"
        ] = "configured" if state is LifecycleState.PROVISIONED else "active"
        if state is LifecycleState.SUSPENDED:
            final_status, credential_status = "suspended", "suspended"
        elif state in {LifecycleState.REVOKED, LifecycleState.RETIRING}:
            final_status, credential_status = "revoked", "revoked"
        elif state is LifecycleState.RETIRED:
            final_status, credential_status = "removed", "removed"
        binding = WorkloadBinding(
            "spiffe://corp.example/prod/travel-booking",
            "attestation:travel-prod-20260927",
            final_status,
        )
        grants = tuple(
            AccessGrant(
                stable_id("grant", capability),
                capability,
                NOW + timedelta(days=30),
                final_status,
            )
            for capability in manifest.requested_capabilities
        )
        credentials = (
            CredentialProfile(
                "travel-search",
                "https://travel.api.corp.example",
                1,
                credential_status,
            ),
            CredentialProfile(
                "travel-book-limited",
                "https://booking.api.corp.example",
                1,
                credential_status,
            ),
        )
        record = replace(
            record,
            workload_bindings=(binding,),
            access_grants=grants,
            credential_profiles=credentials,
        )
    if state in runtime_states:
        session_status: Literal["active", "revoked", "removed"] = "active"
        if state in {LifecycleState.SUSPENDED, LifecycleState.REVOKED, LifecycleState.RETIRING}:
            session_status = "revoked"
        elif state is LifecycleState.RETIRED:
            session_status = "removed"
        record = replace(
            record,
            sessions=(RuntimeSession("session:travel-prod", session_status),),
        )
    if state is LifecycleState.RETIRED:
        record = replace(
            record,
            cleanup_receipts=(
                "cleanup:workload",
                "cleanup:grants",
                "cleanup:credentials",
                "cleanup:sessions",
            ),
        )
    return record


def context(actor_id: str, *roles: Role, tenant_id: str = TENANT_ID) -> VerifiedAdminContext:
    return VerifiedAdminContext(actor_id, tenant_id, frozenset(roles))


class LifecycleController:
    def __init__(self) -> None:
        self.directory, self.blueprints, self.attestations = build_control_plane_data()
        self.records: dict[str, AgentRecord] = {}
        self.audit = AuditLog()
        self.approvals = ApprovalStore()
        self._operations: dict[str, tuple[str, LifecycleResult]] = {}
        self._request_state_before: dict[str, LifecycleState] = {}
        self._lock = RLock()

    def seed(self, record: AgentRecord) -> None:
        self.records[record.agent_id] = record

    def get(self, agent_id: str = AGENT_ID) -> AgentRecord:
        return self.records[agent_id]

    def execute(
        self,
        context: VerifiedAdminContext,
        request: LifecycleRequest,
        *,
        approval: LifecycleApproval | None = None,
        cleanup: CleanupAdapter | None = None,
    ) -> LifecycleResult:
        with self._lock:
            req_digest = request_digest(request)
            prior = self._operations.get(request.operation_id)
            resuming_cleanup = bool(
                prior
                and prior[0] == req_digest
                and prior[1].decision.outcome is Outcome.PARTIAL
                and request.action is Action.RETIRE
            )
            if prior and prior[0] != req_digest:
                return self._finish(
                    context, request, Outcome.DENIED, "idempotency_conflict", False,
                    store=False,
                )
            if prior and not resuming_cleanup:
                original = prior[1]
                return replace(
                    original,
                    decision=replace(
                        original.decision,
                        reason_code="operation_reconciled",
                        reconciled=True,
                    ),
                    effect_committed=False,
                )

            record = self.records.get(request.agent_id)
            if record is None:
                return self._finish(
                    context, request, Outcome.DENIED, "agent_not_found", False
                )
            self._request_state_before.setdefault(request.operation_id, record.state)
            if context.tenant_id != record.tenant_id:
                return self._finish(
                    context, request, Outcome.DENIED, "tenant_mismatch", False
                )
            identity = self.directory.get(context.actor_id)
            if not identity or not identity.active or identity.tenant_id != context.tenant_id:
                return self._finish(
                    context, request, Outcome.DENIED, "actor_not_active", False
                )
            if not context.roles.issubset(identity.roles):
                return self._finish(
                    context, request, Outcome.DENIED, "actor_roles_not_verified", False
                )
            if not ROLE_FOR_ACTION[request.action].intersection(context.roles):
                return self._finish(
                    context, request, Outcome.DENIED, "role_not_authorized", False
                )
            if not resuming_cleanup and request.expected_version != record.version:
                return self._finish(
                    context, request, Outcome.DENIED, "stale_record_version", False
                )
            if record.state not in ALLOWED_STATES[request.action]:
                return self._finish(
                    context, request, Outcome.DENIED, "illegal_state_transition", False
                )
            try:
                payload = PAYLOAD_MODELS[request.action].model_validate(request.payload)
            except ValidationError:
                return self._finish(
                    context, request, Outcome.DENIED, "payload_invalid", False
                )

            handler = getattr(self, f"_handle_{request.action.value}")
            return handler(context, request, record, payload, approval, cleanup)

    def _finish(
        self,
        context: VerifiedAdminContext,
        request: LifecycleRequest,
        outcome: Outcome,
        reason_code: str,
        effect_committed: bool,
        *,
        obligations: tuple[str, ...] = (),
        cleanup_verified: bool = False,
        store: bool = True,
    ) -> LifecycleResult:
        record = self.records.get(request.agent_id)
        state_after = record.state if record else None
        record_version = record.version if record else None
        state_before = self._request_state_before.get(request.operation_id, state_after)
        prior = self._operations.get(request.operation_id)
        if prior and prior[1].decision.state_before is not None:
            state_before = prior[1].decision.state_before
        event = self.audit.append(
            context=context,
            request=request,
            outcome=outcome,
            reason_code=reason_code,
            record_version=record_version,
        )
        decision = LifecycleDecision(
            outcome=outcome,
            reason_code=reason_code,
            decision_id=stable_id("decision", request.operation_id, event.event_id),
            operation_id=request.operation_id,
            agent_id=request.agent_id,
            action=request.action,
            actor_id=context.actor_id,
            request_digest=request_digest(request),
            policy_version=POLICY_VERSION,
            state_before=state_before,
            state_after=state_after,
            record_version=record_version,
            audit_event_id=event.event_id,
            audit_hash=event.event_hash,
            obligations=obligations,
        )
        result = LifecycleResult(decision, effect_committed, cleanup_verified)
        if store:
            self._operations[request.operation_id] = (request_digest(request), result)
        return result

    def _update(self, record: AgentRecord, **changes: Any) -> AgentRecord:
        updated = replace(record, version=record.version + 1, updated_at=NOW, **changes)
        self.records[record.agent_id] = updated
        return updated

    def _approval_error(
        self,
        context: VerifiedAdminContext,
        request: LifecycleRequest,
        record: AgentRecord,
        approval: LifecycleApproval | None,
    ) -> tuple[Outcome, str] | None:
        if approval is None:
            return Outcome.APPROVAL_REQUIRED, "approval_required"
        approver = self.directory.get(approval.approver_id)
        expected = {
            "tenant_id": record.tenant_id,
            "agent_id": record.agent_id,
            "action": request.action,
            "operation_id": request.operation_id,
            "request_digest": request_digest(request),
            "policy_version": POLICY_VERSION,
        }
        actual = {
            "tenant_id": approval.tenant_id,
            "agent_id": approval.agent_id,
            "action": approval.action,
            "operation_id": approval.operation_id,
            "request_digest": approval.request_digest,
            "policy_version": approval.policy_version,
        }
        if actual != expected:
            return Outcome.DENIED, "approval_not_bound"
        if (
            approval.approver_role is not Role.RISK_APPROVER
            or not approver
            or not approver.active
            or approver.tenant_id != record.tenant_id
            or Role.RISK_APPROVER not in approver.roles
        ):
            return Outcome.DENIED, "approver_not_authorized"
        if approval.approver_id in {
            context.actor_id,
            record.manifest.sponsor_id,
            record.manifest.technical_owner_id,
        }:
            return Outcome.DENIED, "separation_of_duties_violation"
        if not (approval.issued_at <= NOW < approval.expires_at):
            return Outcome.DENIED, "approval_expired"
        if not self.approvals.consume(approval.approval_id):
            return Outcome.DENIED, "approval_replayed"
        return None

    def _handle_register(
        self, context: VerifiedAdminContext, request: LifecycleRequest,
        record: AgentRecord, payload: EmptyPayload,
        approval: LifecycleApproval | None, cleanup: CleanupAdapter | None,
    ) -> LifecycleResult:
        manifest = record.manifest
        sponsor = self.directory.get(manifest.sponsor_id)
        owner = self.directory.get(manifest.technical_owner_id)
        blueprint = self.blueprints.get(manifest.blueprint_id)
        if not sponsor or not sponsor.active or sponsor.tenant_id != record.tenant_id:
            return self._finish(context, request, Outcome.DENIED, "sponsor_invalid", False)
        if not owner or not owner.active or owner.tenant_id != record.tenant_id:
            return self._finish(context, request, Outcome.DENIED, "owner_invalid", False)
        if (
            not blueprint
            or not blueprint.active
            or blueprint.tenant_id != record.tenant_id
            or blueprint.version != manifest.blueprint_version
        ):
            return self._finish(context, request, Outcome.DENIED, "blueprint_invalid", False)
        self._update(record, state=LifecycleState.REGISTERED)
        return self._finish(context, request, Outcome.APPLIED, "agent_registered", True)

    def _handle_submit_for_review(
        self, context: VerifiedAdminContext, request: LifecycleRequest,
        record: AgentRecord, payload: EmptyPayload,
        approval: LifecycleApproval | None, cleanup: CleanupAdapter | None,
    ) -> LifecycleResult:
        self._update(record, state=LifecycleState.UNDER_REVIEW)
        return self._finish(context, request, Outcome.APPLIED, "review_started", True)

    def _handle_approve(
        self, context: VerifiedAdminContext, request: LifecycleRequest,
        record: AgentRecord, payload: ApprovalPayload,
        approval: LifecycleApproval | None, cleanup: CleanupAdapter | None,
    ) -> LifecycleResult:
        if payload.manifest_digest != record.manifest_digest:
            return self._finish(context, request, Outcome.DENIED, "manifest_changed", False)
        error = self._approval_error(context, request, record, approval)
        if error:
            outcome, reason = error
            obligations = ("obtain_independent_manifest_approval",) if outcome is Outcome.APPROVAL_REQUIRED else ()
            return self._finish(context, request, outcome, reason, False, obligations=obligations)
        next_review = NOW + timedelta(days=REVIEW_DAYS[record.manifest.risk_tier])
        review = ReviewRecord(
            review_id=stable_id("review", request.operation_id),
            reviewer_id=approval.approver_id,
            verdict=ReviewVerdict.CONTINUE,
            reviewed_at=NOW,
            next_review_at=next_review,
            manifest_digest=record.manifest_digest,
        )
        self._update(
            record,
            state=LifecycleState.APPROVED,
            reviews=(*record.reviews, review),
            next_review_at=next_review,
        )
        return self._finish(context, request, Outcome.APPLIED, "manifest_approved", True)

    def _handle_provision(
        self, context: VerifiedAdminContext, request: LifecycleRequest,
        record: AgentRecord, payload: ProvisionPayload,
        approval: LifecycleApproval | None, cleanup: CleanupAdapter | None,
    ) -> LifecycleResult:
        blueprint = self.blueprints[record.manifest.blueprint_id]
        requested = frozenset(payload.capabilities)
        profiles = frozenset(payload.credential_profiles)
        if requested != frozenset(record.manifest.requested_capabilities):
            return self._finish(context, request, Outcome.DENIED, "capability_manifest_mismatch", False)
        if not requested.issubset(blueprint.allowed_capabilities):
            return self._finish(context, request, Outcome.DENIED, "capability_not_in_blueprint", False)
        if not profiles.issubset(blueprint.allowed_credential_profiles):
            return self._finish(context, request, Outcome.DENIED, "credential_profile_not_allowed", False)
        attestation = self.attestations.get(payload.workload_id)
        if (
            not attestation
            or not attestation.active
            or attestation.agent_id != record.agent_id
            or attestation.tenant_id != record.tenant_id
            or attestation.environment != record.manifest.environment
            or not payload.workload_id.startswith(f"spiffe://{blueprint.workload_trust_domain}/")
        ):
            return self._finish(context, request, Outcome.DENIED, "workload_not_attested", False)
        grants = tuple(
            AccessGrant(
                stable_id("grant", record.agent_id, capability),
                capability,
                min(record.next_review_at or NOW, NOW + timedelta(days=90)),
                "active",
            )
            for capability in sorted(requested)
        )
        credential_records = tuple(
            CredentialProfile(
                profile,
                f"https://{profile}.api.corp.example",
                0,
                "configured",
            )
            for profile in sorted(profiles)
        )
        self._update(
            record,
            state=LifecycleState.PROVISIONED,
            workload_bindings=(
                WorkloadBinding(attestation.workload_id, attestation.evidence_id, "active"),
            ),
            access_grants=grants,
            credential_profiles=credential_records,
        )
        return self._finish(context, request, Outcome.APPLIED, "assets_provisioned", True)

    def _activation_error(self, record: AgentRecord) -> str | None:
        sponsor = self.directory.get(record.manifest.sponsor_id)
        owner = self.directory.get(record.manifest.technical_owner_id)
        if not sponsor or not sponsor.active:
            return "sponsor_inactive"
        if not owner or not owner.active:
            return "owner_inactive"
        if not record.next_review_at or record.next_review_at <= NOW:
            return "review_overdue"
        if not record.workload_bindings or any(
            binding.status != "active" for binding in record.workload_bindings
        ):
            return "workload_binding_inactive"
        if not record.access_grants or any(
            grant.status != "active" or grant.expires_at <= NOW
            for grant in record.access_grants
        ):
            return "access_grant_inactive"
        if not record.credential_profiles:
            return "credential_profile_missing"
        return None

    def _handle_activate(
        self, context: VerifiedAdminContext, request: LifecycleRequest,
        record: AgentRecord, payload: EmptyPayload,
        approval: LifecycleApproval | None, cleanup: CleanupAdapter | None,
    ) -> LifecycleResult:
        error = self._activation_error(record)
        if error:
            return self._finish(context, request, Outcome.DENIED, error, False)
        credentials = tuple(
            replace(item, generation=item.generation + 1, status="active")
            for item in record.credential_profiles
        )
        self._update(
            record,
            state=LifecycleState.ACTIVE,
            credential_profiles=credentials,
            sessions=(RuntimeSession(stable_id("session", request.operation_id), "active"),),
        )
        return self._finish(context, request, Outcome.APPLIED, "agent_activated", True)

    def _handle_recertify(
        self, context: VerifiedAdminContext, request: LifecycleRequest,
        record: AgentRecord, payload: RecertifyPayload,
        approval: LifecycleApproval | None, cleanup: CleanupAdapter | None,
    ) -> LifecycleResult:
        if context.actor_id != record.manifest.sponsor_id:
            return self._finish(context, request, Outcome.DENIED, "reviewer_not_sponsor", False)
        next_review = (
            NOW + timedelta(days=REVIEW_DAYS[record.manifest.risk_tier])
            if payload.verdict is ReviewVerdict.CONTINUE
            else None
        )
        review = ReviewRecord(
            stable_id("review", request.operation_id),
            context.actor_id,
            payload.verdict,
            NOW,
            next_review,
            record.manifest_digest,
        )
        if payload.verdict is ReviewVerdict.CONTINUE:
            self._update(
                record,
                reviews=(*record.reviews, review),
                next_review_at=next_review,
            )
            return self._finish(context, request, Outcome.APPLIED, "access_recertified", True)
        grants = tuple(replace(item, status="revoked") for item in record.access_grants)
        credentials = tuple(replace(item, status="revoked") for item in record.credential_profiles)
        sessions = tuple(replace(item, status="revoked") for item in record.sessions)
        target = LifecycleState.UNDER_REVIEW if payload.verdict is ReviewVerdict.MODIFY else LifecycleState.REVOKED
        self._update(
            record,
            state=target,
            reviews=(*record.reviews, review),
            next_review_at=None,
            access_grants=grants,
            credential_profiles=credentials,
            sessions=sessions,
        )
        return self._finish(context, request, Outcome.APPLIED, f"review_{payload.verdict.value}", True)

    def _handle_transfer_sponsor(
        self, context: VerifiedAdminContext, request: LifecycleRequest,
        record: AgentRecord, payload: SponsorTransferPayload,
        approval: LifecycleApproval | None, cleanup: CleanupAdapter | None,
    ) -> LifecycleResult:
        if payload.expected_old_sponsor_id != record.manifest.sponsor_id:
            return self._finish(context, request, Outcome.DENIED, "sponsor_changed_concurrently", False)
        old = self.directory.get(payload.expected_old_sponsor_id)
        new = self.directory.get(payload.new_sponsor_id)
        if not new or not new.active or new.tenant_id != record.tenant_id:
            return self._finish(context, request, Outcome.DENIED, "new_sponsor_invalid", False)
        if old and old.active:
            return self._finish(context, request, Outcome.DENIED, "active_sponsor_requires_review", False)
        if not old or old.manager_id != new.identity_id:
            return self._finish(context, request, Outcome.DENIED, "succession_not_verified", False)
        manifest = record.manifest.model_copy(update={"sponsor_id": new.identity_id})
        self._update(
            record,
            manifest=manifest,
            manifest_digest=manifest_digest(manifest),
        )
        return self._finish(context, request, Outcome.APPLIED, "sponsor_transferred", True)

    def _handle_material_change(
        self, context: VerifiedAdminContext, request: LifecycleRequest,
        record: AgentRecord, payload: MaterialChangePayload,
        approval: LifecycleApproval | None, cleanup: CleanupAdapter | None,
    ) -> LifecycleResult:
        if context.actor_id not in {record.manifest.technical_owner_id, "user:owner"}:
            return self._finish(context, request, Outcome.DENIED, "actor_not_owner", False)
        old = record.manifest
        new = payload.manifest
        if new.sponsor_id != old.sponsor_id or new.technical_owner_id != old.technical_owner_id:
            return self._finish(context, request, Outcome.DENIED, "ownership_change_requires_workflow", False)
        if manifest_digest(new) == record.manifest_digest:
            return self._finish(context, request, Outcome.DENIED, "no_material_change", False)
        grants = tuple(replace(item, status="suspended") for item in record.access_grants)
        credentials = tuple(replace(item, status="suspended") for item in record.credential_profiles)
        sessions = tuple(replace(item, status="revoked") for item in record.sessions)
        self._update(
            record,
            state=LifecycleState.UNDER_REVIEW,
            manifest=new,
            manifest_digest=manifest_digest(new),
            next_review_at=None,
            access_grants=grants,
            credential_profiles=credentials,
            sessions=sessions,
        )
        return self._finish(context, request, Outcome.APPLIED, "material_change_requires_review", True)

    def _handle_suspend(
        self, context: VerifiedAdminContext, request: LifecycleRequest,
        record: AgentRecord, payload: ReasonPayload,
        approval: LifecycleApproval | None, cleanup: CleanupAdapter | None,
    ) -> LifecycleResult:
        self._update(
            record,
            state=LifecycleState.SUSPENDED,
            access_grants=tuple(replace(item, status="suspended") for item in record.access_grants),
            credential_profiles=tuple(replace(item, status="suspended") for item in record.credential_profiles),
            sessions=tuple(replace(item, status="revoked") for item in record.sessions),
        )
        return self._finish(context, request, Outcome.APPLIED, "agent_suspended", True)

    def _handle_reactivate(
        self, context: VerifiedAdminContext, request: LifecycleRequest,
        record: AgentRecord, payload: ReactivatePayload,
        approval: LifecycleApproval | None, cleanup: CleanupAdapter | None,
    ) -> LifecycleResult:
        error = self._approval_error(context, request, record, approval)
        if error:
            outcome, reason = error
            obligations = ("obtain_independent_reactivation_approval",) if outcome is Outcome.APPROVAL_REQUIRED else ()
            return self._finish(context, request, outcome, reason, False, obligations=obligations)
        if any(payload.credential_generation <= item.generation for item in record.credential_profiles):
            return self._finish(context, request, Outcome.DENIED, "credentials_not_rotated", False)
        activation_candidate = replace(
            record,
            access_grants=tuple(replace(item, status="active") for item in record.access_grants),
            credential_profiles=tuple(
                replace(item, generation=payload.credential_generation, status="active")
                for item in record.credential_profiles
            ),
            workload_bindings=tuple(replace(item, status="active") for item in record.workload_bindings),
        )
        error = self._activation_error(activation_candidate)
        if error:
            return self._finish(context, request, Outcome.DENIED, error, False)
        self._update(
            record,
            state=LifecycleState.ACTIVE,
            access_grants=activation_candidate.access_grants,
            credential_profiles=activation_candidate.credential_profiles,
            workload_bindings=activation_candidate.workload_bindings,
            sessions=(RuntimeSession(stable_id("session", request.operation_id), "active"),),
        )
        return self._finish(context, request, Outcome.APPLIED, "agent_reactivated", True)

    def _handle_revoke(
        self, context: VerifiedAdminContext, request: LifecycleRequest,
        record: AgentRecord, payload: ReasonPayload,
        approval: LifecycleApproval | None, cleanup: CleanupAdapter | None,
    ) -> LifecycleResult:
        self._update(
            record,
            state=LifecycleState.REVOKED,
            access_grants=tuple(replace(item, status="revoked") for item in record.access_grants),
            credential_profiles=tuple(replace(item, status="revoked") for item in record.credential_profiles),
            workload_bindings=tuple(replace(item, status="revoked") for item in record.workload_bindings),
            sessions=tuple(replace(item, status="revoked") for item in record.sessions),
        )
        return self._finish(context, request, Outcome.APPLIED, "revocation_propagated", True)

    def _handle_retire(
        self, context: VerifiedAdminContext, request: LifecycleRequest,
        record: AgentRecord, payload: ReasonPayload,
        approval: LifecycleApproval | None, cleanup: CleanupAdapter | None,
    ) -> LifecycleResult:
        if context.actor_id != record.manifest.sponsor_id and Role.IAM_ADMIN not in context.roles:
            return self._finish(context, request, Outcome.DENIED, "retirement_actor_invalid", False)
        cleanup = cleanup or CleanupAdapter()
        if record.state is LifecycleState.REVOKED:
            record = self._update(record, state=LifecycleState.RETIRING)
        resources = (
            "cleanup:workload",
            "cleanup:grants",
            "cleanup:credentials",
            "cleanup:sessions",
        )
        completed = set(record.cleanup_receipts)
        for resource in resources:
            if resource in completed:
                continue
            if not cleanup.remove(resource):
                self._update(record, cleanup_receipts=tuple(sorted(completed)))
                return self._finish(
                    context, request, Outcome.PARTIAL, "cleanup_incomplete", True,
                    obligations=("retry_idempotent_cleanup",),
                )
            completed.add(resource)
        record = self.get(record.agent_id)
        self._update(
            record,
            state=LifecycleState.RETIRED,
            workload_bindings=tuple(replace(item, status="removed") for item in record.workload_bindings),
            access_grants=tuple(replace(item, status="removed") for item in record.access_grants),
            credential_profiles=tuple(replace(item, status="removed") for item in record.credential_profiles),
            sessions=tuple(replace(item, status="removed") for item in record.sessions),
            cleanup_receipts=tuple(sorted(completed)),
        )
        return self._finish(
            context, request, Outcome.APPLIED, "retirement_verified", True,
            cleanup_verified=True,
        )


class UnsafeLifecycleManager:
    """Teaching baseline: trusts request fields and updates state optimistically."""

    def __init__(self) -> None:
        self.records: dict[str, AgentRecord] = {}
        self.audit = AuditLog()
        self.effect_count = 0

    def seed(self, record: AgentRecord) -> None:
        self.records[record.agent_id] = record

    def get(self, agent_id: str = AGENT_ID) -> AgentRecord:
        return self.records[agent_id]

    def execute(
        self,
        context: VerifiedAdminContext,
        request: LifecycleRequest,
        *,
        approval: LifecycleApproval | None = None,
        cleanup: CleanupAdapter | None = None,
    ) -> LifecycleResult:
        record = self.records[request.agent_id]
        targets = {
            Action.REGISTER: LifecycleState.REGISTERED,
            Action.SUBMIT: LifecycleState.UNDER_REVIEW,
            Action.APPROVE: LifecycleState.APPROVED,
            Action.PROVISION: LifecycleState.PROVISIONED,
            Action.ACTIVATE: LifecycleState.ACTIVE,
            Action.RECERTIFY: record.state,
            Action.TRANSFER_SPONSOR: record.state,
            Action.MATERIAL_CHANGE: LifecycleState.UNDER_REVIEW,
            Action.SUSPEND: LifecycleState.SUSPENDED,
            Action.REACTIVATE: LifecycleState.ACTIVE,
            Action.REVOKE: LifecycleState.REVOKED,
            Action.RETIRE: LifecycleState.RETIRED,
        }
        updated = replace(
            record,
            state=targets[request.action],
            version=record.version + 1,
            updated_at=NOW,
        )
        self.records[record.agent_id] = updated
        self.effect_count += 1
        event = self.audit.append(
            context=context,
            request=request,
            outcome=Outcome.APPLIED,
            reason_code="request_trusted",
            record_version=updated.version,
        )
        decision = LifecycleDecision(
            outcome=Outcome.APPLIED,
            reason_code="request_trusted",
            decision_id=stable_id("baseline", request.operation_id),
            operation_id=request.operation_id,
            agent_id=request.agent_id,
            action=request.action,
            actor_id=context.actor_id,
            request_digest=request_digest(request),
            policy_version="none",
            state_before=record.state,
            state_after=updated.state,
            record_version=updated.version,
            audit_event_id=event.event_id,
            audit_hash=event.event_hash,
        )
        return LifecycleResult(decision, True, request.action is Action.RETIRE)


def make_request(
    manager: LifecycleController | UnsafeLifecycleManager,
    action: Action,
    payload: dict[str, Any] | None = None,
    *,
    operation_id: str | None = None,
    expected_version: int | None = None,
) -> LifecycleRequest:
    record = manager.get()
    return LifecycleRequest(
        operation_id=operation_id or f"operation:{action.value}",
        agent_id=record.agent_id,
        action=action,
        expected_version=record.version if expected_version is None else expected_version,
        payload=payload or {},
    )


def make_approval(
    request: LifecycleRequest,
    *,
    approver_id: str = "user:risk",
    approver_role: Role = Role.RISK_APPROVER,
    request_digest_override: str | None = None,
) -> LifecycleApproval:
    return LifecycleApproval(
        approval_id=stable_id("approval", request.operation_id, approver_id),
        approver_id=approver_id,
        approver_role=approver_role,
        tenant_id=TENANT_ID,
        agent_id=request.agent_id,
        action=request.action,
        operation_id=request.operation_id,
        request_digest=request_digest_override or request_digest(request),
        policy_version=POLICY_VERSION,
        issued_at=NOW - timedelta(minutes=1),
        expires_at=NOW + timedelta(minutes=10),
    )


@dataclass(frozen=True)
class Scenario:
    case_id: str
    state: LifecycleState
    action: Action
    expected: Outcome
    actor_id: str
    roles: tuple[Role, ...]
    payload_factory: Callable[[AgentRecord], dict[str, Any]]
    mutation: str | None = None
    approval_mode: str | None = None
    stale_version: bool = False
    cleanup_failure: str | None = None


def _empty(record: AgentRecord) -> dict[str, Any]:
    return {}


def _approve_payload(record: AgentRecord) -> dict[str, Any]:
    return {"manifest_digest": record.manifest_digest}


def _valid_provision(record: AgentRecord) -> dict[str, Any]:
    return {
        "workload_id": "spiffe://corp.example/prod/travel-booking",
        "capabilities": tuple(record.manifest.requested_capabilities),
        "credential_profiles": ("travel-search", "travel-book-limited"),
    }


def _recertify(record: AgentRecord) -> dict[str, Any]:
    return {
        "verdict": ReviewVerdict.CONTINUE,
        "justification": "Business purpose and bounded access remain required.",
    }


def _reason(record: AgentRecord) -> dict[str, Any]:
    return {"reason": "Confirmed incident or lifecycle retirement requirement."}


def _reactivate(record: AgentRecord) -> dict[str, Any]:
    generation = max(item.generation for item in record.credential_profiles) + 1
    return {"incident_id": "incident:travel-2026-09", "credential_generation": generation}


def _material_change(record: AgentRecord) -> dict[str, Any]:
    changed = record.manifest.model_copy(
        update={
            "requested_capabilities": (
                *record.manifest.requested_capabilities,
                "itinerary.send_internal",
            )
        }
    )
    return {
        "manifest": changed,
        "reason": "Add internal itinerary delivery to the production agent.",
    }


def build_cases() -> list[Scenario]:
    return [
        Scenario("valid_registration", LifecycleState.DRAFT, Action.REGISTER, Outcome.APPLIED, "user:owner", (Role.OWNER,), _empty),
        Scenario("inactive_sponsor", LifecycleState.DRAFT, Action.REGISTER, Outcome.DENIED, "user:owner", (Role.OWNER,), _empty, mutation="inactive_sponsor"),
        Scenario("cross_tenant_admin", LifecycleState.REGISTERED, Action.SUBMIT, Outcome.DENIED, "user:outsider", (Role.IAM_ADMIN,), _empty),
        Scenario("valid_approval", LifecycleState.UNDER_REVIEW, Action.APPROVE, Outcome.APPLIED, "user:iam", (Role.IAM_ADMIN,), _approve_payload, approval_mode="valid"),
        Scenario("self_approval", LifecycleState.UNDER_REVIEW, Action.APPROVE, Outcome.DENIED, "user:risk", (Role.IAM_ADMIN,), _approve_payload, approval_mode="self"),
        Scenario("altered_approval", LifecycleState.UNDER_REVIEW, Action.APPROVE, Outcome.DENIED, "user:iam", (Role.IAM_ADMIN,), _approve_payload, approval_mode="altered"),
        Scenario("overbroad_provisioning", LifecycleState.APPROVED, Action.PROVISION, Outcome.DENIED, "user:provisioner", (Role.PROVISIONER,), lambda record: {**_valid_provision(record), "capabilities": (*record.manifest.requested_capabilities, "payment.refund")}),
        Scenario("wrong_workload_binding", LifecycleState.APPROVED, Action.PROVISION, Outcome.DENIED, "user:provisioner", (Role.PROVISIONER,), lambda record: {**_valid_provision(record), "workload_id": "spiffe://attacker.example/prod/travel"}),
        Scenario("valid_provisioning", LifecycleState.APPROVED, Action.PROVISION, Outcome.APPLIED, "user:provisioner", (Role.PROVISIONER,), _valid_provision),
        Scenario("overdue_activation", LifecycleState.PROVISIONED, Action.ACTIVATE, Outcome.DENIED, "workload:platform", (Role.PLATFORM,), _empty, mutation="overdue_review"),
        Scenario("valid_activation", LifecycleState.PROVISIONED, Action.ACTIVATE, Outcome.APPLIED, "workload:platform", (Role.PLATFORM,), _empty),
        Scenario("stale_recertification", LifecycleState.ACTIVE, Action.RECERTIFY, Outcome.DENIED, "user:alice", (Role.SPONSOR,), _recertify, stale_version=True),
        Scenario("wrong_reviewer", LifecycleState.ACTIVE, Action.RECERTIFY, Outcome.DENIED, "user:bob", (Role.SPONSOR,), _recertify),
        Scenario("valid_recertification", LifecycleState.ACTIVE, Action.RECERTIFY, Outcome.APPLIED, "user:alice", (Role.SPONSOR,), _recertify),
        Scenario("material_change", LifecycleState.ACTIVE, Action.MATERIAL_CHANGE, Outcome.APPLIED, "user:owner", (Role.OWNER,), _material_change),
        Scenario("reactivation_needs_approval", LifecycleState.SUSPENDED, Action.REACTIVATE, Outcome.APPROVAL_REQUIRED, "service:soc", (Role.SECURITY,), _reactivate),
        Scenario("altered_reactivation_approval", LifecycleState.SUSPENDED, Action.REACTIVATE, Outcome.DENIED, "service:soc", (Role.SECURITY,), _reactivate, approval_mode="altered"),
        Scenario("valid_revocation", LifecycleState.ACTIVE, Action.REVOKE, Outcome.APPLIED, "service:soc", (Role.SECURITY,), _reason),
        Scenario("cleanup_outage", LifecycleState.REVOKED, Action.RETIRE, Outcome.PARTIAL, "user:alice", (Role.SPONSOR,), _reason, cleanup_failure="cleanup:credentials"),
        Scenario("retired_reactivation", LifecycleState.RETIRED, Action.REACTIVATE, Outcome.DENIED, "service:soc", (Role.SECURITY,), _reactivate),
    ]


def run_case(
    scenario: Scenario,
    factory: Callable[[], LifecycleController | UnsafeLifecycleManager],
) -> LifecycleResult:
    manager = factory()
    record = build_record(
        scenario.state,
        overdue_review=scenario.mutation == "overdue_review",
    )
    manager.seed(record)
    if scenario.mutation == "inactive_sponsor" and isinstance(manager, LifecycleController):
        manager.directory[record.manifest.sponsor_id] = replace(
            manager.directory[record.manifest.sponsor_id], active=False
        )
    admin_context = context(
        scenario.actor_id,
        *scenario.roles,
        tenant_id=("tenant:other" if scenario.case_id == "cross_tenant_admin" else TENANT_ID),
    )
    expected_version = record.version - 1 if scenario.stale_version else record.version
    request = make_request(
        manager,
        scenario.action,
        scenario.payload_factory(record),
        operation_id=f"operation:{scenario.case_id}",
        expected_version=expected_version,
    )
    approval = None
    if scenario.approval_mode:
        if scenario.approval_mode == "self":
            approval = make_approval(request, approver_id=admin_context.actor_id)
        elif scenario.approval_mode == "altered":
            approval = make_approval(request, request_digest_override=digest("altered"))
        else:
            approval = make_approval(request)
    cleanup = CleanupAdapter(scenario.cleanup_failure) if scenario.cleanup_failure else None
    return manager.execute(admin_context, request, approval=approval, cleanup=cleanup)


def baseline_factory() -> UnsafeLifecycleManager:
    return UnsafeLifecycleManager()


def hardened_factory() -> LifecycleController:
    return LifecycleController()


def evaluate(
    cases: Iterable[Scenario],
    factory: Callable[[], LifecycleController | UnsafeLifecycleManager],
) -> tuple[EvaluationMetrics, list[tuple[str, Outcome, LifecycleResult]]]:
    rows = [(case.case_id, case.expected, run_case(case, factory)) for case in cases]
    expected_applied = sum(expected is Outcome.APPLIED for _, expected, _ in rows)
    expected_blocked = sum(
        expected in {Outcome.DENIED, Outcome.APPROVAL_REQUIRED}
        for _, expected, _ in rows
    )
    expected_partial = sum(expected is Outcome.PARTIAL for _, expected, _ in rows)
    metrics = EvaluationMetrics(
        attempts=len(rows),
        expected_applied=expected_applied,
        expected_blocked=expected_blocked,
        expected_partial=expected_partial,
        outcome_matches=sum(result.decision.outcome is expected for _, expected, result in rows),
        valid_applied=sum(
            expected is Outcome.APPLIED and result.decision.outcome is Outcome.APPLIED
            for _, expected, result in rows
        ),
        forbidden_effects=sum(
            expected in {Outcome.DENIED, Outcome.APPROVAL_REQUIRED}
            and result.effect_committed
            for _, expected, result in rows
        ),
        partial_detected=sum(
            expected is Outcome.PARTIAL and result.decision.outcome is Outcome.PARTIAL
            for _, expected, result in rows
        ),
        duplicate_effects=sum(result.decision.reconciled and result.effect_committed for _, _, result in rows),
        complete_evidence=sum(result.decision.evidence_complete for _, _, result in rows),
    )
    return metrics, rows


def release_gate(metrics: EvaluationMetrics) -> bool:
    return (
        metrics.outcome_match_rate == 1.0
        and metrics.valid_apply_rate == 1.0
        and metrics.forbidden_effect_rate == 0.0
        and metrics.partial_detection_rate == 1.0
        and metrics.duplicate_effect_rate == 0.0
        and metrics.evidence_completeness_rate == 1.0
    )


def lifecycle_json_schemas() -> dict[str, dict[str, Any]]:
    """Schemas suitable for an API, workflow engine, or administrative UI."""

    return {
        action.value: model.model_json_schema()
        for action, model in PAYLOAD_MODELS.items()
    }


def demo() -> None:
    cases = build_cases()
    baseline, _ = evaluate(cases, baseline_factory)
    hardened, rows = evaluate(cases, hardened_factory)
    print("Baseline:", baseline)
    print("Hardened:", hardened)
    print("Release gate:", release_gate(hardened))
    print("\nHardened decisions")
    for case_id, expected, result in rows:
        print(
            f"{case_id:31} expected={expected.value:17} "
            f"actual={result.decision.outcome.value:17} "
            f"reason={result.decision.reason_code}"
        )


if __name__ == "__main__":
    demo()
