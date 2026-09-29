"""Deterministic risk, assurance, and step-up authorization lab.

The lab treats human authentication, workload evidence, transaction risk,
business approval, and authorization eligibility as separate dimensions.  It
implements RFC 9470 challenges exactly enough to contract-test their HTTP
shape, but it never allows stronger authentication to repair an ineligible
task, resource, tenant, or prohibited agent action.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from enum import Enum
from hashlib import sha256
import json
from threading import RLock
from typing import Any, Callable, Literal, Mapping
from urllib.parse import urlencode

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import BaseModel, ConfigDict, Field, ValidationError


NOW = 1_800_000_000
ISSUER = "https://id.northstar.example"
RESOURCE = "https://claims-api.northstar.example"
SUBJECT = "user:alice"
TENANT = "tenant:northstar"
AGENT = "agent:claims-adjuster"
CLIENT = "client:claims-copilot"
WORKLOAD = "spiffe://northstar.example/prod/claims/adjuster"
IMAGE_DIGEST = "sha256:approved-claims-build"
TASK = "task:clm-100-review"
CLAIM = "claim:clm-100"
POLICY_VERSION = 14
RISK_MODEL_VERSION = 8
SIGNAL_VERSION = 11
RESOURCE_VERSION = 4

ACR_AAL1 = "urn:northstar:auth:aal1"
ACR_AAL2 = "urn:northstar:auth:aal2"
ACR_AAL2_PHISHING = "urn:northstar:auth:aal2:phishing-resistant"
ACR_AAL3 = "urn:northstar:auth:aal3"


class Outcome(str, Enum):
    ALLOW = "allow"
    CONSTRAIN = "constrain"
    USER_STEP_UP = "user_step_up"
    WORKLOAD_STEP_UP = "workload_step_up"
    APPROVAL_REQUIRED = "approval_required"
    SCOPE_REQUIRED = "scope_required"
    DENY = "deny"
    RECONCILED = "reconciled"


class RiskTier(str, Enum):
    R1 = "R1"
    R2 = "R2"
    R3 = "R3"
    R4 = "R4"
    PROHIBITED = "PROHIBITED"


class LabError(RuntimeError):
    def __init__(self, reason_code: str):
        self.reason_code = reason_code
        super().__init__(reason_code)


class UnknownOutcome(RuntimeError):
    pass


def canonical(value: Any) -> str:
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json")
    elif hasattr(value, "__dataclass_fields__"):
        value = asdict(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=list)


def digest(value: Any) -> str:
    return sha256(canonical(value).encode()).hexdigest()


@dataclass(frozen=True)
class AcrProfile:
    aal: int
    phishing_resistant: bool
    non_exportable_key: bool


ACR_REGISTRY: dict[str, AcrProfile] = {
    ACR_AAL1: AcrProfile(1, False, False),
    ACR_AAL2: AcrProfile(2, False, False),
    ACR_AAL2_PHISHING: AcrProfile(2, True, False),
    ACR_AAL3: AcrProfile(3, True, True),
}


@dataclass(frozen=True)
class UserSession:
    subject_id: str
    tenant_id: str
    agent_id: str
    client_id: str
    task_id: str
    scopes: frozenset[str]
    acr: str
    aal: int
    phishing_resistant: bool
    non_exportable_key: bool
    auth_time: int
    token_id: str


class SessionIssuer:
    """Deterministic JWT access-token fixture; production uses an external AS."""

    def __init__(
        self, seed: bytes = b"\x33" * 32, kid: str = "northstar-session-2026-09"
    ):
        self.private_key = Ed25519PrivateKey.from_private_bytes(seed)
        self.public_key = self.private_key.public_key()
        self.kid = kid

    def issue(
        self,
        *,
        subject_id: str = SUBJECT,
        tenant_id: str = TENANT,
        agent_id: str = AGENT,
        client_id: str = CLIENT,
        task_id: str = TASK,
        scopes: tuple[str, ...] = ("claims:read", "claims:update", "payments:create"),
        acr: str = ACR_AAL2_PHISHING,
        auth_time: int = NOW - 60,
        issuer: str = ISSUER,
        audience: str = RESOURCE,
        issued_at: int = NOW - 5,
        expires_at: int = NOW + 300,
        jti: str = "session-001",
        typ: str = "at+jwt",
        header_kid: str | None = None,
        private_key: Any | None = None,
        extra: Mapping[str, Any] | None = None,
    ) -> str:
        claims: dict[str, Any] = {
            "iss": issuer,
            "aud": audience,
            "sub": subject_id,
            "tenant_id": tenant_id,
            "agent_id": agent_id,
            "client_id": client_id,
            "task_id": task_id,
            "scope": " ".join(scopes),
            "acr": acr,
            "auth_time": auth_time,
            "iat": issued_at,
            "nbf": issued_at,
            "exp": expires_at,
            "jti": jti,
        }
        claims.update(extra or {})
        return jwt.encode(
            claims,
            private_key or self.private_key,
            algorithm="EdDSA",
            headers={"alg": "EdDSA", "typ": typ, "kid": header_kid or self.kid},
        )


class SessionVerifier:
    def __init__(self, issuer: SessionIssuer, *, now: int = NOW):
        self.issuer = issuer
        self.now = now

    def verify(self, compact: str) -> UserSession:
        try:
            header = jwt.get_unverified_header(compact)
        except jwt.PyJWTError as exc:
            raise LabError("token_malformed") from exc
        if (
            header.get("alg") != "EdDSA"
            or header.get("typ") != "at+jwt"
            or header.get("kid") != self.issuer.kid
        ):
            raise LabError("token_profile_invalid")
        try:
            claims = jwt.decode(
                compact,
                self.issuer.public_key,
                algorithms=["EdDSA"],
                issuer=ISSUER,
                audience=RESOURCE,
                options={
                    "verify_exp": False,
                    "verify_nbf": False,
                    "verify_iat": False,
                    "require": [
                        "iss",
                        "aud",
                        "sub",
                        "tenant_id",
                        "agent_id",
                        "client_id",
                        "task_id",
                        "scope",
                        "acr",
                        "auth_time",
                        "iat",
                        "nbf",
                        "exp",
                        "jti",
                    ],
                },
            )
        except jwt.PyJWTError as exc:
            raise LabError("token_invalid") from exc
        if claims["nbf"] > self.now or claims["iat"] > self.now + 30:
            raise LabError("token_not_current")
        if claims["exp"] <= self.now:
            raise LabError("token_expired")
        if claims["exp"] - claims["iat"] > 600:
            raise LabError("token_lifetime_excessive")
        if claims["auth_time"] > self.now + 30:
            raise LabError("auth_time_invalid")
        try:
            profile = ACR_REGISTRY[claims["acr"]]
        except KeyError as exc:
            raise LabError("acr_untrusted") from exc
        return UserSession(
            subject_id=claims["sub"],
            tenant_id=claims["tenant_id"],
            agent_id=claims["agent_id"],
            client_id=claims["client_id"],
            task_id=claims["task_id"],
            scopes=frozenset(str(claims["scope"]).split()),
            acr=claims["acr"],
            aal=profile.aal,
            phishing_resistant=profile.phishing_resistant,
            non_exportable_key=profile.non_exportable_key,
            auth_time=claims["auth_time"],
            token_id=claims["jti"],
        )


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class FaqArgs(StrictModel):
    query: str = Field(min_length=2, max_length=120)


class ReadArgs(StrictModel):
    claim_id: str = Field(pattern=r"^claim:clm-[0-9]+$")


class UpdateArgs(StrictModel):
    claim_id: str = Field(pattern=r"^claim:clm-[0-9]+$")
    expected_version: int = Field(ge=1)
    note: str = Field(min_length=2, max_length=240)
    operation_id: str = Field(pattern=r"^op-[a-z0-9-]+$")


class PaymentArgs(StrictModel):
    claim_id: str = Field(pattern=r"^claim:clm-[0-9]+$")
    amount_cents: int = Field(gt=0, le=10_000_000)
    currency: Literal["CAD"]
    beneficiary_id: str = Field(pattern=r"^vendor:[a-z0-9-]+$")
    approval_id: str = Field(pattern=r"^approval-[a-z0-9-]+$")
    operation_id: str = Field(pattern=r"^op-[a-z0-9-]+$")


class DisableAuditArgs(StrictModel):
    control: Literal["authorization-audit"]
    operation_id: str = Field(pattern=r"^op-[a-z0-9-]+$")


@dataclass(frozen=True)
class ActionSpec:
    name: str
    scope: str
    model: type[StrictModel]
    base_risk: int
    tier: RiskTier
    side_effect: bool


ACTIONS: dict[str, ActionSpec] = {
    "faq.search": ActionSpec("faq.search", "", FaqArgs, 5, RiskTier.R1, False),
    "claim.read": ActionSpec(
        "claim.read", "claims:read", ReadArgs, 20, RiskTier.R2, False
    ),
    "claim.update": ActionSpec(
        "claim.update", "claims:update", UpdateArgs, 40, RiskTier.R3, True
    ),
    "payment.create": ActionSpec(
        "payment.create", "payments:create", PaymentArgs, 50, RiskTier.R4, True
    ),
    "audit.disable": ActionSpec(
        "audit.disable", "admin:audit", DisableAuditArgs, 100, RiskTier.PROHIBITED, True
    ),
}


@dataclass
class TaskGrant:
    task_id: str = TASK
    subject_id: str = SUBJECT
    tenant_id: str = TENANT
    agent_id: str = AGENT
    client_id: str = CLIENT
    workload_id: str = WORKLOAD
    resources: frozenset[str] = frozenset({CLAIM})
    actions: frozenset[str] = frozenset(
        {"faq.search", "claim.read", "claim.update", "payment.create"}
    )
    max_payment_cents: int = 2_000_000
    max_delegation_depth: int = 2
    active: bool = True
    expires_at: int = NOW + 900
    version: int = 5


@dataclass
class ResourceRecord:
    resource_id: str = CLAIM
    tenant_id: str = TENANT
    owner_id: str = SUBJECT
    classification: Literal["internal", "confidential", "restricted"] = "confidential"
    version: int = RESOURCE_VERSION


@dataclass
class WorkloadEvidence:
    workload_id: str = WORKLOAD
    image_digest: str = IMAGE_DIGEST
    environment: str = "prod"
    attested: bool = True
    observed_at: int = NOW - 30
    expires_at: int = NOW + 270
    verifier: str = "spire-server:northstar"
    version: int = 6


@dataclass
class DynamicSignals:
    device_state: Literal["compliant", "unknown", "compromised"] = "compliant"
    device_observed_at: int = NOW - 60
    behavior_score: int = 5
    prompt_injection_score: float = 0.05
    behavior_observed_at: int = NOW - 20
    behavior_source: str = "behavior-service:v5"
    account_state: Literal["normal", "high-risk", "suspended"] = "normal"
    version: int = SIGNAL_VERSION


@dataclass(frozen=True)
class RiskAssessment:
    score: int
    tier: RiskTier
    reason_codes: tuple[str, ...]
    hard_denials: tuple[str, ...]
    model_version: int
    signal_version: int


@dataclass(frozen=True)
class AssuranceRequirements:
    min_aal: int
    phishing_resistant: bool
    non_exportable_key: bool
    max_auth_age: int
    max_workload_age: int
    approval_count: int
    acr_values: tuple[str, ...]


@dataclass(frozen=True)
class StepUpChallenge:
    acr_values: tuple[str, ...]
    max_age: int
    error: str = "insufficient_user_authentication"
    status: int = 401

    @property
    def www_authenticate(self) -> str:
        acr = " ".join(self.acr_values)
        return (
            f'Bearer error="{self.error}", '
            'error_description="Stronger or more recent user authentication is required", '
            f'acr_values="{acr}", max_age="{self.max_age}"'
        )

    def authorization_parameters(self) -> dict[str, str]:
        return {"acr_values": " ".join(self.acr_values), "max_age": str(self.max_age)}


@dataclass
class ApprovalReceipt:
    approval_id: str
    proposal_digest: str
    approver_ids: tuple[str, ...]
    subject_id: str
    tenant_id: str
    agent_id: str
    task_id: str
    risk_score: int
    policy_version: int
    risk_model_version: int
    signal_version: int
    resource_version: int
    expires_at: int
    used: bool = False


@dataclass(frozen=True)
class Decision:
    outcome: Outcome
    reason_codes: tuple[str, ...]
    proposal_digest: str
    risk: RiskAssessment
    requirements: AssuranceRequirements
    challenge: StepUpChallenge | None
    obligations: tuple[str, ...]
    policy_version: int
    resource_version: int | None


@dataclass(frozen=True)
class ExecutionReceipt:
    operation_id: str
    request_digest: str
    result: Mapping[str, Any]
    decision_digest: str
    effect_count: int


@dataclass(frozen=True)
class StepUpTransaction:
    handle: str
    request_digest: str
    subject_id: str
    tenant_id: str
    agent_id: str
    client_id: str
    task_id: str
    challenge: StepUpChallenge
    expires_at: int
    used: bool = False


def proposal_document(
    action: str, args: StrictModel, session: UserSession
) -> dict[str, Any]:
    values = args.model_dump(mode="json")
    values.pop("approval_id", None)
    return {
        "action": action,
        "arguments": values,
        "subject_id": session.subject_id,
        "tenant_id": session.tenant_id,
        "agent_id": session.agent_id,
        "client_id": session.client_id,
        "task_id": session.task_id,
    }


class RiskEngine:
    def assess(
        self,
        action: str,
        args: StrictModel,
        resource: ResourceRecord | None,
        task: TaskGrant,
        signals: DynamicSignals,
    ) -> RiskAssessment:
        spec = ACTIONS[action]
        score = spec.base_risk
        reasons = [f"base_risk:{spec.base_risk}"]
        hard: list[str] = []
        if spec.tier is RiskTier.PROHIBITED:
            hard.append("agent_action_prohibited")
        if resource and resource.classification == "confidential":
            score += 10
            reasons.append("classification_confidential:+10")
        elif resource and resource.classification == "restricted":
            score += 20
            reasons.append("classification_restricted:+20")
        if isinstance(args, PaymentArgs):
            if args.amount_cents > task.max_payment_cents:
                hard.append("task_payment_limit_exceeded")
            if args.amount_cents > 5_000_000:
                hard.append("agent_payment_ceiling_exceeded")
            elif args.amount_cents > 1_000_000:
                score += 25
                reasons.append("amount_over_10000:+25")
            elif args.amount_cents > 50_000:
                score += 10
                reasons.append("amount_over_500:+10")
            if args.beneficiary_id not in {"vendor:clinic", "vendor:pharmacy"}:
                score += 15
                reasons.append("new_beneficiary:+15")
        if signals.account_state == "suspended":
            hard.append("account_suspended")
        elif signals.account_state == "high-risk":
            score += 20
            reasons.append("account_high_risk:+20")
        if signals.device_state == "compromised":
            hard.append("device_compromised")
        elif signals.device_state == "unknown":
            score += 15
            reasons.append("device_unknown:+15")
        if signals.behavior_source != "behavior-service:v5":
            hard.append("behavior_source_untrusted")
        if signals.behavior_observed_at < NOW - 300 and spec.side_effect:
            hard.append("behavior_signal_stale")
        score += min(max(signals.behavior_score, 0), 20)
        if signals.behavior_score:
            reasons.append(f"behavior:+{min(max(signals.behavior_score, 0), 20)}")
        if signals.prompt_injection_score >= 0.8:
            score += 25
            reasons.append("prompt_injection_high:+25")
            if spec.side_effect:
                hard.append("prompt_injection_blocks_side_effect")
        if task.max_delegation_depth < 0:
            hard.append("delegation_policy_invalid")
        score = min(score, 100)
        if hard or score >= 95:
            tier = (
                RiskTier.PROHIBITED if spec.tier is RiskTier.PROHIBITED else RiskTier.R4
            )
        elif score >= 60:
            tier = RiskTier.R4
        elif score >= 40:
            tier = RiskTier.R3
        elif score >= 20:
            tier = RiskTier.R2
        else:
            tier = RiskTier.R1
        return RiskAssessment(
            score,
            tier,
            tuple(reasons),
            tuple(sorted(set(hard))),
            RISK_MODEL_VERSION,
            signals.version,
        )


def requirements_for(action: str, risk: RiskAssessment) -> AssuranceRequirements:
    if action == "faq.search":
        return AssuranceRequirements(0, False, False, 86_400, 1_800, 0, ())
    if action == "claim.read":
        return AssuranceRequirements(
            1, False, False, 28_800, 1_800, 0, (ACR_AAL1, ACR_AAL2)
        )
    if action == "claim.update":
        approval_count = 1 if risk.score >= 60 else 0
        return AssuranceRequirements(
            2, False, False, 900, 600, approval_count, (ACR_AAL2_PHISHING, ACR_AAL3)
        )
    if action == "payment.create" and risk.score >= 75:
        return AssuranceRequirements(3, True, True, 120, 300, 2, (ACR_AAL3,))
    if action == "payment.create":
        return AssuranceRequirements(
            2, True, False, 300, 300, 1, (ACR_AAL2_PHISHING, ACR_AAL3)
        )
    return AssuranceRequirements(3, True, True, 0, 0, 0, (ACR_AAL3,))


class AuthorizationEngine:
    def __init__(self, issuer: SessionIssuer | None = None, *, now: int = NOW):
        self.issuer = issuer or SessionIssuer()
        self.verifier = SessionVerifier(self.issuer, now=now)
        self.now = now
        self.task = TaskGrant()
        self.resource = ResourceRecord()
        self.workload = WorkloadEvidence()
        self.signals = DynamicSignals()
        self.risk_engine = RiskEngine()
        self.approvals: dict[str, ApprovalReceipt] = {}
        self.operations: dict[str, ExecutionReceipt] = {}
        self.stepup_transactions: dict[str, StepUpTransaction] = {}
        self.audit: list[dict[str, Any]] = []
        self.effect_count = 0
        self._lock = RLock()

    def parse_args(self, action: str, raw: Mapping[str, Any]) -> StrictModel:
        try:
            return ACTIONS[action].model.model_validate(dict(raw))
        except KeyError as exc:
            raise LabError("action_unknown") from exc
        except ValidationError as exc:
            raise LabError("arguments_invalid") from exc

    def _eligible(
        self, session: UserSession, action: str, args: StrictModel
    ) -> tuple[list[str], ResourceRecord | None]:
        reasons: list[str] = []
        if action == "audit.disable":
            reasons.append("agent_action_prohibited")
        if not self.task.active or self.task.expires_at <= self.now:
            reasons.append("task_inactive")
        if action not in self.task.actions and action != "audit.disable":
            reasons.append("action_not_delegated")
        if (
            session.subject_id != self.task.subject_id
            or session.tenant_id != self.task.tenant_id
            or session.agent_id != self.task.agent_id
            or session.client_id != self.task.client_id
            or session.task_id != self.task.task_id
        ):
            reasons.append("identity_task_binding_invalid")
        claim_id = getattr(args, "claim_id", None)
        resource = self.resource if claim_id == self.resource.resource_id else None
        if claim_id and resource is None:
            reasons.append("resource_unknown")
        if resource and (
            resource.resource_id not in self.task.resources
            or resource.tenant_id != session.tenant_id
            or resource.owner_id != session.subject_id
        ):
            reasons.append("resource_not_authorized")
        if (
            isinstance(args, UpdateArgs)
            and resource
            and args.expected_version != resource.version
        ):
            reasons.append("resource_version_stale")
        if (
            isinstance(args, PaymentArgs)
            and args.amount_cents > self.task.max_payment_cents
        ):
            reasons.append("task_payment_limit_exceeded")
        return reasons, resource

    def _workload_status(
        self, requirement: AssuranceRequirements
    ) -> tuple[Outcome | None, str | None]:
        evidence = self.workload
        if (
            evidence.workload_id != self.task.workload_id
            or evidence.environment != "prod"
        ):
            return Outcome.DENY, "workload_binding_invalid"
        if evidence.image_digest != IMAGE_DIGEST:
            return Outcome.DENY, "workload_image_unapproved"
        if not evidence.attested or evidence.expires_at <= self.now:
            return Outcome.WORKLOAD_STEP_UP, "fresh_workload_attestation_required"
        if self.now - evidence.observed_at > requirement.max_workload_age:
            return Outcome.WORKLOAD_STEP_UP, "workload_attestation_stale"
        return None, None

    def authorize(
        self, compact_token: str, action: str, raw_args: Mapping[str, Any]
    ) -> Decision:
        args = self.parse_args(action, raw_args)
        try:
            session = self.verifier.verify(compact_token)
        except LabError as exc:
            return self._terminal_denial(action, args, exc.reason_code)
        proposal_hash = digest(proposal_document(action, args, session))
        eligibility, resource = self._eligible(session, action, args)
        risk = self.risk_engine.assess(action, args, resource, self.task, self.signals)
        requirement = requirements_for(action, risk)
        if eligibility or risk.hard_denials or risk.score >= 95:
            reasons = tuple(
                sorted(
                    set(eligibility)
                    | set(risk.hard_denials)
                    | ({"risk_ceiling_exceeded"} if risk.score >= 95 else set())
                )
            )
            return self._record(
                Decision(
                    Outcome.DENY,
                    reasons,
                    proposal_hash,
                    risk,
                    requirement,
                    None,
                    (),
                    POLICY_VERSION,
                    resource.version if resource else None,
                ),
                session,
                action,
            )
        spec = ACTIONS[action]
        if spec.scope and spec.scope not in session.scopes:
            return self._record(
                Decision(
                    Outcome.SCOPE_REQUIRED,
                    ("scope_insufficient",),
                    proposal_hash,
                    risk,
                    requirement,
                    None,
                    (f"request_scope:{spec.scope}",),
                    POLICY_VERSION,
                    resource.version if resource else None,
                ),
                session,
                action,
            )
        workload_outcome, workload_reason = self._workload_status(requirement)
        if workload_outcome:
            return self._record(
                Decision(
                    workload_outcome,
                    (str(workload_reason),),
                    proposal_hash,
                    risk,
                    requirement,
                    None,
                    ("refresh_workload_attestation",)
                    if workload_outcome is Outcome.WORKLOAD_STEP_UP
                    else (),
                    POLICY_VERSION,
                    resource.version if resource else None,
                ),
                session,
                action,
            )
        auth_age = self.now - session.auth_time
        user_insufficient = (
            session.aal < requirement.min_aal
            or (requirement.phishing_resistant and not session.phishing_resistant)
            or (requirement.non_exportable_key and not session.non_exportable_key)
            or auth_age > requirement.max_auth_age
        )
        if user_insufficient:
            challenge = StepUpChallenge(
                requirement.acr_values, requirement.max_auth_age
            )
            reasons = []
            if session.aal < requirement.min_aal:
                reasons.append("human_aal_insufficient")
            if requirement.phishing_resistant and not session.phishing_resistant:
                reasons.append("phishing_resistance_required")
            if requirement.non_exportable_key and not session.non_exportable_key:
                reasons.append("non_exportable_key_required")
            if auth_age > requirement.max_auth_age:
                reasons.append("user_authentication_stale")
            return self._record(
                Decision(
                    Outcome.USER_STEP_UP,
                    tuple(reasons),
                    proposal_hash,
                    risk,
                    requirement,
                    challenge,
                    ("complete_rfc9470_step_up",),
                    POLICY_VERSION,
                    resource.version if resource else None,
                ),
                session,
                action,
            )
        if requirement.approval_count:
            approval_id = getattr(args, "approval_id", "")
            approval = self.approvals.get(approval_id)
            approval_problem = self._approval_problem(
                approval, proposal_hash, session, risk, resource, requirement
            )
            if approval_problem:
                outcome = (
                    Outcome.APPROVAL_REQUIRED
                    if approval_problem in {"approval_missing", "approval_expired"}
                    else Outcome.DENY
                )
                return self._record(
                    Decision(
                        outcome,
                        (approval_problem,),
                        proposal_hash,
                        risk,
                        requirement,
                        None,
                        (f"collect_{requirement.approval_count}_approval",)
                        if outcome is Outcome.APPROVAL_REQUIRED
                        else (),
                        POLICY_VERSION,
                        resource.version if resource else None,
                    ),
                    session,
                    action,
                )
        outcome = (
            Outcome.CONSTRAIN
            if risk.score >= 40 and not spec.side_effect
            else Outcome.ALLOW
        )
        obligations = (
            ("redact_sensitive_fields",) if outcome is Outcome.CONSTRAIN else ()
        )
        return self._record(
            Decision(
                outcome,
                ("requirements_satisfied",),
                proposal_hash,
                risk,
                requirement,
                None,
                obligations,
                POLICY_VERSION,
                resource.version if resource else None,
            ),
            session,
            action,
        )

    def _terminal_denial(self, action: str, args: StrictModel, reason: str) -> Decision:
        risk = self.risk_engine.assess(action, args, None, self.task, self.signals)
        return Decision(
            Outcome.DENY,
            (reason,),
            digest({"action": action, "untrusted_args": args.model_dump(mode="json")}),
            risk,
            requirements_for(action, risk),
            None,
            (),
            POLICY_VERSION,
            None,
        )

    def _record(
        self, decision: Decision, session: UserSession, action: str
    ) -> Decision:
        self.audit.append(
            {
                "action": action,
                "subject_id": session.subject_id,
                "agent_id": session.agent_id,
                "client_id": session.client_id,
                "task_id": session.task_id,
                "outcome": decision.outcome.value,
                "reason_codes": list(decision.reason_codes),
                "proposal_digest": decision.proposal_digest,
                "risk_score": decision.risk.score,
                "risk_tier": decision.risk.tier.value,
                "policy_version": decision.policy_version,
                "risk_model_version": decision.risk.model_version,
                "signal_version": decision.risk.signal_version,
                "resource_version": decision.resource_version,
                "acr": session.acr,
                "auth_age_seconds": self.now - session.auth_time,
                "token_fingerprint": digest(session.token_id)[:16],
            }
        )
        return decision

    def _approval_problem(
        self,
        approval: ApprovalReceipt | None,
        proposal_hash: str,
        session: UserSession,
        risk: RiskAssessment,
        resource: ResourceRecord | None,
        requirement: AssuranceRequirements,
    ) -> str | None:
        if approval is None:
            return "approval_missing"
        if approval.used:
            return "approval_consumed"
        if approval.expires_at <= self.now:
            return "approval_expired"
        if len(set(approval.approver_ids)) < requirement.approval_count:
            return "approval_count_insufficient"
        forbidden_approvers = {session.subject_id, session.agent_id}
        if forbidden_approvers & set(approval.approver_ids):
            return "separation_of_duties_violated"
        if (
            approval.proposal_digest != proposal_hash
            or approval.subject_id != session.subject_id
            or approval.tenant_id != session.tenant_id
            or approval.agent_id != session.agent_id
            or approval.task_id != session.task_id
            or approval.risk_score != risk.score
            or approval.policy_version != POLICY_VERSION
            or approval.risk_model_version != risk.model_version
            or approval.signal_version != risk.signal_version
            or approval.resource_version != (resource.version if resource else -1)
        ):
            return "approval_binding_invalid"
        return None

    def record_approval(
        self,
        compact_token: str,
        raw_args: Mapping[str, Any],
        *,
        approver_ids: tuple[str, ...] = ("manager:bob",),
        approval_id: str = "approval-001",
    ) -> ApprovalReceipt:
        """Simulate a trusted approval service recording exact informed consent."""

        session = self.verifier.verify(compact_token)
        args = self.parse_args(
            "payment.create", {**raw_args, "approval_id": approval_id}
        )
        eligibility, resource = self._eligible(session, "payment.create", args)
        if eligibility or resource is None:
            raise LabError("proposal_ineligible_for_approval")
        risk = self.risk_engine.assess(
            "payment.create", args, resource, self.task, self.signals
        )
        receipt = ApprovalReceipt(
            approval_id,
            digest(proposal_document("payment.create", args, session)),
            approver_ids,
            session.subject_id,
            session.tenant_id,
            session.agent_id,
            session.task_id,
            risk.score,
            POLICY_VERSION,
            risk.model_version,
            risk.signal_version,
            resource.version,
            self.now + 180,
        )
        with self._lock:
            self.approvals[approval_id] = receipt
        return receipt

    def begin_user_step_up(
        self, compact_token: str, action: str, raw_args: Mapping[str, Any]
    ) -> tuple[StepUpTransaction, str]:
        decision = self.authorize(compact_token, action, raw_args)
        if decision.outcome is not Outcome.USER_STEP_UP or not decision.challenge:
            raise LabError("user_step_up_not_required")
        session = self.verifier.verify(compact_token)
        handle = (
            "stepup-"
            + digest({"p": decision.proposal_digest, "jti": session.token_id})[:24]
        )
        transaction = StepUpTransaction(
            handle,
            decision.proposal_digest,
            session.subject_id,
            session.tenant_id,
            session.agent_id,
            session.client_id,
            session.task_id,
            decision.challenge,
            self.now + 300,
        )
        self.stepup_transactions[handle] = transaction
        params = {
            "client_id": session.client_id,
            "response_type": "code",
            "redirect_uri": "https://client.northstar.example/callback",
            "scope": "openid",
            "state": handle,
            **decision.challenge.authorization_parameters(),
        }
        return transaction, f"{ISSUER}/authorize?{urlencode(params)}"

    def complete_user_step_up(self, handle: str, stepped_token: str) -> UserSession:
        transaction = self.stepup_transactions.get(handle)
        if not transaction or transaction.expires_at <= self.now:
            raise LabError("step_up_transaction_invalid")
        if transaction.used:
            raise LabError("step_up_transaction_consumed")
        session = self.verifier.verify(stepped_token)
        if (
            session.subject_id != transaction.subject_id
            or session.tenant_id != transaction.tenant_id
            or session.agent_id != transaction.agent_id
            or session.client_id != transaction.client_id
            or session.task_id != transaction.task_id
        ):
            raise LabError("step_up_identity_binding_invalid")
        if session.acr not in transaction.challenge.acr_values:
            raise LabError("step_up_acr_unsatisfied")
        if self.now - session.auth_time > transaction.challenge.max_age:
            raise LabError("step_up_freshness_unsatisfied")
        self.stepup_transactions[handle] = replace(transaction, used=True)
        return session

    def execute(
        self,
        compact_token: str,
        action: str,
        raw_args: Mapping[str, Any],
        *,
        before_commit: Callable[["AuthorizationEngine"], None] | None = None,
        lose_response_after_commit: bool = False,
    ) -> Mapping[str, Any]:
        args = self.parse_args(action, raw_args)
        session = self.verifier.verify(compact_token)
        request_hash = digest(proposal_document(action, args, session))
        operation_id = getattr(args, "operation_id", None)
        with self._lock:
            prior = self._reconcile(operation_id, request_hash)
            if prior is not None:
                return prior
            first = self.authorize(compact_token, action, raw_args)
            if first.outcome not in {Outcome.ALLOW, Outcome.CONSTRAIN}:
                raise LabError(first.reason_codes[0])
        if before_commit:
            before_commit(self)
        with self._lock:
            prior = self._reconcile(operation_id, request_hash)
            if prior is not None:
                return prior
            current = self.authorize(compact_token, action, raw_args)
            if current.outcome not in {Outcome.ALLOW, Outcome.CONSTRAIN}:
                raise LabError(current.reason_codes[0])
            result = self._apply(action, args)
            if operation_id:
                self.operations[operation_id] = ExecutionReceipt(
                    operation_id,
                    request_hash,
                    dict(result),
                    digest(current),
                    self.effect_count,
                )
            approval_id = getattr(args, "approval_id", None)
            if approval_id and approval_id in self.approvals:
                self.approvals[approval_id].used = True
        if lose_response_after_commit:
            raise UnknownOutcome(operation_id or action)
        return result

    def _reconcile(
        self, operation_id: str | None, request_hash: str
    ) -> dict[str, Any] | None:
        if not operation_id or operation_id not in self.operations:
            return None
        prior = self.operations[operation_id]
        if prior.request_digest != request_hash:
            raise LabError("operation_id_conflict")
        return dict(prior.result) | {"reconciled": True}

    def _apply(self, action: str, args: StrictModel) -> dict[str, Any]:
        if action == "faq.search":
            return {"items": ["claims handbook"], "constrained": False}
        if action == "claim.read":
            return {
                "claim_id": CLAIM,
                "classification": self.resource.classification,
                "redacted": False,
            }
        if action == "claim.update":
            self.resource.version += 1
            self.effect_count += 1
            return {
                "claim_id": CLAIM,
                "version": self.resource.version,
                "operation_id": args.operation_id,
            }
        if action == "payment.create":
            self.effect_count += 1
            return {
                "payment_id": "payment-" + digest(args.model_dump(mode="json"))[:12],
                "operation_id": args.operation_id,
                "status": "submitted",
            }
        raise LabError("prohibited_action_not_executable")


@dataclass(frozen=True)
class Scenario:
    case_id: str
    expected: Outcome
    mutation: str


def build_cases() -> list[Scenario]:
    cases = [
        Scenario("valid_faq", Outcome.ALLOW, "valid_faq"),
        Scenario("valid_read", Outcome.ALLOW, "valid_read"),
        Scenario("valid_update", Outcome.ALLOW, "valid_update"),
        Scenario("valid_payment", Outcome.ALLOW, "valid_payment"),
        Scenario("valid_constrained_read", Outcome.CONSTRAIN, "valid_constrained_read"),
        Scenario("low_aal_payment", Outcome.USER_STEP_UP, "low_aal_payment"),
        Scenario("stale_auth_payment", Outcome.USER_STEP_UP, "stale_auth_payment"),
        Scenario("non_phishing_payment", Outcome.USER_STEP_UP, "non_phishing_payment"),
        Scenario(
            "high_payment_needs_aal3", Outcome.USER_STEP_UP, "high_payment_needs_aal3"
        ),
        Scenario(
            "unattested_workload", Outcome.WORKLOAD_STEP_UP, "unattested_workload"
        ),
        Scenario("expired_workload", Outcome.WORKLOAD_STEP_UP, "expired_workload"),
        Scenario("stale_workload", Outcome.WORKLOAD_STEP_UP, "stale_workload"),
        Scenario("approval_missing", Outcome.APPROVAL_REQUIRED, "approval_missing"),
        Scenario("approval_expired", Outcome.APPROVAL_REQUIRED, "approval_expired"),
        Scenario("scope_missing", Outcome.SCOPE_REQUIRED, "scope_missing"),
    ]
    denials = [
        "wrong_signature",
        "unknown_kid",
        "wrong_issuer",
        "wrong_audience",
        "expired_token",
        "untrusted_acr",
        "future_auth_time",
        "subject_substitution",
        "tenant_substitution",
        "agent_substitution",
        "client_substitution",
        "task_substitution",
        "task_inactive",
        "task_expired",
        "action_not_delegated",
        "cross_resource",
        "resource_wrong_owner",
        "resource_wrong_tenant",
        "stale_resource_version",
        "workload_wrong_id",
        "workload_wrong_image",
        "workload_wrong_environment",
        "account_suspended",
        "device_compromised",
        "behavior_source_untrusted",
        "behavior_signal_stale",
        "prompt_injection_write",
        "payment_task_limit",
        "payment_agent_ceiling",
        "prohibited_audit",
        "approval_changed_amount",
        "approval_changed_beneficiary",
        "approval_consumed",
        "approval_wrong_policy",
        "approval_wrong_risk",
        "approval_wrong_resource_version",
        "approval_sod_violation",
        "high_payment_one_approver",
        "extra_argument",
        "wrong_argument_type",
    ]
    return cases + [Scenario(name, Outcome.DENY, name) for name in denials]


def payment_args(**updates: Any) -> dict[str, Any]:
    value = {
        "claim_id": CLAIM,
        "amount_cents": 30_000,
        "currency": "CAD",
        "beneficiary_id": "vendor:clinic",
        "approval_id": "approval-001",
        "operation_id": "op-payment",
    }
    value.update(updates)
    return value


def run_case(case: Scenario, *, hardened: bool = True) -> Outcome:
    if not hardened:
        # Deliberately weak baseline: any parseable session is treated as
        # sufficient assurance and every action is dispatched.
        return Outcome.ALLOW
    issuer = SessionIssuer()
    engine = AuthorizationEngine(issuer)
    action = "claim.read"
    args: dict[str, Any] = {"claim_id": CLAIM}
    token_kwargs: dict[str, Any] = {}
    mutation = case.mutation
    if mutation == "valid_faq":
        action, args = "faq.search", {"query": "claim status"}
    elif mutation in {
        "valid_update",
        "stale_resource_version",
        "prompt_injection_write",
        "behavior_signal_stale",
    }:
        action, args = (
            "claim.update",
            {
                "claim_id": CLAIM,
                "expected_version": 4,
                "note": "reviewed documents",
                "operation_id": "op-update",
            },
        )
    elif mutation in {
        "valid_payment",
        "low_aal_payment",
        "stale_auth_payment",
        "non_phishing_payment",
        "high_payment_needs_aal3",
        "approval_missing",
        "approval_expired",
        "approval_changed_amount",
        "approval_changed_beneficiary",
        "approval_consumed",
        "approval_wrong_policy",
        "approval_wrong_risk",
        "approval_wrong_resource_version",
        "approval_sod_violation",
        "high_payment_one_approver",
        "payment_task_limit",
        "payment_agent_ceiling",
        "scope_missing",
    }:
        action, args = "payment.create", payment_args()
    elif mutation == "prohibited_audit":
        action, args = (
            "audit.disable",
            {"control": "authorization-audit", "operation_id": "op-audit"},
        )
    if mutation == "wrong_signature":
        token_kwargs["private_key"] = SessionIssuer(seed=b"\x55" * 32).private_key
    elif mutation == "unknown_kid":
        token_kwargs["header_kid"] = "caller-key"
    elif mutation == "wrong_issuer":
        token_kwargs["issuer"] = "https://evil.example"
    elif mutation == "wrong_audience":
        token_kwargs["audience"] = "https://other.example"
    elif mutation == "expired_token":
        token_kwargs["expires_at"] = NOW - 1
    elif mutation == "untrusted_acr":
        token_kwargs["acr"] = "urn:caller:aal99"
    elif mutation == "future_auth_time":
        token_kwargs["auth_time"] = NOW + 120
    elif mutation == "subject_substitution":
        token_kwargs["subject_id"] = "user:mallory"
    elif mutation == "tenant_substitution":
        token_kwargs["tenant_id"] = "tenant:evil"
    elif mutation == "agent_substitution":
        token_kwargs["agent_id"] = "agent:evil"
    elif mutation == "client_substitution":
        token_kwargs["client_id"] = "client:evil"
    elif mutation == "task_substitution":
        token_kwargs["task_id"] = "task:evil"
    elif mutation == "low_aal_payment":
        token_kwargs["acr"] = ACR_AAL1
    elif mutation == "stale_auth_payment":
        token_kwargs["auth_time"] = NOW - 1_000
    elif mutation == "non_phishing_payment":
        token_kwargs["acr"] = ACR_AAL2
    elif mutation == "high_payment_needs_aal3":
        args["amount_cents"] = 1_500_000
    elif mutation == "scope_missing":
        token_kwargs["scopes"] = ("claims:read",)
    token = issuer.issue(**token_kwargs)
    if mutation == "valid_constrained_read":
        engine.resource.classification = "restricted"
        engine.signals.behavior_score = 15
    elif mutation == "task_inactive":
        engine.task.active = False
    elif mutation == "task_expired":
        engine.task.expires_at = NOW
    elif mutation == "action_not_delegated":
        engine.task.actions = frozenset({"faq.search"})
    elif mutation == "cross_resource":
        args["claim_id"] = "claim:clm-999"
    elif mutation == "resource_wrong_owner":
        engine.resource.owner_id = "user:mallory"
    elif mutation == "resource_wrong_tenant":
        engine.resource.tenant_id = "tenant:evil"
    elif mutation == "stale_resource_version":
        args["expected_version"] = 3
    elif mutation == "workload_wrong_id":
        engine.workload.workload_id = "spiffe://evil.example/workload"
    elif mutation == "workload_wrong_image":
        engine.workload.image_digest = "sha256:unapproved"
    elif mutation == "workload_wrong_environment":
        engine.workload.environment = "dev"
    elif mutation == "unattested_workload":
        engine.workload.attested = False
    elif mutation == "expired_workload":
        engine.workload.expires_at = NOW
    elif mutation == "stale_workload":
        engine.workload.observed_at = NOW - 2_000
    elif mutation == "account_suspended":
        engine.signals.account_state = "suspended"
    elif mutation == "device_compromised":
        engine.signals.device_state = "compromised"
    elif mutation == "behavior_source_untrusted":
        engine.signals.behavior_source = "caller:self-report"
    elif mutation == "behavior_signal_stale":
        engine.signals.behavior_observed_at = NOW - 1_000
    elif mutation == "prompt_injection_write":
        engine.signals.prompt_injection_score = 0.95
    elif mutation == "payment_task_limit":
        args["amount_cents"] = engine.task.max_payment_cents + 1
    elif mutation == "payment_agent_ceiling":
        engine.task.max_payment_cents = 10_000_000
        args["amount_cents"] = 5_000_001
        token = issuer.issue(acr=ACR_AAL3)
    elif mutation == "extra_argument":
        args["admin"] = True
    elif mutation == "wrong_argument_type":
        args["claim_id"] = 100
    if action == "payment.create" and mutation not in {
        "approval_missing",
        "payment_task_limit",
        "payment_agent_ceiling",
        "scope_missing",
        "low_aal_payment",
        "stale_auth_payment",
        "non_phishing_payment",
        "high_payment_needs_aal3",
    }:
        approval_input = dict(args)
        approval_input.pop("approval_id")
        approvers = ("manager:bob",)
        engine.record_approval(token, approval_input, approver_ids=approvers)
        approval = engine.approvals["approval-001"]
        if mutation == "approval_expired":
            approval.expires_at = NOW
        elif mutation == "approval_changed_amount":
            args["amount_cents"] += 1
        elif mutation == "approval_changed_beneficiary":
            args["beneficiary_id"] = "vendor:attacker"
            token = issuer.issue(acr=ACR_AAL3)
        elif mutation == "approval_consumed":
            approval.used = True
        elif mutation == "approval_wrong_policy":
            approval.policy_version -= 1
        elif mutation == "approval_wrong_risk":
            approval.risk_score -= 1
        elif mutation == "approval_wrong_resource_version":
            approval.resource_version -= 1
        elif mutation == "approval_sod_violation":
            approval.approver_ids = (SUBJECT,)
        elif mutation == "high_payment_one_approver":
            args["amount_cents"] = 1_500_000
            token = issuer.issue(acr=ACR_AAL3)
            approval_input = dict(args)
            approval_input.pop("approval_id")
            engine.record_approval(token, approval_input, approver_ids=("manager:bob",))
    try:
        return engine.authorize(token, action, args).outcome
    except LabError:
        return Outcome.DENY


@dataclass(frozen=True)
class EvaluationMetrics:
    total: int
    matches: int
    invalid_allows: int
    valid_work_blocked: int
    by_outcome: Mapping[str, int]


def evaluate(
    cases: list[Scenario], *, hardened: bool = True
) -> tuple[EvaluationMetrics, list[dict[str, Any]]]:
    rows = []
    for case in cases:
        observed = run_case(case, hardened=hardened)
        rows.append(
            {
                "case_id": case.case_id,
                "expected": case.expected.value,
                "observed": observed.value,
                "match": observed is case.expected,
            }
        )
    invalid_allows = sum(
        row["expected"] == Outcome.DENY.value
        and row["observed"] in {Outcome.ALLOW.value, Outcome.CONSTRAIN.value}
        for row in rows
    )
    valid_work_blocked = sum(
        row["expected"] in {Outcome.ALLOW.value, Outcome.CONSTRAIN.value}
        and row["observed"] == Outcome.DENY.value
        for row in rows
    )
    by_outcome = {
        outcome.value: sum(row["observed"] == outcome.value for row in rows)
        for outcome in Outcome
    }
    return EvaluationMetrics(
        len(rows),
        sum(row["match"] for row in rows),
        invalid_allows,
        valid_work_blocked,
        by_outcome,
    ), rows


def release_gate(metrics: EvaluationMetrics) -> bool:
    return (
        metrics.matches == metrics.total
        and metrics.invalid_allows == 0
        and metrics.valid_work_blocked == 0
    )


def fixture(**token_kwargs: Any) -> tuple[SessionIssuer, AuthorizationEngine, str]:
    issuer = SessionIssuer()
    engine = AuthorizationEngine(issuer)
    return issuer, engine, issuer.issue(**token_kwargs)


def main() -> None:
    metrics, _ = evaluate(build_cases())
    print(canonical(metrics))
    print("release_gate", "PASS" if release_gate(metrics) else "FAIL")


if __name__ == "__main__":
    main()
