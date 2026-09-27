"""Deterministic RFC 8693 teaching lab for agent delegation.

This is an offline security simulator, not a production authorization server.
It demonstrates protocol validation, issuer-qualified actor chains, authority
attenuation, exact approvals, idempotency, revocation, and sender binding.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from enum import Enum
import base64
import hashlib
import json
from threading import Lock
from typing import Callable, Iterable, Mapping

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


NOW = datetime(2026, 9, 27, 16, 0, tzinfo=timezone.utc)
USER_ISSUER = "https://login.northstar.example"
ACTOR_ISSUER = "https://workload.northstar.example"
BROKER_ISSUER = "https://sts.northstar.example"
BROKER_AUDIENCE = "https://sts.northstar.example/token"
TRAVEL_API = "https://api.northstar.example/travel"
FLIGHT_API = "https://api.northstar.example/flights"
LEGACY_API = "https://legacy.northstar.example/travel"
PAYMENT_API = "https://api.northstar.example/payments"
ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"
ACTOR_TOKEN_TYPE = "urn:northstar:params:oauth:token-type:actor-credential"
ID_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:id_token"
TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"
CLIENT_ID = "northstar-agent-platform"
TENANT_ID = "tenant:northstar"
USER_ID = "user:alice"
SUPERVISOR = "agent:travel-supervisor"
SPECIALIST = "agent:flight-specialist"
SUPERVISOR_WORKLOAD = "spiffe://northstar.example/prod/agent/travel-supervisor"
SPECIALIST_WORKLOAD = "spiffe://northstar.example/prod/agent/flight-specialist"
TASK_ID = "task:trip-483"
FAMILY_ID = "delegation:trip-483:v3"
POLICY_VERSION = "token-exchange-policy:2026-09-27.1"


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def stable_value(label: str, length: int = 32) -> str:
    return b64url(hashlib.sha256(label.encode()).digest())[:length]


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def timestamp(value: datetime) -> int:
    return int(value.timestamp())


def canonical_digest(value: Mapping[str, object]) -> str:
    return digest(json.dumps(value, sort_keys=True, separators=(",", ":"), default=list))


class ProtocolError(Exception):
    def __init__(self, reason_code: str):
        super().__init__(reason_code)
        self.reason_code = reason_code


class KeyState(str, Enum):
    ACTIVE = "active"
    RETIRING = "retiring"
    REVOKED = "revoked"


class Semantics(str, Enum):
    DELEGATION = "delegation"
    IMPERSONATION = "impersonation"


@dataclass(frozen=True)
class SigningKey:
    kid: str
    private_key: ed25519.Ed25519PrivateKey
    state: KeyState

    @property
    def public_key(self) -> ed25519.Ed25519PublicKey:
        return self.private_key.public_key()


class KeyRing:
    def __init__(self, issuer: str, label: str):
        self.issuer = issuer
        self.keys = {
            f"{label}-active": SigningKey(
                f"{label}-active",
                ed25519.Ed25519PrivateKey.from_private_bytes(hashlib.sha256(f"{label}:active".encode()).digest()),
                KeyState.ACTIVE,
            ),
            f"{label}-retiring": SigningKey(
                f"{label}-retiring",
                ed25519.Ed25519PrivateKey.from_private_bytes(hashlib.sha256(f"{label}:retiring".encode()).digest()),
                KeyState.RETIRING,
            ),
            f"{label}-revoked": SigningKey(
                f"{label}-revoked",
                ed25519.Ed25519PrivateKey.from_private_bytes(hashlib.sha256(f"{label}:revoked".encode()).digest()),
                KeyState.REVOKED,
            ),
        }
        self.active_kid = f"{label}-active"

    def active(self) -> SigningKey:
        return self.keys[self.active_kid]

    def verification_key(self, kid: object) -> ed25519.Ed25519PublicKey:
        if not isinstance(kid, str) or kid not in self.keys:
            raise ProtocolError("token_key_untrusted")
        key = self.keys[kid]
        if key.state is KeyState.REVOKED:
            raise ProtocolError("token_key_revoked")
        return key.public_key

    def jwks(self) -> dict[str, object]:
        values = []
        for key in self.keys.values():
            if key.state is KeyState.REVOKED:
                continue
            raw = key.public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            values.append({"kty": "OKP", "crv": "Ed25519", "x": b64url(raw), "kid": key.kid, "alg": "EdDSA", "use": "sig"})
        return {"keys": values}


class TokenCodec:
    def __init__(self, rings: Mapping[str, KeyRing], now: datetime = NOW):
        self.rings = dict(rings)
        self.now = now

    def issue(
        self,
        issuer: str,
        subject: str,
        audience: str,
        token_typ: str,
        lifetime: int,
        claims: Mapping[str, object],
        *,
        kid: str | None = None,
    ) -> str:
        ring = self.rings[issuer]
        key = ring.keys[kid] if kid else ring.active()
        payload = {
            "iss": issuer,
            "sub": subject,
            "aud": audience,
            "iat": timestamp(self.now),
            "nbf": timestamp(self.now),
            "exp": timestamp(self.now + timedelta(seconds=lifetime)),
            "jti": stable_value(f"jti:{issuer}:{subject}:{audience}:{token_typ}:{canonical_digest(dict(claims))}", 28),
            **claims,
        }
        return jwt.encode(payload, key.private_key, algorithm="EdDSA", headers={"kid": key.kid, "typ": token_typ})

    def validate(
        self,
        token: str,
        *,
        issuer: str,
        audience: str,
        token_typ: str,
        max_lifetime: int,
    ) -> dict[str, object]:
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as exc:
            raise ProtocolError("token_malformed") from exc
        if header.get("alg") != "EdDSA" or header.get("typ") != token_typ:
            raise ProtocolError("token_profile_invalid")
        ring = self.rings.get(issuer)
        if not ring:
            raise ProtocolError("token_issuer_untrusted")
        key = ring.verification_key(header.get("kid"))
        try:
            claims = jwt.decode(
                token,
                key,
                algorithms=["EdDSA"],
                issuer=issuer,
                audience=audience,
                options={"verify_exp": False, "verify_iat": False, "verify_nbf": False, "require": ["iss", "sub", "aud", "iat", "exp", "jti"]},
            )
        except jwt.PyJWTError as exc:
            raise ProtocolError("token_signature_or_claim_invalid") from exc
        now = timestamp(self.now)
        iat = claims.get("iat")
        nbf = claims.get("nbf", iat)
        exp = claims.get("exp")
        if not all(isinstance(value, int) for value in (iat, nbf, exp)):
            raise ProtocolError("token_time_invalid")
        if iat > now or nbf > now:
            raise ProtocolError("token_not_yet_valid")
        if exp <= now:
            raise ProtocolError("token_expired")
        if exp - iat > max_lifetime:
            raise ProtocolError("token_lifetime_excessive")
        return claims

    @staticmethod
    def unverified(token: str) -> dict[str, object]:
        try:
            return jwt.decode(token, options={"verify_signature": False, "verify_aud": False, "verify_exp": False})
        except jwt.PyJWTError as exc:
            raise ProtocolError("token_malformed") from exc


@dataclass(frozen=True)
class OAuthClient:
    client_id: str
    tenant_id: str
    active: bool
    audiences: frozenset[str]
    resources: frozenset[str]
    scopes: frozenset[str]
    can_impersonate: bool


@dataclass(frozen=True)
class VerifiedCaller:
    client_id: str
    tenant_id: str
    agent_id: str
    workload_id: str
    attestation_id: str
    verified: bool


@dataclass(frozen=True)
class ActorPolicy:
    agent_id: str
    workload_id: str
    tenant_id: str
    scopes: frozenset[str]
    audiences: frozenset[str]
    resources: frozenset[str]
    actions: frozenset[str]
    max_amount: int
    active: bool = True


@dataclass(frozen=True)
class TaskGrant:
    family_id: str
    subject: str
    tenant_id: str
    task_id: str
    actors: frozenset[str]
    delegation_edges: frozenset[tuple[str, str]]
    audiences: frozenset[str]
    resources: frozenset[str]
    scopes: frozenset[str]
    actions: frozenset[str]
    max_amount: int
    purpose: str
    expires_at: datetime
    max_depth: int
    allow_redelegation: bool
    active: bool = True
    version: int = 3


@dataclass(frozen=True)
class ExchangeRequest:
    operation_id: str
    grant_type: str
    subject_token: str
    subject_token_type: str
    actor_token: str | None
    actor_token_type: str | None
    requested_token_type: str
    audience: str
    resource: str
    requested_scopes: frozenset[str]
    actions: frozenset[str]
    max_amount: int
    purpose: str
    task_id: str
    requested_lifetime: int
    sender_jkt: str
    semantics: Semantics = Semantics.DELEGATION
    request_redelegation: bool = False
    approval_id: str | None = None


@dataclass(frozen=True)
class ExchangeResponse:
    access_token: str
    issued_token_type: str
    token_type: str
    expires_in: int
    scope: str
    exchange_id: str


@dataclass(frozen=True)
class ApprovalReceipt:
    approval_id: str
    operation_id: str
    request_digest: str
    approver: str
    approver_role: str
    issued_at: datetime
    expires_at: datetime
    policy_version: str


@dataclass(frozen=True)
class ExchangeDecision:
    operation_id: str
    exchange_id: str | None
    allowed: bool
    reason_code: str
    subject: str | None
    current_actor: str | None
    actor_history: tuple[str, ...]
    audience: str
    resource: str
    scopes: tuple[str, ...]
    task_id: str
    family_id: str | None
    policy_version: str
    subject_token_digest: str
    actor_token_digest: str | None
    approval_id: str | None


class ApprovalStore:
    def __init__(self):
        self.receipts: dict[str, ApprovalReceipt] = {}
        self.consumed: set[str] = set()
        self._lock = Lock()

    def add(self, receipt: ApprovalReceipt) -> None:
        self.receipts[receipt.approval_id] = receipt

    def consume(self, approval_id: str | None, request: ExchangeRequest, now: datetime) -> None:
        if not approval_id or approval_id not in self.receipts:
            raise ProtocolError("approval_missing")
        with self._lock:
            receipt = self.receipts[approval_id]
            if approval_id in self.consumed:
                raise ProtocolError("approval_replayed")
            if receipt.operation_id != request.operation_id or receipt.request_digest != exchange_request_digest(request):
                raise ProtocolError("approval_request_mismatch")
            if receipt.approver_role != "travel-risk-approver" or receipt.policy_version != POLICY_VERSION:
                raise ProtocolError("approval_authority_invalid")
            if receipt.issued_at > now or receipt.expires_at <= now:
                raise ProtocolError("approval_expired")
            self.consumed.add(approval_id)


def exchange_request_digest(request: ExchangeRequest) -> str:
    return canonical_digest(
        {
            "operation_id": request.operation_id,
            "subject_token_digest": digest(request.subject_token),
            "actor_token_digest": digest(request.actor_token) if request.actor_token else None,
            "audience": request.audience,
            "resource": request.resource,
            "scopes": sorted(request.requested_scopes),
            "actions": sorted(request.actions),
            "max_amount": request.max_amount,
            "purpose": request.purpose,
            "task_id": request.task_id,
            "lifetime": request.requested_lifetime,
            "sender_jkt": request.sender_jkt,
            "semantics": request.semantics.value,
            "redelegation": request.request_redelegation,
        }
    )


def actor_chain(claims: Mapping[str, object], max_nodes: int = 8) -> tuple[str, ...]:
    node = claims.get("act")
    result: list[str] = []
    seen: set[tuple[str, str]] = set()
    while node is not None:
        if not isinstance(node, dict) or not isinstance(node.get("iss"), str) or not isinstance(node.get("sub"), str):
            raise ProtocolError("actor_chain_invalid")
        identity = (node["iss"], node["sub"])
        if identity in seen:
            raise ProtocolError("actor_chain_cycle")
        seen.add(identity)
        result.append(node["sub"])
        if len(result) > max_nodes:
            raise ProtocolError("actor_chain_too_deep")
        node = node.get("act")
    return tuple(result)


def build_actor_claim(current: str, prior: object | None) -> dict[str, object]:
    value: dict[str, object] = {"iss": ACTOR_ISSUER, "sub": current}
    if prior is not None:
        value["act"] = prior
    return value


class TokenBroker:
    def __init__(
        self,
        codec: TokenCodec,
        client: OAuthClient,
        actors: Mapping[str, ActorPolicy],
        grant: TaskGrant,
        approvals: ApprovalStore,
        now: datetime = NOW,
    ):
        self.codec = codec
        self.client = client
        self.actors = dict(actors)
        self.grant = grant
        self.approvals = approvals
        self.now = now
        self.revoked_families: set[str] = set()
        self.operation_ledger: dict[str, tuple[str, ExchangeResponse]] = {}
        self.audit: list[ExchangeDecision] = []
        self._lock = Lock()

    def _deny(self, request: ExchangeRequest, reason: str, subject: str | None = None, actor: str | None = None, history: tuple[str, ...] = ()) -> None:
        self.audit.append(
            ExchangeDecision(
                request.operation_id, None, False, reason, subject, actor, history,
                request.audience, request.resource, tuple(sorted(request.requested_scopes)),
                request.task_id, self.grant.family_id, POLICY_VERSION,
                digest(request.subject_token), digest(request.actor_token) if request.actor_token else None,
                request.approval_id,
            )
        )
        raise ProtocolError(reason)

    def exchange(self, request: ExchangeRequest, caller: VerifiedCaller) -> ExchangeResponse:
        request_hash = exchange_request_digest(request)
        with self._lock:
            previous = self.operation_ledger.get(request.operation_id)
            if previous:
                if previous[0] != request_hash:
                    self._deny(request, "operation_id_conflict")
                return previous[1]
            try:
                response, subject, actor, history = self._exchange_once(request, caller)
            except ProtocolError as exc:
                if not self.audit or self.audit[-1].operation_id != request.operation_id:
                    self._deny(request, exc.reason_code)
                raise
            self.operation_ledger[request.operation_id] = (request_hash, response)
            self.audit.append(
                ExchangeDecision(
                    request.operation_id, response.exchange_id, True, "exchange_issued", subject, actor,
                    history, request.audience, request.resource, tuple(sorted(request.requested_scopes)),
                    request.task_id, self.grant.family_id, POLICY_VERSION, digest(request.subject_token),
                    digest(request.actor_token) if request.actor_token else None, request.approval_id,
                )
            )
            return response

    def _exchange_once(self, request: ExchangeRequest, caller: VerifiedCaller) -> tuple[ExchangeResponse, str, str, tuple[str, ...]]:
        if request.grant_type != TOKEN_EXCHANGE_GRANT:
            raise ProtocolError("grant_type_invalid")
        if request.subject_token_type != ACCESS_TOKEN_TYPE:
            raise ProtocolError("subject_token_type_unsupported")
        if request.requested_token_type != ACCESS_TOKEN_TYPE:
            raise ProtocolError("requested_token_type_unsupported")
        if not self.client.active:
            raise ProtocolError("client_inactive")
        if not caller.verified:
            raise ProtocolError("caller_unverified")
        if caller.client_id != self.client.client_id or caller.tenant_id != self.client.tenant_id:
            raise ProtocolError("caller_client_or_tenant_mismatch")
        caller_policy = self.actors.get(caller.agent_id)
        if not caller_policy or not caller_policy.active or caller_policy.workload_id != caller.workload_id:
            raise ProtocolError("caller_workload_not_bound")

        # Initial user tokens are intended for the broker. Broker-issued child
        # tokens may be re-exchanged only by their recorded current actor.
        unverified = self.codec.unverified(request.subject_token)
        subject_issuer = unverified.get("iss")
        if subject_issuer == USER_ISSUER:
            subject = self.codec.validate(request.subject_token, issuer=USER_ISSUER, audience=BROKER_AUDIENCE, token_typ="at+jwt", max_lifetime=3600)
        elif subject_issuer == BROKER_ISSUER:
            expected_audience = unverified.get("aud")
            if not isinstance(expected_audience, str):
                raise ProtocolError("subject_audience_invalid")
            subject = self.codec.validate(request.subject_token, issuer=BROKER_ISSUER, audience=expected_audience, token_typ="at+jwt", max_lifetime=300)
            if not subject.get("exchangeable"):
                raise ProtocolError("subject_not_exchangeable")
        else:
            raise ProtocolError("subject_issuer_untrusted")

        if request.actor_token_type != ACTOR_TOKEN_TYPE or not request.actor_token:
            raise ProtocolError("actor_token_required_or_unsupported")
        actor_claims = self.codec.validate(request.actor_token, issuer=ACTOR_ISSUER, audience=BROKER_AUDIENCE, token_typ="actor+jwt", max_lifetime=900)
        new_actor = actor_claims["sub"]
        if not isinstance(new_actor, str):
            raise ProtocolError("actor_identity_invalid")
        actor_policy = self.actors.get(new_actor)
        if not actor_policy or not actor_policy.active:
            raise ProtocolError("actor_not_registered")
        if actor_claims.get("client_id") != self.client.client_id or actor_claims.get("tenant_id") != self.client.tenant_id:
            raise ProtocolError("actor_client_or_tenant_mismatch")
        if actor_claims.get("workload_id") != actor_policy.workload_id:
            raise ProtocolError("actor_workload_not_bound")

        subject_id = subject.get("sub")
        if subject_id != self.grant.subject or self.grant.tenant_id != caller.tenant_id:
            raise ProtocolError("subject_or_tenant_not_granted")
        if not self.grant.active or self.grant.expires_at <= self.now:
            raise ProtocolError("delegation_grant_inactive")
        if self.grant.family_id in self.revoked_families:
            raise ProtocolError("delegation_family_revoked")
        if request.task_id != self.grant.task_id:
            raise ProtocolError("task_not_granted")

        history = actor_chain(subject)
        current_actor = history[0] if history else None
        if current_actor:
            if caller.agent_id != current_actor:
                raise ProtocolError("current_presenter_mismatch")
            if not subject.get("redelegation") or not self.grant.allow_redelegation:
                raise ProtocolError("redelegation_forbidden")
            if (current_actor, new_actor) not in self.grant.delegation_edges:
                raise ProtocolError("delegation_edge_forbidden")
        else:
            allowed = subject.get("may_act")
            if not isinstance(allowed, dict) or allowed.get("iss") != ACTOR_ISSUER or allowed.get("sub") != new_actor:
                raise ProtocolError("actor_not_authorized_by_subject")
            if caller.agent_id != new_actor:
                raise ProtocolError("initial_actor_presenter_mismatch")

        depth = len(history) + 1
        if depth > self.grant.max_depth:
            raise ProtocolError("delegation_depth_exceeded")
        if new_actor not in self.grant.actors:
            raise ProtocolError("actor_not_granted")

        parent_scopes = frozenset(subject.get("delegation_scopes", str(subject.get("scope", "")).split()))
        parent_audiences = frozenset(subject.get("delegation_audiences", subject.get("allowed_audiences", [request.audience])))
        parent_resources = frozenset(subject.get("delegation_resources", subject.get("resource_ids", [])))
        parent_actions = frozenset(subject.get("delegation_actions", subject.get("actions", [])))
        parent_amount = int(subject.get("delegation_max_amount", subject.get("max_amount", 0)))
        parent_purpose = subject.get("delegation_purpose", subject.get("purpose"))
        if not request.requested_scopes or not request.requested_scopes <= parent_scopes & self.grant.scopes & actor_policy.scopes & self.client.scopes:
            raise ProtocolError("scope_amplification")
        if request.audience not in parent_audiences & self.grant.audiences & actor_policy.audiences & self.client.audiences:
            raise ProtocolError("audience_amplification")
        if request.resource not in parent_resources & self.grant.resources & actor_policy.resources & self.client.resources:
            raise ProtocolError("resource_amplification")
        if not request.actions or not request.actions <= parent_actions & self.grant.actions & actor_policy.actions:
            raise ProtocolError("action_amplification")
        if request.max_amount < 0 or request.max_amount > min(parent_amount, self.grant.max_amount, actor_policy.max_amount):
            raise ProtocolError("amount_amplification")
        if request.purpose != parent_purpose or request.purpose != self.grant.purpose:
            raise ProtocolError("purpose_mismatch")
        if request.requested_lifetime <= 0:
            raise ProtocolError("requested_lifetime_invalid")

        parent_remaining = int(subject["exp"]) - timestamp(self.now)
        actor_remaining = int(actor_claims["exp"]) - timestamp(self.now)
        grant_remaining = timestamp(self.grant.expires_at) - timestamp(self.now)
        lifetime = min(request.requested_lifetime, parent_remaining, actor_remaining, grant_remaining, 300)
        if lifetime <= 0:
            raise ProtocolError("authority_expired")

        if request.semantics is Semantics.IMPERSONATION:
            if not self.client.can_impersonate or request.audience != LEGACY_API or current_actor:
                raise ProtocolError("impersonation_not_permitted")
            self.approvals.consume(request.approval_id, request, self.now)
            act_value = None
            redelegation = False
        else:
            act_value = build_actor_claim(new_actor, subject.get("act"))
            redelegation = bool(request.request_redelegation and self.grant.allow_redelegation and depth < self.grant.max_depth)

        exchange_id = f"exchange:{stable_value(request.operation_id, 18)}"
        extra: dict[str, object] = {
            "client_id": self.client.client_id,
            "tenant_id": caller.tenant_id,
            "workload_id": actor_policy.workload_id,
            "scope": " ".join(sorted(request.requested_scopes)),
            "allowed_audiences": [request.audience],
            "resource_ids": [request.resource],
            "actions": sorted(request.actions),
            "max_amount": request.max_amount,
            "purpose": request.purpose,
            "task_id": request.task_id,
            "delegation_family": self.grant.family_id,
            "delegation_depth": depth,
            "redelegation": redelegation,
            "exchangeable": redelegation,
            "cnf": {"jkt": request.sender_jkt},
            "policy_version": POLICY_VERSION,
            "grant_version": self.grant.version,
            "exchange_id": exchange_id,
        }
        if act_value is not None:
            extra["act"] = act_value
        if redelegation:
            extra.update(
                {
                    "delegation_scopes": sorted(request.requested_scopes),
                    "delegation_audiences": sorted(parent_audiences & self.grant.audiences & actor_policy.audiences & self.client.audiences),
                    "delegation_resources": sorted(parent_resources & self.grant.resources & actor_policy.resources & self.client.resources),
                    "delegation_actions": sorted(request.actions),
                    "delegation_max_amount": request.max_amount,
                    "delegation_purpose": request.purpose,
                }
            )
        token = self.codec.issue(BROKER_ISSUER, str(subject_id), request.audience, "at+jwt", lifetime, extra)
        return (
            ExchangeResponse(token, ACCESS_TOKEN_TYPE, "Bearer", lifetime, extra["scope"], exchange_id),
            str(subject_id),
            new_actor,
            (new_actor, *history),
        )


class ResourceServer:
    def __init__(self, codec: TokenCodec, audience: str, revoked_families: set[str], now: datetime = NOW):
        self.codec = codec
        self.audience = audience
        self.revoked_families = revoked_families
        self.now = now

    def authorize(
        self,
        token: str,
        *,
        sender_jkt: str,
        resource: str,
        action: str,
        amount: int,
        purpose: str,
        tenant_id: str = TENANT_ID,
        owner: str = USER_ID,
    ) -> dict[str, object]:
        claims = self.codec.validate(token, issuer=BROKER_ISSUER, audience=self.audience, token_typ="at+jwt", max_lifetime=300)
        if claims.get("delegation_family") in self.revoked_families:
            raise ProtocolError("delegation_family_revoked")
        if claims.get("cnf", {}).get("jkt") != sender_jkt:
            raise ProtocolError("sender_binding_mismatch")
        if claims.get("tenant_id") != tenant_id or claims.get("sub") != owner:
            raise ProtocolError("resource_subject_or_tenant_mismatch")
        if resource not in claims.get("resource_ids", []):
            raise ProtocolError("resource_not_authorized")
        if action not in claims.get("actions", []):
            raise ProtocolError("action_not_authorized")
        if amount > int(claims.get("max_amount", -1)):
            raise ProtocolError("amount_not_authorized")
        if claims.get("purpose") != purpose:
            raise ProtocolError("purpose_not_authorized")
        return claims


def default_client(**changes: object) -> OAuthClient:
    value = OAuthClient(
        CLIENT_ID, TENANT_ID, True,
        frozenset({TRAVEL_API, FLIGHT_API, LEGACY_API}),
        frozenset({"trip:483", "flight-search:483"}),
        frozenset({"travel:read", "travel:book", "flights:search"}),
        True,
    )
    return replace(value, **changes)


def default_actors() -> dict[str, ActorPolicy]:
    return {
        SUPERVISOR: ActorPolicy(
            SUPERVISOR, SUPERVISOR_WORKLOAD, TENANT_ID,
            frozenset({"travel:read", "travel:book", "flights:search"}),
            frozenset({TRAVEL_API, FLIGHT_API, LEGACY_API}),
            frozenset({"trip:483", "flight-search:483"}),
            frozenset({"view", "book", "search"}), 1200,
        ),
        SPECIALIST: ActorPolicy(
            SPECIALIST, SPECIALIST_WORKLOAD, TENANT_ID,
            frozenset({"flights:search"}), frozenset({FLIGHT_API}),
            frozenset({"flight-search:483"}), frozenset({"search"}), 0,
        ),
    }


def default_grant(**changes: object) -> TaskGrant:
    value = TaskGrant(
        FAMILY_ID, USER_ID, TENANT_ID, TASK_ID,
        frozenset({SUPERVISOR, SPECIALIST}), frozenset({(SUPERVISOR, SPECIALIST)}),
        frozenset({TRAVEL_API, FLIGHT_API, LEGACY_API}),
        frozenset({"trip:483", "flight-search:483"}),
        frozenset({"travel:read", "travel:book", "flights:search"}),
        frozenset({"view", "book", "search"}), 1000, "book-trip-483",
        NOW + timedelta(minutes=20), 2, True,
    )
    return replace(value, **changes)


class Environment:
    def __init__(self, *, client: OAuthClient | None = None, grant: TaskGrant | None = None):
        self.rings = {
            USER_ISSUER: KeyRing(USER_ISSUER, "user"),
            ACTOR_ISSUER: KeyRing(ACTOR_ISSUER, "actor"),
            BROKER_ISSUER: KeyRing(BROKER_ISSUER, "broker"),
        }
        self.codec = TokenCodec(self.rings)
        self.client = client or default_client()
        self.actors = default_actors()
        self.grant = grant or default_grant()
        self.approvals = ApprovalStore()
        self.broker = TokenBroker(self.codec, self.client, self.actors, self.grant, self.approvals)

    def user_token(self, **overrides: object) -> str:
        claims: dict[str, object] = {
            "client_id": CLIENT_ID,
            "tenant_id": TENANT_ID,
            "scope": "flights:search travel:book travel:read",
            "allowed_audiences": [TRAVEL_API, FLIGHT_API, LEGACY_API],
            "resource_ids": ["trip:483", "flight-search:483"],
            "actions": ["view", "book", "search"],
            "max_amount": 1000,
            "purpose": "book-trip-483",
            "may_act": {"iss": ACTOR_ISSUER, "sub": SUPERVISOR},
        }
        claims.update(overrides.pop("claims", {}))
        return self.codec.issue(
            str(overrides.pop("issuer", USER_ISSUER)), USER_ID,
            str(overrides.pop("audience", BROKER_AUDIENCE)),
            str(overrides.pop("token_typ", "at+jwt")), int(overrides.pop("lifetime", 1800)), claims,
            kid=overrides.pop("kid", None),
        )

    def actor_token(self, actor: str = SUPERVISOR, **overrides: object) -> str:
        policy = self.actors.get(actor)
        workload = policy.workload_id if policy else "spiffe://northstar.example/prod/agent/evil"
        claims: dict[str, object] = {"client_id": CLIENT_ID, "tenant_id": TENANT_ID, "workload_id": workload}
        claims.update(overrides.pop("claims", {}))
        return self.codec.issue(
            ACTOR_ISSUER, actor, BROKER_AUDIENCE, str(overrides.pop("token_typ", "actor+jwt")),
            int(overrides.pop("lifetime", 600)), claims,
        )

    def caller(self, actor: str = SUPERVISOR, **changes: object) -> VerifiedCaller:
        policy = self.actors.get(actor)
        value = VerifiedCaller(CLIENT_ID, TENANT_ID, actor, policy.workload_id if policy else "evil", "attestation:spire:v4", True)
        return replace(value, **changes)

    def request(self, **changes: object) -> ExchangeRequest:
        value = ExchangeRequest(
            "operation:trip-483:travel-token", TOKEN_EXCHANGE_GRANT, self.user_token(), ACCESS_TOKEN_TYPE,
            self.actor_token(), ACTOR_TOKEN_TYPE, ACCESS_TOKEN_TYPE, TRAVEL_API, "trip:483",
            frozenset({"travel:book", "flights:search"}), frozenset({"book", "search"}),
            900, "book-trip-483", TASK_ID, 240, stable_value("supervisor:dpop", 32),
            Semantics.DELEGATION, True, None,
        )
        return replace(value, **changes)

    def approve(self, request: ExchangeRequest, *, role: str = "travel-risk-approver", request_digest: str | None = None) -> ExchangeRequest:
        approval_id = f"approval:{stable_value(request.operation_id, 16)}"
        approved = replace(request, approval_id=approval_id)
        self.approvals.add(
            ApprovalReceipt(
                approval_id, request.operation_id, request_digest or exchange_request_digest(approved),
                "user:risk-manager", role, NOW - timedelta(seconds=10), NOW + timedelta(minutes=2), POLICY_VERSION,
            )
        )
        return approved


def child_attempt(env: Environment, *, grant: TaskGrant | None = None) -> tuple[ExchangeRequest, VerifiedCaller]:
    parent_request = env.request()
    parent = env.broker.exchange(parent_request, env.caller())
    request = env.request(
        operation_id="operation:trip-483:flight-token",
        subject_token=parent.access_token,
        actor_token=env.actor_token(SPECIALIST),
        audience=FLIGHT_API,
        resource="flight-search:483",
        requested_scopes=frozenset({"flights:search"}),
        actions=frozenset({"search"}),
        max_amount=0,
        requested_lifetime=120,
        sender_jkt=stable_value("specialist:dpop", 32),
        request_redelegation=False,
    )
    return request, env.caller(SUPERVISOR)


def impersonation_attempt(env: Environment, *, approve: bool = True, role: str = "travel-risk-approver") -> tuple[ExchangeRequest, VerifiedCaller]:
    request = env.request(
        operation_id="operation:trip-483:legacy-token",
        audience=LEGACY_API,
        requested_scopes=frozenset({"travel:read"}),
        actions=frozenset({"view"}),
        max_amount=0,
        requested_lifetime=60,
        sender_jkt=stable_value("legacy:dpop", 32),
        semantics=Semantics.IMPERSONATION,
        request_redelegation=False,
    )
    if approve:
        request = env.approve(request, role=role)
    return request, env.caller()


@dataclass(frozen=True)
class ScenarioCase:
    case_id: str
    expected_allowed: bool
    category: str


@dataclass(frozen=True)
class Metrics:
    attempts: int
    expected_allowed: int
    expected_blocked: int
    outcome_matches: int
    invalid_acceptances: int
    valid_work_blocked: int
    authority_amplifications: int
    identity_substitutions: int
    replay_or_lifecycle_acceptances: int

    @property
    def accuracy(self) -> float:
        return self.outcome_matches / self.attempts if self.attempts else 0.0


def build_cases() -> tuple[ScenarioCase, ...]:
    valid = [
        ScenarioCase("valid_first_delegation", True, "valid"),
        ScenarioCase("valid_child_delegation", True, "valid"),
        ScenarioCase("valid_impersonation_with_approval", True, "valid"),
        ScenarioCase("valid_exact_idempotent_retry", True, "valid"),
    ]
    blocked = [
        ("wrong_grant_type", "protocol"), ("wrong_subject_token_type", "protocol"),
        ("wrong_requested_token_type", "protocol"), ("id_token_substitution", "identity"),
        ("tampered_subject_token", "identity"), ("wrong_subject_audience", "identity"),
        ("expired_subject_token", "lifecycle"), ("missing_actor_token", "identity"),
        ("wrong_actor_token_type", "identity"), ("actor_substitution", "identity"),
        ("caller_unverified", "identity"), ("client_inactive", "lifecycle"),
        ("caller_workload_mismatch", "identity"), ("caller_tenant_mismatch", "identity"),
        ("scope_amplification", "authority"), ("audience_amplification", "authority"),
        ("resource_amplification", "authority"), ("action_amplification", "authority"),
        ("amount_amplification", "authority"), ("purpose_substitution", "authority"),
        ("redelegation_forbidden", "authority"), ("delegation_depth_exceeded", "authority"),
        ("presenter_substitution", "identity"), ("delegation_family_revoked", "lifecycle"),
        ("approval_missing", "authority"), ("approval_wrong_request", "authority"),
        ("approval_wrong_role", "authority"), ("operation_id_conflict", "replay"),
        ("sender_binding_mismatch", "replay"),
    ]
    return tuple(valid + [ScenarioCase(case_id, False, category) for case_id, category in blocked])


def prepare_case(case_id: str) -> tuple[Environment, ExchangeRequest, VerifiedCaller, Callable[[ExchangeResponse], None] | None]:
    env = Environment()
    request = env.request()
    caller = env.caller()
    postcheck = None
    if case_id == "valid_first_delegation":
        pass
    elif case_id == "valid_child_delegation":
        request, caller = child_attempt(env)
    elif case_id == "valid_impersonation_with_approval":
        request, caller = impersonation_attempt(env)
    elif case_id == "valid_exact_idempotent_retry":
        first = env.broker.exchange(request, caller)
        postcheck = lambda response: (_ for _ in ()).throw(ProtocolError("idempotency_changed")) if response != first else None
    elif case_id == "wrong_grant_type":
        request = replace(request, grant_type="authorization_code")
    elif case_id == "wrong_subject_token_type":
        request = replace(request, subject_token_type=ID_TOKEN_TYPE)
    elif case_id == "wrong_requested_token_type":
        request = replace(request, requested_token_type=ID_TOKEN_TYPE)
    elif case_id == "id_token_substitution":
        request = replace(request, subject_token=env.user_token(token_typ="JWT"))
    elif case_id == "tampered_subject_token":
        token = request.subject_token
        request = replace(request, subject_token=token[:-1] + ("A" if token[-1] != "A" else "B"))
    elif case_id == "wrong_subject_audience":
        request = replace(request, subject_token=env.user_token(audience=PAYMENT_API))
    elif case_id == "expired_subject_token":
        request = replace(request, subject_token=env.user_token(lifetime=-1))
    elif case_id == "missing_actor_token":
        request = replace(request, actor_token=None, actor_token_type=None)
    elif case_id == "wrong_actor_token_type":
        request = replace(request, actor_token_type=ACCESS_TOKEN_TYPE)
    elif case_id == "actor_substitution":
        request = replace(request, actor_token=env.actor_token("agent:evil"))
    elif case_id == "caller_unverified":
        caller = env.caller(verified=False)
    elif case_id == "client_inactive":
        env = Environment(client=default_client(active=False)); request = env.request(); caller = env.caller()
    elif case_id == "caller_workload_mismatch":
        caller = env.caller(workload_id="spiffe://northstar.example/dev/agent/travel-supervisor")
    elif case_id == "caller_tenant_mismatch":
        caller = env.caller(tenant_id="tenant:other")
    elif case_id == "scope_amplification":
        request = replace(request, requested_scopes=frozenset({"admin"}))
    elif case_id == "audience_amplification":
        request = replace(request, audience=PAYMENT_API)
    elif case_id == "resource_amplification":
        request = replace(request, resource="tenant:all")
    elif case_id == "action_amplification":
        request = replace(request, actions=frozenset({"refund"}))
    elif case_id == "amount_amplification":
        request = replace(request, max_amount=5000)
    elif case_id == "purpose_substitution":
        request = replace(request, purpose="export-customer-data")
    elif case_id == "redelegation_forbidden":
        env = Environment(grant=default_grant(allow_redelegation=False)); request, caller = child_attempt(env)
    elif case_id == "delegation_depth_exceeded":
        env = Environment(grant=default_grant(max_depth=1)); request, caller = child_attempt(env)
    elif case_id == "presenter_substitution":
        request, _ = child_attempt(env); caller = env.caller(SPECIALIST)
    elif case_id == "delegation_family_revoked":
        env.broker.revoked_families.add(FAMILY_ID)
    elif case_id == "approval_missing":
        request, caller = impersonation_attempt(env, approve=False)
    elif case_id == "approval_wrong_request":
        request, caller = impersonation_attempt(env, approve=False)
        approved = env.approve(request)
        request = replace(approved, max_amount=1)
    elif case_id == "approval_wrong_role":
        request, caller = impersonation_attempt(env, role="travel-agent")
    elif case_id == "operation_id_conflict":
        env.broker.exchange(request, caller)
        request = replace(request, requested_scopes=frozenset({"travel:read"}))
    elif case_id == "sender_binding_mismatch":
        def check(response: ExchangeResponse) -> None:
            ResourceServer(env.codec, TRAVEL_API, env.broker.revoked_families).authorize(
                response.access_token, sender_jkt="attacker-key", resource="trip:483", action="book",
                amount=900, purpose="book-trip-483",
            )
        postcheck = check
    else:
        raise KeyError(case_id)
    return env, request, caller, postcheck


def unsafe_claim_copy_baseline(request: ExchangeRequest) -> bool:
    """Intentionally unsafe: trusts unverified claims and checks only scope."""
    try:
        claims = TokenCodec.unverified(request.subject_token)
        parent_scopes = frozenset(str(claims.get("scope", "")).split())
        return bool(request.requested_scopes) and request.requested_scopes <= parent_scopes
    except ProtocolError:
        return False


def evaluate(cases: Iterable[ScenarioCase], *, hardened: bool) -> tuple[Metrics, list[tuple[ScenarioCase, bool, str]]]:
    rows: list[tuple[ScenarioCase, bool, str]] = []
    for case in cases:
        env, request, caller, postcheck = prepare_case(case.case_id)
        if hardened:
            try:
                response = env.broker.exchange(request, caller)
                if postcheck:
                    postcheck(response)
                allowed, reason = True, "allowed"
            except ProtocolError as exc:
                allowed, reason = False, exc.reason_code
        else:
            allowed = unsafe_claim_copy_baseline(request)
            reason = "scope_only_allow" if allowed else "scope_only_deny"
        rows.append((case, allowed, reason))
    attempts = len(rows)
    expected_allowed = sum(case.expected_allowed for case, _, _ in rows)
    expected_blocked = attempts - expected_allowed
    outcome_matches = sum(allowed == case.expected_allowed for case, allowed, _ in rows)
    invalid_acceptances = sum(not case.expected_allowed and allowed for case, allowed, _ in rows)
    valid_work_blocked = sum(case.expected_allowed and not allowed for case, allowed, _ in rows)
    authority_amplifications = sum(case.category == "authority" and allowed for case, allowed, _ in rows)
    identity_substitutions = sum(case.category == "identity" and allowed for case, allowed, _ in rows)
    replay_or_lifecycle = sum(case.category in {"replay", "lifecycle"} and allowed for case, allowed, _ in rows)
    return Metrics(attempts, expected_allowed, expected_blocked, outcome_matches, invalid_acceptances, valid_work_blocked, authority_amplifications, identity_substitutions, replay_or_lifecycle), rows


def release_gate(metrics: Metrics) -> bool:
    return (
        metrics.attempts == 33
        and metrics.outcome_matches == metrics.attempts
        and metrics.invalid_acceptances == 0
        and metrics.valid_work_blocked == 0
        and metrics.authority_amplifications == 0
        and metrics.identity_substitutions == 0
        and metrics.replay_or_lifecycle_acceptances == 0
    )


def public_decision(decision: ExchangeDecision) -> dict[str, object]:
    return {
        "operation_id": decision.operation_id,
        "exchange_id": decision.exchange_id,
        "allowed": decision.allowed,
        "reason_code": decision.reason_code,
        "subject": decision.subject,
        "current_actor": decision.current_actor,
        "actor_history": list(decision.actor_history),
        "audience": decision.audience,
        "resource": decision.resource,
        "scopes": list(decision.scopes),
        "task_id": decision.task_id,
        "family_id": decision.family_id,
        "policy_version": decision.policy_version,
        "subject_token_digest": decision.subject_token_digest,
        "actor_token_digest": decision.actor_token_digest,
        "approval_id": decision.approval_id,
    }


if __name__ == "__main__":
    for hardened in (False, True):
        metrics, rows = evaluate(build_cases(), hardened=hardened)
        print("hardened" if hardened else "scope-only baseline", metrics)
        if hardened:
            print("release_gate", release_gate(metrics))
            for case, allowed, reason in rows:
                print(f"{case.case_id:36} expected={case.expected_allowed!s:5} allowed={allowed!s:5} {reason}")
