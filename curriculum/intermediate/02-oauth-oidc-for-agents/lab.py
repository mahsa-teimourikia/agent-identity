"""Deterministic OAuth/OIDC security lab for Intermediate 02.

Northstar Travel uses an interactive OAuth client for Alice's booking agent and
a machine client for inventory synchronization. This credential-free simulator
models the controls around an authorization server, token broker, DPoP-bound
client, and resource server. It is not an OAuth/OIDC provider or conformance
suite; production systems should use maintained protocol implementations.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from enum import Enum
import hashlib
import hmac
import json
from threading import Lock
from typing import Iterable, Mapping
from urllib.parse import urlsplit

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


NOW = datetime(2026, 9, 27, 17, 0, tzinfo=timezone.utc)
ISSUER = "https://id.northstar.example"
TRAVEL_API = "https://api.northstar.example/travel"
PAYMENT_API = "https://api.northstar.example/payments"
MCP_RESOURCE = "https://mcp.northstar.example/mcp"
CLIENT_ID = "client:northstar:travel-agent-ui"
AGENT_ID = "agent:northstar:travel-booking"
WORKLOAD_ID = "spiffe://corp.example/ns/travel/sa/booking-agent"
TENANT_ID = "tenant:northstar"
USER_ID = "user:alice"
POLICY_VERSION = "oauth-agent/2026-09-27.1"


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def digest_text(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode()).hexdigest()


def stable_value(label: str, length: int = 32) -> str:
    """Deterministic fixture value. Production state/nonces use a CSPRNG."""

    return b64url(hashlib.sha256(label.encode()).digest())[:length]


def canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


class Outcome(str, Enum):
    ALLOW = "allow"
    DENY = "deny"


class KeyState(str, Enum):
    ACTIVE = "active"
    RETIRING = "retiring"
    REVOKED = "revoked"


class TokenKind(str, Enum):
    ACCESS = "access_token"
    ID = "id_token"


@dataclass(frozen=True)
class SigningKey:
    kid: str
    private_key: ed25519.Ed25519PrivateKey
    state: KeyState

    @property
    def public_key(self) -> ed25519.Ed25519PublicKey:
        return self.private_key.public_key()


@dataclass(frozen=True)
class OAuthClient:
    client_id: str
    redirect_uris: frozenset[str]
    allowed_resources: frozenset[str]
    allowed_scopes: frozenset[str]
    agent_id: str
    workload_id: str
    tenant_id: str
    active: bool = True


@dataclass(frozen=True)
class VerifiedWorkload:
    """Trusted context created by workload authentication middleware."""

    workload_id: str
    client_id: str
    agent_id: str
    tenant_id: str
    evidence_id: str
    active: bool = True


@dataclass(frozen=True)
class DelegationGrant:
    grant_id: str
    subject: str
    tenant_id: str
    agent_id: str
    task_id: str
    resources: frozenset[str]
    scopes: frozenset[str]
    expires_at: datetime
    active: bool = True


@dataclass(frozen=True)
class AuthorizationTransaction:
    transaction_id: str
    client_id: str
    redirect_uri: str
    expected_issuer: str
    state_digest: str
    nonce_digest: str
    pkce_challenge: str
    resource: str
    scopes: frozenset[str]
    subject: str
    task_id: str
    expires_at: datetime
    consumed: bool = False


@dataclass(frozen=True)
class AuthorizationStart:
    transaction_id: str
    state: str
    nonce: str
    code_verifier: str
    code_challenge: str
    resource: str
    scopes: tuple[str, ...]


@dataclass(frozen=True)
class AuthorizationResponse:
    transaction_id: str
    code: str
    state: str
    issuer: str


@dataclass(frozen=True)
class TokenSet:
    access_token: str
    id_token: str
    token_type: str
    expires_in: int


@dataclass(frozen=True)
class BrokerRequest:
    request_id: str
    subject: str
    client_id: str
    agent_id: str
    task_id: str
    resource: str
    requested_scopes: frozenset[str]
    dpop_jkt: str | None = None


@dataclass(frozen=True)
class ResourceRecord:
    resource_id: str
    tenant_id: str
    owner_subject: str
    allowed_actions: frozenset[str]
    allowed_clients: frozenset[str]
    allowed_actors: frozenset[str]
    allowed_workloads: frozenset[str]


@dataclass(frozen=True)
class APIRequest:
    request_id: str
    access_token: str
    method: str
    uri: str
    action: str
    resource_id: str
    dpop_proof: str | None = None


@dataclass(frozen=True)
class Decision:
    request_id: str
    outcome: Outcome
    reason_code: str
    subject: str | None
    actor: str | None
    client_id: str | None
    workload_id: str | None
    audience: str | None
    scopes: tuple[str, ...]
    action: str
    resource_id: str
    policy_version: str
    token_digest: str | None
    evidence_ids: tuple[str, ...]


@dataclass(frozen=True)
class ScenarioCase:
    case_id: str
    expected: Outcome
    description: str


@dataclass(frozen=True)
class Metrics:
    attempts: int
    expected_allowed: int
    expected_blocked: int
    outcome_matches: int
    invalid_acceptances: int
    valid_work_blocked: int
    authority_amplifications: int
    replay_acceptances: int
    cross_resource_acceptances: int

    @property
    def accuracy(self) -> float:
        return self.outcome_matches / self.attempts if self.attempts else 0.0


class ProtocolError(Exception):
    def __init__(self, reason_code: str):
        super().__init__(reason_code)
        self.reason_code = reason_code


def deterministic_key(label: str) -> ed25519.Ed25519PrivateKey:
    return ed25519.Ed25519PrivateKey.from_private_bytes(
        hashlib.sha256(label.encode()).digest()
    )


class IssuerKeyRing:
    def __init__(self, keys: Iterable[SigningKey], active_kid: str):
        self.keys = {key.kid: key for key in keys}
        self.active_kid = active_kid

    @classmethod
    def default(cls) -> "IssuerKeyRing":
        return cls(
            (
                SigningKey("northstar-2026-09", deterministic_key("issuer:v1"), KeyState.ACTIVE),
                SigningKey("northstar-2026-08", deterministic_key("issuer:old"), KeyState.RETIRING),
                SigningKey("northstar-compromised", deterministic_key("issuer:bad"), KeyState.REVOKED),
            ),
            "northstar-2026-09",
        )

    def active(self) -> SigningKey:
        key = self.keys[self.active_kid]
        if key.state is not KeyState.ACTIVE:
            raise ProtocolError("signing_key_not_active")
        return key

    def verification_key(self, kid: object) -> ed25519.Ed25519PublicKey:
        if not isinstance(kid, str) or kid not in self.keys:
            raise ProtocolError("token_key_untrusted")
        key = self.keys[kid]
        if key.state is KeyState.REVOKED:
            raise ProtocolError("token_key_revoked")
        return key.public_key

    def public_jwks(self) -> dict[str, object]:
        values = []
        for key in self.keys.values():
            if key.state is KeyState.REVOKED:
                continue
            raw = key.public_key.public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
            values.append(
                {"kty": "OKP", "crv": "Ed25519", "x": b64url(raw), "kid": key.kid, "use": "sig", "alg": "EdDSA"}
            )
        return {"keys": values}


def default_client() -> OAuthClient:
    return OAuthClient(
        CLIENT_ID,
        frozenset({"https://agent.northstar.example/oauth/callback"}),
        frozenset({TRAVEL_API, PAYMENT_API, MCP_RESOURCE}),
        frozenset({"openid", "profile", "trips:read", "trips:book", "payments:create", "inventory:read"}),
        AGENT_ID,
        WORKLOAD_ID,
        TENANT_ID,
    )


def default_workload(**changes: object) -> VerifiedWorkload:
    value = VerifiedWorkload(
        WORKLOAD_ID,
        CLIENT_ID,
        AGENT_ID,
        TENANT_ID,
        "attestation:spire:booking-agent:v3",
        True,
    )
    return replace(value, **changes)


def default_grant(**changes: object) -> DelegationGrant:
    value = DelegationGrant(
        "grant:alice:trip-1042:v2",
        USER_ID,
        TENANT_ID,
        AGENT_ID,
        "task:book-trip-1042",
        frozenset({TRAVEL_API, PAYMENT_API}),
        frozenset({"trips:read", "trips:book", "payments:create"}),
        NOW + timedelta(minutes=20),
        True,
    )
    return replace(value, **changes)


class TokenIssuer:
    def __init__(self, keys: IssuerKeyRing, now: datetime = NOW):
        self.keys = keys
        self.now = now

    def issue_access_token(
        self,
        *,
        subject: str,
        audience: str,
        scopes: Iterable[str],
        client_id: str,
        actor: str | None,
        workload_id: str,
        tenant_id: str,
        task_id: str | None,
        ttl_seconds: int = 180,
        issued_at: datetime | None = None,
        dpop_jkt: str | None = None,
        kid: str | None = None,
        typ: str = "at+jwt",
    ) -> str:
        key = self.keys.keys[kid] if kid else self.keys.active()
        start = issued_at or self.now
        claims: dict[str, object] = {
            "iss": ISSUER,
            "sub": subject,
            "aud": [audience],
            "client_id": client_id,
            "scope": " ".join(sorted(set(scopes))),
            "iat": int(start.timestamp()),
            "exp": int((start + timedelta(seconds=ttl_seconds)).timestamp()),
            "jti": stable_value(f"access:{subject}:{client_id}:{audience}:{start.isoformat()}:{task_id}", 40),
            "workload_id": workload_id,
            "tenant_id": tenant_id,
        }
        if actor:
            claims["act"] = {"sub": actor}
        if task_id:
            claims["task_id"] = task_id
        if dpop_jkt:
            claims["cnf"] = {"jkt": dpop_jkt}
        return jwt.encode(claims, key.private_key, algorithm="EdDSA", headers={"kid": key.kid, "typ": typ})

    def issue_id_token(
        self,
        *,
        subject: str,
        client_id: str,
        nonce: str,
        auth_time: datetime,
        ttl_seconds: int = 180,
    ) -> str:
        key = self.keys.active()
        claims = {
            "iss": ISSUER,
            "sub": subject,
            "aud": [client_id],
            "azp": client_id,
            "iat": int(self.now.timestamp()),
            "exp": int((self.now + timedelta(seconds=ttl_seconds)).timestamp()),
            "auth_time": int(auth_time.timestamp()),
            "nonce": nonce,
        }
        return jwt.encode(claims, key.private_key, algorithm="EdDSA", headers={"kid": key.kid, "typ": "JWT"})


class AuthorizationServer:
    """One-time authorization transaction and code redemption simulator."""

    def __init__(self, client: OAuthClient, issuer: TokenIssuer, now: datetime = NOW):
        self.client = client
        self.issuer = issuer
        self.now = now
        self.transactions: dict[str, AuthorizationTransaction] = {}
        self.codes: dict[str, str] = {}
        self._lock = Lock()

    def begin(
        self,
        *,
        transaction_id: str,
        redirect_uri: str,
        resource: str,
        scopes: Iterable[str],
        subject: str,
        task_id: str,
    ) -> AuthorizationStart:
        requested = frozenset(scopes)
        if not self.client.active:
            raise ProtocolError("client_inactive")
        if redirect_uri not in self.client.redirect_uris:
            raise ProtocolError("redirect_uri_unregistered")
        if resource not in self.client.allowed_resources:
            raise ProtocolError("resource_not_registered")
        if not requested or not requested <= self.client.allowed_scopes:
            raise ProtocolError("scope_not_registered")
        if "openid" not in requested:
            raise ProtocolError("openid_scope_required")
        state = stable_value(f"state:{transaction_id}", 36)
        nonce = stable_value(f"nonce:{transaction_id}", 36)
        verifier = stable_value(f"verifier:{transaction_id}", 64)
        challenge = b64url(hashlib.sha256(verifier.encode()).digest())
        transaction = AuthorizationTransaction(
            transaction_id,
            self.client.client_id,
            redirect_uri,
            ISSUER,
            digest_text(state),
            digest_text(nonce),
            challenge,
            resource,
            requested,
            subject,
            task_id,
            self.now + timedelta(minutes=5),
        )
        self.transactions[transaction_id] = transaction
        return AuthorizationStart(transaction_id, state, nonce, verifier, challenge, resource, tuple(sorted(requested)))

    def authorize(self, start: AuthorizationStart) -> AuthorizationResponse:
        transaction = self.transactions.get(start.transaction_id)
        if not transaction or transaction.consumed or self.now >= transaction.expires_at:
            raise ProtocolError("authorization_transaction_invalid")
        code = stable_value(f"code:{start.transaction_id}", 40)
        self.codes[digest_text(code)] = start.transaction_id
        return AuthorizationResponse(start.transaction_id, code, start.state, ISSUER)

    def redeem(
        self,
        response: AuthorizationResponse,
        *,
        code_verifier: str,
        redirect_uri: str,
        workload: VerifiedWorkload,
        grant: DelegationGrant,
        dpop_jkt: str | None,
    ) -> TokenSet:
        with self._lock:
            transaction = self.transactions.get(response.transaction_id)
            if transaction is None:
                raise ProtocolError("authorization_transaction_unknown")
            if transaction.consumed:
                raise ProtocolError("authorization_code_replayed")
            if self.now >= transaction.expires_at:
                raise ProtocolError("authorization_transaction_expired")
            if response.issuer != transaction.expected_issuer:
                raise ProtocolError("authorization_issuer_mismatch")
            if not hmac.compare_digest(digest_text(response.state), transaction.state_digest):
                raise ProtocolError("authorization_state_mismatch")
            if redirect_uri != transaction.redirect_uri:
                raise ProtocolError("redirect_uri_mismatch")
            challenge = b64url(hashlib.sha256(code_verifier.encode()).digest())
            if not hmac.compare_digest(challenge, transaction.pkce_challenge):
                raise ProtocolError("pkce_verification_failed")
            code_transaction = self.codes.get(digest_text(response.code))
            if code_transaction != transaction.transaction_id:
                raise ProtocolError("authorization_code_invalid")
            self._validate_binding(transaction, workload, grant)
            self.transactions[transaction.transaction_id] = replace(transaction, consumed=True)
            access = self.issuer.issue_access_token(
                subject=transaction.subject,
                audience=transaction.resource,
                scopes=transaction.scopes - {"openid", "profile"},
                client_id=transaction.client_id,
                actor=workload.agent_id,
                workload_id=workload.workload_id,
                tenant_id=workload.tenant_id,
                task_id=transaction.task_id,
                dpop_jkt=dpop_jkt,
            )
            # Nonce is not stored in plaintext. The caller supplies the value it retained.
            nonce = state_nonce_for(transaction.transaction_id)
            identity = self.issuer.issue_id_token(
                subject=transaction.subject,
                client_id=transaction.client_id,
                nonce=nonce,
                auth_time=self.now - timedelta(minutes=1),
            )
            return TokenSet(access, identity, "DPoP" if dpop_jkt else "Bearer", 180)

    def _validate_binding(
        self,
        transaction: AuthorizationTransaction,
        workload: VerifiedWorkload,
        grant: DelegationGrant,
    ) -> None:
        if not workload.active:
            raise ProtocolError("workload_inactive")
        if (
            workload.client_id != self.client.client_id
            or workload.agent_id != self.client.agent_id
            or workload.workload_id != self.client.workload_id
            or workload.tenant_id != self.client.tenant_id
        ):
            raise ProtocolError("workload_client_binding_invalid")
        if not grant.active or self.now >= grant.expires_at:
            raise ProtocolError("delegation_inactive")
        if (
            grant.subject != transaction.subject
            or grant.agent_id != workload.agent_id
            or grant.tenant_id != workload.tenant_id
            or grant.task_id != transaction.task_id
        ):
            raise ProtocolError("delegation_binding_invalid")
        api_scopes = transaction.scopes - {"openid", "profile"}
        if transaction.resource not in grant.resources or not api_scopes <= grant.scopes:
            raise ProtocolError("delegation_authority_exceeded")


def state_nonce_for(transaction_id: str) -> str:
    return stable_value(f"nonce:{transaction_id}", 36)


def validate_id_token(
    token: str,
    *,
    keys: IssuerKeyRing,
    expected_client_id: str,
    expected_nonce: str,
    now: datetime = NOW,
) -> dict[str, object]:
    header = jwt.get_unverified_header(token)
    if header.get("alg") != "EdDSA" or header.get("typ") != "JWT":
        raise ProtocolError("id_token_header_invalid")
    key = keys.verification_key(header.get("kid"))
    try:
        claims = jwt.decode(
            token,
            key,
            algorithms=["EdDSA"],
            issuer=ISSUER,
            audience=expected_client_id,
            options={"require": ["iss", "sub", "aud", "azp", "iat", "exp", "nonce"], "verify_exp": False, "verify_iat": False},
        )
    except jwt.PyJWTError as exc:
        raise ProtocolError("id_token_invalid") from exc
    if claims.get("azp") != expected_client_id:
        raise ProtocolError("id_token_azp_mismatch")
    if not hmac.compare_digest(str(claims.get("nonce", "")), expected_nonce):
        raise ProtocolError("id_token_nonce_mismatch")
    issued = datetime.fromtimestamp(int(claims["iat"]), tz=timezone.utc)
    expires = datetime.fromtimestamp(int(claims["exp"]), tz=timezone.utc)
    if now < issued or now >= expires or (expires - issued).total_seconds() > 300:
        raise ProtocolError("id_token_time_invalid")
    return claims


class TokenBroker:
    """Issues a narrower token from trusted workload and delegation state."""

    def __init__(self, client: OAuthClient, issuer: TokenIssuer, now: datetime = NOW):
        self.client = client
        self.issuer = issuer
        self.now = now
        self.operation_log: dict[str, str] = {}

    def issue(
        self,
        workload: VerifiedWorkload,
        grant: DelegationGrant,
        request: BrokerRequest,
    ) -> str:
        request_digest = digest_text(canonical_json({
            "subject": request.subject,
            "client": request.client_id,
            "agent": request.agent_id,
            "task": request.task_id,
            "resource": request.resource,
            "scopes": sorted(request.requested_scopes),
            "jkt": request.dpop_jkt,
        }).decode())
        previous = self.operation_log.get(request.request_id)
        if previous and previous != request_digest:
            raise ProtocolError("broker_idempotency_conflict")
        if not workload.active or (
            workload.client_id,
            workload.agent_id,
            workload.workload_id,
            workload.tenant_id,
        ) != (
            self.client.client_id,
            self.client.agent_id,
            self.client.workload_id,
            self.client.tenant_id,
        ):
            raise ProtocolError("workload_client_binding_invalid")
        if (request.client_id, request.agent_id) != (workload.client_id, workload.agent_id):
            raise ProtocolError("request_actor_binding_invalid")
        if not grant.active or self.now >= grant.expires_at:
            raise ProtocolError("delegation_inactive")
        if (
            request.subject != grant.subject
            or request.agent_id != grant.agent_id
            or request.task_id != grant.task_id
            or workload.tenant_id != grant.tenant_id
        ):
            raise ProtocolError("delegation_binding_invalid")
        if request.resource not in self.client.allowed_resources or request.resource not in grant.resources:
            raise ProtocolError("resource_not_delegated")
        if not request.requested_scopes:
            raise ProtocolError("scope_empty")
        effective = self.client.allowed_scopes & grant.scopes
        if not request.requested_scopes <= effective:
            raise ProtocolError("scope_amplification")
        token = self.issuer.issue_access_token(
            subject=request.subject,
            audience=request.resource,
            scopes=request.requested_scopes,
            client_id=request.client_id,
            actor=request.agent_id,
            workload_id=workload.workload_id,
            tenant_id=workload.tenant_id,
            task_id=request.task_id,
            ttl_seconds=120,
            dpop_jkt=request.dpop_jkt,
        )
        self.operation_log[request.request_id] = request_digest
        return token

    def client_credentials(
        self,
        workload: VerifiedWorkload,
        *,
        resource: str,
        scopes: frozenset[str],
    ) -> str:
        if not workload.active or workload.client_id != self.client.client_id or workload.workload_id != self.client.workload_id:
            raise ProtocolError("workload_client_binding_invalid")
        service_allowed = frozenset({"inventory:read"})
        if resource != TRAVEL_API or not scopes or not scopes <= service_allowed:
            raise ProtocolError("client_credentials_authority_exceeded")
        return self.issuer.issue_access_token(
            subject=self.client.client_id,
            audience=resource,
            scopes=scopes,
            client_id=self.client.client_id,
            actor=None,
            workload_id=workload.workload_id,
            tenant_id=workload.tenant_id,
            task_id=None,
            ttl_seconds=120,
        )


def public_okp_jwk(key: ed25519.Ed25519PrivateKey) -> dict[str, str]:
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return {"kty": "OKP", "crv": "Ed25519", "x": b64url(raw)}


def jwk_thumbprint(jwk: Mapping[str, str]) -> str:
    canonical = {"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"]}
    return b64url(hashlib.sha256(canonical_json(canonical)).digest())


def access_token_hash(token: str) -> str:
    return b64url(hashlib.sha256(token.encode()).digest())


class DPoPClient:
    def __init__(self, label: str = "dpop:travel-agent:v1"):
        self.private_key = deterministic_key(label)
        self.jwk = public_okp_jwk(self.private_key)
        self.jkt = jwk_thumbprint(self.jwk)

    def proof(
        self,
        *,
        method: str,
        uri: str,
        access_token: str,
        jti: str,
        issued_at: datetime = NOW,
        nonce: str | None = None,
    ) -> str:
        claims: dict[str, object] = {
            "jti": jti,
            "htm": method.upper(),
            "htu": uri,
            "iat": int(issued_at.timestamp()),
            "ath": access_token_hash(access_token),
        }
        if nonce:
            claims["nonce"] = nonce
        return jwt.encode(
            claims,
            self.private_key,
            algorithm="EdDSA",
            headers={"typ": "dpop+jwt", "jwk": self.jwk},
        )


class ReplayStore:
    def __init__(self):
        self.values: set[tuple[str, str]] = set()
        self._lock = Lock()

    def consume(self, jkt: str, jti: str) -> bool:
        with self._lock:
            key = (jkt, jti)
            if key in self.values:
                return False
            self.values.add(key)
            return True


class ResourceServer:
    def __init__(
        self,
        *,
        audience: str,
        keys: IssuerKeyRing,
        resources: Mapping[str, ResourceRecord],
        now: datetime = NOW,
        replay_store: ReplayStore | None = None,
    ):
        self.audience = audience
        self.keys = keys
        self.resources = dict(resources)
        self.now = now
        self.replays = replay_store or ReplayStore()

    def handle(self, request: APIRequest) -> Decision:
        token_digest = digest_text(request.access_token)
        try:
            claims = self._validate_access_token(request.access_token)
            cnf = claims.get("cnf")
            if cnf is not None:
                if not isinstance(cnf, dict) or not isinstance(cnf.get("jkt"), str):
                    raise ProtocolError("token_confirmation_invalid")
                self._validate_dpop(request, cnf["jkt"])
            elif request.dpop_proof:
                raise ProtocolError("unbound_dpop_proof")
            scopes = frozenset(str(claims.get("scope", "")).split())
            required_scope = action_scope(request.action)
            if required_scope not in scopes:
                raise ProtocolError("scope_insufficient")
            resource = self.resources.get(request.resource_id)
            if resource is None:
                raise ProtocolError("resource_unknown")
            if claims.get("tenant_id") != resource.tenant_id:
                raise ProtocolError("tenant_mismatch")
            if claims.get("sub") != resource.owner_subject:
                raise ProtocolError("subject_not_resource_owner")
            if claims.get("client_id") not in resource.allowed_clients:
                raise ProtocolError("client_not_authorized")
            actor = claims.get("act")
            actor_id = actor.get("sub") if isinstance(actor, dict) else None
            if actor_id not in resource.allowed_actors:
                raise ProtocolError("actor_not_authorized")
            if claims.get("workload_id") not in resource.allowed_workloads:
                raise ProtocolError("workload_not_authorized")
            if request.action not in resource.allowed_actions:
                raise ProtocolError("action_not_authorized")
            return self._decision(request, Outcome.ALLOW, "authenticated_and_authorized", claims, token_digest)
        except ProtocolError as exc:
            return self._decision(request, Outcome.DENY, exc.reason_code, {}, token_digest)

    def _validate_access_token(self, token: str) -> dict[str, object]:
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as exc:
            raise ProtocolError("token_malformed") from exc
        if header.get("alg") != "EdDSA" or header.get("typ") != "at+jwt":
            raise ProtocolError("access_token_header_invalid")
        key = self.keys.verification_key(header.get("kid"))
        try:
            claims = jwt.decode(
                token,
                key,
                algorithms=["EdDSA"],
                issuer=ISSUER,
                audience=self.audience,
                options={
                    "require": ["iss", "sub", "aud", "client_id", "scope", "iat", "exp", "jti", "workload_id", "tenant_id"],
                    "verify_exp": False,
                    "verify_iat": False,
                },
            )
        except jwt.InvalidAudienceError as exc:
            raise ProtocolError("token_audience_mismatch") from exc
        except jwt.InvalidIssuerError as exc:
            raise ProtocolError("token_issuer_mismatch") from exc
        except jwt.PyJWTError as exc:
            raise ProtocolError("token_invalid") from exc
        issued = datetime.fromtimestamp(int(claims["iat"]), tz=timezone.utc)
        expires = datetime.fromtimestamp(int(claims["exp"]), tz=timezone.utc)
        if self.now < issued:
            raise ProtocolError("token_not_yet_valid")
        if self.now >= expires:
            raise ProtocolError("token_expired")
        if (expires - issued).total_seconds() > 300:
            raise ProtocolError("token_lifetime_exceeds_policy")
        if not str(claims.get("scope", "")).strip():
            raise ProtocolError("token_scope_empty")
        actor = claims.get("act")
        if actor is not None and (not isinstance(actor, dict) or not isinstance(actor.get("sub"), str)):
            raise ProtocolError("token_actor_invalid")
        return claims

    def _validate_dpop(self, request: APIRequest, expected_jkt: str) -> None:
        if not request.dpop_proof:
            raise ProtocolError("dpop_proof_required")
        try:
            header = jwt.get_unverified_header(request.dpop_proof)
        except jwt.PyJWTError as exc:
            raise ProtocolError("dpop_malformed") from exc
        if header.get("typ") != "dpop+jwt" or header.get("alg") != "EdDSA":
            raise ProtocolError("dpop_header_invalid")
        jwk = header.get("jwk")
        if not isinstance(jwk, dict) or jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
            raise ProtocolError("dpop_jwk_invalid")
        try:
            raw = base64.urlsafe_b64decode(str(jwk["x"]) + "==")
            key = ed25519.Ed25519PublicKey.from_public_bytes(raw)
            claims = jwt.decode(
                request.dpop_proof,
                key,
                algorithms=["EdDSA"],
                options={"verify_aud": False, "verify_exp": False, "verify_iat": False, "require": ["jti", "htm", "htu", "iat", "ath"]},
            )
        except Exception as exc:
            raise ProtocolError("dpop_signature_invalid") from exc
        actual_jkt = jwk_thumbprint(jwk)
        if not hmac.compare_digest(actual_jkt, expected_jkt):
            raise ProtocolError("dpop_key_binding_mismatch")
        if claims["htm"] != request.method.upper():
            raise ProtocolError("dpop_method_mismatch")
        if claims["htu"] != request.uri:
            raise ProtocolError("dpop_uri_mismatch")
        issued = datetime.fromtimestamp(int(claims["iat"]), tz=timezone.utc)
        if abs((self.now - issued).total_seconds()) > 60:
            raise ProtocolError("dpop_proof_stale")
        if not hmac.compare_digest(str(claims["ath"]), access_token_hash(request.access_token)):
            raise ProtocolError("dpop_access_token_mismatch")
        if not self.replays.consume(actual_jkt, str(claims["jti"])):
            raise ProtocolError("dpop_replay")

    def _decision(
        self,
        request: APIRequest,
        outcome: Outcome,
        reason: str,
        claims: Mapping[str, object],
        token_digest: str,
    ) -> Decision:
        actor = claims.get("act")
        actor_id = actor.get("sub") if isinstance(actor, dict) else None
        aud = claims.get("aud")
        audience = aud[0] if isinstance(aud, list) and aud else aud if isinstance(aud, str) else None
        return Decision(
            request.request_id,
            outcome,
            reason,
            claims.get("sub") if isinstance(claims.get("sub"), str) else None,
            actor_id if isinstance(actor_id, str) else None,
            claims.get("client_id") if isinstance(claims.get("client_id"), str) else None,
            claims.get("workload_id") if isinstance(claims.get("workload_id"), str) else None,
            audience,
            tuple(sorted(str(claims.get("scope", "")).split())),
            request.action,
            request.resource_id,
            POLICY_VERSION,
            token_digest,
            tuple(
                item
                for item in (
                    f"token:{claims.get('jti')}" if claims.get("jti") else None,
                    f"task:{claims.get('task_id')}" if claims.get("task_id") else None,
                )
                if item
            ),
        )


def action_scope(action: str) -> str:
    values = {"read": "trips:read", "book": "trips:book", "pay": "payments:create", "inventory": "inventory:read"}
    return values.get(action, f"unsupported:{action}")


def default_resources() -> dict[str, ResourceRecord]:
    clients = frozenset({CLIENT_ID})
    actors = frozenset({AGENT_ID})
    workloads = frozenset({WORKLOAD_ID})
    return {
        "trip:1042": ResourceRecord("trip:1042", TENANT_ID, USER_ID, frozenset({"read", "book"}), clients, actors, workloads),
        "trip:9999": ResourceRecord("trip:9999", TENANT_ID, "user:bob", frozenset({"read", "book"}), clients, actors, workloads),
        "payment:1042": ResourceRecord("payment:1042", TENANT_ID, USER_ID, frozenset({"pay"}), clients, actors, workloads),
    }


def trusted_protected_resource_metadata(metadata: Mapping[str, object]) -> bool:
    resource = metadata.get("resource")
    servers = metadata.get("authorization_servers")
    if not isinstance(resource, str) or not isinstance(servers, list) or not servers:
        return False
    resource_parts = urlsplit(resource)
    if resource_parts.scheme != "https" or resource_parts.fragment:
        return False
    return resource == MCP_RESOURCE and servers == [ISSUER]


def unsafe_claims_only_baseline(request: APIRequest) -> Decision:
    """Anti-pattern: decode claims without trust, time, sender, or resource policy."""

    try:
        claims = jwt.decode(request.access_token, options={"verify_signature": False, "verify_exp": False})
        outcome = Outcome.ALLOW if action_scope(request.action) in str(claims.get("scope", "")).split() else Outcome.DENY
        reason = "scope_string_present" if outcome is Outcome.ALLOW else "scope_string_missing"
    except Exception:
        claims, outcome, reason = {}, Outcome.DENY, "token_unreadable"
    actor = claims.get("act")
    return Decision(
        request.request_id,
        outcome,
        reason,
        claims.get("sub"),
        actor.get("sub") if isinstance(actor, dict) else None,
        claims.get("client_id"),
        claims.get("workload_id"),
        (claims.get("aud") or [None])[0] if isinstance(claims.get("aud"), list) else claims.get("aud"),
        tuple(sorted(str(claims.get("scope", "")).split())),
        request.action,
        request.resource_id,
        "unsafe-baseline",
        digest_text(request.access_token),
        (),
    )


def build_cases() -> tuple[ScenarioCase, ...]:
    return (
        ScenarioCase("valid_dpop_booking", Outcome.ALLOW, "bound user-agent-workload books its authorized trip"),
        ScenarioCase("valid_bearer_read", Outcome.ALLOW, "low-risk bearer token reads its authorized trip"),
        ScenarioCase("wrong_audience", Outcome.DENY, "travel token forwarded to payment API"),
        ScenarioCase("expired_token", Outcome.DENY, "access token is expired"),
        ScenarioCase("future_token", Outcome.DENY, "access token was issued in the future"),
        ScenarioCase("overlong_token", Outcome.DENY, "token lifetime exceeds local policy"),
        ScenarioCase("unknown_key", Outcome.DENY, "kid is absent from issuer-bound keys"),
        ScenarioCase("revoked_key", Outcome.DENY, "signing key is revoked"),
        ScenarioCase("id_token_at_api", Outcome.DENY, "OIDC ID token is sent to the API"),
        ScenarioCase("missing_scope", Outcome.DENY, "token lacks the action scope"),
        ScenarioCase("cross_subject_resource", Outcome.DENY, "Alice token targets Bob's trip"),
        ScenarioCase("cross_tenant_resource", Outcome.DENY, "token and resource tenants differ"),
        ScenarioCase("wrong_client_binding", Outcome.DENY, "token client is not approved for the object"),
        ScenarioCase("wrong_actor_binding", Outcome.DENY, "token actor is not approved for the object"),
        ScenarioCase("wrong_workload_binding", Outcome.DENY, "token workload is not approved for the object"),
        ScenarioCase("unsupported_action", Outcome.DENY, "scope does not grant an unknown action"),
        ScenarioCase("dpop_missing", Outcome.DENY, "bound token is presented without proof"),
        ScenarioCase("dpop_wrong_key", Outcome.DENY, "proof key differs from token confirmation"),
        ScenarioCase("dpop_wrong_method", Outcome.DENY, "proof is replayed across HTTP methods"),
        ScenarioCase("dpop_wrong_uri", Outcome.DENY, "proof is replayed at another URI"),
        ScenarioCase("dpop_wrong_token", Outcome.DENY, "proof ath binds another access token"),
        ScenarioCase("dpop_stale", Outcome.DENY, "proof iat exceeds the freshness window"),
        ScenarioCase("dpop_replay", Outcome.DENY, "same proof jti is consumed twice"),
        ScenarioCase("malformed_actor", Outcome.DENY, "act claim has an invalid shape"),
        ScenarioCase("empty_scope", Outcome.DENY, "access token carries no authority"),
    )


def scenario_request(case: ScenarioCase) -> tuple[ResourceServer, APIRequest]:
    keys = IssuerKeyRing.default()
    issuer = TokenIssuer(keys)
    dpop = DPoPClient()
    token = issuer.issue_access_token(
        subject=USER_ID,
        audience=TRAVEL_API,
        scopes={"trips:read", "trips:book"},
        client_id=CLIENT_ID,
        actor=AGENT_ID,
        workload_id=WORKLOAD_ID,
        tenant_id=TENANT_ID,
        task_id="task:book-trip-1042",
        dpop_jkt=dpop.jkt if case.case_id == "valid_dpop_booking" or case.case_id.startswith("dpop_") else None,
    )
    action = "book" if case.case_id == "valid_dpop_booking" or case.case_id.startswith("dpop_") else "read"
    resource_id = "trip:1042"
    method = "POST" if action == "book" else "GET"
    uri = f"{TRAVEL_API}/trips/1042"
    resources = default_resources()
    server = ResourceServer(audience=TRAVEL_API, keys=keys, resources=resources)

    if case.case_id == "wrong_audience":
        server = ResourceServer(audience=PAYMENT_API, keys=keys, resources=resources)
    elif case.case_id == "expired_token":
        token = issuer.issue_access_token(subject=USER_ID, audience=TRAVEL_API, scopes={"trips:read"}, client_id=CLIENT_ID, actor=AGENT_ID, workload_id=WORKLOAD_ID, tenant_id=TENANT_ID, task_id="task:book-trip-1042", issued_at=NOW-timedelta(minutes=10), ttl_seconds=60)
    elif case.case_id == "future_token":
        token = issuer.issue_access_token(subject=USER_ID, audience=TRAVEL_API, scopes={"trips:read"}, client_id=CLIENT_ID, actor=AGENT_ID, workload_id=WORKLOAD_ID, tenant_id=TENANT_ID, task_id="task:book-trip-1042", issued_at=NOW+timedelta(minutes=1))
    elif case.case_id == "overlong_token":
        token = issuer.issue_access_token(subject=USER_ID, audience=TRAVEL_API, scopes={"trips:read"}, client_id=CLIENT_ID, actor=AGENT_ID, workload_id=WORKLOAD_ID, tenant_id=TENANT_ID, task_id="task:book-trip-1042", ttl_seconds=3600)
    elif case.case_id == "unknown_key":
        foreign = IssuerKeyRing((SigningKey("foreign-key", deterministic_key("foreign"), KeyState.ACTIVE),), "foreign-key")
        token = TokenIssuer(foreign).issue_access_token(subject=USER_ID, audience=TRAVEL_API, scopes={"trips:read"}, client_id=CLIENT_ID, actor=AGENT_ID, workload_id=WORKLOAD_ID, tenant_id=TENANT_ID, task_id="task:book-trip-1042")
    elif case.case_id == "revoked_key":
        token = issuer.issue_access_token(subject=USER_ID, audience=TRAVEL_API, scopes={"trips:read"}, client_id=CLIENT_ID, actor=AGENT_ID, workload_id=WORKLOAD_ID, tenant_id=TENANT_ID, task_id="task:book-trip-1042", kid="northstar-compromised")
    elif case.case_id == "id_token_at_api":
        token = issuer.issue_id_token(subject=USER_ID, client_id=CLIENT_ID, nonce="nonce", auth_time=NOW)
    elif case.case_id == "missing_scope":
        token = issuer.issue_access_token(subject=USER_ID, audience=TRAVEL_API, scopes={"trips:book"}, client_id=CLIENT_ID, actor=AGENT_ID, workload_id=WORKLOAD_ID, tenant_id=TENANT_ID, task_id="task:book-trip-1042")
    elif case.case_id == "cross_subject_resource":
        resource_id = "trip:9999"
    elif case.case_id == "cross_tenant_resource":
        resources["trip:1042"] = replace(resources["trip:1042"], tenant_id="tenant:other")
        server = ResourceServer(audience=TRAVEL_API, keys=keys, resources=resources)
    elif case.case_id in {"wrong_client_binding", "wrong_actor_binding", "wrong_workload_binding"}:
        key = keys.active()
        claims = jwt.decode(token, options={"verify_signature": False})
        if case.case_id == "wrong_client_binding":
            claims["client_id"] = "client:attacker"
        elif case.case_id == "wrong_actor_binding":
            claims["act"] = {"sub": "agent:attacker"}
        else:
            claims["workload_id"] = "spiffe://corp.example/ns/attacker/sa/runtime"
        token = jwt.encode(claims, key.private_key, algorithm="EdDSA", headers={"kid": key.kid, "typ": "at+jwt"})
    elif case.case_id == "unsupported_action":
        action = "delete"
    elif case.case_id == "malformed_actor":
        key = keys.active()
        claims = jwt.decode(token, options={"verify_signature": False})
        claims["act"] = AGENT_ID
        token = jwt.encode(claims, key.private_key, algorithm="EdDSA", headers={"kid": key.kid, "typ": "at+jwt"})
    elif case.case_id == "empty_scope":
        key = keys.active()
        claims = jwt.decode(token, options={"verify_signature": False})
        claims["scope"] = ""
        token = jwt.encode(claims, key.private_key, algorithm="EdDSA", headers={"kid": key.kid, "typ": "at+jwt"})

    proof: str | None = None
    if case.case_id == "valid_dpop_booking" or case.case_id.startswith("dpop_"):
        proof_client = dpop
        proof_method = method
        proof_uri = uri
        proof_token = token
        issued_at = NOW
        jti = f"proof:{case.case_id}"
        if case.case_id == "dpop_missing":
            proof_client = None
        elif case.case_id == "dpop_wrong_key":
            proof_client = DPoPClient("dpop:attacker")
        elif case.case_id == "dpop_wrong_method":
            proof_method = "DELETE"
        elif case.case_id == "dpop_wrong_uri":
            proof_uri = f"{PAYMENT_API}/payments/1042"
        elif case.case_id == "dpop_wrong_token":
            proof_token = token + "changed"
        elif case.case_id == "dpop_stale":
            issued_at = NOW - timedelta(minutes=5)
        if proof_client:
            proof = proof_client.proof(method=proof_method, uri=proof_uri, access_token=proof_token, jti=jti, issued_at=issued_at)
        if case.case_id == "dpop_replay":
            assert proof
            first = APIRequest("request:dpop-replay:first", token, method, uri, action, resource_id, proof)
            assert server.handle(first).outcome is Outcome.ALLOW

    return server, APIRequest(f"request:{case.case_id}", token, method, uri, action, resource_id, proof)


def run_case(case: ScenarioCase, *, hardened: bool) -> Decision:
    server, request = scenario_request(case)
    return server.handle(request) if hardened else unsafe_claims_only_baseline(request)


def evaluate(cases: Iterable[ScenarioCase], *, hardened: bool) -> tuple[Metrics, tuple[tuple[ScenarioCase, Decision], ...]]:
    rows = tuple((case, run_case(case, hardened=hardened)) for case in cases)
    expected_allowed = sum(case.expected is Outcome.ALLOW for case, _ in rows)
    expected_blocked = len(rows) - expected_allowed
    invalid = sum(case.expected is Outcome.DENY and decision.outcome is Outcome.ALLOW for case, decision in rows)
    valid_blocked = sum(case.expected is Outcome.ALLOW and decision.outcome is Outcome.DENY for case, decision in rows)
    authority_cases = {"missing_scope", "cross_subject_resource", "cross_tenant_resource", "wrong_client_binding", "wrong_actor_binding", "wrong_workload_binding", "unsupported_action", "malformed_actor", "empty_scope"}
    replay_cases = {"dpop_replay", "dpop_wrong_method", "dpop_wrong_uri", "dpop_wrong_token", "dpop_stale"}
    cross_resource_cases = {"wrong_audience", "cross_subject_resource", "cross_tenant_resource"}
    metrics = Metrics(
        len(rows), expected_allowed, expected_blocked,
        sum(case.expected is decision.outcome for case, decision in rows),
        invalid, valid_blocked,
        sum(case.case_id in authority_cases and decision.outcome is Outcome.ALLOW for case, decision in rows),
        sum(case.case_id in replay_cases and decision.outcome is Outcome.ALLOW for case, decision in rows),
        sum(case.case_id in cross_resource_cases and decision.outcome is Outcome.ALLOW for case, decision in rows),
    )
    return metrics, rows


def release_gate(metrics: Metrics) -> bool:
    return (
        metrics.attempts == 25
        and metrics.outcome_matches == metrics.attempts
        and metrics.invalid_acceptances == 0
        and metrics.valid_work_blocked == 0
        and metrics.authority_amplifications == 0
        and metrics.replay_acceptances == 0
        and metrics.cross_resource_acceptances == 0
    )


def decision_record(decision: Decision) -> dict[str, object]:
    return {
        "request_id": decision.request_id,
        "outcome": decision.outcome.value,
        "reason_code": decision.reason_code,
        "subject": decision.subject,
        "actor": decision.actor,
        "client_id": decision.client_id,
        "workload_id": decision.workload_id,
        "audience": decision.audience,
        "scopes": list(decision.scopes),
        "action": decision.action,
        "resource_id": decision.resource_id,
        "policy_version": decision.policy_version,
        "token_digest": decision.token_digest,
        "evidence_ids": list(decision.evidence_ids),
    }


def demo() -> None:
    baseline, _ = evaluate(build_cases(), hardened=False)
    hardened, rows = evaluate(build_cases(), hardened=True)
    print("Northstar OAuth/OIDC evaluation")
    print(json.dumps({"baseline": baseline.__dict__, "hardened": hardened.__dict__, "release_gate": release_gate(hardened)}, indent=2))
    for case, decision in rows:
        print(f"{case.case_id:30} expected={case.expected.value:5} actual={decision.outcome.value:5} reason={decision.reason_code}")


if __name__ == "__main__":
    demo()
