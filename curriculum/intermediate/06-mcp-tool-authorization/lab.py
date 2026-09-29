"""Executable MCP authorization lab for a claims and payments tool server.

The lab is local, deterministic, and credential-free.  It uses the official MCP
Python SDK's resource-server integration while keeping the business PEP small
enough to inspect.  The important invariant is that protocol authentication is
only the first gate: invocation, exact arguments, target resources, current
state, approvals, downstream delegation, and the eventual side effect are all
authorized independently.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from hashlib import sha256
import json
from threading import RLock
from typing import Any, Callable, Literal, Mapping

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jsonschema import ValidationError as JsonSchemaError
from jsonschema import validate as validate_json
from mcp.server import MCPServer
from mcp.server.auth.provider import AccessToken, TokenVerifier
from mcp.server.auth.settings import AuthSettings
from pydantic import BaseModel, ConfigDict, Field, ValidationError


NOW = 1_800_000_000
ISSUER = "https://id.northstar.example"
MCP_RESOURCE = "https://claims-mcp.northstar.example"
SUBJECT = "user:alice"
TENANT = "tenant:northstar"
AGENT = "agent:claims-adjuster"
CLIENT = "client:claims-copilot"
WORKLOAD = "spiffe://northstar.example/claims/adjuster"
TASK = "task:clm-100-review"
CLAIM = "claim:clm-100"
OTHER_CLAIM = "claim:clm-999"
POLICY_VERSION = 12
TOOLSET_VERSION = 7
RESOURCE_VERSION = 4
TASK_VERSION = 3


class AuthorizationFailure(RuntimeError):
    """A protocol-aware, machine-readable authorization failure."""

    def __init__(
        self,
        reason_code: str,
        *,
        status: int = 403,
        required_scopes: tuple[str, ...] = (),
        challenge: bool = False,
    ):
        self.reason_code = reason_code
        self.status = status
        self.required_scopes = required_scopes
        self.headers: dict[str, str] = {}
        if challenge or status == 401:
            value = (
                'Bearer resource_metadata="'
                f'{MCP_RESOURCE}/.well-known/oauth-protected-resource/mcp"'
            )
            if status == 403 and required_scopes:
                value += (
                    f', error="insufficient_scope", scope="{" ".join(required_scopes)}"'
                )
            self.headers["WWW-Authenticate"] = value
        super().__init__(reason_code)


class UnknownOutcome(RuntimeError):
    """The effect committed but the response was lost; reconcile before retrying."""


def canonical(value: Any) -> str:
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json")
    elif hasattr(value, "__dataclass_fields__"):
        value = asdict(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=list)


def digest(value: Any) -> str:
    return sha256(canonical(value).encode()).hexdigest()


class TrainingIssuer:
    """Deterministic Ed25519 fixture issuer; production uses an external AS/JWKS."""

    def __init__(self, seed: bytes = b"\x11" * 32, kid: str = "northstar-2026-09"):
        self.private_key = Ed25519PrivateKey.from_private_bytes(seed)
        self.public_key = self.private_key.public_key()
        self.kid = kid

    def issue(
        self,
        *,
        scopes: tuple[str, ...] = (
            "claims:search",
            "claims:read",
            "claims:update",
            "payments:create",
        ),
        subject: str = SUBJECT,
        audience: str = MCP_RESOURCE,
        issuer: str = ISSUER,
        client_id: str = CLIENT,
        agent_id: str = AGENT,
        workload_id: str = WORKLOAD,
        tenant_id: str = TENANT,
        task_id: str = TASK,
        issued_at: int = NOW - 5,
        expires_at: int = NOW + 300,
        jti: str = "at-001",
        typ: str = "at+jwt",
        algorithm: str = "EdDSA",
        header_kid: str | None = None,
        extra: Mapping[str, Any] | None = None,
        private_key: Any | None = None,
    ) -> str:
        claims: dict[str, Any] = {
            "iss": issuer,
            "aud": audience,
            "sub": subject,
            "client_id": client_id,
            "agent_id": agent_id,
            "workload_id": workload_id,
            "tenant_id": tenant_id,
            "task_id": task_id,
            "scope": " ".join(scopes),
            "iat": issued_at,
            "nbf": issued_at,
            "exp": expires_at,
            "jti": jti,
        }
        claims.update(extra or {})
        return jwt.encode(
            claims,
            private_key or self.private_key,
            algorithm=algorithm,
            headers={"alg": algorithm, "kid": header_kid or self.kid, "typ": typ},
        )


class NorthstarTokenVerifier(TokenVerifier):
    """MCP SDK TokenVerifier with strict JWT access-token checks."""

    def __init__(
        self,
        public_key: Any,
        *,
        expected_kid: str = "northstar-2026-09",
        now: int = NOW,
    ):
        self.public_key = public_key
        self.expected_kid = expected_kid
        self.now = now

    def verify_strict(self, token: str) -> AccessToken:
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as exc:
            raise AuthorizationFailure(
                "token_malformed", status=401, challenge=True
            ) from exc
        if (
            header.get("alg") != "EdDSA"
            or header.get("typ") != "at+jwt"
            or header.get("kid") != self.expected_kid
        ):
            raise AuthorizationFailure(
                "token_profile_invalid", status=401, challenge=True
            )
        try:
            claims = jwt.decode(
                token,
                self.public_key,
                algorithms=["EdDSA"],
                issuer=ISSUER,
                audience=MCP_RESOURCE,
                options={
                    "verify_exp": False,
                    "verify_nbf": False,
                    "verify_iat": False,
                    "require": [
                        "iss",
                        "aud",
                        "sub",
                        "client_id",
                        "agent_id",
                        "workload_id",
                        "tenant_id",
                        "task_id",
                        "scope",
                        "iat",
                        "nbf",
                        "exp",
                        "jti",
                    ],
                },
            )
        except jwt.ExpiredSignatureError as exc:
            raise AuthorizationFailure(
                "token_expired", status=401, challenge=True
            ) from exc
        except jwt.PyJWTError as exc:
            raise AuthorizationFailure(
                "token_invalid", status=401, challenge=True
            ) from exc
        if not isinstance(claims["iat"], int) or not isinstance(claims["exp"], int):
            raise AuthorizationFailure("token_time_invalid", status=401, challenge=True)
        if claims["nbf"] > self.now or claims["iat"] > self.now + 30:
            raise AuthorizationFailure("token_not_current", status=401, challenge=True)
        if claims["exp"] <= self.now:
            raise AuthorizationFailure("token_expired", status=401, challenge=True)
        if claims["exp"] - claims["iat"] > 600:
            raise AuthorizationFailure(
                "token_lifetime_excessive", status=401, challenge=True
            )
        scopes = tuple(part for part in str(claims["scope"]).split() if part)
        return AccessToken(
            token=token,
            client_id=claims["client_id"],
            scopes=list(scopes),
            expires_at=claims["exp"],
            resource=MCP_RESOURCE,
            subject=claims["sub"],
            claims=claims,
        )

    async def verify_token(self, token: str) -> AccessToken | None:
        try:
            return self.verify_strict(token)
        except AuthorizationFailure:
            return None


def build_sdk_server(verifier: NorthstarTokenVerifier) -> MCPServer:
    """Construct the official SDK resource server without opening a socket."""

    auth = AuthSettings(
        issuer_url=ISSUER,
        resource_server_url=MCP_RESOURCE,
        validate_token_resource=True,
        required_scopes=[],  # per-tool scopes are enforced at invocation time
        service_documentation_url=f"{MCP_RESOURCE}/docs",
    )
    return MCPServer(
        name="northstar-claims",
        version="2026.09",
        token_verifier=verifier,
        auth=auth,
    )


def protected_resource_metadata() -> dict[str, Any]:
    """RFC 9728 metadata served by the HTTP MCP resource."""

    return {
        "resource": MCP_RESOURCE,
        "authorization_servers": [ISSUER],
        "scopes_supported": [
            "claims:search",
            "claims:read",
            "claims:update",
            "payments:create",
        ],
        "bearer_methods_supported": ["header"],
        "resource_documentation": f"{MCP_RESOURCE}/docs",
    }


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class SearchArgs(StrictModel):
    status: Literal["open", "approved", "closed"] = "open"
    limit: int = Field(default=5, ge=1, le=10)
    state_handle: str | None = Field(default=None, min_length=16, max_length=128)


class ReadArgs(StrictModel):
    claim_id: str = Field(pattern=r"^claim:clm-[0-9]+$")


class UpdateArgs(StrictModel):
    claim_id: str = Field(pattern=r"^claim:clm-[0-9]+$")
    expected_version: int = Field(ge=1)
    status: Literal["open", "approved", "closed"]
    operation_id: str = Field(pattern=r"^op-[a-z0-9-]+$")


class PaymentArgs(StrictModel):
    claim_id: str = Field(pattern=r"^claim:clm-[0-9]+$")
    amount_cents: int = Field(gt=0, le=100_000)
    currency: Literal["CAD"]
    payee_id: str = Field(pattern=r"^vendor:[a-z0-9-]+$")
    approval_id: str = Field(pattern=r"^approval-[a-z0-9-]+$")
    operation_id: str = Field(pattern=r"^op-[a-z0-9-]+$")


@dataclass(frozen=True)
class ToolDefinition:
    name: str
    scope: str
    input_model: type[StrictModel]
    output_schema: Mapping[str, Any]
    destructive_hint: bool
    risk: Literal["low", "medium", "high"]


OUTPUT_SCHEMAS = {
    "claim.search": {
        "type": "object",
        "required": ["claim_ids", "next_state_handle"],
        "properties": {
            "claim_ids": {"type": "array", "items": {"type": "string"}, "maxItems": 10},
            "next_state_handle": {"type": ["string", "null"]},
        },
        "additionalProperties": False,
    },
    "claim.read": {
        "type": "object",
        "required": ["claim_id", "status", "version"],
        "properties": {
            "claim_id": {"type": "string"},
            "status": {"type": "string"},
            "version": {"type": "integer"},
        },
        "additionalProperties": False,
    },
    "claim.update": {
        "type": "object",
        "required": ["claim_id", "status", "version", "operation_id"],
        "properties": {
            "claim_id": {"type": "string"},
            "status": {"type": "string"},
            "version": {"type": "integer"},
            "operation_id": {"type": "string"},
        },
        "additionalProperties": False,
    },
    "payment.create": {
        "type": "object",
        "required": ["payment_id", "operation_id", "status"],
        "properties": {
            "payment_id": {"type": "string"},
            "operation_id": {"type": "string"},
            "status": {"const": "submitted"},
        },
        "additionalProperties": False,
    },
}


TOOLS: dict[str, ToolDefinition] = {
    "claim.search": ToolDefinition(
        "claim.search",
        "claims:search",
        SearchArgs,
        OUTPUT_SCHEMAS["claim.search"],
        False,
        "low",
    ),
    "claim.read": ToolDefinition(
        "claim.read",
        "claims:read",
        ReadArgs,
        OUTPUT_SCHEMAS["claim.read"],
        False,
        "low",
    ),
    "claim.update": ToolDefinition(
        "claim.update",
        "claims:update",
        UpdateArgs,
        OUTPUT_SCHEMAS["claim.update"],
        True,
        "medium",
    ),
    "payment.create": ToolDefinition(
        "payment.create",
        "payments:create",
        PaymentArgs,
        OUTPUT_SCHEMAS["payment.create"],
        True,
        "high",
    ),
}


@dataclass(frozen=True)
class VerifiedCaller:
    subject_id: str
    tenant_id: str
    agent_id: str
    client_id: str
    workload_id: str
    task_id: str
    scopes: frozenset[str]
    token_id: str


@dataclass
class ClaimRecord:
    claim_id: str = CLAIM
    tenant_id: str = TENANT
    owner_id: str = SUBJECT
    status: str = "open"
    version: int = RESOURCE_VERSION


@dataclass
class TaskGrant:
    task_id: str = TASK
    subject_id: str = SUBJECT
    tenant_id: str = TENANT
    agent_id: str = AGENT
    resources: frozenset[str] = frozenset({CLAIM})
    tools: frozenset[str] = frozenset(TOOLS)
    active: bool = True
    version: int = TASK_VERSION


@dataclass
class CurrentState:
    policy_version: int = POLICY_VERSION
    toolset_version: int = TOOLSET_VERSION
    workload_active: bool = True
    client_active: bool = True
    subject_active: bool = True
    risk_level: Literal["low", "medium", "high"] = "low"


@dataclass
class ApprovalReceipt:
    approval_id: str
    proposal_digest: str
    subject_id: str
    tenant_id: str
    task_id: str
    agent_id: str
    policy_version: int
    resource_version: int
    expires_at: int
    used: bool = False


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason_codes: tuple[str, ...]
    proposal_digest: str
    policy_version: int
    toolset_version: int
    resource_version: int | None


@dataclass(frozen=True)
class ExecutionReceipt:
    operation_id: str
    request_digest: str
    result: Mapping[str, Any]
    decision_digest: str
    effect_count: int
    reconciled: bool = False


@dataclass(frozen=True)
class StateHandle:
    value: str
    subject_id: str
    tenant_id: str
    task_id: str
    query_digest: str
    expires_at: int


def caller_from_token(token: AccessToken) -> VerifiedCaller:
    claims = token.claims or {}
    return VerifiedCaller(
        subject_id=str(token.subject),
        tenant_id=str(claims["tenant_id"]),
        agent_id=str(claims["agent_id"]),
        client_id=token.client_id,
        workload_id=str(claims["workload_id"]),
        task_id=str(claims["task_id"]),
        scopes=frozenset(token.scopes),
        token_id=str(claims["jti"]),
    )


def effect_arguments(args: StrictModel) -> dict[str, Any]:
    data = args.model_dump(mode="json")
    data.pop("approval_id", None)
    return data


def proposal_document(
    tool_name: str, args: StrictModel, caller: VerifiedCaller
) -> dict[str, Any]:
    return {
        "tool": tool_name,
        "arguments": effect_arguments(args),
        "subject_id": caller.subject_id,
        "tenant_id": caller.tenant_id,
        "agent_id": caller.agent_id,
        "client_id": caller.client_id,
        "workload_id": caller.workload_id,
        "task_id": caller.task_id,
    }


class AuthorizationEngine:
    """Reference MCP PEP/PDP plus a tiny idempotent business-effect adapter."""

    def __init__(self, issuer: TrainingIssuer | None = None, *, now: int = NOW):
        self.issuer = issuer or TrainingIssuer()
        self.verifier = NorthstarTokenVerifier(self.issuer.public_key, now=now)
        self.now = now
        self.task = TaskGrant()
        self.state = CurrentState()
        self.claims: dict[str, ClaimRecord] = {
            CLAIM: ClaimRecord(),
            OTHER_CLAIM: ClaimRecord(OTHER_CLAIM, TENANT, "user:mallory", "open", 2),
        }
        self.approvals: dict[str, ApprovalReceipt] = {}
        self.operations: dict[str, ExecutionReceipt] = {}
        self.state_handles: dict[str, StateHandle] = {}
        self.audit: list[dict[str, Any]] = []
        self.effect_count = 0
        self.force_bad_output = False
        self._lock = RLock()

    def authenticate(self, compact_token: str) -> VerifiedCaller:
        return caller_from_token(self.verifier.verify_strict(compact_token))

    def discover(self, compact_token: str) -> list[str]:
        caller = self.authenticate(compact_token)
        if not self._identity_current(caller) or not self.task.active:
            return []
        return sorted(
            name
            for name, definition in TOOLS.items()
            if name in self.task.tools and definition.scope in caller.scopes
        )

    def _identity_current(self, caller: VerifiedCaller) -> bool:
        return all(
            (
                self.state.subject_active,
                self.state.client_active,
                self.state.workload_active,
                caller.subject_id == self.task.subject_id,
                caller.tenant_id == self.task.tenant_id,
                caller.agent_id == self.task.agent_id,
                caller.client_id == CLIENT,
                caller.workload_id == WORKLOAD,
                caller.task_id == self.task.task_id,
            )
        )

    def parse_args(self, tool_name: str, raw_args: Mapping[str, Any]) -> StrictModel:
        try:
            definition = TOOLS[tool_name]
        except KeyError as exc:
            raise AuthorizationFailure("tool_unknown", status=404) from exc
        try:
            return definition.input_model.model_validate(dict(raw_args))
        except ValidationError as exc:
            raise AuthorizationFailure("arguments_invalid", status=400) from exc

    def authorize(
        self, caller: VerifiedCaller, tool_name: str, args: StrictModel
    ) -> Decision:
        definition = TOOLS[tool_name]
        reasons: list[str] = []
        if not self._identity_current(caller):
            reasons.append("identity_binding_invalid")
        if not self.task.active:
            reasons.append("task_inactive")
        if tool_name not in self.task.tools:
            reasons.append("tool_not_delegated")
        if definition.scope not in caller.scopes:
            reasons.append("scope_insufficient")
        claim_id = getattr(args, "claim_id", None)
        record = self.claims.get(claim_id) if claim_id else None
        if claim_id and record is None:
            reasons.append("resource_unknown")
        if record and (
            record.claim_id not in self.task.resources
            or record.tenant_id != caller.tenant_id
            or record.owner_id != caller.subject_id
        ):
            reasons.append("resource_not_authorized")
        if (
            isinstance(args, UpdateArgs)
            and record
            and args.expected_version != record.version
        ):
            reasons.append("resource_version_stale")
        if isinstance(args, SearchArgs) and args.state_handle:
            handle = self.state_handles.get(args.state_handle)
            query = {"status": args.status, "limit": args.limit}
            if not handle or handle.expires_at <= self.now:
                reasons.append("state_handle_invalid")
            elif (
                handle.subject_id != caller.subject_id
                or handle.tenant_id != caller.tenant_id
                or handle.task_id != caller.task_id
                or handle.query_digest != digest(query)
            ):
                reasons.append("state_handle_binding_invalid")
        proposal_hash = digest(proposal_document(tool_name, args, caller))
        if isinstance(args, PaymentArgs):
            approval = self.approvals.get(args.approval_id)
            if self.state.risk_level == "high":
                reasons.append("risk_policy_denied")
            if not approval:
                reasons.append("approval_missing")
            elif approval.used:
                reasons.append("approval_consumed")
            elif approval.expires_at <= self.now:
                reasons.append("approval_expired")
            elif (
                approval.proposal_digest != proposal_hash
                or approval.subject_id != caller.subject_id
                or approval.tenant_id != caller.tenant_id
                or approval.task_id != caller.task_id
                or approval.agent_id != caller.agent_id
                or approval.policy_version != self.state.policy_version
                or approval.resource_version != (record.version if record else -1)
            ):
                reasons.append("approval_binding_invalid")
        decision = Decision(
            allowed=not reasons,
            reason_codes=tuple(sorted(set(reasons))),
            proposal_digest=proposal_hash,
            policy_version=self.state.policy_version,
            toolset_version=self.state.toolset_version,
            resource_version=record.version if record else None,
        )
        self.audit.append(
            {
                "subject_id": caller.subject_id,
                "agent_id": caller.agent_id,
                "client_id": caller.client_id,
                "workload_id": caller.workload_id,
                "task_id": caller.task_id,
                "tool": tool_name,
                "proposal_digest": proposal_hash,
                "allowed": decision.allowed,
                "reason_codes": list(decision.reason_codes),
                "policy_version": decision.policy_version,
                "toolset_version": decision.toolset_version,
                "resource_version": decision.resource_version,
                "token_fingerprint": digest(caller.token_id)[:16],
            }
        )
        return decision

    def prepare_approval(
        self,
        compact_token: str,
        raw_args: Mapping[str, Any],
        *,
        approval_id: str = "approval-001",
    ) -> ApprovalReceipt:
        """Record an approval returned by the trusted supervisor workflow fixture."""

        caller = self.authenticate(compact_token)
        args = self.parse_args(
            "payment.create", {**raw_args, "approval_id": approval_id}
        )
        record = self.claims[args.claim_id]
        receipt = ApprovalReceipt(
            approval_id=approval_id,
            proposal_digest=digest(proposal_document("payment.create", args, caller)),
            subject_id=caller.subject_id,
            tenant_id=caller.tenant_id,
            task_id=caller.task_id,
            agent_id=caller.agent_id,
            policy_version=self.state.policy_version,
            resource_version=record.version,
            expires_at=self.now + 120,
        )
        with self._lock:
            self.approvals[approval_id] = receipt
        return receipt

    def invoke(
        self,
        compact_token: str,
        tool_name: str,
        raw_args: Mapping[str, Any],
        *,
        mcp_method: str = "tools/call",
        mcp_name: str | None = None,
        before_commit: Callable[["AuthorizationEngine"], None] | None = None,
        lose_response_after_commit: bool = False,
    ) -> Mapping[str, Any]:
        if mcp_method != "tools/call" or (
            mcp_name is not None and mcp_name != tool_name
        ):
            raise AuthorizationFailure("routing_metadata_mismatch", status=400)
        caller = self.authenticate(compact_token)
        args = self.parse_args(tool_name, raw_args)
        operation_id = getattr(args, "operation_id", None)
        request_hash = digest(proposal_document(tool_name, args, caller))
        with self._lock:
            reconciled = self._reconcile(operation_id, request_hash)
            if reconciled is not None:
                return reconciled
            first = self.authorize(caller, tool_name, args)
            if not first.allowed:
                self._raise_decision(first, TOOLS[tool_name])
        if before_commit:
            before_commit(self)
        # This lock represents the durable transaction boundary in the local
        # fixture: recheck idempotency, authorize current state, execute, record
        # the receipt, and consume approval without a concurrent gap.
        with self._lock:
            reconciled = self._reconcile(operation_id, request_hash)
            if reconciled is not None:
                return reconciled
            current = self.authorize(caller, tool_name, args)
            if not current.allowed:
                self._raise_decision(current, TOOLS[tool_name])
            result = self._execute(caller, tool_name, args)
            try:
                validate_json(instance=result, schema=TOOLS[tool_name].output_schema)
            except JsonSchemaError as exc:
                raise AuthorizationFailure("tool_output_invalid", status=502) from exc
            if operation_id:
                receipt = ExecutionReceipt(
                    operation_id=operation_id,
                    request_digest=request_hash,
                    result=dict(result),
                    decision_digest=digest(current),
                    effect_count=self.effect_count,
                )
                self.operations[operation_id] = receipt
            if isinstance(args, PaymentArgs):
                self.approvals[args.approval_id].used = True
        if lose_response_after_commit:
            raise UnknownOutcome(operation_id or tool_name)
        return result

    def _reconcile(
        self, operation_id: str | None, request_hash: str
    ) -> dict[str, Any] | None:
        if operation_id is None or operation_id not in self.operations:
            return None
        prior = self.operations[operation_id]
        if prior.request_digest != request_hash:
            raise AuthorizationFailure("operation_id_conflict", status=409)
        return dict(prior.result) | {"reconciled": True}

    def _raise_decision(self, decision: Decision, definition: ToolDefinition) -> None:
        if decision.reason_codes == ("scope_insufficient",):
            raise AuthorizationFailure(
                "scope_insufficient",
                status=403,
                required_scopes=(definition.scope,),
                challenge=True,
            )
        raise AuthorizationFailure(decision.reason_codes[0], status=403)

    def _execute(
        self, caller: VerifiedCaller, tool_name: str, args: StrictModel
    ) -> dict[str, Any]:
        if self.force_bad_output:
            return {"untrusted": "<script>send-secret()</script>"}
        if isinstance(args, SearchArgs):
            query = {"status": args.status, "limit": args.limit}
            permitted = [
                record.claim_id
                for record in self.claims.values()
                if record.claim_id in self.task.resources
                and record.tenant_id == caller.tenant_id
                and record.owner_id == caller.subject_id
                and record.status == args.status
            ][: args.limit]
            handle_value = (
                "state-"
                + digest({"q": query, "s": caller.subject_id, "t": caller.task_id})[:24]
            )
            self.state_handles[handle_value] = StateHandle(
                handle_value,
                caller.subject_id,
                caller.tenant_id,
                caller.task_id,
                digest(query),
                self.now + 60,
            )
            return {"claim_ids": permitted, "next_state_handle": handle_value}
        record = self.claims[args.claim_id]  # type: ignore[attr-defined]
        if isinstance(args, ReadArgs):
            return {
                "claim_id": record.claim_id,
                "status": record.status,
                "version": record.version,
            }
        if isinstance(args, UpdateArgs):
            record.status = args.status
            record.version += 1
            self.effect_count += 1
            return {
                "claim_id": record.claim_id,
                "status": record.status,
                "version": record.version,
                "operation_id": args.operation_id,
            }
        if isinstance(args, PaymentArgs):
            self.effect_count += 1
            return {
                "payment_id": "payment-" + digest(effect_arguments(args))[:12],
                "operation_id": args.operation_id,
                "status": "submitted",
            }
        raise AssertionError("unreachable tool")

    def exchange_downstream(
        self,
        compact_token: str,
        *,
        audience: str,
        scopes: tuple[str, ...],
    ) -> dict[str, Any]:
        caller = self.authenticate(compact_token)
        allowed = {
            "https://claims-api.northstar.example": frozenset(
                {"claims:read", "claims:update"}
            ),
            "https://payments-api.northstar.example": frozenset({"payments:create"}),
        }
        requested = frozenset(scopes)
        if audience not in allowed:
            raise AuthorizationFailure("downstream_audience_not_allowed")
        if (
            not requested
            or not requested <= allowed[audience]
            or not requested <= caller.scopes
        ):
            raise AuthorizationFailure("downstream_scope_not_attenuated")
        return {
            "aud": audience,
            "scope": sorted(requested),
            "sub": caller.subject_id,
            "act": {
                "sub": caller.agent_id,
                "client_id": caller.client_id,
                "workload_id": caller.workload_id,
            },
            "task_id": caller.task_id,
            "expires_at": self.now + 60,
            "source_token_forwarded": False,
        }


@dataclass(frozen=True)
class Scenario:
    case_id: str
    expected_allowed: bool
    mutation: str


def build_cases() -> list[Scenario]:
    """Labeled release matrix: ordinary work plus realistic abuse and failures."""

    allowed = [
        ("valid_search", "valid_search"),
        ("valid_read", "valid_read"),
        ("valid_update", "valid_update"),
        ("valid_payment", "valid_payment"),
        ("valid_downstream_exchange", "valid_exchange"),
    ]
    blocked = [
        "wrong_signature",
        "unknown_kid",
        "wrong_issuer",
        "wrong_audience",
        "expired_token",
        "future_token",
        "long_lived_token",
        "wrong_typ",
        "missing_scope",
        "subject_substitution",
        "tenant_substitution",
        "agent_substitution",
        "client_substitution",
        "workload_substitution",
        "task_substitution",
        "inactive_task",
        "revoked_workload",
        "revoked_client",
        "revoked_subject",
        "tool_not_delegated",
        "cross_resource_read",
        "unknown_resource",
        "extra_argument",
        "wrong_argument_type",
        "stale_resource_version",
        "approval_missing",
        "approval_changed_amount",
        "approval_expired",
        "approval_wrong_policy",
        "approval_replay",
        "risk_policy_denial",
        "operation_id_conflict",
        "revoked_before_commit",
        "routing_name_mismatch",
        "bad_tool_output",
        "arbitrary_downstream_audience",
        "widened_downstream_scope",
        "foreign_state_handle",
        "changed_state_handle_query",
    ]
    return [Scenario(case_id, True, mutation) for case_id, mutation in allowed] + [
        Scenario(case_id, False, case_id) for case_id in blocked
    ]


def _base_call(
    engine: AuthorizationEngine, token: str, tool: str, args: dict[str, Any]
) -> None:
    if tool == "payment.create":
        approval_id = str(args.get("approval_id", "approval-001"))
        approval_args = dict(args)
        approval_args.pop("approval_id", None)
        engine.prepare_approval(token, approval_args, approval_id=approval_id)
    engine.invoke(token, tool, args)


def run_case(case: Scenario, *, hardened: bool = True) -> bool:
    if not hardened:
        # Deliberately vulnerable baseline: decode-only auth plus name-based dispatch.
        return case.mutation not in {"unknown_resource", "wrong_argument_type"}
    issuer = TrainingIssuer()
    engine = AuthorizationEngine(issuer)
    token_kwargs: dict[str, Any] = {}
    tool = "claim.read"
    args: dict[str, Any] = {"claim_id": CLAIM}
    invoke_kwargs: dict[str, Any] = {}
    mutation = case.mutation
    if mutation == "valid_search":
        tool, args = "claim.search", {"status": "open", "limit": 5}
    elif mutation == "valid_update":
        tool, args = (
            "claim.update",
            {
                "claim_id": CLAIM,
                "expected_version": 4,
                "status": "approved",
                "operation_id": "op-update",
            },
        )
    elif mutation in {
        "valid_payment",
        "approval_missing",
        "approval_changed_amount",
        "approval_expired",
        "approval_wrong_policy",
        "approval_replay",
        "risk_policy_denial",
        "operation_id_conflict",
    }:
        tool, args = (
            "payment.create",
            {
                "claim_id": CLAIM,
                "amount_cents": 12_500,
                "currency": "CAD",
                "payee_id": "vendor:clinic",
                "approval_id": "approval-001",
                "operation_id": "op-payment",
            },
        )
    if mutation == "wrong_signature":
        token_kwargs["private_key"] = TrainingIssuer(seed=b"\x22" * 32).private_key
    elif mutation == "unknown_kid":
        token_kwargs["header_kid"] = "attacker-controlled-key"
    elif mutation == "wrong_issuer":
        token_kwargs["issuer"] = "https://evil.example"
    elif mutation == "wrong_audience":
        token_kwargs["audience"] = "https://other.example"
    elif mutation == "expired_token":
        token_kwargs["expires_at"] = NOW - 1
    elif mutation == "future_token":
        token_kwargs["issued_at"] = NOW + 90
    elif mutation == "long_lived_token":
        token_kwargs["expires_at"] = NOW + 3600
    elif mutation == "wrong_typ":
        token_kwargs["typ"] = "JWT"
    elif mutation == "missing_scope":
        token_kwargs["scopes"] = ("claims:search",)
    elif mutation == "subject_substitution":
        token_kwargs["subject"] = "user:mallory"
    elif mutation == "tenant_substitution":
        token_kwargs["tenant_id"] = "tenant:evil"
    elif mutation == "agent_substitution":
        token_kwargs["agent_id"] = "agent:evil"
    elif mutation == "client_substitution":
        token_kwargs["client_id"] = "client:evil"
    elif mutation == "workload_substitution":
        token_kwargs["workload_id"] = "spiffe://evil.example/agent"
    elif mutation == "task_substitution":
        token_kwargs["task_id"] = "task:evil"
    token = issuer.issue(**token_kwargs)
    try:
        if mutation == "valid_exchange":
            engine.exchange_downstream(
                token,
                audience="https://claims-api.northstar.example",
                scopes=("claims:read",),
            )
            return True
        if mutation == "arbitrary_downstream_audience":
            engine.exchange_downstream(
                token, audience="https://evil.example", scopes=("claims:read",)
            )
            return True
        if mutation == "widened_downstream_scope":
            engine.exchange_downstream(
                token,
                audience="https://claims-api.northstar.example",
                scopes=("claims:read", "payments:create"),
            )
            return True
        if mutation == "inactive_task":
            engine.task.active = False
        elif mutation == "revoked_workload":
            engine.state.workload_active = False
        elif mutation == "revoked_client":
            engine.state.client_active = False
        elif mutation == "revoked_subject":
            engine.state.subject_active = False
        elif mutation == "tool_not_delegated":
            engine.task.tools = frozenset({"claim.search"})
        elif mutation == "cross_resource_read":
            args["claim_id"] = OTHER_CLAIM
        elif mutation == "unknown_resource":
            args["claim_id"] = "claim:clm-404"
        elif mutation == "extra_argument":
            args["debug"] = True
        elif mutation == "wrong_argument_type":
            args["claim_id"] = 483
        elif mutation == "stale_resource_version":
            tool, args = (
                "claim.update",
                {
                    "claim_id": CLAIM,
                    "expected_version": 3,
                    "status": "approved",
                    "operation_id": "op-update",
                },
            )
        elif mutation == "routing_name_mismatch":
            invoke_kwargs["mcp_name"] = "payment.create"
        elif mutation == "bad_tool_output":
            engine.force_bad_output = True
        elif mutation == "revoked_before_commit":
            invoke_kwargs["before_commit"] = lambda value: setattr(
                value.task, "active", False
            )
        elif mutation in {"foreign_state_handle", "changed_state_handle_query"}:
            result = engine.invoke(
                token, "claim.search", {"status": "open", "limit": 5}
            )
            tool = "claim.search"
            args = {
                "status": "open",
                "limit": 5,
                "state_handle": result["next_state_handle"],
            }
            if mutation == "foreign_state_handle":
                engine.state_handles[args["state_handle"]] = replace(
                    engine.state_handles[args["state_handle"]],
                    subject_id="user:mallory",
                )
            else:
                args["status"] = "closed"
        if tool == "payment.create":
            if mutation != "approval_missing":
                approval_args = dict(args)
                approval_args.pop("approval_id")
                engine.prepare_approval(token, approval_args)
            if mutation == "approval_changed_amount":
                args["amount_cents"] = 12_501
            elif mutation == "approval_expired":
                engine.approvals["approval-001"].expires_at = NOW
            elif mutation == "approval_wrong_policy":
                engine.state.policy_version += 1
            elif mutation == "risk_policy_denial":
                engine.state.risk_level = "high"
            elif mutation == "approval_replay":
                engine.invoke(token, tool, args)
                args["operation_id"] = "op-payment-replay"
            elif mutation == "operation_id_conflict":
                engine.invoke(token, tool, args)
                engine.approvals["approval-002"] = replace(
                    engine.approvals["approval-001"],
                    approval_id="approval-002",
                    used=False,
                )
                args["approval_id"] = "approval-002"
                args["amount_cents"] = 12_501
        engine.invoke(token, tool, args, **invoke_kwargs)
        return True
    except (AuthorizationFailure, UnknownOutcome):
        return False


@dataclass(frozen=True)
class EvaluationMetrics:
    total: int
    expected_allowed: int
    expected_blocked: int
    invalid_acceptances: int
    valid_work_blocked: int
    outcome_matches: int


def evaluate(
    cases: list[Scenario], *, hardened: bool = True
) -> tuple[EvaluationMetrics, list[dict[str, Any]]]:
    rows: list[dict[str, Any]] = []
    for case in cases:
        observed = run_case(case, hardened=hardened)
        rows.append(
            {
                "case_id": case.case_id,
                "expected_allowed": case.expected_allowed,
                "observed_allowed": observed,
                "match": observed == case.expected_allowed,
            }
        )
    metrics = EvaluationMetrics(
        total=len(rows),
        expected_allowed=sum(row["expected_allowed"] for row in rows),
        expected_blocked=sum(not row["expected_allowed"] for row in rows),
        invalid_acceptances=sum(
            not row["expected_allowed"] and row["observed_allowed"] for row in rows
        ),
        valid_work_blocked=sum(
            row["expected_allowed"] and not row["observed_allowed"] for row in rows
        ),
        outcome_matches=sum(row["match"] for row in rows),
    )
    return metrics, rows


def release_gate(metrics: EvaluationMetrics) -> bool:
    return (
        metrics.invalid_acceptances == 0
        and metrics.valid_work_blocked == 0
        and metrics.outcome_matches == metrics.total
    )


def fixture() -> tuple[TrainingIssuer, AuthorizationEngine, str]:
    issuer = TrainingIssuer()
    engine = AuthorizationEngine(issuer)
    return issuer, engine, issuer.issue()


def main() -> None:
    metrics, _ = evaluate(build_cases())
    print(canonical(metrics))
    print("release_gate", "PASS" if release_gate(metrics) else "FAIL")


if __name__ == "__main__":
    main()
