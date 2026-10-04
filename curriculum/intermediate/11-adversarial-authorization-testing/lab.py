"""Deterministic adversarial authorization lab for a claims agent.

The lab is deliberately local: it uses synthetic identities and an in-memory
resource. PyJWT exercises a common token library and Ed25519 authenticates the
PDP decision consumed by the policy-enforcement point (PEP).
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass, is_dataclass, replace
from enum import Enum
from hashlib import sha256
from typing import Any

import jwt
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

NOW = 1_800_200_000
ISSUER = "https://identity.northstar.example"
AUDIENCE = "https://claims-api.northstar.example"
TENANT = "tenant:northstar"
POLICY_VERSION = "claims-authz/2026-10-04"
JWT_KEY = "course-only-hs256-key-never-use-in-production"
DECISION_SEED = bytes.fromhex("22" * 32)


class DecisionOutcome(str, Enum):
    ALLOW = "allow"
    DENY = "deny"


class SecurityError(RuntimeError):
    """A stable defensive outcome suitable for tests and telemetry."""


@dataclass(frozen=True)
class Delegation:
    delegation_id: str
    parent_id: str | None
    delegator: str
    delegatee: str
    tenant_id: str
    task_id: str
    actions: tuple[str, ...]
    resources: tuple[str, ...]
    not_before: int
    expires_at: int
    depth: int
    max_depth: int
    redelegable: bool


@dataclass(frozen=True)
class ToolBinding:
    tool_id: str
    server_id: str
    schema_hash: str


@dataclass(frozen=True)
class AuthorizationRequest:
    operation_id: str
    principal_id: str
    agent_id: str
    workload_id: str
    tenant_id: str
    task_id: str
    action: str
    resource_id: str
    resource_tenant: str
    resource_version: int
    arguments: Mapping[str, Any]
    tool: ToolBinding


@dataclass(frozen=True)
class AuthorizationDecision:
    decision_id: str
    outcome: DecisionOutcome
    reason_code: str
    operation_id: str
    request_digest: str
    token_jti: str
    delegation_id: str
    resource_version: int
    issued_at: int
    expires_at: int
    policy_version: str


@dataclass(frozen=True)
class SignedDecision:
    decision: AuthorizationDecision
    signature: str


@dataclass(frozen=True)
class ExecutionReceipt:
    execution_id: str
    operation_id: str
    decision_id: str
    request_digest: str
    resource_version_before: int
    resource_version_after: int
    effect: str


@dataclass(frozen=True)
class AttackResult:
    attack_id: str
    category: str
    expected: str
    observed: str
    reason_code: str
    passed: bool


@dataclass(frozen=True)
class SecurityReport:
    total: int
    passed: int
    failed: int
    prevention_rate: float
    categories_covered: tuple[str, ...]


def canonical(value: Any) -> str:
    def convert(item: Any) -> Any:
        if is_dataclass(item) and not isinstance(item, type):
            return asdict(item)
        if isinstance(item, Enum):
            return item.value
        if isinstance(item, tuple):
            return list(item)
        raise TypeError(type(item).__name__)

    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=convert)


def digest(value: Any) -> str:
    return sha256(canonical(value).encode()).hexdigest()


def request_digest(request: AuthorizationRequest) -> str:
    """Bind every security-relevant field, including consequential arguments."""
    return digest(request)


class DecisionAuthority:
    def __init__(self) -> None:
        self._private = Ed25519PrivateKey.from_private_bytes(DECISION_SEED)
        self.public = self._private.public_key()

    def sign(self, decision: AuthorizationDecision) -> SignedDecision:
        signature = self._private.sign(canonical(decision).encode()).hex()
        return SignedDecision(decision, signature)

    def verify(self, signed: SignedDecision) -> None:
        try:
            self.public.verify(
                bytes.fromhex(signed.signature), canonical(signed.decision).encode()
            )
        except (InvalidSignature, ValueError) as exc:
            raise SecurityError("DECISION_SIGNATURE_INVALID") from exc


def issue_token(
    *,
    principal_id: str = "user:alice",
    agent_id: str = "agent:claims",
    workload_id: str = "spiffe://northstar.example/prod/claims",
    tenant_id: str = TENANT,
    task_id: str = "task:483",
    delegation_id: str = "delegation:leaf",
    scopes: tuple[str, ...] = ("claim.read", "claim.update"),
    issuer: str = ISSUER,
    audience: str = AUDIENCE,
    issued_at: int = NOW - 5,
    not_before: int = NOW - 5,
    expires_at: int = NOW + 300,
    jti: str = "token:operation-483",
    key: str = JWT_KEY,
    algorithm: str = "HS256",
) -> str:
    claims = {
        "iss": issuer,
        "aud": audience,
        "sub": principal_id,
        "act": {"sub": agent_id},
        "workload_id": workload_id,
        "tenant_id": tenant_id,
        "task_id": task_id,
        "delegation_id": delegation_id,
        "scope": " ".join(scopes),
        "iat": issued_at,
        "nbf": not_before,
        "exp": expires_at,
        "jti": jti,
    }
    return jwt.encode(claims, key, algorithm=algorithm)


def _resource_allowed(resource_id: str, allowed: tuple[str, ...]) -> bool:
    return resource_id in allowed or any(
        pattern.endswith("*") and resource_id.startswith(pattern[:-1])
        for pattern in allowed
    )


class AuthorizationService:
    """A strict, deny-by-default oracle used by the red-team corpus."""

    def __init__(
        self,
        *,
        delegations: Mapping[str, Delegation],
        tools: Mapping[str, ToolBinding],
        trusted_workloads: tuple[str, ...],
        revoked_delegations: set[str] | None = None,
        authority: DecisionAuthority | None = None,
    ) -> None:
        self.delegations = dict(delegations)
        self.tools = dict(tools)
        self.trusted_workloads = trusted_workloads
        self.revoked_delegations = revoked_delegations or set()
        self.authority = authority or DecisionAuthority()

    @staticmethod
    def _deny(request: AuthorizationRequest, reason: str, jti: str = "unverified"):
        decision = AuthorizationDecision(
            "decision:" + request.operation_id,
            DecisionOutcome.DENY,
            reason,
            request.operation_id,
            request_digest(request),
            jti,
            "unverified",
            request.resource_version,
            NOW,
            NOW,
            POLICY_VERSION,
        )
        return decision

    def _decode_token(self, token: str) -> dict[str, Any]:
        try:
            claims = jwt.decode(
                token,
                JWT_KEY,
                algorithms=["HS256"],
                issuer=ISSUER,
                audience=AUDIENCE,
                options={
                    "verify_exp": False,
                    "verify_iat": False,
                    "verify_nbf": False,
                    "require": ["iss", "aud", "sub", "exp", "iat", "nbf", "jti"],
                },
            )
        except jwt.PyJWTError as exc:
            raise SecurityError("TOKEN_INVALID") from exc
        if not isinstance(claims.get("act"), dict) or not claims["act"].get("sub"):
            raise SecurityError("TOKEN_ACTOR_MISSING")
        if claims["iat"] > NOW + 30 or claims["nbf"] > NOW or claims["exp"] <= NOW:
            raise SecurityError("TOKEN_TIME_INVALID")
        if claims["exp"] - claims["iat"] > 600:
            raise SecurityError("TOKEN_LIFETIME_EXCESSIVE")
        required = ("workload_id", "tenant_id", "task_id", "delegation_id", "scope")
        if any(not claims.get(field) for field in required):
            raise SecurityError("TOKEN_CONTEXT_MISSING")
        return claims

    def _validate_chain(
        self, leaf_id: str, request: AuthorizationRequest
    ) -> tuple[Delegation, ...]:
        chain: list[Delegation] = []
        seen: set[str] = set()
        current_id: str | None = leaf_id
        while current_id:
            if current_id in seen:
                raise SecurityError("DELEGATION_CYCLE")
            seen.add(current_id)
            current = self.delegations.get(current_id)
            if not current:
                raise SecurityError("DELEGATION_UNKNOWN")
            chain.append(current)
            current_id = current.parent_id
            if len(chain) > 8:
                raise SecurityError("DELEGATION_CHAIN_EXCESSIVE")
        chain.reverse()
        root, leaf = chain[0], chain[-1]
        if root.delegator != request.principal_id:
            raise SecurityError("DELEGATION_PRINCIPAL_MISMATCH")
        if leaf.delegatee != request.agent_id:
            raise SecurityError("DELEGATION_ACTOR_MISMATCH")
        for index, item in enumerate(chain):
            if item.delegation_id in self.revoked_delegations:
                raise SecurityError("DELEGATION_REVOKED")
            if (
                item.tenant_id != request.tenant_id
                or item.task_id != request.task_id
                or not item.not_before <= NOW < item.expires_at
                or item.depth != index
                or item.depth > item.max_depth
            ):
                raise SecurityError("DELEGATION_CONTEXT_INVALID")
            if index:
                parent = chain[index - 1]
                if not parent.redelegable or parent.delegatee != item.delegator:
                    raise SecurityError("REDELEGATION_INVALID")
                if (
                    not set(item.actions).issubset(parent.actions)
                    or not set(item.resources).issubset(parent.resources)
                    or item.not_before < parent.not_before
                    or item.expires_at > parent.expires_at
                    or item.max_depth > parent.max_depth
                ):
                    raise SecurityError("DELEGATION_ESCALATION")
        if request.action not in leaf.actions or not _resource_allowed(
            request.resource_id, leaf.resources
        ):
            raise SecurityError("DELEGATION_SCOPE_DENIED")
        return tuple(chain)

    def authorize(
        self,
        request: AuthorizationRequest,
        token: str,
        *,
        dependencies_available: bool = True,
    ) -> SignedDecision:
        reason = "POLICY_DEPENDENCY_UNAVAILABLE"
        jti = "unverified"
        delegation_id = "unverified"
        try:
            if not dependencies_available:
                raise SecurityError(reason)
            claims = self._decode_token(token)
            jti = claims["jti"]
            delegation_id = claims["delegation_id"]
            if claims["sub"] != request.principal_id:
                raise SecurityError("TOKEN_SUBJECT_MISMATCH")
            if claims["act"]["sub"] != request.agent_id:
                raise SecurityError("TOKEN_ACTOR_MISMATCH")
            if claims["workload_id"] != request.workload_id:
                raise SecurityError("TOKEN_WORKLOAD_MISMATCH")
            if request.workload_id not in self.trusted_workloads:
                raise SecurityError("WORKLOAD_UNTRUSTED")
            if claims["tenant_id"] != request.tenant_id:
                raise SecurityError("TOKEN_TENANT_MISMATCH")
            if request.tenant_id != request.resource_tenant:
                raise SecurityError("CROSS_TENANT_RESOURCE")
            if claims["task_id"] != request.task_id:
                raise SecurityError("TOKEN_TASK_MISMATCH")
            if request.action not in claims["scope"].split():
                raise SecurityError("TOKEN_SCOPE_DENIED")
            self._validate_chain(delegation_id, request)
            expected_tool = self.tools.get(request.tool.tool_id)
            if expected_tool != request.tool:
                raise SecurityError("TOOL_BINDING_MISMATCH")
        except SecurityError as exc:
            reason = str(exc)
            denied = replace(
                self._deny(request, reason, jti), delegation_id=delegation_id
            )
            return self.authority.sign(denied)

        allowed = AuthorizationDecision(
            "decision:" + request.operation_id,
            DecisionOutcome.ALLOW,
            "ALLOW_ASSIGNED_CLAIM",
            request.operation_id,
            request_digest(request),
            jti,
            delegation_id,
            request.resource_version,
            NOW,
            NOW + 30,
            POLICY_VERSION,
        )
        return self.authority.sign(allowed)


class PolicyEnforcementPoint:
    """Checks the authorized proposal again at the effect boundary."""

    def __init__(self, service: AuthorizationService) -> None:
        self.service = service
        self.resource_versions = {"claim:483": 7}
        self.receipts: dict[str, ExecutionReceipt] = {}

    def execute(
        self,
        signed: SignedDecision | None,
        request: AuthorizationRequest,
        *,
        now: int = NOW + 1,
    ) -> tuple[str, ExecutionReceipt]:
        if signed is None:
            raise SecurityError("PEP_DECISION_REQUIRED")
        self.service.authority.verify(signed)
        decision = signed.decision
        if decision.outcome is not DecisionOutcome.ALLOW:
            raise SecurityError("PEP_DENIED_DECISION")
        if decision.operation_id != request.operation_id:
            raise SecurityError("PEP_OPERATION_MISMATCH")
        if decision.request_digest != request_digest(request):
            raise SecurityError("PEP_REQUEST_MISMATCH")
        if now > decision.expires_at:
            raise SecurityError("PEP_DECISION_EXPIRED")
        if decision.delegation_id in self.service.revoked_delegations:
            raise SecurityError("PEP_DELEGATION_REVOKED")
        receipt_id = "execution:" + request.operation_id
        existing = self.receipts.get(receipt_id)
        if existing:
            if existing.request_digest != decision.request_digest:
                raise SecurityError("PEP_IDEMPOTENCY_CONFLICT")
            return "reconciled", existing
        current_version = self.resource_versions.get(request.resource_id)
        if current_version != decision.resource_version:
            raise SecurityError("PEP_RESOURCE_VERSION_CHANGED")
        next_version = current_version + int(request.action == "claim.update")
        receipt = ExecutionReceipt(
            receipt_id,
            request.operation_id,
            decision.decision_id,
            decision.request_digest,
            current_version,
            next_version,
            "claim_read" if request.action == "claim.read" else "claim_updated",
        )
        self.resource_versions[request.resource_id] = next_version
        self.receipts[receipt_id] = receipt
        return "executed", receipt


def course_fixture():
    root = Delegation(
        "delegation:root",
        None,
        "user:alice",
        "agent:supervisor",
        TENANT,
        "task:483",
        ("claim.read", "claim.update"),
        ("claim:483",),
        NOW - 60,
        NOW + 600,
        0,
        2,
        True,
    )
    leaf = Delegation(
        "delegation:leaf",
        root.delegation_id,
        root.delegatee,
        "agent:claims",
        TENANT,
        "task:483",
        ("claim.read", "claim.update"),
        ("claim:483",),
        NOW - 30,
        NOW + 300,
        1,
        2,
        False,
    )
    tool = ToolBinding("claims.get", "mcp://claims-prod", digest({"schema": 3}))
    service = AuthorizationService(
        delegations={root.delegation_id: root, leaf.delegation_id: leaf},
        tools={tool.tool_id: tool},
        trusted_workloads=("spiffe://northstar.example/prod/claims",),
    )
    request = AuthorizationRequest(
        "operation:483",
        "user:alice",
        "agent:claims",
        "spiffe://northstar.example/prod/claims",
        TENANT,
        "task:483",
        "claim.read",
        "claim:483",
        TENANT,
        7,
        {"fields": ["status", "amount"], "purpose": "assigned-claim"},
        tool,
    )
    return service, PolicyEnforcementPoint(service), request, issue_token()


def run_attack_corpus() -> tuple[list[AttackResult], SecurityReport]:
    """Run representative mutations through the real authorization oracle."""
    cases: list[
        tuple[
            str,
            str,
            Callable[[AuthorizationRequest, str], tuple[AuthorizationRequest, str]],
            str,
        ]
    ] = [
        (
            "token-wrong-audience",
            "token",
            lambda r, _t: (r, issue_token(audience="https://evil.example")),
            "TOKEN_INVALID",
        ),
        (
            "token-expired",
            "token",
            lambda r, _t: (
                r,
                issue_token(
                    issued_at=NOW - 400, not_before=NOW - 400, expires_at=NOW - 1
                ),
            ),
            "TOKEN_TIME_INVALID",
        ),
        (
            "actor-substitution",
            "identity",
            lambda r, t: (replace(r, agent_id="agent:attacker"), t),
            "TOKEN_ACTOR_MISMATCH",
        ),
        (
            "workload-substitution",
            "identity",
            lambda r, t: (replace(r, workload_id="spiffe://evil/workload"), t),
            "TOKEN_WORKLOAD_MISMATCH",
        ),
        (
            "cross-tenant",
            "resource",
            lambda r, t: (replace(r, resource_tenant="tenant:evil"), t),
            "CROSS_TENANT_RESOURCE",
        ),
        (
            "idor",
            "resource",
            lambda r, t: (replace(r, resource_id="claim:999"), t),
            "DELEGATION_SCOPE_DENIED",
        ),
        (
            "scope-escalation",
            "delegation",
            lambda r, t: (replace(r, action="claim.delete"), t),
            "TOKEN_SCOPE_DENIED",
        ),
        (
            "tool-substitution",
            "tool",
            lambda r, t: (replace(r, tool=replace(r.tool, server_id="mcp://evil")), t),
            "TOOL_BINDING_MISMATCH",
        ),
        (
            "schema-substitution",
            "tool",
            lambda r, t: (replace(r, tool=replace(r.tool, schema_hash="0" * 64)), t),
            "TOOL_BINDING_MISMATCH",
        ),
        (
            "task-substitution",
            "delegation",
            lambda r, t: (replace(r, task_id="task:attacker"), t),
            "TOKEN_TASK_MISMATCH",
        ),
    ]
    results: list[AttackResult] = []
    for attack_id, category, mutate, expected_reason in cases:
        service, _pep, request, token = course_fixture()
        attacked_request, attacked_token = mutate(request, token)
        decision = service.authorize(attacked_request, attacked_token).decision
        observed = decision.outcome.value
        passed = observed == "deny" and decision.reason_code == expected_reason
        results.append(
            AttackResult(
                attack_id, category, "deny", observed, decision.reason_code, passed
            )
        )
    passed = sum(result.passed for result in results)
    report = SecurityReport(
        len(results),
        passed,
        len(results) - passed,
        passed / len(results),
        tuple(sorted({result.category for result in results})),
    )
    return results, report


def main() -> None:
    service, pep, request, token = course_fixture()
    signed = service.authorize(request, token)
    status, receipt = pep.execute(signed, request)
    results, report = run_attack_corpus()
    print(
        canonical(
            {"baseline": signed.decision, "execution": status, "receipt": receipt}
        )
    )
    print(canonical(report))
    print(canonical(results))
    print("release_gate", "PASS" if report.failed == 0 else "FAIL")


if __name__ == "__main__":
    main()
