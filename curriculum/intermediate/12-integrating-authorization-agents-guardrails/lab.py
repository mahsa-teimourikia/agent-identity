"""Secure, deterministic agent execution loop for Intermediate 12.

The model-facing input is always untrusted. Trusted application code parses,
normalizes, guardrails, authorizes, approves, executes, validates, and records.
All fixtures are synthetic and credential-free.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import asdict, dataclass, is_dataclass, replace
from enum import Enum
from hashlib import sha256
from threading import RLock
from typing import Any, Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

NOW = 1_800_300_000
TENANT = "tenant:northstar"
POLICY_VERSION = "agent-tools/2026-10-04"
TOOL_REGISTRY_VERSION = "tools/2026-10-04"
DECISION_SEED = bytes.fromhex("33" * 32)
APPROVAL_SEED = bytes.fromhex("44" * 32)


class DecisionOutcome(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    APPROVAL_REQUIRED = "approval_required"
    RETRYABLE_ERROR = "retryable_error"


class TerminalState(str, Enum):
    EXECUTED = "executed"
    RECONCILED = "reconciled"
    DENIED = "denied"
    APPROVAL_REQUIRED = "approval_required"
    INVALID_INTENT = "invalid_intent"
    GUARDRAIL_BLOCKED = "guardrail_blocked"
    RETRYABLE_ERROR = "retryable_error"
    UNKNOWN_OUTCOME = "unknown_outcome"
    RESULT_INVALID = "result_invalid"


class SecurityError(RuntimeError):
    """Stable failure at an application-owned security boundary."""


class ModelIntent(BaseModel):
    """The only fields the untrusted planner may propose."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    operation_id: str = Field(pattern=r"^operation:[a-z0-9-]+$")
    tool_name: str = Field(min_length=1, max_length=80)
    resource_id: str = Field(min_length=1, max_length=120)
    arguments: dict[str, Any]
    purpose: str = Field(min_length=3, max_length=160)

    @field_validator("arguments")
    @classmethod
    def bounded_arguments(cls, value: dict[str, Any]) -> dict[str, Any]:
        if len(canonical(value)) > 2_000:
            raise ValueError("arguments exceed 2000 canonical bytes")
        return value


class ClaimReadResult(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    claim_id: str
    status: str
    version: int


class ClaimUpdateResult(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    claim_id: str
    updated: tuple[str, ...]
    version: int


class KnowledgeSearchResult(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    document_ids: tuple[str, ...]
    count: int


class PaymentResult(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    payment_id: str
    status: Literal["accepted"]
    amount_cents: int


@dataclass(frozen=True)
class SecurityContext:
    principal_id: str
    tenant_id: str
    agent_id: str
    workload_id: str
    task_id: str
    delegation_id: str
    authenticated: bool = True


@dataclass(frozen=True)
class Delegation:
    delegation_id: str
    principal_id: str
    delegatee: str
    workload_id: str
    tenant_id: str
    task_id: str
    actions: tuple[str, ...]
    resources: tuple[str, ...]
    expires_at: int
    revoked: bool = False


@dataclass(frozen=True)
class ToolSpec:
    tool_name: str
    action: str
    server_id: str
    audience: str
    schema_hash: str
    risk_tier: Literal["R1", "R2", "R3", "R4"]
    read_only: bool


@dataclass(frozen=True)
class Resource:
    resource_id: str
    tenant_id: str
    version: int
    state: Mapping[str, Any]


@dataclass(frozen=True)
class PolicyDecision:
    decision_id: str
    outcome: DecisionOutcome
    reason_code: str
    operation_id: str
    proposal_digest: str
    action: str
    resource_id: str
    resource_version: int
    policy_version: str
    tool_registry_version: str
    issued_at: int
    expires_at: int
    constraints: Mapping[str, Any]


@dataclass(frozen=True)
class SignedDecision:
    decision: PolicyDecision
    signature: str


@dataclass(frozen=True)
class ApprovalManifest:
    approval_id: str
    operation_id: str
    proposal_digest: str
    tenant_id: str
    principal_id: str
    action: str
    resource_id: str
    resource_version: int
    decision_id: str
    policy_version: str
    approver_id: str
    approver_role: str
    issued_at: int
    expires_at: int


@dataclass(frozen=True)
class SignedApproval:
    manifest: ApprovalManifest
    signature: str


@dataclass(frozen=True)
class ExecutionReceipt:
    execution_id: str
    operation_id: str
    decision_id: str
    proposal_digest: str
    action: str
    resource_id: str
    version_before: int
    version_after: int
    result_digest: str
    approval_id: str | None


@dataclass(frozen=True)
class RunResult:
    terminal_state: TerminalState
    reason_code: str
    operation_id: str
    decision: PolicyDecision | None = None
    receipt: ExecutionReceipt | None = None
    output: Mapping[str, Any] | None = None
    attempts: int = 1


@dataclass(frozen=True)
class Scenario:
    case_id: str
    raw_intent: Mapping[str, Any]
    expected: TerminalState
    context_changes: Mapping[str, Any] | None = None
    runtime_change: str | None = None


@dataclass(frozen=True)
class EvaluationMetrics:
    total_cases: int
    valid_cases: int
    valid_executed: int
    valid_execution_rate: float
    invalid_cases: int
    invalid_executed: int
    invalid_execution_rate: float
    expected_outcomes_matched: int
    outcome_accuracy: float
    actual_forbidden_effects: int


def canonical(value: Any) -> str:
    def convert(item: Any) -> Any:
        if isinstance(item, BaseModel):
            return item.model_dump(mode="json")
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


def proposal_digest(
    context: SecurityContext,
    intent: ModelIntent,
    tool: ToolSpec,
    resource_version: int,
) -> str:
    return digest(
        {
            "operation_id": intent.operation_id,
            "principal_id": context.principal_id,
            "tenant_id": context.tenant_id,
            "agent_id": context.agent_id,
            "workload_id": context.workload_id,
            "task_id": context.task_id,
            "delegation_id": context.delegation_id,
            "tool_name": tool.tool_name,
            "tool_server": tool.server_id,
            "tool_schema": tool.schema_hash,
            "action": tool.action,
            "resource_id": intent.resource_id,
            "resource_version": resource_version,
            "arguments": intent.arguments,
            "purpose": intent.purpose,
        }
    )


class SigningAuthority:
    def __init__(self, seed: bytes) -> None:
        self._private = Ed25519PrivateKey.from_private_bytes(seed)
        self.public = self._private.public_key()

    def sign(self, value: Any) -> str:
        return self._private.sign(canonical(value).encode()).hex()

    def verify(self, value: Any, signature: str, reason: str) -> None:
        try:
            self.public.verify(bytes.fromhex(signature), canonical(value).encode())
        except (InvalidSignature, ValueError) as exc:
            raise SecurityError(reason) from exc


class ApprovalRegistry:
    """Issues exact, signed approvals and consumes them atomically once."""

    def __init__(self) -> None:
        self.authority = SigningAuthority(APPROVAL_SEED)
        self._consumed: set[str] = set()
        self._lock = RLock()

    def issue(
        self,
        context: SecurityContext,
        decision: PolicyDecision,
        *,
        approver_id: str = "user:claims-manager",
        approver_role: str = "claims_manager",
        expires_at: int = NOW + 120,
    ) -> SignedApproval:
        if approver_role != "claims_manager":
            raise SecurityError("APPROVER_NOT_ELIGIBLE")
        manifest = ApprovalManifest(
            "approval:" + decision.operation_id,
            decision.operation_id,
            decision.proposal_digest,
            context.tenant_id,
            context.principal_id,
            decision.action,
            decision.resource_id,
            decision.resource_version,
            decision.decision_id,
            decision.policy_version,
            approver_id,
            approver_role,
            NOW,
            expires_at,
        )
        return SignedApproval(manifest, self.authority.sign(manifest))

    def validate(
        self,
        approval: SignedApproval,
        context: SecurityContext,
        decision: PolicyDecision,
        *,
        now: int,
    ) -> None:
        self.authority.verify(
            approval.manifest, approval.signature, "APPROVAL_SIGNATURE_INVALID"
        )
        manifest = approval.manifest
        expected = (
            manifest.operation_id == decision.operation_id
            and manifest.proposal_digest == decision.proposal_digest
            and manifest.tenant_id == context.tenant_id
            and manifest.principal_id == context.principal_id
            and manifest.action == decision.action
            and manifest.resource_id == decision.resource_id
            and manifest.resource_version == decision.resource_version
            and manifest.decision_id == decision.decision_id
            and manifest.policy_version == decision.policy_version
            and manifest.approver_role == "claims_manager"
        )
        if not expected:
            raise SecurityError("APPROVAL_BINDING_INVALID")
        if manifest.issued_at > now or manifest.expires_at <= now:
            raise SecurityError("APPROVAL_EXPIRED")

    def consume(self, approval: SignedApproval) -> None:
        with self._lock:
            approval_id = approval.manifest.approval_id
            if approval_id in self._consumed:
                raise SecurityError("APPROVAL_REPLAYED")
            self._consumed.add(approval_id)

    def consumed(self, approval_id: str) -> bool:
        return approval_id in self._consumed


def build_tool_registry() -> dict[str, ToolSpec]:
    definitions = [
        ("claims.get", "claim.read", "mcp://claims-prod", "R1", True),
        ("claims.update", "claim.update", "mcp://claims-prod", "R3", False),
        ("knowledge.search", "knowledge.search", "mcp://knowledge-prod", "R1", True),
        ("payments.create", "payment.create", "mcp://payments-prod", "R4", False),
    ]
    return {
        name: ToolSpec(
            name,
            action,
            server,
            "https://" + server.removeprefix("mcp://"),
            digest({"tool": name, "schema_version": 1}),
            risk,
            read_only,
        )
        for name, action, server, risk, read_only in definitions
    }


class SecureAgentRuntime:
    """Policy-enforced router and PEP around an untrusted planner."""

    def __init__(self) -> None:
        self.tools = build_tool_registry()
        self.resources: dict[str, Resource] = {
            "claim:483": Resource(
                "claim:483", TENANT, 7, {"status": "open", "notes": "synthetic"}
            ),
            "account:42": Resource(
                "account:42", TENANT, 3, {"currency": "CAD", "balance": 50_000}
            ),
            "kb:claims": Resource("kb:claims", TENANT, 12, {"documents": 240}),
            "claim:evil": Resource("claim:evil", "tenant:evil", 2, {"status": "open"}),
        }
        self.delegation = Delegation(
            "delegation:483",
            "user:alice",
            "agent:claims",
            "spiffe://northstar.example/prod/claims",
            TENANT,
            "task:483",
            ("claim.read", "claim.update", "knowledge.search", "payment.create"),
            ("claim:483", "account:42", "kb:claims"),
            NOW + 600,
        )
        self.decision_authority = SigningAuthority(DECISION_SEED)
        self.approvals = ApprovalRegistry()
        self.policy_available = True
        self.receipts: dict[str, ExecutionReceipt] = {}
        self.results: dict[str, Mapping[str, Any]] = {}
        self.evidence: list[dict[str, Any]] = []
        self._lock = RLock()

    def discover_tools(self, context: SecurityContext) -> tuple[str, ...]:
        """Reduce model-visible capabilities; invocation is authorized again."""
        if not self._context_matches_delegation(context):
            return ()
        return tuple(
            sorted(
                spec.tool_name
                for spec in self.tools.values()
                if spec.action in self.delegation.actions
            )
        )

    def parse_intent(self, raw_intent: Mapping[str, Any]) -> ModelIntent:
        try:
            return ModelIntent.model_validate(raw_intent)
        except ValidationError as exc:
            raise SecurityError("INTENT_SCHEMA_INVALID") from exc

    @staticmethod
    def guardrail(intent: ModelIntent) -> str | None:
        """Content/business validation, never an identity or permission check."""
        serialized = canonical(intent).lower()
        if any(
            marker in serialized for marker in ("api_key", "password", "secret-token")
        ):
            return "SENSITIVE_CONTENT_BLOCKED"
        if intent.tool_name == "payments.create":
            amount = intent.arguments.get("amount_cents")
            if not isinstance(amount, int) or amount <= 0 or amount > 5_000_000:
                return "PAYMENT_BUSINESS_RULE_BLOCKED"
        return None

    def _context_matches_delegation(self, context: SecurityContext) -> bool:
        delegation = self.delegation
        return (
            context.authenticated
            and context.principal_id == delegation.principal_id
            and context.tenant_id == delegation.tenant_id
            and context.agent_id == delegation.delegatee
            and context.workload_id == delegation.workload_id
            and context.task_id == delegation.task_id
            and context.delegation_id == delegation.delegation_id
            and not delegation.revoked
            and NOW < delegation.expires_at
        )

    def _decision(
        self,
        context: SecurityContext,
        intent: ModelIntent,
        outcome: DecisionOutcome,
        reason: str,
        *,
        resource: Resource | None = None,
        tool: ToolSpec | None = None,
        constraints: Mapping[str, Any] | None = None,
    ) -> SignedDecision:
        resource_version = resource.version if resource else 0
        bound_digest = (
            proposal_digest(context, intent, tool, resource_version)
            if resource and tool
            else digest({"context": context, "intent": intent})
        )
        decision = PolicyDecision(
            "decision:"
            + digest({"operation": intent.operation_id, "proposal": bound_digest})[:20],
            outcome,
            reason,
            intent.operation_id,
            bound_digest,
            tool.action if tool else "unknown",
            intent.resource_id,
            resource_version,
            POLICY_VERSION,
            TOOL_REGISTRY_VERSION,
            NOW,
            NOW + 30,
            constraints or {},
        )
        return SignedDecision(decision, self.decision_authority.sign(decision))

    def authorize(
        self, context: SecurityContext, intent: ModelIntent
    ) -> SignedDecision:
        if not self.policy_available:
            return self._decision(
                context,
                intent,
                DecisionOutcome.RETRYABLE_ERROR,
                "POLICY_DEPENDENCY_UNAVAILABLE",
            )
        tool = self.tools.get(intent.tool_name)
        resource = self.resources.get(intent.resource_id)
        if not tool:
            return self._decision(context, intent, DecisionOutcome.DENY, "TOOL_UNKNOWN")
        if not self._context_matches_delegation(context):
            return self._decision(
                context, intent, DecisionOutcome.DENY, "TRUSTED_CONTEXT_INVALID"
            )
        if not resource:
            return self._decision(
                context, intent, DecisionOutcome.DENY, "RESOURCE_UNKNOWN", tool=tool
            )
        if resource.tenant_id != context.tenant_id:
            return self._decision(
                context,
                intent,
                DecisionOutcome.DENY,
                "CROSS_TENANT_RESOURCE",
                resource=resource,
                tool=tool,
            )
        if tool.action not in self.delegation.actions:
            return self._decision(
                context,
                intent,
                DecisionOutcome.DENY,
                "ACTION_OUT_OF_SCOPE",
                resource=resource,
                tool=tool,
            )
        if intent.resource_id not in self.delegation.resources:
            return self._decision(
                context,
                intent,
                DecisionOutcome.DENY,
                "RESOURCE_OUT_OF_SCOPE",
                resource=resource,
                tool=tool,
            )
        expected_prefix = {
            "claim.read": "claim:",
            "claim.update": "claim:",
            "knowledge.search": "kb:",
            "payment.create": "account:",
        }[tool.action]
        if not intent.resource_id.startswith(expected_prefix):
            return self._decision(
                context,
                intent,
                DecisionOutcome.DENY,
                "RESOURCE_TYPE_INVALID",
                resource=resource,
                tool=tool,
            )
        constraints: dict[str, Any] = {}
        if tool.action == "claim.read" and intent.arguments:
            return self._decision(
                context,
                intent,
                DecisionOutcome.DENY,
                "PARAMETER_CONSTRAINT_INVALID",
                resource=resource,
                tool=tool,
            )
        if tool.action == "knowledge.search":
            query = intent.arguments.get("query")
            if (
                set(intent.arguments) != {"query"}
                or not isinstance(query, str)
                or not query.strip()
            ):
                return self._decision(
                    context,
                    intent,
                    DecisionOutcome.DENY,
                    "PARAMETER_CONSTRAINT_INVALID",
                    resource=resource,
                    tool=tool,
                )
        if tool.action == "claim.update":
            allowed = {"status", "notes"}
            if not set(intent.arguments).issubset(allowed):
                return self._decision(
                    context,
                    intent,
                    DecisionOutcome.DENY,
                    "FIELD_NOT_AUTHORIZED",
                    resource=resource,
                    tool=tool,
                )
            constraints["allowed_fields"] = tuple(sorted(allowed))
        if tool.action == "payment.create":
            amount = intent.arguments.get("amount_cents")
            if (
                not isinstance(amount, int)
                or amount <= 0
                or amount > 1_000_000
                or intent.arguments.get("currency") != "CAD"
                or not intent.arguments.get("payee")
            ):
                return self._decision(
                    context,
                    intent,
                    DecisionOutcome.DENY,
                    "PAYMENT_CONSTRAINT_INVALID",
                    resource=resource,
                    tool=tool,
                )
            constraints["max_amount_cents"] = 1_000_000
            if amount > 50_000:
                return self._decision(
                    context,
                    intent,
                    DecisionOutcome.APPROVAL_REQUIRED,
                    "MANAGER_APPROVAL_REQUIRED",
                    resource=resource,
                    tool=tool,
                    constraints=constraints,
                )
        return self._decision(
            context,
            intent,
            DecisionOutcome.ALLOW,
            "ALLOW_POLICY",
            resource=resource,
            tool=tool,
            constraints=constraints,
        )

    def _validate_result(self, action: str, output: Mapping[str, Any]) -> bool:
        models: dict[str, type[BaseModel]] = {
            "claim.read": ClaimReadResult,
            "claim.update": ClaimUpdateResult,
            "knowledge.search": KnowledgeSearchResult,
            "payment.create": PaymentResult,
        }
        try:
            models[action].model_validate(output)
        except (KeyError, ValidationError):
            return False
        return True

    def _perform_effect(
        self, action: str, intent: ModelIntent, resource: Resource
    ) -> tuple[Mapping[str, Any], Resource]:
        if action == "claim.read":
            return (
                {
                    "claim_id": resource.resource_id,
                    "status": resource.state["status"],
                    "version": resource.version,
                },
                resource,
            )
        if action == "claim.update":
            new_state = {**resource.state, **intent.arguments}
            updated = replace(resource, version=resource.version + 1, state=new_state)
            return (
                {
                    "claim_id": resource.resource_id,
                    "updated": tuple(sorted(intent.arguments)),
                    "version": updated.version,
                },
                updated,
            )
        if action == "knowledge.search":
            return ({"document_ids": ("doc:claims-1",), "count": 1}, resource)
        if action == "payment.create":
            return (
                {
                    "payment_id": "payment:" + intent.operation_id.split(":", 1)[-1],
                    "status": "accepted",
                    "amount_cents": intent.arguments["amount_cents"],
                },
                resource,
            )
        raise SecurityError("TOOL_ACTION_UNSUPPORTED")

    def _record(self, result: RunResult, context: SecurityContext) -> RunResult:
        self.evidence.append(
            {
                "operation_id": result.operation_id,
                "terminal_state": result.terminal_state.value,
                "reason_code": result.reason_code,
                "tenant_id": context.tenant_id,
                "principal_id": context.principal_id,
                "decision_id": result.decision.decision_id if result.decision else None,
                "receipt_id": result.receipt.execution_id if result.receipt else None,
                "policy_version": POLICY_VERSION,
            }
        )
        return result

    def run(
        self,
        context: SecurityContext,
        raw_intent: Mapping[str, Any],
        *,
        approval: SignedApproval | None = None,
        now: int = NOW + 1,
        inject_unknown_outcome: bool = False,
        inject_invalid_result: bool = False,
    ) -> RunResult:
        operation_id = str(raw_intent.get("operation_id", "operation:invalid"))
        try:
            intent = self.parse_intent(raw_intent)
        except SecurityError as exc:
            return self._record(
                RunResult(TerminalState.INVALID_INTENT, str(exc), operation_id), context
            )
        guardrail_reason = self.guardrail(intent)
        if guardrail_reason:
            return self._record(
                RunResult(
                    TerminalState.GUARDRAIL_BLOCKED,
                    guardrail_reason,
                    intent.operation_id,
                ),
                context,
            )
        signed = self.authorize(context, intent)
        decision = signed.decision
        if decision.outcome is DecisionOutcome.DENY:
            return self._record(
                RunResult(
                    TerminalState.DENIED,
                    decision.reason_code,
                    intent.operation_id,
                    decision,
                ),
                context,
            )
        if decision.outcome is DecisionOutcome.RETRYABLE_ERROR:
            return self._record(
                RunResult(
                    TerminalState.RETRYABLE_ERROR,
                    decision.reason_code,
                    intent.operation_id,
                    decision,
                ),
                context,
            )
        if decision.outcome is DecisionOutcome.APPROVAL_REQUIRED and not approval:
            return self._record(
                RunResult(
                    TerminalState.APPROVAL_REQUIRED,
                    decision.reason_code,
                    intent.operation_id,
                    decision,
                ),
                context,
            )

        with self._lock:
            tool = self.tools[intent.tool_name]
            resource = self.resources[intent.resource_id]
            prior = self.receipts.get(intent.operation_id)
            if prior:
                retry_digest = proposal_digest(
                    context, intent, tool, prior.version_before
                )
                if prior.proposal_digest != retry_digest:
                    return self._record(
                        RunResult(
                            TerminalState.DENIED,
                            "IDEMPOTENCY_CONFLICT",
                            intent.operation_id,
                            decision,
                        ),
                        context,
                    )
                return self._record(
                    RunResult(
                        TerminalState.RECONCILED,
                        "OUTCOME_RECONCILED",
                        intent.operation_id,
                        decision,
                        prior,
                        self.results[intent.operation_id],
                    ),
                    context,
                )

            # Re-authorize current state at the effect boundary.
            current_signed = self.authorize(context, intent)
            self.decision_authority.verify(
                current_signed.decision,
                current_signed.signature,
                "DECISION_SIGNATURE_INVALID",
            )
            current = current_signed.decision
            if current.outcome not in {
                DecisionOutcome.ALLOW,
                DecisionOutcome.APPROVAL_REQUIRED,
            }:
                return self._record(
                    RunResult(
                        TerminalState.DENIED,
                        "COMMIT_REAUTHORIZATION_DENIED",
                        intent.operation_id,
                        current,
                    ),
                    context,
                )
            if current.expires_at <= now:
                return self._record(
                    RunResult(
                        TerminalState.DENIED,
                        "DECISION_EXPIRED",
                        intent.operation_id,
                        current,
                    ),
                    context,
                )
            if current.proposal_digest != decision.proposal_digest:
                return self._record(
                    RunResult(
                        TerminalState.DENIED,
                        "STALE_PROPOSAL_OR_RESOURCE",
                        intent.operation_id,
                        current,
                    ),
                    context,
                )
            approval_id: str | None = None
            if current.outcome is DecisionOutcome.APPROVAL_REQUIRED:
                if not approval:
                    return self._record(
                        RunResult(
                            TerminalState.APPROVAL_REQUIRED,
                            current.reason_code,
                            intent.operation_id,
                            current,
                        ),
                        context,
                    )
                try:
                    self.approvals.validate(approval, context, current, now=now)
                    self.approvals.consume(approval)
                except SecurityError as exc:
                    return self._record(
                        RunResult(
                            TerminalState.DENIED,
                            str(exc),
                            intent.operation_id,
                            current,
                        ),
                        context,
                    )
                approval_id = approval.manifest.approval_id

            output, updated_resource = self._perform_effect(
                tool.action, intent, resource
            )
            if inject_invalid_result:
                output = {"unexpected": True}
            if not self._validate_result(tool.action, output):
                return self._record(
                    RunResult(
                        TerminalState.RESULT_INVALID,
                        "TOOL_RESULT_SCHEMA_INVALID",
                        intent.operation_id,
                        current,
                    ),
                    context,
                )
            receipt = ExecutionReceipt(
                "execution:" + intent.operation_id,
                intent.operation_id,
                current.decision_id,
                current.proposal_digest,
                current.action,
                current.resource_id,
                resource.version,
                updated_resource.version,
                digest(output),
                approval_id,
            )
            self.resources[resource.resource_id] = updated_resource
            self.receipts[intent.operation_id] = receipt
            self.results[intent.operation_id] = output
            terminal = (
                TerminalState.UNKNOWN_OUTCOME
                if inject_unknown_outcome
                else TerminalState.EXECUTED
            )
            reason = "TRANSPORT_RESPONSE_LOST" if inject_unknown_outcome else "EXECUTED"
            return self._record(
                RunResult(
                    terminal,
                    reason,
                    intent.operation_id,
                    current,
                    receipt,
                    None if inject_unknown_outcome else output,
                ),
                context,
            )

    def run_with_retry(
        self,
        context: SecurityContext,
        raw_intent: Mapping[str, Any],
        *,
        max_attempts: int = 2,
    ) -> RunResult:
        if max_attempts not in {1, 2, 3}:
            raise ValueError("max_attempts must be between 1 and 3")
        result: RunResult | None = None
        for attempt in range(1, max_attempts + 1):
            result = self.run(context, raw_intent)
            if result.terminal_state is not TerminalState.RETRYABLE_ERROR:
                return replace(result, attempts=attempt)
        assert result is not None
        return replace(result, attempts=max_attempts)


class PromptOnlyBaseline:
    """Explicitly insecure simulation: trusts model-selected known tool names."""

    def run(self, raw_intent: Mapping[str, Any]) -> RunResult:
        operation_id = str(raw_intent.get("operation_id", "operation:invalid"))
        known = raw_intent.get("tool_name") in build_tool_registry()
        if known:
            return RunResult(TerminalState.EXECUTED, "PROMPT_TRUSTED", operation_id)
        return RunResult(TerminalState.DENIED, "UNKNOWN_TOOL", operation_id)


def valid_context() -> SecurityContext:
    return SecurityContext(
        "user:alice",
        TENANT,
        "agent:claims",
        "spiffe://northstar.example/prod/claims",
        "task:483",
        "delegation:483",
    )


def intent(
    operation: str,
    tool: str = "claims.get",
    resource: str = "claim:483",
    arguments: Mapping[str, Any] | None = None,
    purpose: str = "handle assigned synthetic claim",
) -> dict[str, Any]:
    return {
        "operation_id": "operation:" + operation,
        "tool_name": tool,
        "resource_id": resource,
        "arguments": dict(arguments or {}),
        "purpose": purpose,
    }


def build_scenarios() -> list[Scenario]:
    return [
        Scenario("valid-read", intent("valid-read"), TerminalState.EXECUTED),
        Scenario(
            "valid-update",
            intent("valid-update", "claims.update", arguments={"status": "reviewed"}),
            TerminalState.EXECUTED,
        ),
        Scenario(
            "valid-search",
            intent(
                "valid-search", "knowledge.search", "kb:claims", {"query": "appeal"}
            ),
            TerminalState.EXECUTED,
        ),
        Scenario(
            "approval-required",
            intent(
                "approval",
                "payments.create",
                "account:42",
                {"amount_cents": 75_000, "currency": "CAD", "payee": "vendor:7"},
            ),
            TerminalState.APPROVAL_REQUIRED,
        ),
        Scenario(
            "cross-tenant",
            intent("cross-tenant", resource="claim:evil"),
            TerminalState.DENIED,
        ),
        Scenario(
            "field-escalation",
            intent(
                "field-escalation",
                "claims.update",
                arguments={"status": "paid", "payout": 999_999},
            ),
            TerminalState.DENIED,
        ),
        Scenario(
            "unknown-admin-tool",
            intent("admin", "admin.export_all", "claim:483"),
            TerminalState.DENIED,
        ),
        Scenario(
            "untrusted-workload",
            intent("workload"),
            TerminalState.DENIED,
            {"workload_id": "spiffe://evil/workload"},
        ),
        Scenario(
            "identity-in-model-output",
            {**intent("identity"), "tenant_id": "tenant:evil"},
            TerminalState.INVALID_INTENT,
        ),
        Scenario(
            "sensitive-content",
            intent("secret", arguments={"password": "secret-token"}),
            TerminalState.GUARDRAIL_BLOCKED,
        ),
        Scenario(
            "revoked-delegation",
            intent("revoked"),
            TerminalState.DENIED,
            runtime_change="revoke",
        ),
        Scenario(
            "policy-outage",
            intent("outage"),
            TerminalState.RETRYABLE_ERROR,
            runtime_change="outage",
        ),
    ]


def evaluate(secure: bool = True) -> tuple[EvaluationMetrics, list[dict[str, Any]]]:
    rows: list[dict[str, Any]] = []
    for scenario in build_scenarios():
        context = valid_context()
        if scenario.context_changes:
            context = replace(context, **scenario.context_changes)
        if secure:
            runtime = SecureAgentRuntime()
            if scenario.runtime_change == "revoke":
                runtime.delegation = replace(runtime.delegation, revoked=True)
            if scenario.runtime_change == "outage":
                runtime.policy_available = False
            result = runtime.run(context, scenario.raw_intent)
        else:
            result = PromptOnlyBaseline().run(scenario.raw_intent)
        rows.append(
            {
                "case_id": scenario.case_id,
                "expected": scenario.expected.value,
                "observed": result.terminal_state.value,
                "reason_code": result.reason_code,
                "matched": result.terminal_state is scenario.expected,
                "executed": result.terminal_state
                in {TerminalState.EXECUTED, TerminalState.RECONCILED},
            }
        )
    valid = [row for row in rows if row["expected"] == TerminalState.EXECUTED.value]
    invalid = [row for row in rows if row["expected"] != TerminalState.EXECUTED.value]
    valid_executed = sum(row["executed"] for row in valid)
    invalid_executed = sum(row["executed"] for row in invalid)
    matched = sum(row["matched"] for row in rows)
    metrics = EvaluationMetrics(
        len(rows),
        len(valid),
        valid_executed,
        valid_executed / len(valid),
        len(invalid),
        invalid_executed,
        invalid_executed / len(invalid),
        matched,
        matched / len(rows),
        invalid_executed,
    )
    return metrics, rows


def release_gate(metrics: EvaluationMetrics) -> bool:
    return (
        metrics.valid_execution_rate == 1.0
        and metrics.invalid_execution_rate == 0.0
        and metrics.outcome_accuracy == 1.0
        and metrics.actual_forbidden_effects == 0
    )


def main() -> None:
    metrics, rows = evaluate()
    print(canonical(metrics))
    print(canonical(rows))
    print("release_gate", "PASS" if release_gate(metrics) else "FAIL")


if __name__ == "__main__":
    main()
