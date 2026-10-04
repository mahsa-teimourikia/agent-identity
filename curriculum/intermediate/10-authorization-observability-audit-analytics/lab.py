"""Deterministic authorization-observability and audit-evidence lab.

The lab treats telemetry as security evidence: producers are authenticated,
events are schema-shaped and privacy-minimized, retries reconcile exactly,
decision-to-action bindings are verified, and append order is tamper-evident.
"""

from __future__ import annotations

import hmac
import json
import math
import re
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass, is_dataclass
from enum import Enum
from hashlib import sha256
from threading import RLock
from typing import Any, Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

NOW = 1_800_100_000
TENANT = "tenant:northstar"
SCHEMA_VERSION = "1.0.0"
POLICY_VERSION = "policy:v21"
MODEL_VERSION = "authz-model:01KOBSERVE"
DATA_VERSION = "relationships:913"
TRUSTED_PDP = "service:authorization-pdp"
TRUSTED_PEP = "service:tool-gateway"
TRACE_ID = "4bf92f3577b34da6a3ce929d0e0e4736"
SPAN_ID = "00f067aa0ba902b7"
PSEUDONYM_KEY = b"northstar-training-pseudonym-key"
SIGNING_SEED = b"\x19" * 32
SENSITIVE_MARKERS = (
    "bearer ",
    "customer_ssn",
    "alice@example.com",
    "raw_prompt",
    "secret-token",
)


class AuditError(RuntimeError):
    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


class Decision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"


class ReceiptOutcome(str, Enum):
    EXECUTED = "executed"
    REJECTED = "rejected"
    ERROR = "error"


@dataclass(frozen=True)
class ActorEvidence:
    principal_pseudonym: str
    agent_id: str
    workload_id: str
    task_id: str
    delegation_id: str
    tenant_id: str = TENANT


@dataclass(frozen=True)
class ResourceEvidence:
    resource_type: str
    resource_pseudonym: str
    classification: Literal["internal", "confidential", "restricted"]
    version: int


@dataclass(frozen=True)
class PolicyEvidence:
    policy_version: str
    authorization_model_id: str
    relationship_data_version: str
    determining_policy_ids: tuple[str, ...]
    evaluation_error_codes: tuple[str, ...] = ()


@dataclass(frozen=True)
class DecisionEvidence:
    outcome: Decision
    reason_code: str
    risk_tier: Literal["R1", "R2", "R3", "R4"]


@dataclass(frozen=True)
class DecisionEvent:
    schema_version: str
    event_type: Literal["authorization.decision"]
    decision_id: str
    timestamp: int
    observed_at: int
    valid_until: int
    producer_sequence: int
    trace_id: str
    span_id: str
    request_id: str
    operation_id: str
    attempt: int
    action: str
    request_digest: str
    actor: ActorEvidence
    resource: ResourceEvidence
    policy: PolicyEvidence
    decision: DecisionEvidence
    latency_ms: int
    emitted_by: str = TRUSTED_PDP


@dataclass(frozen=True)
class ExecutionReceipt:
    schema_version: str
    event_type: Literal["authorization.enforcement"]
    execution_id: str
    decision_id: str
    timestamp: int
    trace_id: str
    operation_id: str
    tenant_id: str
    request_digest: str
    outcome: ReceiptOutcome
    resource_version_after: int | None
    emitted_by: str = TRUSTED_PEP


@dataclass(frozen=True)
class LedgerEntry:
    index: int
    kind: Literal["decision", "enforcement"]
    record_id: str
    record_digest: str
    previous_hash: str
    chain_hash: str


@dataclass(frozen=True)
class Finding:
    code: str
    severity: Literal["low", "medium", "high", "critical"]
    operation_id: str
    evidence_ids: tuple[str, ...]
    actual_violation: bool = False


@dataclass(frozen=True)
class SignedCheckpoint:
    checkpoint_id: str
    entry_count: int
    chain_root: str
    first_timestamp: int
    last_timestamp: int
    schema_version: str
    policy_versions: tuple[str, ...]
    signature: str


@dataclass(frozen=True)
class AuditMetrics:
    protected_operations: int
    operations_with_decision: int
    decision_coverage: float
    expected_executions: int
    compliant_executions: int
    valid_work_execution_rate: float
    actual_forbidden_executions: int
    missing_source_sequences: int
    duplicate_deliveries_reconciled: int
    integrity_valid: bool
    privacy_leaks: int
    p95_decision_latency_ms: int


@dataclass(frozen=True)
class ProtectedOperation:
    operation_id: str
    expected_decision: Decision
    should_execute: bool


def canonical(value: Any) -> str:
    def convert(item: Any) -> Any:
        if is_dataclass(item) and not isinstance(item, type):
            return asdict(item)
        if isinstance(item, Enum):
            return item.value
        if isinstance(item, (set, frozenset)):
            return sorted(item)
        raise TypeError(f"cannot canonicalize {type(item).__name__}")

    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=convert)


def digest(value: Any) -> str:
    return sha256(canonical(value).encode()).hexdigest()


def pseudonym(value: str) -> str:
    value_digest = hmac.new(PSEUDONYM_KEY, value.encode(), sha256).hexdigest()
    return "psn:" + value_digest[:24]


def request_digest(
    operation_id: str,
    tenant_id: str,
    agent_id: str,
    action: str,
    resource_id: str,
    critical_arguments: Mapping[str, Any],
) -> str:
    return digest(
        {
            "operation_id": operation_id,
            "tenant_id": tenant_id,
            "agent_id": agent_id,
            "action": action,
            "resource_id": resource_id,
            "critical_arguments": critical_arguments,
        }
    )


class TelemetryAuthority:
    """Authenticates trusted evidence producers with deterministic lab keys."""

    def __init__(self, seed: bytes = SIGNING_SEED):
        self._private_key = Ed25519PrivateKey.from_private_bytes(seed)
        self.public_key = self._private_key.public_key()

    def sign(self, value: Any) -> str:
        return self._private_key.sign(canonical(value).encode()).hex()

    def verify(self, value: Any, signature: str) -> None:
        try:
            self.public_key.verify(bytes.fromhex(signature), canonical(value).encode())
        except (InvalidSignature, ValueError) as exc:
            raise AuditError("producer_signature_invalid") from exc

    def public_key_hex(self) -> str:
        return self.public_key.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        ).hex()


def make_event(
    *,
    sequence: int = 1,
    decision_id: str | None = None,
    operation_id: str | None = None,
    request_id: str | None = None,
    attempt: int = 1,
    principal_id: str = "user:alice",
    agent_id: str = "agent:claims",
    workload_id: str = "spiffe://northstar.example/prod/claims",
    task_id: str = "task:483",
    delegation_id: str = "del:483",
    tenant_id: str = TENANT,
    action: str = "claim.read",
    resource_type: str = "claim",
    resource_id: str = "claim:483",
    resource_version: int = 7,
    classification: Literal["internal", "confidential", "restricted"] = "confidential",
    critical_arguments: Mapping[str, Any] | None = None,
    outcome: Decision = Decision.ALLOW,
    reason_code: str = "ALLOW_TASK_SCOPE",
    risk_tier: Literal["R1", "R2", "R3", "R4"] = "R2",
    determining_policy_ids: tuple[str, ...] = ("policy:claims-task",),
    evaluation_error_codes: tuple[str, ...] = (),
    policy_version: str = POLICY_VERSION,
    timestamp: int = NOW,
    observed_at: int = NOW + 1,
    valid_until: int = NOW + 60,
    latency_ms: int = 12,
    trace_id: str = TRACE_ID,
    span_id: str = SPAN_ID,
    emitted_by: str = TRUSTED_PDP,
) -> DecisionEvent:
    operation_id = operation_id or f"op:{sequence}"
    request_id = request_id or f"request:{sequence}"
    decision_id = decision_id or f"decision:{sequence}"
    critical_arguments = critical_arguments or {"purpose": "assigned-claim"}
    bound_digest = request_digest(
        operation_id,
        tenant_id,
        agent_id,
        action,
        resource_id,
        critical_arguments,
    )
    return DecisionEvent(
        SCHEMA_VERSION,
        "authorization.decision",
        decision_id,
        timestamp,
        observed_at,
        valid_until,
        sequence,
        trace_id,
        span_id,
        request_id,
        operation_id,
        attempt,
        action,
        bound_digest,
        ActorEvidence(
            pseudonym(principal_id),
            agent_id,
            workload_id,
            task_id,
            delegation_id,
            tenant_id,
        ),
        ResourceEvidence(
            resource_type, pseudonym(resource_id), classification, resource_version
        ),
        PolicyEvidence(
            policy_version,
            MODEL_VERSION,
            DATA_VERSION,
            determining_policy_ids,
            evaluation_error_codes,
        ),
        DecisionEvidence(outcome, reason_code, risk_tier),
        latency_ms,
        emitted_by,
    )


def make_receipt(
    event: DecisionEvent,
    *,
    execution_id: str | None = None,
    timestamp: int | None = None,
    request_digest_override: str | None = None,
    operation_id: str | None = None,
    tenant_id: str | None = None,
    outcome: ReceiptOutcome = ReceiptOutcome.EXECUTED,
    resource_version_after: int | None = 8,
    emitted_by: str = TRUSTED_PEP,
) -> ExecutionReceipt:
    return ExecutionReceipt(
        SCHEMA_VERSION,
        "authorization.enforcement",
        execution_id or "execution:" + event.operation_id.split(":", 1)[-1],
        event.decision_id,
        timestamp if timestamp is not None else event.timestamp + 2,
        event.trace_id,
        operation_id or event.operation_id,
        tenant_id or event.actor.tenant_id,
        request_digest_override or event.request_digest,
        outcome,
        resource_version_after,
        emitted_by,
    )


class AuditPipeline:
    def __init__(
        self,
        authority: TelemetryAuthority | None = None,
        tenant_id: str = TENANT,
    ):
        self.authority = authority or TelemetryAuthority()
        self.tenant_id = tenant_id
        self.decisions: dict[str, DecisionEvent] = {}
        self.decision_signatures: dict[str, str] = {}
        self.executions: dict[str, ExecutionReceipt] = {}
        self.execution_signatures: dict[str, str] = {}
        self.sequence_digests: dict[int, str] = {}
        self.ledger: list[LedgerEntry] = []
        self.reconciled_duplicates = 0
        self._lock = RLock()

    @staticmethod
    def _validate_trace_id(value: str, length: int) -> bool:
        return (
            bool(re.fullmatch(rf"[0-9a-f]{{{length}}}", value)) and int(value, 16) != 0
        )

    def validate_event(self, event: DecisionEvent) -> None:
        if (
            event.schema_version != SCHEMA_VERSION
            or event.event_type != "authorization.decision"
            or event.emitted_by != TRUSTED_PDP
        ):
            raise AuditError("event_contract_invalid")
        if event.actor.tenant_id != self.tenant_id:
            raise AuditError("event_tenant_invalid")
        if not self._validate_trace_id(
            event.trace_id, 32
        ) or not self._validate_trace_id(event.span_id, 16):
            raise AuditError("trace_context_invalid")
        if (
            event.producer_sequence < 1
            or event.attempt < 1
            or event.observed_at < event.timestamp
            or event.observed_at - event.timestamp > 300
            or event.timestamp > NOW + 30
            or event.valid_until < event.timestamp
            or event.valid_until - event.timestamp > 300
            or not 0 <= event.latency_ms <= 60_000
        ):
            raise AuditError("event_freshness_invalid")
        required_text = (
            event.decision_id,
            event.request_id,
            event.operation_id,
            event.action,
            event.actor.agent_id,
            event.actor.workload_id,
            event.actor.task_id,
            event.actor.delegation_id,
            event.resource.resource_type,
            event.policy.policy_version,
            event.policy.authorization_model_id,
            event.policy.relationship_data_version,
            event.decision.reason_code,
        )
        if any(not value.strip() for value in required_text):
            raise AuditError("event_field_invalid")
        if len(
            event.request_digest
        ) != 64 or not event.actor.principal_pseudonym.startswith("psn:"):
            raise AuditError("event_binding_invalid")
        if (
            event.decision.outcome is Decision.ALLOW
            and not event.policy.determining_policy_ids
        ):
            raise AuditError("allow_provenance_missing")
        if event.policy.evaluation_error_codes and (
            event.decision.outcome is not Decision.DENY
            or event.decision.reason_code != "DENY_POLICY_EVALUATION_ERROR"
        ):
            raise AuditError("evaluation_error_semantics_invalid")
        serialized = canonical(event).lower()
        if any(marker in serialized for marker in SENSITIVE_MARKERS):
            raise AuditError("sensitive_data_present")

    def validate_receipt(self, receipt: ExecutionReceipt) -> None:
        if (
            receipt.schema_version != SCHEMA_VERSION
            or receipt.event_type != "authorization.enforcement"
            or receipt.emitted_by != TRUSTED_PEP
            or receipt.tenant_id != self.tenant_id
        ):
            raise AuditError("receipt_contract_invalid")
        if not self._validate_trace_id(receipt.trace_id, 32):
            raise AuditError("trace_context_invalid")
        if receipt.timestamp > NOW + 600 or len(receipt.request_digest) != 64:
            raise AuditError("receipt_binding_invalid")

    def _append(self, kind: Literal["decision", "enforcement"], record: Any) -> None:
        record_id = record.decision_id if kind == "decision" else record.execution_id
        record_hash = digest(record)
        previous = self.ledger[-1].chain_hash if self.ledger else "GENESIS"
        index = len(self.ledger) + 1
        chain_hash = digest(
            {
                "index": index,
                "kind": kind,
                "record_id": record_id,
                "record_digest": record_hash,
                "previous_hash": previous,
            }
        )
        self.ledger.append(
            LedgerEntry(index, kind, record_id, record_hash, previous, chain_hash)
        )

    def ingest_decision(self, event: DecisionEvent, signature: str) -> str:
        with self._lock:
            self.authority.verify(event, signature)
            self.validate_event(event)
            prior = self.decisions.get(event.decision_id)
            if prior:
                if (
                    prior != event
                    or self.decision_signatures[event.decision_id] != signature
                ):
                    raise AuditError("decision_id_conflict")
                self.reconciled_duplicates += 1
                return "reconciled"
            event_hash = digest(event)
            sequence_hash = self.sequence_digests.get(event.producer_sequence)
            if sequence_hash and sequence_hash != event_hash:
                raise AuditError("producer_sequence_conflict")
            self.sequence_digests[event.producer_sequence] = event_hash
            self.decisions[event.decision_id] = event
            self.decision_signatures[event.decision_id] = signature
            self._append("decision", event)
            return "accepted"

    def record_execution(self, receipt: ExecutionReceipt, signature: str) -> str:
        with self._lock:
            self.authority.verify(receipt, signature)
            self.validate_receipt(receipt)
            prior = self.executions.get(receipt.execution_id)
            if prior:
                if (
                    prior != receipt
                    or self.execution_signatures[receipt.execution_id] != signature
                ):
                    raise AuditError("execution_id_conflict")
                self.reconciled_duplicates += 1
                return "reconciled"
            self.executions[receipt.execution_id] = receipt
            self.execution_signatures[receipt.execution_id] = signature
            self._append("enforcement", receipt)
            return "accepted"

    def missing_sequences(self) -> tuple[int, ...]:
        if not self.sequence_digests:
            return ()
        expected = set(range(1, max(self.sequence_digests) + 1))
        return tuple(sorted(expected - set(self.sequence_digests)))

    def verify_chain(self, entries: Iterable[LedgerEntry] | None = None) -> bool:
        entries = list(entries if entries is not None else self.ledger)
        previous = "GENESIS"
        for index, entry in enumerate(entries, start=1):
            expected = digest(
                {
                    "index": index,
                    "kind": entry.kind,
                    "record_id": entry.record_id,
                    "record_digest": entry.record_digest,
                    "previous_hash": previous,
                }
            )
            if (
                entry.index != index
                or entry.previous_hash != previous
                or entry.chain_hash != expected
            ):
                return False
            previous = entry.chain_hash
        return True

    def findings(self) -> list[Finding]:
        results: list[Finding] = []
        for receipt in self.executions.values():
            decision = self.decisions.get(receipt.decision_id)
            executed = receipt.outcome is ReceiptOutcome.EXECUTED
            if not decision:
                results.append(
                    Finding(
                        "PEP_BYPASS",
                        "critical",
                        receipt.operation_id,
                        (receipt.execution_id,),
                        executed,
                    )
                )
                continue
            if executed and decision.decision.outcome is Decision.DENY:
                results.append(
                    Finding(
                        "DENIED_OPERATION_EXECUTED",
                        "critical",
                        receipt.operation_id,
                        (decision.decision_id, receipt.execution_id),
                        True,
                    )
                )
            mismatched = (
                receipt.request_digest != decision.request_digest
                or receipt.operation_id != decision.operation_id
                or receipt.tenant_id != decision.actor.tenant_id
                or receipt.trace_id != decision.trace_id
            )
            if executed and mismatched:
                results.append(
                    Finding(
                        "DECISION_ACTION_MISMATCH",
                        "critical",
                        receipt.operation_id,
                        (decision.decision_id, receipt.execution_id),
                        True,
                    )
                )
            if executed and receipt.timestamp > decision.valid_until:
                results.append(
                    Finding(
                        "STALE_DECISION_EXECUTED",
                        "critical",
                        receipt.operation_id,
                        (decision.decision_id, receipt.execution_id),
                        True,
                    )
                )
        for decision in self.decisions.values():
            if decision.policy.evaluation_error_codes:
                results.append(
                    Finding(
                        "POLICY_EVALUATION_ERROR",
                        "high",
                        decision.operation_id,
                        (decision.decision_id, *decision.policy.evaluation_error_codes),
                    )
                )
            if (
                decision.decision.outcome is Decision.ALLOW
                and decision.decision.risk_tier == "R4"
            ):
                results.append(
                    Finding(
                        "HIGH_RISK_ALLOW",
                        "high",
                        decision.operation_id,
                        (decision.decision_id,),
                    )
                )
        for sequence in self.missing_sequences():
            results.append(
                Finding(
                    "SOURCE_SEQUENCE_GAP",
                    "high",
                    "producer:" + TRUSTED_PDP,
                    (str(sequence),),
                )
            )
        operations = Counter(
            receipt.operation_id
            for receipt in self.executions.values()
            if receipt.outcome is ReceiptOutcome.EXECUTED
        )
        for operation_id, count in operations.items():
            if count > 1:
                evidence = tuple(
                    sorted(
                        receipt.execution_id
                        for receipt in self.executions.values()
                        if receipt.operation_id == operation_id
                        and receipt.outcome is ReceiptOutcome.EXECUTED
                    )
                )
                results.append(
                    Finding(
                        "DUPLICATE_EFFECT",
                        "critical",
                        operation_id,
                        evidence,
                        True,
                    )
                )
        return sorted(results, key=lambda item: (item.code, item.operation_id))

    def checkpoint(self, checkpoint_id: str = "checkpoint:hour-14") -> SignedCheckpoint:
        if not self.ledger:
            raise AuditError("checkpoint_empty")
        decision_times = [event.timestamp for event in self.decisions.values()]
        execution_times = [receipt.timestamp for receipt in self.executions.values()]
        manifest = {
            "checkpoint_id": checkpoint_id,
            "entry_count": len(self.ledger),
            "chain_root": self.ledger[-1].chain_hash,
            "first_timestamp": min(decision_times + execution_times),
            "last_timestamp": max(decision_times + execution_times),
            "schema_version": SCHEMA_VERSION,
            "policy_versions": tuple(
                sorted(
                    {event.policy.policy_version for event in self.decisions.values()}
                )
            ),
        }
        return SignedCheckpoint(**manifest, signature=self.authority.sign(manifest))

    def verify_checkpoint(self, checkpoint: SignedCheckpoint) -> bool:
        manifest = asdict(checkpoint)
        signature = manifest.pop("signature")
        try:
            self.authority.verify(manifest, signature)
        except AuditError:
            return False
        return (
            checkpoint.entry_count == len(self.ledger)
            and bool(self.ledger)
            and checkpoint.chain_root == self.ledger[-1].chain_hash
            and self.verify_chain()
        )

    def privacy_leaks(self) -> int:
        exported = canonical(
            {
                "decisions": self.decisions,
                "executions": self.executions,
                "ledger": self.ledger,
            }
        ).lower()
        return sum(marker in exported for marker in SENSITIVE_MARKERS)

    def metrics(self, operations: Iterable[ProtectedOperation]) -> AuditMetrics:
        operations = list(operations)
        decisions_by_operation = {
            event.operation_id: event for event in self.decisions.values()
        }
        executions_by_operation: dict[str, list[ExecutionReceipt]] = {}
        for receipt in self.executions.values():
            executions_by_operation.setdefault(receipt.operation_id, []).append(receipt)
        operations_with_decision = sum(
            operation.operation_id in decisions_by_operation for operation in operations
        )
        expected_executions = sum(operation.should_execute for operation in operations)
        compliant_executions = 0
        for operation in operations:
            if not operation.should_execute:
                continue
            decision = decisions_by_operation.get(operation.operation_id)
            receipts = executions_by_operation.get(operation.operation_id, [])
            compliant_executions += int(
                bool(decision)
                and decision.decision.outcome is Decision.ALLOW
                and sum(
                    receipt.outcome is ReceiptOutcome.EXECUTED
                    and receipt.decision_id == decision.decision_id
                    and receipt.request_digest == decision.request_digest
                    and receipt.timestamp <= decision.valid_until
                    for receipt in receipts
                )
                == 1
            )
        latencies = sorted(event.latency_ms for event in self.decisions.values())
        p95_index = max(0, math.ceil(0.95 * len(latencies)) - 1) if latencies else 0
        actual_violations = sum(item.actual_violation for item in self.findings())
        count = len(operations)
        return AuditMetrics(
            count,
            operations_with_decision,
            operations_with_decision / count if count else 0.0,
            expected_executions,
            compliant_executions,
            compliant_executions / expected_executions if expected_executions else 1.0,
            actual_violations,
            len(self.missing_sequences()),
            self.reconciled_duplicates,
            self.verify_chain(),
            self.privacy_leaks(),
            latencies[p95_index] if latencies else 0,
        )


def otel_span_attributes(event: DecisionEvent) -> Mapping[str, str | int]:
    """Low-content attributes; IDs are acceptable on spans, not metric labels."""
    return {
        "authz.decision.id": event.decision_id,
        "authz.decision.outcome": event.decision.outcome.value,
        "authz.reason_code": event.decision.reason_code,
        "authz.action": event.action,
        "authz.risk_tier": event.decision.risk_tier,
        "authz.policy.version": event.policy.policy_version,
        "authz.model.version": event.policy.authorization_model_id,
        "authz.latency_ms": event.latency_ms,
    }


def emit_in_memory_span(event: DecisionEvent):
    """Emit one real OpenTelemetry span without a network exporter."""
    from opentelemetry import trace
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
        InMemorySpanExporter,
    )

    provider = TracerProvider()
    exporter = InMemorySpanExporter()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    remote_context = trace.SpanContext(
        trace_id=int(event.trace_id, 16),
        span_id=int(event.span_id, 16),
        is_remote=True,
        trace_flags=trace.TraceFlags(1),
        trace_state=trace.TraceState(),
    )
    parent = trace.set_span_in_context(trace.NonRecordingSpan(remote_context))
    tracer = provider.get_tracer("northstar.authorization", SCHEMA_VERSION)
    with tracer.start_as_current_span(
        "authorize " + event.action, context=parent
    ) as span:
        for key, value in otel_span_attributes(event).items():
            span.set_attribute(key, value)
    provider.shutdown()
    return exporter.get_finished_spans()[0]


def course_fixture() -> tuple[
    AuditPipeline, list[ProtectedOperation], list[DecisionEvent], list[ExecutionReceipt]
]:
    authority = TelemetryAuthority()
    pipeline = AuditPipeline(authority)
    specifications = [
        ("read", Decision.ALLOW, True, "claim.read", "ALLOW_TASK_SCOPE", "R2"),
        ("update", Decision.ALLOW, True, "claim.update", "ALLOW_TASK_SCOPE", "R3"),
        ("delete", Decision.DENY, False, "claim.delete", "DENY_TASK_SCOPE", "R4"),
        ("tenant", Decision.DENY, False, "claim.read", "DENY_TENANT", "R4"),
        (
            "expired",
            Decision.DENY,
            False,
            "claim.update",
            "DENY_DELEGATION_EXPIRED",
            "R3",
        ),
        (
            "policy-error",
            Decision.DENY,
            False,
            "claim.read",
            "DENY_POLICY_EVALUATION_ERROR",
            "R2",
        ),
        ("export", Decision.ALLOW, True, "claim.export", "ALLOW_APPROVED_EXPORT", "R4"),
        ("retry", Decision.ALLOW, True, "claim.read", "ALLOW_TASK_SCOPE", "R2"),
    ]
    operations: list[ProtectedOperation] = []
    events: list[DecisionEvent] = []
    receipts: list[ExecutionReceipt] = []
    for sequence, (name, outcome, should_execute, action, reason, risk) in enumerate(
        specifications, start=1
    ):
        operation_id = "op:" + name
        errors = ("policy:entity-attribute-missing",) if name == "policy-error" else ()
        determining = () if outcome is Decision.DENY else ("policy:claims-task",)
        event = make_event(
            sequence=sequence,
            decision_id="decision:" + name,
            operation_id=operation_id,
            request_id="request:" + name,
            action=action,
            outcome=outcome,
            reason_code=reason,
            risk_tier=risk,
            determining_policy_ids=determining,
            evaluation_error_codes=errors,
            latency_ms=9 + sequence,
            span_id=f"{sequence:016x}",
        )
        pipeline.ingest_decision(event, authority.sign(event))
        if should_execute:
            receipt = make_receipt(
                event,
                execution_id="execution:" + name,
                resource_version_after=8 if action != "claim.export" else 7,
            )
            pipeline.record_execution(receipt, authority.sign(receipt))
            receipts.append(receipt)
        operations.append(ProtectedOperation(operation_id, outcome, should_execute))
        events.append(event)
    retry = events[-1]
    pipeline.ingest_decision(retry, authority.sign(retry))
    return pipeline, operations, events, receipts


def evaluate() -> tuple[AuditMetrics, list[Finding]]:
    pipeline, operations, _, _ = course_fixture()
    return pipeline.metrics(operations), pipeline.findings()


def release_gate(metrics: AuditMetrics) -> bool:
    return (
        metrics.decision_coverage == 1.0
        and metrics.valid_work_execution_rate == 1.0
        and metrics.actual_forbidden_executions == 0
        and metrics.missing_source_sequences == 0
        and metrics.integrity_valid
        and metrics.privacy_leaks == 0
    )


def main() -> None:
    metrics, findings = evaluate()
    print(canonical(metrics))
    print("findings", canonical([asdict(item) for item in findings]))
    print("release_gate", "PASS" if release_gate(metrics) else "FAIL")


if __name__ == "__main__":
    main()
