"""Credential-free identity observability and forensics lab.

Northstar Mutual must reconstruct a suspicious claims-agent run across a human
request, agent delegation, token exchange, policy decision, enforcement point,
MCP tool, and claims API. The lab keeps telemetry as untrusted input until its
producer, authority, tenant, time, and replay properties have been verified.
"""

from __future__ import annotations

import base64
import copy
import hmac
import json
import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import asdict, dataclass
from hashlib import sha256
from pathlib import Path
from threading import RLock
from typing import Any, Literal

import networkx as nx
import yaml
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
    InMemorySpanExporter,
)
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

COURSE = Path(__file__).parent
TENANT = "tenant:northstar"
NOW = 1_800_000_000
SCHEMA_VERSION = "2.0"
POLICY_VERSION = "claims-access-17"
PSEUDONYM_KEY = b"northstar-course10-deterministic-fixture-key"


class ForensicsError(ValueError):
    """Stable, testable failure at an observability trust boundary."""


def canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()


def digest(value: Any) -> str:
    raw = value if isinstance(value, bytes) else canonical(value)
    return sha256(raw).hexdigest()


def encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def deterministic_key(label: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(sha256(label.encode()).digest())


EventType = Literal[
    "request.received",
    "agent.invoke",
    "delegation.issued",
    "credential.exchanged",
    "authorization.decision",
    "authorization.enforced",
    "tool.execute",
    "api.access",
    "telemetry.heartbeat",
]


class IdentityEvent(BaseModel):
    """Normalized producer event. Validation alone does not make it trusted."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_name: Literal["agent.identity.event"] = "agent.identity.event"
    schema_version: Literal["2.0"] = SCHEMA_VERSION
    event_id: str = Field(pattern=r"^evt:[a-z0-9-]+$")
    event_type: EventType
    tenant_id: str = TENANT
    producer: str
    sequence: int = Field(ge=1)
    occurred_at: int = NOW
    trace_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    span_id: str = Field(pattern=r"^[0-9a-f]{16}$")
    parent_span_id: str | None = Field(default=None, pattern=r"^[0-9a-f]{16}$")
    actor_id: str
    actor_type: Literal["human", "agent", "workload", "service"]
    subject_id: str | None = None
    workload_id: str | None = None
    expected_workload_id: str | None = None
    action: str
    resource: str
    outcome: Literal["success", "denied", "failure"] = "success"
    decision: Literal["permit", "deny"] | None = None
    authorization_request_id: str | None = None
    policy_version: str | None = None
    delegation_id: str | None = None
    parent_scope: frozenset[str] = frozenset()
    delegated_scope: frozenset[str] = frozenset()
    credential_fingerprint: str | None = None
    causes_event_id: str | None = None
    attributes: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def event_requirements(self) -> IdentityEvent:
        if any(
            value and "@" in value
            for value in (self.actor_id, self.subject_id, self.workload_id)
        ):
            raise ValueError("raw email identity is not allowed")
        if self.event_type.startswith("authorization.") and (
            not self.authorization_request_id or not self.policy_version
        ):
            raise ValueError("authorization evidence requires request and policy IDs")
        if self.event_type == "authorization.decision" and self.decision is None:
            raise ValueError("authorization decision missing")
        if self.event_type == "delegation.issued" and not self.delegation_id:
            raise ValueError("delegation identifier missing")
        if (
            self.event_type == "credential.exchanged"
            and not self.credential_fingerprint
        ):
            raise ValueError("credential fingerprint missing")
        return self

    def record(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


@dataclass(frozen=True)
class Producer:
    producer_id: str
    allowed_types: frozenset[str]
    key: Ed25519PrivateKey


class TelemetryAuthority:
    """Owns deterministic teaching keys and producer-to-event authority."""

    def __init__(self) -> None:
        definitions = {
            "edge-gateway": {"request.received"},
            "agent-runtime": {"agent.invoke"},
            "governance": {"delegation.issued"},
            "token-service": {"credential.exchanged"},
            "policy-engine": {"authorization.decision"},
            "policy-enforcer": {"authorization.enforced"},
            "mcp-gateway": {"tool.execute"},
            "claims-api": {"api.access"},
            "telemetry-control": {"telemetry.heartbeat"},
        }
        self.producers = {
            name: Producer(
                name,
                frozenset(types),
                deterministic_key(f"northstar-telemetry:{name}"),
            )
            for name, types in definitions.items()
        }

    def issue(self, event: IdentityEvent, *, envelope_id: str | None = None) -> str:
        try:
            producer = self.producers[event.producer]
        except KeyError as exc:
            raise ForensicsError("producer_unknown") from exc
        body = {
            "envelope_id": envelope_id or f"env:{event.event_id}",
            "producer": producer.producer_id,
            "event": event.record(),
        }
        envelope = {**body, "signature": encode(producer.key.sign(canonical(body)))}
        return canonical(envelope).decode()


SENSITIVE_KEYS = {
    "access_token",
    "refresh_token",
    "api_key",
    "client_secret",
    "private_key",
    "authorization",
    "cookie",
    "prompt",
    "tool_arguments",
    "tool_result",
}
SECRET_PATTERNS = (
    re.compile(r"(?i)bearer\s+[a-z0-9._~+/=-]{8,}"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{8,}\b"),
)
EMAIL = re.compile(r"(?i)^[^@\s]+@[^@\s]+\.[^@\s]+$")


def fingerprint(identifier: str, key: bytes) -> str:
    if len(key) < 16:
        raise ForensicsError("pseudonym_key_too_short")
    return "hmac:" + hmac.new(key, identifier.encode(), sha256).hexdigest()


def sanitize(value: Any, key: bytes = PSEUDONYM_KEY) -> tuple[Any, int]:
    """Recursively redact secrets and pseudonymize standalone email values."""

    count = 0
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for raw_key, raw_value in value.items():
            field_name = str(raw_key)
            if field_name.lower() in SENSITIVE_KEYS:
                result[field_name] = "[REDACTED]"
                count += 1
            else:
                result[field_name], nested = sanitize(raw_value, key)
                count += nested
        return result, count
    if isinstance(value, list):
        result = []
        for item in value:
            cleaned, nested = sanitize(item, key)
            result.append(cleaned)
            count += nested
        return result, count
    if isinstance(value, str):
        if EMAIL.fullmatch(value):
            return fingerprint(value.lower(), key), 1
        cleaned = value
        for pattern in SECRET_PATTERNS:
            cleaned, replacements = pattern.subn("[REDACTED]", cleaned)
            count += replacements
        return cleaned, count
    return value, count


@dataclass(frozen=True)
class CollectedEvent:
    event: IdentityEvent
    observed_at: int
    envelope_id: str
    signed_event_digest: str
    verification_id: str
    redaction_count: int
    collection_anomalies: tuple[str, ...] = ()

    def record(self) -> dict[str, Any]:
        return {
            "event": self.event.record(),
            "observed_at": self.observed_at,
            "envelope_id": self.envelope_id,
            "signed_event_digest": self.signed_event_digest,
            "verification_id": self.verification_id,
            "redaction_count": self.redaction_count,
            "collection_anomalies": self.collection_anomalies,
        }


class TrustedCollector:
    """Authenticates, authorizes, sanitizes, and records collection anomalies."""

    def __init__(self, authority: TelemetryAuthority) -> None:
        self.authority = authority
        self.seen_envelopes: set[str] = set()
        self.seen_events: set[str] = set()
        self.seen_sequences: dict[str, set[int]] = {}
        self.watermarks: dict[str, int] = {}
        self.lock = RLock()

    def ingest(self, raw: str, *, observed_at: int = NOW) -> CollectedEvent:
        try:
            envelope = json.loads(raw)
            if set(envelope) != {"envelope_id", "producer", "event", "signature"}:
                raise ForensicsError("envelope_shape_invalid")
            producer = self.authority.producers[envelope["producer"]]
            body = {key: envelope[key] for key in ("envelope_id", "producer", "event")}
            producer.key.public_key().verify(
                decode(envelope["signature"]), canonical(body)
            )
            event = IdentityEvent.model_validate(envelope["event"])
        except ForensicsError:
            raise
        except (
            KeyError,
            TypeError,
            ValueError,
            InvalidSignature,
            ValidationError,
        ) as exc:
            raise ForensicsError("envelope_invalid") from exc

        if event.producer != producer.producer_id:
            raise ForensicsError("producer_binding_invalid")
        if event.event_type not in producer.allowed_types:
            raise ForensicsError("producer_authority_invalid")
        if event.tenant_id != TENANT:
            raise ForensicsError("tenant_invalid")
        if (
            event.occurred_at > observed_at + 30
            or observed_at - event.occurred_at > 3_600
        ):
            raise ForensicsError("event_time_invalid")

        signed_event_digest = digest(envelope["event"])
        cleaned_attributes, redactions = sanitize(event.attributes)
        event = event.model_copy(update={"attributes": cleaned_attributes})
        with self.lock:
            if envelope["envelope_id"] in self.seen_envelopes:
                raise ForensicsError("envelope_replayed")
            if event.event_id in self.seen_events:
                raise ForensicsError("event_replayed")
            sequences = self.seen_sequences.setdefault(event.producer, set())
            if event.sequence in sequences:
                raise ForensicsError("sequence_replayed")
            watermark = self.watermarks.get(event.producer, 0)
            anomalies = []
            if event.sequence > watermark + 1:
                anomalies.append("sequence_gap")
            elif event.sequence <= watermark:
                anomalies.append("late_out_of_order")
            sequences.add(event.sequence)
            self.watermarks[event.producer] = max(watermark, event.sequence)
            self.seen_envelopes.add(envelope["envelope_id"])
            self.seen_events.add(event.event_id)
        return CollectedEvent(
            event,
            observed_at,
            envelope["envelope_id"],
            signed_event_digest,
            digest(
                {
                    "envelope_id": envelope["envelope_id"],
                    "producer": producer.producer_id,
                    "signed_event_digest": signed_event_digest,
                }
            ),
            redactions,
            tuple(anomalies),
        )


@dataclass(frozen=True)
class TraceView:
    trace_id: str
    events: tuple[CollectedEvent, ...]
    graph: nx.DiGraph
    orphan_span_ids: tuple[str, ...]

    @property
    def ordered(self) -> tuple[CollectedEvent, ...]:
        return tuple(
            sorted(
                self.events,
                key=lambda item: (
                    item.event.occurred_at,
                    item.observed_at,
                    item.event.producer,
                    item.event.sequence,
                ),
            )
        )


def correlate(events: Iterable[CollectedEvent]) -> TraceView:
    values = tuple(events)
    if not values:
        raise ForensicsError("trace_empty")
    trace_ids = {item.event.trace_id for item in values}
    if len(trace_ids) != 1:
        raise ForensicsError("trace_mixed")
    graph = nx.DiGraph()
    for item in values:
        event = item.event
        graph.add_node(
            event.span_id, event_id=event.event_id, event_type=event.event_type
        )
    orphans = []
    for item in values:
        event = item.event
        if event.parent_span_id:
            if event.parent_span_id in graph:
                graph.add_edge(event.parent_span_id, event.span_id, relation="parent")
            else:
                orphans.append(event.span_id)
        if event.causes_event_id:
            source = next(
                (
                    other.event.span_id
                    for other in values
                    if other.event.event_id == event.causes_event_id
                ),
                None,
            )
            if source:
                graph.add_edge(source, event.span_id, relation="causes")
    return TraceView(next(iter(trace_ids)), values, graph, tuple(sorted(orphans)))


@dataclass(frozen=True)
class Rule:
    rule_id: str
    name: str
    severity: Literal["medium", "high", "critical"]
    detector: str
    evidence_requirement: str


@dataclass(frozen=True)
class Finding:
    finding_id: str
    rule_id: str
    severity: str
    trace_id: str
    evidence_event_ids: tuple[str, ...]
    status: Literal["observed", "evidence_gap"]
    explanation: str


Detector = Callable[[TraceView, int], tuple[tuple[str, ...], str] | None]


def _permit_without_enforcement(view: TraceView, _: int):
    decisions = {
        item.event.authorization_request_id: item.event
        for item in view.events
        if item.event.event_type == "authorization.decision"
        and item.event.decision == "permit"
    }
    enforced = {
        item.event.authorization_request_id
        for item in view.events
        if item.event.event_type == "authorization.enforced"
    }
    missing = sorted(set(decisions) - enforced)
    if missing:
        evidence = tuple(decisions[key].event_id for key in missing)
        return evidence, "permit decision lacks matching PEP enforcement evidence"
    return None


def _delegation_widened(view: TraceView, _: int):
    events = [
        item.event
        for item in view.events
        if item.event.event_type == "delegation.issued"
        and not item.event.delegated_scope.issubset(item.event.parent_scope)
    ]
    if events:
        return tuple(
            event.event_id for event in events
        ), "child scope exceeds parent scope"
    return None


def _orphan_span(view: TraceView, _: int):
    if view.orphan_span_ids:
        ids = tuple(
            view.graph.nodes[span_id]["event_id"] for span_id in view.orphan_span_ids
        )
        return ids, "parent span is absent; causality cannot be proven"
    return None


def _sequence_gap(view: TraceView, _: int):
    events = [
        item.event.event_id
        for item in view.events
        if "sequence_gap" in item.collection_anomalies
    ]
    if events:
        return tuple(events), "producer sequence contains an unexplained gap"
    return None


def _clock_skew(view: TraceView, _: int):
    events = [
        item.event.event_id
        for item in view.events
        if item.observed_at - item.event.occurred_at > 300
    ]
    if events:
        return tuple(events), "collection delay exceeds the forensic ordering SLO"
    return None


def _heartbeat_overdue(view: TraceView, now: int):
    heartbeats = [
        item.event
        for item in view.events
        if item.event.event_type == "telemetry.heartbeat"
    ]
    if heartbeats and now - max(event.occurred_at for event in heartbeats) > 300:
        return tuple(
            event.event_id for event in heartbeats
        ), "telemetry heartbeat overdue"
    return None


def _policy_mismatch(view: TraceView, _: int):
    versions: dict[str, set[str]] = {}
    evidence: dict[str, list[str]] = {}
    for item in view.events:
        event = item.event
        if event.authorization_request_id and event.policy_version:
            versions.setdefault(event.authorization_request_id, set()).add(
                event.policy_version
            )
            evidence.setdefault(event.authorization_request_id, []).append(
                event.event_id
            )
    mismatches = [key for key, value in versions.items() if len(value) > 1]
    if mismatches:
        ids = tuple(item for key in sorted(mismatches) for item in evidence[key])
        return ids, "PDP and PEP policy versions disagree"
    return None


def _runtime_mismatch(view: TraceView, _: int):
    events = [
        item.event
        for item in view.events
        if item.event.workload_id
        and item.event.expected_workload_id
        and item.event.workload_id != item.event.expected_workload_id
    ]
    if events:
        return tuple(
            event.event_id for event in events
        ), "runtime identity binding mismatch"
    return None


DETECTORS: dict[str, Detector] = {
    "permit_without_enforcement": _permit_without_enforcement,
    "delegation_widened": _delegation_widened,
    "orphan_span": _orphan_span,
    "sequence_gap": _sequence_gap,
    "clock_skew": _clock_skew,
    "heartbeat_overdue": _heartbeat_overdue,
    "policy_mismatch": _policy_mismatch,
    "runtime_mismatch": _runtime_mismatch,
}


def load_rules(path: Path | None = None) -> list[Rule]:
    raw = yaml.safe_load(
        (path or COURSE / "detections/identity_rules.yaml").read_text()
    )
    if set(raw) != {"rules"} or not isinstance(raw["rules"], list):
        raise ForensicsError("rules_document_invalid")
    fields = {"id", "name", "severity", "detector", "evidence_requirement"}
    rules, seen = [], set()
    for item in raw["rules"]:
        if (
            set(item) != fields
            or item["id"] in seen
            or item["detector"] not in DETECTORS
        ):
            raise ForensicsError("rule_invalid")
        seen.add(item["id"])
        rules.append(
            Rule(
                item["id"],
                item["name"],
                item["severity"],
                item["detector"],
                item["evidence_requirement"],
            )
        )
    return rules


class DetectionEngine:
    def __init__(self, rules: list[Rule] | None = None) -> None:
        self.rules = rules or load_rules()

    def detect(self, view: TraceView, *, now: int = NOW) -> list[Finding]:
        findings = []
        for rule in self.rules:
            result = DETECTORS[rule.detector](view, now)
            if result:
                ids, explanation = result
                status = (
                    "evidence_gap"
                    if rule.detector
                    in {
                        "permit_without_enforcement",
                        "orphan_span",
                        "sequence_gap",
                        "heartbeat_overdue",
                    }
                    else "observed"
                )
                findings.append(
                    Finding(
                        f"finding:{view.trace_id}:{rule.rule_id}",
                        rule.rule_id,
                        rule.severity,
                        view.trace_id,
                        tuple(sorted(ids)),
                        status,
                        explanation,
                    )
                )
        return findings


@dataclass(frozen=True)
class Checkpoint:
    count: int
    root_hash: str
    signer: str
    signature: str


class EvidenceLedger:
    """Hash-chained records with an independently verifiable signed checkpoint."""

    def __init__(self) -> None:
        self.entries: list[dict[str, Any]] = []

    def append(self, item: CollectedEvent) -> dict[str, Any]:
        previous = self.entries[-1]["entry_hash"] if self.entries else "GENESIS"
        body = {
            "sequence": len(self.entries) + 1,
            "previous_hash": previous,
            "record": item.record(),
        }
        entry = {**body, "entry_hash": digest(body)}
        self.entries.append(entry)
        return copy.deepcopy(entry)

    def checkpoint(
        self, key: Ed25519PrivateKey, signer: str = "audit-anchor"
    ) -> Checkpoint:
        root = self.entries[-1]["entry_hash"] if self.entries else "GENESIS"
        body = {"count": len(self.entries), "root_hash": root, "signer": signer}
        return Checkpoint(
            len(self.entries), root, signer, encode(key.sign(canonical(body)))
        )

    def verify(self, checkpoint: Checkpoint, public_key: Any) -> bool:
        previous = "GENESIS"
        for sequence, entry in enumerate(self.entries, 1):
            body = {key: value for key, value in entry.items() if key != "entry_hash"}
            if (
                body["sequence"] != sequence
                or body["previous_hash"] != previous
                or entry["entry_hash"] != digest(body)
            ):
                return False
            previous = entry["entry_hash"]
        body = {
            "count": checkpoint.count,
            "root_hash": checkpoint.root_hash,
            "signer": checkpoint.signer,
        }
        try:
            public_key.verify(decode(checkpoint.signature), canonical(body))
        except InvalidSignature:
            return False
        return (
            checkpoint.count == len(self.entries) and checkpoint.root_hash == previous
        )


EXPECTED_PHASES = frozenset(
    {
        "request.received",
        "agent.invoke",
        "delegation.issued",
        "credential.exchanged",
        "authorization.decision",
        "authorization.enforced",
        "tool.execute",
        "api.access",
    }
)


@dataclass(frozen=True)
class Completeness:
    expected_phases: int
    observed_phases: int
    phase_coverage: float
    attributed_events: int
    attribution_coverage: float
    permit_decisions: int
    matched_enforcements: int
    enforcement_coverage: float
    missing_phases: tuple[str, ...]


def completeness(view: TraceView) -> Completeness:
    event_types = {item.event.event_type for item in view.events}
    observed = EXPECTED_PHASES.intersection(event_types)
    attributed = sum(
        bool(item.event.actor_id and item.event.actor_type) for item in view.events
    )
    permits = {
        item.event.authorization_request_id
        for item in view.events
        if item.event.event_type == "authorization.decision"
        and item.event.decision == "permit"
    }
    enforcement = {
        item.event.authorization_request_id
        for item in view.events
        if item.event.event_type == "authorization.enforced"
    }
    return Completeness(
        len(EXPECTED_PHASES),
        len(observed),
        round(len(observed) / len(EXPECTED_PHASES), 3),
        attributed,
        round(attributed / len(view.events), 3),
        len(permits),
        len(permits.intersection(enforcement)),
        round(len(permits.intersection(enforcement)) / len(permits), 3)
        if permits
        else 1.0,
        tuple(sorted(EXPECTED_PHASES - observed)),
    )


def build_case_bundle(
    view: TraceView,
    findings: Iterable[Finding],
    checkpoint: Checkpoint,
) -> dict[str, Any]:
    timeline = [
        {
            "event_id": item.event.event_id,
            "event_type": item.event.event_type,
            "occurred_at": item.event.occurred_at,
            "observed_at": item.observed_at,
            "actor_id": item.event.actor_id,
            "resource": item.event.resource,
            "verification_id": item.verification_id,
            "claim_status": "observed",
        }
        for item in view.ordered
    ]
    gaps = [
        {
            "rule_id": finding.rule_id,
            "status": finding.status,
            "explanation": finding.explanation,
            "evidence_event_ids": finding.evidence_event_ids,
        }
        for finding in findings
    ]
    result = {
        "trace_id": view.trace_id,
        "timeline": timeline,
        "findings": gaps,
        "completeness": asdict(completeness(view)),
        "checkpoint": asdict(checkpoint),
    }
    result["manifest_digest"] = digest(result)
    return result


def otel_trace_demo() -> list[dict[str, Any]]:
    """Exercise the real OpenTelemetry SDK with privacy-safe low-cardinality data."""

    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    tracer = provider.get_tracer("northstar.identity", "1.0")
    with tracer.start_as_current_span("invoke_agent claims") as root:
        root.set_attribute("gen_ai.operation.name", "invoke_agent")
        root.set_attribute("gen_ai.agent.name", "claims")
        root.set_attribute("northstar.tenant.id", TENANT)
        with tracer.start_as_current_span("execute_tool policy-search") as tool:
            tool.set_attribute("gen_ai.operation.name", "execute_tool")
            tool.set_attribute("gen_ai.tool.name", "policy-search")
            tool.set_attribute("northstar.authorization.decision", "permit")
    provider.shutdown()
    return [
        {
            "name": span.name,
            "trace_id": format(span.context.trace_id, "032x"),
            "span_id": format(span.context.span_id, "016x"),
            "parent_span_id": format(span.parent.span_id, "016x")
            if span.parent
            else None,
            "attributes": dict(span.attributes),
        }
        for span in exporter.get_finished_spans()
    ]


TRACE_ID = "4bf92f3577b34da6a3ce929d0e0e4736"
SPANS = {
    "request": "00f067aa0ba902b7",
    "agent": "b7ad6b7169203331",
    "delegate": "a4f0d1c2b3e4f501",
    "token": "a4f0d1c2b3e4f502",
    "decision": "a4f0d1c2b3e4f503",
    "enforce": "a4f0d1c2b3e4f504",
    "tool": "a4f0d1c2b3e4f505",
    "api": "a4f0d1c2b3e4f506",
    "heartbeat": "a4f0d1c2b3e4f507",
}
SOURCE_FOR_TYPE = {
    "request.received": "edge-gateway",
    "agent.invoke": "agent-runtime",
    "delegation.issued": "governance",
    "credential.exchanged": "token-service",
    "authorization.decision": "policy-engine",
    "authorization.enforced": "policy-enforcer",
    "tool.execute": "mcp-gateway",
    "api.access": "claims-api",
    "telemetry.heartbeat": "telemetry-control",
}


def make_event(
    label: str,
    event_type: EventType,
    *,
    sequence: int = 1,
    seconds: int = 0,
    span: str | None = None,
    parent: str | None = SPANS["agent"],
    **changes: Any,
) -> IdentityEvent:
    values: dict[str, Any] = {
        "event_id": f"evt:{label}",
        "event_type": event_type,
        "producer": SOURCE_FOR_TYPE[event_type],
        "sequence": sequence,
        "occurred_at": NOW + seconds,
        "trace_id": TRACE_ID,
        "span_id": span or digest(label)[:16],
        "parent_span_id": parent,
        "actor_id": "agent:claims",
        "actor_type": "agent",
        "subject_id": "user:1042",
        "workload_id": "spiffe://northstar.example/prod/claims-agent",
        "expected_workload_id": "spiffe://northstar.example/prod/claims-agent",
        "action": "claims.read",
        "resource": "claim:synthetic-42",
    }
    if event_type.startswith("authorization."):
        values.update(
            authorization_request_id="authz:42",
            policy_version=POLICY_VERSION,
        )
    if event_type == "authorization.decision":
        values["decision"] = "permit"
    if event_type == "delegation.issued":
        values.update(
            delegation_id="delegation:42",
            parent_scope={"claims.read"},
            delegated_scope={"claims.read"},
        )
    if event_type == "credential.exchanged":
        values["credential_fingerprint"] = fingerprint("credential:42", PSEUDONYM_KEY)
    values.update(changes)
    return IdentityEvent(**values)


def complete_trace(prefix: str = "normal") -> list[IdentityEvent]:
    return [
        make_event(
            f"{prefix}-request",
            "request.received",
            span=SPANS["request"],
            parent=None,
            actor_id="user:1042",
            actor_type="human",
        ),
        make_event(
            f"{prefix}-agent",
            "agent.invoke",
            seconds=1,
            span=SPANS["agent"],
            parent=SPANS["request"],
        ),
        make_event(
            f"{prefix}-delegation",
            "delegation.issued",
            seconds=2,
            span=SPANS["delegate"],
        ),
        make_event(
            f"{prefix}-token",
            "credential.exchanged",
            seconds=3,
            span=SPANS["token"],
        ),
        make_event(
            f"{prefix}-decision",
            "authorization.decision",
            seconds=4,
            span=SPANS["decision"],
        ),
        make_event(
            f"{prefix}-enforce",
            "authorization.enforced",
            seconds=5,
            span=SPANS["enforce"],
            causes_event_id=f"evt:{prefix}-decision",
        ),
        make_event(
            f"{prefix}-tool",
            "tool.execute",
            seconds=6,
            span=SPANS["tool"],
        ),
        make_event(
            f"{prefix}-api",
            "api.access",
            seconds=7,
            span=SPANS["api"],
        ),
    ]


@dataclass(frozen=True)
class Case:
    case_id: str
    events: tuple[IdentityEvent, ...]
    expected_rules: tuple[str, ...]
    observed_at: int = NOW + 10

    @property
    def expected_detected(self) -> bool:
        return bool(self.expected_rules)


def cases() -> list[Case]:
    normal = complete_trace()

    def changed(case_id: str, index: int, **updates: Any) -> Case:
        events = copy.deepcopy(normal)
        events[index] = events[index].model_copy(
            update={"event_id": f"evt:{case_id}", **updates}
        )
        return Case(case_id, tuple(events), ())

    values = [
        Case("normal-complete", tuple(normal), ()),
        Case(
            "denied-without-enforcement",
            tuple(
                event.model_copy(update={"decision": "deny", "outcome": "denied"})
                if event.event_type == "authorization.decision"
                else event
                for event in normal
                if event.event_type != "authorization.enforced"
            ),
            (),
        ),
        changed(
            "normal-redaction", 6, attributes={"user_email": "analyst@example.test"}
        ),
        changed("normal-single-sequence", 7, sequence=1),
        changed("normal-policy", 4, policy_version=POLICY_VERSION),
        changed("normal-runtime", 1),
    ]
    missing_enforcement = tuple(
        event for event in normal if event.event_type != "authorization.enforced"
    )
    values.extend(
        [
            Case("missing-enforcement", missing_enforcement, ("OBS-001",)),
            Case(
                "widened-delegation",
                tuple(
                    event.model_copy(
                        update={
                            "event_id": "evt:widened-delegation",
                            "delegated_scope": frozenset(
                                {"claims.read", "claims.export"}
                            ),
                        }
                    )
                    if event.event_type == "delegation.issued"
                    else event
                    for event in normal
                ),
                ("OBS-002",),
            ),
            Case(
                "orphan-tool",
                tuple(
                    event.model_copy(
                        update={
                            "event_id": "evt:orphan-tool",
                            "parent_span_id": "ffffffffffffffff",
                        }
                    )
                    if event.event_type == "tool.execute"
                    else event
                    for event in normal
                ),
                ("OBS-003",),
            ),
            Case(
                "producer-sequence-gap",
                tuple(
                    event.model_copy(
                        update={"event_id": "evt:producer-sequence-gap", "sequence": 3}
                    )
                    if event.event_type == "api.access"
                    else event
                    for event in normal
                ),
                ("OBS-004",),
            ),
            Case(
                "clock-skew",
                tuple(
                    event.model_copy(
                        update={"event_id": "evt:clock-skew", "occurred_at": NOW - 500}
                    )
                    if event.event_type == "tool.execute"
                    else event
                    for event in normal
                ),
                ("OBS-005",),
            ),
            Case(
                "heartbeat-overdue",
                tuple(normal)
                + (
                    make_event(
                        "heartbeat-overdue",
                        "telemetry.heartbeat",
                        occurred_at=NOW - 600,
                        span=SPANS["heartbeat"],
                        parent=None,
                    ),
                ),
                ("OBS-005", "OBS-006"),
            ),
            Case(
                "policy-mismatch",
                tuple(
                    event.model_copy(
                        update={
                            "event_id": "evt:policy-mismatch",
                            "policy_version": "claims-access-16",
                        }
                    )
                    if event.event_type == "authorization.enforced"
                    else event
                    for event in normal
                ),
                ("OBS-007",),
            ),
            Case(
                "runtime-mismatch",
                tuple(
                    event.model_copy(
                        update={
                            "event_id": "evt:runtime-mismatch",
                            "workload_id": "spiffe://northstar.example/dev/unknown",
                        }
                    )
                    if event.event_type == "agent.invoke"
                    else event
                    for event in normal
                ),
                ("OBS-008",),
            ),
        ]
    )
    compounds = [
        ("missing-and-widened", {"OBS-001", "OBS-002"}),
        ("orphan-and-skew", {"OBS-003", "OBS-005"}),
        ("gap-and-runtime", {"OBS-004", "OBS-008"}),
        ("policy-and-orphan", {"OBS-003", "OBS-007"}),
        ("widened-and-runtime", {"OBS-002", "OBS-008"}),
        ("triple-gap", {"OBS-001", "OBS-003", "OBS-004"}),
    ]
    for case_id, rules in compounds:
        events = list(copy.deepcopy(normal))
        if "OBS-001" in rules:
            events = [
                event
                for event in events
                if event.event_type != "authorization.enforced"
            ]
        if "OBS-002" in rules:
            idx = next(
                i
                for i, event in enumerate(events)
                if event.event_type == "delegation.issued"
            )
            events[idx] = events[idx].model_copy(
                update={"delegated_scope": frozenset({"claims.read", "claims.export"})}
            )
        if "OBS-003" in rules:
            idx = next(
                i
                for i, event in enumerate(events)
                if event.event_type == "tool.execute"
            )
            events[idx] = events[idx].model_copy(
                update={"parent_span_id": "ffffffffffffffff"}
            )
        if "OBS-004" in rules:
            idx = next(
                i for i, event in enumerate(events) if event.event_type == "api.access"
            )
            events[idx] = events[idx].model_copy(update={"sequence": 3})
        if "OBS-005" in rules:
            idx = next(
                i
                for i, event in enumerate(events)
                if event.event_type == "tool.execute"
            )
            events[idx] = events[idx].model_copy(update={"occurred_at": NOW - 500})
        if "OBS-007" in rules:
            idx = next(
                i
                for i, event in enumerate(events)
                if event.event_type == "authorization.enforced"
            )
            events[idx] = events[idx].model_copy(
                update={"policy_version": "claims-access-16"}
            )
        if "OBS-008" in rules:
            idx = next(
                i
                for i, event in enumerate(events)
                if event.event_type == "agent.invoke"
            )
            events[idx] = events[idx].model_copy(
                update={"workload_id": "spiffe://northstar.example/dev/unknown"}
            )
        events = [
            event.model_copy(update={"event_id": f"evt:{case_id}-{i}"})
            for i, event in enumerate(events)
        ]
        values.append(Case(case_id, tuple(events), tuple(sorted(rules))))
    return values


def run_case(case: Case) -> tuple[str, ...]:
    authority = TelemetryAuthority()
    collector = TrustedCollector(authority)
    collected = [
        collector.ingest(authority.issue(event), observed_at=case.observed_at)
        for event in case.events
    ]
    return tuple(
        sorted(
            finding.rule_id
            for finding in DetectionEngine().detect(correlate(collected))
        )
    )


def baseline_detect(case: Case) -> bool:
    """Deliberately weak baseline: search raw logs for deny/failure strings."""

    return any(
        event.decision == "deny" or event.outcome == "failure" for event in case.events
    )


@dataclass(frozen=True)
class Evaluation:
    total: int
    exact: int
    true_positives: int
    true_negatives: int
    false_positives: int
    false_negatives: int
    precision: float
    recall: float


def evaluate(use_baseline: bool = False) -> tuple[Evaluation, list[dict[str, Any]]]:
    rows = []
    for case in cases():
        if use_baseline:
            detected = baseline_detect(case)
            actual = ("raw-deny-or-failure",) if detected else ()
            exact = detected == case.expected_detected
        else:
            actual = run_case(case)
            detected = bool(actual)
            exact = actual == case.expected_rules
        rows.append(
            {
                "case_id": case.case_id,
                "expected_detected": case.expected_detected,
                "expected_rules": case.expected_rules,
                "actual_detected": detected,
                "actual_rules": actual,
                "exact": exact,
            }
        )
    tp = sum(row["expected_detected"] and row["actual_detected"] for row in rows)
    tn = sum(
        not row["expected_detected"] and not row["actual_detected"] for row in rows
    )
    fp = sum(not row["expected_detected"] and row["actual_detected"] for row in rows)
    fn = sum(row["expected_detected"] and not row["actual_detected"] for row in rows)
    return Evaluation(
        len(rows),
        sum(row["exact"] for row in rows),
        tp,
        tn,
        fp,
        fn,
        round(tp / (tp + fp), 3) if tp + fp else 0.0,
        round(tp / (tp + fn), 3) if tp + fn else 0.0,
    ), rows


def main() -> None:
    hardened, _ = evaluate()
    baseline, _ = evaluate(True)
    print(
        json.dumps(
            {"hardened": asdict(hardened), "raw_log_baseline": asdict(baseline)},
            sort_keys=True,
            separators=(",", ":"),
        )
    )


if __name__ == "__main__":
    main()
