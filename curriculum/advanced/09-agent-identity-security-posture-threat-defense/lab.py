"""Deterministic identity posture and threat-defense teaching lab.

Northstar Mutual's research agent is compromised and used to pivot through a
tool ecosystem toward claims data and a signing key. The lab demonstrates the
trusted control plane around that incident: authenticated telemetry, typed
normalization, detection-as-code, attack-path analysis, scoped containment,
recovery gates, evidence, and measurable release criteria.
"""

from __future__ import annotations

import base64
import itertools
import json
from collections.abc import Callable, Iterable
from dataclasses import asdict, dataclass, field
from hashlib import sha256
from pathlib import Path
from threading import RLock
from typing import Any, ClassVar, Literal

import jwt
import networkx as nx
import yaml
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import BaseModel, ConfigDict, Field, ValidationError

NOW = 1_800_000_000
TENANT = "tenant:northstar"
AUDIENCE = "urn:northstar:itdr"
POLICY_VERSION = "identity-threat-2026-10"
COURSE = Path(__file__).parent


class ThreatDefenseError(ValueError):
    """Stable, testable failure at a threat-defense trust boundary."""


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def digest(value: Any) -> str:
    raw = value if isinstance(value, bytes) else canonical(value).encode()
    return base64.urlsafe_b64encode(sha256(raw).digest()).rstrip(b"=").decode()


def deterministic_key(label: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(sha256(label.encode()).digest())


EventType = Literal[
    "access",
    "admin",
    "credential",
    "delegation",
    "telemetry",
    "workload",
]


class IdentityEvent(BaseModel):
    """Normalized event; typed structure is not proof that the event is trusted."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    event_id: str = Field(pattern=r"^evt:[a-z0-9-]+$")
    event_type: EventType
    tenant_id: str = TENANT
    source: str
    sequence: int = Field(ge=1)
    occurred_at: int = NOW
    principal: str
    action: str
    target: str
    trace_id: str = Field(pattern=r"^trace:[a-z0-9-]+$")
    policy_version: str = POLICY_VERSION
    outcome: Literal["success", "denied", "failure"] = "success"
    identity_status: Literal["active", "suspended", "revoked"] = "active"
    credential_id: str = ""
    credential_version: int = Field(default=1, ge=1)
    current_credential_version: int = Field(default=1, ge=1)
    audience: str = ""
    expected_audience: str = ""
    parent_scope: frozenset[str] = frozenset()
    delegated_scope: frozenset[str] = frozenset()
    actor_type: Literal["human", "workload"] = "workload"
    assumed_identity_type: Literal["human", "workload"] = "workload"
    break_glass: bool = False
    telemetry_healthy: bool = True
    principal_env: Literal["dev", "test", "stage", "prod"] = "prod"
    target_env: Literal["dev", "test", "stage", "prod"] = "prod"
    proof_jti: str = ""
    workload_id: str = ""
    expected_workload_id: str = ""
    after_compromise: bool = False
    observed_count: int = Field(default=0, ge=0)
    baseline_count: int = Field(default=0, ge=0)
    reported_risk: int = Field(default=0, ge=0, le=100)

    def record(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


@dataclass(frozen=True)
class VerifiedEvent:
    event: IdentityEvent
    issuer: str
    envelope_id: str
    verification_id: str


@dataclass(frozen=True)
class TelemetrySource:
    issuer: str
    allowed_event_types: frozenset[str]
    key: Ed25519PrivateKey


class TelemetryAuthority:
    """Issues and verifies SET-shaped signed teaching envelopes."""

    def __init__(self) -> None:
        definitions = {
            "gateway": {"access", "credential"},
            "governance": {"admin", "delegation"},
            "workload-control": {"workload"},
            "telemetry-control": {"telemetry"},
            "kms": {"access"},
        }
        self.sources = {
            issuer: TelemetrySource(
                issuer, frozenset(event_types), deterministic_key(f"telemetry:{issuer}")
            )
            for issuer, event_types in definitions.items()
        }

    def issue(
        self,
        event: IdentityEvent,
        *,
        now: int = NOW,
        lifetime: int = 300,
        envelope_id: str | None = None,
    ) -> str:
        source = self.sources[event.source]
        claims = {
            "iss": source.issuer,
            "aud": AUDIENCE,
            "iat": now,
            "nbf": now,
            "exp": now + lifetime,
            "jti": envelope_id or f"set:{event.event_id}",
            "events": {"urn:northstar:identity-event": event.record()},
        }
        return jwt.encode(
            claims,
            source.key,
            algorithm="EdDSA",
            headers={"kid": source.issuer, "typ": "secevent+jwt"},
        )


class TelemetryIngestor:
    """Authenticates sources and enforces source authority, replay, and order."""

    def __init__(self, authority: TelemetryAuthority) -> None:
        self.authority = authority
        self.seen_envelopes: set[str] = set()
        self.watermarks: dict[tuple[str, str], int] = {}
        self.lock = RLock()

    def ingest(self, token: str, *, now: int = NOW) -> VerifiedEvent:
        try:
            header = jwt.get_unverified_header(token)
            issuer = header["kid"]
            source = self.authority.sources[issuer]
            if header.get("typ") != "secevent+jwt":
                raise ThreatDefenseError("telemetry_type_invalid")
            claims = jwt.decode(
                token,
                source.key.public_key(),
                algorithms=["EdDSA"],
                audience=AUDIENCE,
                issuer=issuer,
                options={
                    "require": ["iss", "aud", "iat", "nbf", "exp", "jti", "events"],
                    "verify_exp": False,
                    "verify_iat": False,
                    "verify_nbf": False,
                },
            )
            raw = claims["events"]["urn:northstar:identity-event"]
            event = IdentityEvent.model_validate(raw)
        except ThreatDefenseError:
            raise
        except (KeyError, ValidationError, jwt.PyJWTError) as exc:
            raise ThreatDefenseError("telemetry_invalid") from exc

        if not (claims["nbf"] <= now < claims["exp"]):
            raise ThreatDefenseError("telemetry_time_invalid")
        if event.source != issuer or event.event_type not in source.allowed_event_types:
            raise ThreatDefenseError("source_authority_invalid")
        if event.tenant_id != TENANT:
            raise ThreatDefenseError("tenant_invalid")
        if abs(event.occurred_at - now) > 600:
            raise ThreatDefenseError("event_stale")

        key = (issuer, event.tenant_id)
        with self.lock:
            if claims["jti"] in self.seen_envelopes:
                raise ThreatDefenseError("envelope_replayed")
            expected_sequence = self.watermarks.get(key, 0) + 1
            if event.sequence != expected_sequence:
                raise ThreatDefenseError("sequence_gap")
            self.seen_envelopes.add(claims["jti"])
            self.watermarks[key] = event.sequence
        return VerifiedEvent(
            event=event,
            issuer=issuer,
            envelope_id=claims["jti"],
            verification_id=digest({"issuer": issuer, "jti": claims["jti"]}),
        )


@dataclass(frozen=True)
class GraphEdge:
    source: str
    target: str
    relation: str
    actions: tuple[str, ...]
    exposure: float
    privilege: float
    detectability: float
    enabled: bool = True
    business_required: bool = False


class IdentityGraph:
    """A tenant-aware graph of effective authority and transitive trust."""

    def __init__(self) -> None:
        self.graph = nx.DiGraph()

    def add_node(
        self,
        node: str,
        kind: str,
        *,
        tenant_id: str = TENANT,
        environment: str = "prod",
        crown_jewel: bool = False,
        impact: float = 0.0,
    ) -> None:
        if not 0 <= impact <= 1:
            raise ThreatDefenseError("impact_out_of_range")
        self.graph.add_node(
            node,
            kind=kind,
            tenant_id=tenant_id,
            environment=environment,
            crown_jewel=crown_jewel,
            impact=impact,
        )

    def add_edge(self, edge: GraphEdge) -> None:
        if edge.source not in self.graph or edge.target not in self.graph:
            raise ThreatDefenseError("graph_node_unknown")
        if not all(
            0 <= value <= 1
            for value in (edge.exposure, edge.privilege, edge.detectability)
        ):
            raise ThreatDefenseError("edge_score_out_of_range")
        self.graph.add_edge(edge.source, edge.target, **asdict(edge))

    def _enabled(self) -> nx.DiGraph:
        return nx.edge_subgraph(
            self.graph,
            [(a, b) for a, b, data in self.graph.edges(data=True) if data["enabled"]],
        ).copy()

    def crown_jewels(self) -> set[str]:
        return {
            node
            for node, data in self.graph.nodes(data=True)
            if data.get("crown_jewel")
        }

    def attack_paths(self, source: str, *, cutoff: int = 7) -> list[list[str]]:
        enabled = self._enabled()
        paths: list[list[str]] = []
        if source not in enabled:
            return paths
        for target in sorted(self.crown_jewels()):
            if target in enabled and nx.has_path(enabled, source, target):
                paths.extend(
                    nx.all_simple_paths(enabled, source, target, cutoff=cutoff)
                )
        return sorted(paths, key=lambda path: (len(path), path))

    def blast_radius(self, source: str) -> set[str]:
        enabled = self._enabled()
        return set() if source not in enabled else set(nx.descendants(enabled, source))

    def path_priority(self, path: list[str]) -> dict[str, Any]:
        if len(path) < 2:
            raise ThreatDefenseError("path_too_short")
        edge_scores = []
        for source, target in itertools.pairwise(path):
            data = self.graph[source][target]
            edge_scores.append(
                0.35 * data["exposure"]
                + 0.35 * data["privilege"]
                + 0.15 * (1 - data["detectability"])
            )
        impact = self.graph.nodes[path[-1]]["impact"]
        score = round(100 * (0.8 * sum(edge_scores) / len(edge_scores) + 0.2 * impact))
        return {
            "score": score,
            "edge_count": len(edge_scores),
            "target_impact": impact,
            "label": "prioritization_index_not_probability",
        }

    def choke_points(self, sources: Iterable[str]) -> list[tuple[str, int]]:
        counts: dict[str, int] = {}
        for source in sources:
            for path in self.attack_paths(source):
                for node in path[1:-1]:
                    counts[node] = counts.get(node, 0) + 1
        return sorted(counts.items(), key=lambda item: (-item[1], item[0]))

    def simulate_edge_removal(
        self, source: str, target: str, attacker: str
    ) -> dict[str, Any]:
        if not self.graph.has_edge(source, target):
            raise ThreatDefenseError("edge_unknown")
        before = len(self.attack_paths(attacker))
        required = self.graph[source][target]["business_required"]
        self.graph[source][target]["enabled"] = False
        after = len(self.attack_paths(attacker))
        self.graph[source][target]["enabled"] = True
        return {
            "before_paths": before,
            "after_paths": after,
            "paths_removed": before - after,
            "breaks_required_business_path": required,
        }


def northstar_graph() -> IdentityGraph:
    graph = IdentityGraph()
    graph.add_node("external:vendor", "external-agent", tenant_id="tenant:partner")
    graph.add_node("agent:research", "agent")
    graph.add_node("agent:data", "agent")
    graph.add_node("tool:vector", "tool")
    graph.add_node("api:claims", "api", crown_jewel=True, impact=0.9)
    graph.add_node("kms:claims", "kms", crown_jewel=True, impact=1.0)
    graph.add_node("store:research", "data", impact=0.4)
    for edge in [
        GraphEdge(
            "external:vendor",
            "agent:research",
            "federated_access",
            ("research.read",),
            0.8,
            0.3,
            0.4,
        ),
        GraphEdge(
            "agent:research",
            "tool:vector",
            "can_invoke",
            ("search",),
            0.7,
            0.4,
            0.7,
            business_required=True,
        ),
        GraphEdge(
            "tool:vector",
            "store:research",
            "can_read",
            ("read",),
            0.4,
            0.3,
            0.8,
            business_required=True,
        ),
        GraphEdge(
            "tool:vector",
            "api:claims",
            "misconfigured_pivot",
            ("claim.read",),
            0.9,
            0.8,
            0.3,
        ),
        GraphEdge(
            "agent:research",
            "agent:data",
            "can_delegate",
            ("claim.read",),
            0.8,
            0.7,
            0.5,
        ),
        GraphEdge(
            "agent:data", "api:claims", "can_access", ("claim.read",), 0.6, 0.8, 0.6
        ),
        GraphEdge(
            "api:claims",
            "kms:claims",
            "can_sign",
            ("sign.receipt",),
            0.5,
            1.0,
            0.5,
            business_required=True,
        ),
    ]:
        graph.add_edge(edge)
    return graph


@dataclass(frozen=True)
class Rule:
    rule_id: str
    name: str
    severity: Literal["medium", "high", "critical"]
    kind: Literal["confirmed_control_violation", "behavioral_anomaly"]
    detector: str
    response: tuple[str, ...]
    attack_mapping: tuple[str, ...]


@dataclass(frozen=True)
class Finding:
    finding_id: str
    rule_id: str
    name: str
    severity: str
    kind: str
    principal: str
    target: str
    credential_id: str
    event_id: str
    trace_id: str
    response: tuple[str, ...]
    evidence_digest: str


Detector = Callable[[IdentityEvent, "DetectionEngine"], bool]


def _revoked(event: IdentityEvent, _: DetectionEngine) -> bool:
    return event.identity_status == "revoked"


def _delegation_widened(event: IdentityEvent, _: DetectionEngine) -> bool:
    return bool(event.delegated_scope - event.parent_scope)


def _stale_credential(event: IdentityEvent, _: DetectionEngine) -> bool:
    return event.credential_version != event.current_credential_version


def _human_nhi(event: IdentityEvent, _: DetectionEngine) -> bool:
    return (
        event.actor_type == "human"
        and event.assumed_identity_type == "workload"
        and not event.break_glass
    )


def _telemetry_suppressed(event: IdentityEvent, _: DetectionEngine) -> bool:
    return not event.telemetry_healthy


def _audience_mismatch(event: IdentityEvent, _: DetectionEngine) -> bool:
    return bool(
        event.audience
        and event.expected_audience
        and event.audience != event.expected_audience
    )


def _cross_environment(event: IdentityEvent, _: DetectionEngine) -> bool:
    return event.principal_env != event.target_env


def _workload_mismatch(event: IdentityEvent, _: DetectionEngine) -> bool:
    return bool(
        event.expected_workload_id and event.workload_id != event.expected_workload_id
    )


def _oauth_persistence(event: IdentityEvent, _: DetectionEngine) -> bool:
    return event.action == "oauth_client.create" and event.after_compromise


def _proof_replay(event: IdentityEvent, engine: DetectionEngine) -> bool:
    return bool(event.proof_jti and event.proof_jti in engine.seen_proofs)


def _kms_spike(event: IdentityEvent, _: DetectionEngine) -> bool:
    return (
        event.action == "kms.sign"
        and event.baseline_count > 0
        and event.observed_count >= max(10, 5 * event.baseline_count)
    )


DETECTORS: dict[str, Detector] = {
    "revoked_identity": _revoked,
    "delegation_widening": _delegation_widened,
    "stale_credential": _stale_credential,
    "human_use_of_nhi": _human_nhi,
    "telemetry_suppression": _telemetry_suppressed,
    "audience_mismatch": _audience_mismatch,
    "cross_environment": _cross_environment,
    "workload_mismatch": _workload_mismatch,
    "oauth_persistence": _oauth_persistence,
    "proof_replay": _proof_replay,
    "kms_volume_spike": _kms_spike,
}


def load_rules(path: Path | None = None) -> list[Rule]:
    raw = yaml.safe_load((path or COURSE / "detections/rules.yaml").read_text())
    if set(raw) != {"rules"} or not isinstance(raw["rules"], list):
        raise ThreatDefenseError("rules_document_invalid")
    allowed = {
        "id",
        "name",
        "severity",
        "kind",
        "detector",
        "response",
        "attack_mapping",
    }
    rules = []
    seen: set[str] = set()
    for item in raw["rules"]:
        if (
            set(item) != allowed
            or item["detector"] not in DETECTORS
            or item["id"] in seen
        ):
            raise ThreatDefenseError("rule_invalid")
        seen.add(item["id"])
        rules.append(
            Rule(
                item["id"],
                item["name"],
                item["severity"],
                item["kind"],
                item["detector"],
                tuple(item["response"]),
                tuple(item["attack_mapping"]),
            )
        )
    return rules


class DetectionEngine:
    """Runs allowlisted deterministic detectors over authenticated events."""

    def __init__(self, rules: list[Rule] | None = None) -> None:
        self.rules = rules or load_rules()
        self.seen_proofs: set[str] = set()

    def detect(self, verified: VerifiedEvent) -> list[Finding]:
        if not verified.verification_id:
            raise ThreatDefenseError("event_not_verified")
        event = verified.event
        findings = []
        for rule in self.rules:
            if DETECTORS[rule.detector](event, self):
                findings.append(
                    Finding(
                        finding_id=f"finding:{event.event_id}:{rule.rule_id}",
                        rule_id=rule.rule_id,
                        name=rule.name,
                        severity=rule.severity,
                        kind=rule.kind,
                        principal=event.principal,
                        target=event.target,
                        credential_id=event.credential_id,
                        event_id=event.event_id,
                        trace_id=event.trace_id,
                        response=rule.response,
                        evidence_digest=digest(event.record()),
                    )
                )
        if event.proof_jti:
            self.seen_proofs.add(event.proof_jti)
        return findings


@dataclass
class ControlState:
    quarantined_principals: set[str] = field(default_factory=set)
    revoked_credentials: set[str] = field(default_factory=set)
    disabled_delegations: set[tuple[str, str]] = field(default_factory=set)
    disabled_clients: set[str] = field(default_factory=set)
    review_queue: set[str] = field(default_factory=set)


@dataclass(frozen=True)
class ResponseResult:
    operation_id: str
    finding_id: str
    actions: tuple[str, ...]
    status: Literal["contained", "review_required", "no_safe_automatic_action"]
    evidence_hash: str


class ResponseOrchestrator:
    """Applies only scoped, allowlisted, idempotent simulated containment."""

    AUTO_ACTIONS: ClassVar[set[str]] = {
        "quarantine_principal",
        "revoke_credential",
        "disable_delegation",
        "disable_oauth_client",
    }

    def __init__(self, state: ControlState | None = None) -> None:
        self.state = state or ControlState()
        self.operations: dict[str, tuple[str, ResponseResult]] = {}
        self.evidence: list[dict[str, Any]] = []
        self.lock = RLock()

    def respond(self, finding: Finding, *, operation_id: str) -> ResponseResult:
        request_digest = digest(
            {"finding": asdict(finding), "operation_id": operation_id}
        )
        with self.lock:
            prior = self.operations.get(operation_id)
            if prior:
                if prior[0] != request_digest:
                    raise ThreatDefenseError("idempotency_conflict")
                return prior[1]

            automatic = tuple(
                action for action in finding.response if action in self.AUTO_ACTIONS
            )
            review = tuple(
                action for action in finding.response if action == "human_review"
            )
            if finding.kind == "behavioral_anomaly":
                automatic = ()
                review = ("human_review",)

            for action in automatic:
                if action == "quarantine_principal":
                    self.state.quarantined_principals.add(finding.principal)
                elif action == "revoke_credential" and finding.credential_id:
                    self.state.revoked_credentials.add(finding.credential_id)
                elif action == "disable_delegation":
                    self.state.disabled_delegations.add(
                        (finding.principal, finding.target)
                    )
                elif action == "disable_oauth_client":
                    self.state.disabled_clients.add(finding.target)
            if review:
                self.state.review_queue.add(finding.finding_id)

            if automatic:
                status = "contained"
            elif review:
                status = "review_required"
            else:
                status = "no_safe_automatic_action"
            evidence = {
                "sequence": len(self.evidence) + 1,
                "operation_id": operation_id,
                "finding_id": finding.finding_id,
                "actions": automatic + review,
                "status": status,
                "previous_hash": self.evidence[-1]["event_hash"]
                if self.evidence
                else "GENESIS",
            }
            event_hash = digest(evidence)
            evidence["event_hash"] = event_hash
            self.evidence.append(evidence)
            result = ResponseResult(
                operation_id, finding.finding_id, automatic + review, status, event_hash
            )
            self.operations[operation_id] = (request_digest, result)
            return result

    def verify_evidence(self) -> bool:
        previous = "GENESIS"
        for item in self.evidence:
            body = {key: value for key, value in item.items() if key != "event_hash"}
            if body["previous_hash"] != previous or digest(body) != item["event_hash"]:
                return False
            previous = item["event_hash"]
        return True


def recovery_ready(checks: dict[str, bool]) -> bool:
    required = {
        "persistence_removed",
        "credentials_rotated",
        "workload_reattested",
        "delegations_reviewed",
        "telemetry_healthy",
        "policy_validated",
        "incident_closed",
    }
    if set(checks) != required:
        raise ThreatDefenseError("recovery_evidence_incomplete")
    return all(checks.values())


@dataclass(frozen=True)
class PostureResult:
    score: int
    dimensions: dict[str, float]
    critical_findings: tuple[str, ...]
    label: str = "prioritization_index_not_breach_probability"


POSTURE_WEIGHTS = {
    "inventory": 0.10,
    "least_privilege": 0.15,
    "credential_hygiene": 0.15,
    "delegation": 0.15,
    "detection": 0.15,
    "runtime_binding": 0.10,
    "external_trust": 0.10,
    "response": 0.10,
}
CRITICAL_POSTURE = {
    "leaked_active_credential",
    "revoked_but_active",
    "compromised_trust_root",
    "unaudited_critical_identity",
}


def posture_score(
    dimensions: dict[str, float], critical_findings: Iterable[str] = ()
) -> PostureResult:
    if set(dimensions) != set(POSTURE_WEIGHTS) or not all(
        0 <= value <= 1 for value in dimensions.values()
    ):
        raise ThreatDefenseError("posture_dimensions_invalid")
    raw = round(
        100 * sum(dimensions[name] * weight for name, weight in POSTURE_WEIGHTS.items())
    )
    critical = tuple(sorted(CRITICAL_POSTURE.intersection(critical_findings)))
    return PostureResult(min(raw, 25) if critical else raw, dict(dimensions), critical)


def make_event(
    case_id: str,
    event_type: EventType = "access",
    source: str = "gateway",
    **changes: Any,
) -> IdentityEvent:
    values = {
        "event_id": f"evt:{case_id}",
        "event_type": event_type,
        "source": source,
        "sequence": 1,
        "principal": "agent:research",
        "action": "claim.read",
        "target": "api:claims",
        "trace_id": f"trace:{case_id}",
        "credential_id": "cred:research:v2",
        "audience": "claims-api",
        "expected_audience": "claims-api",
        "workload_id": "spiffe://northstar.example/prod/research",
        "expected_workload_id": "spiffe://northstar.example/prod/research",
        "baseline_count": 2,
        "observed_count": 3,
        "reported_risk": 10,
    }
    values.update(changes)
    return IdentityEvent(**values)


@dataclass(frozen=True)
class Case:
    case_id: str
    event: IdentityEvent
    expected_rules: tuple[str, ...]
    prelude: tuple[IdentityEvent, ...] = ()

    @property
    def expected_detected(self) -> bool:
        return bool(self.expected_rules)


def cases() -> list[Case]:
    values = [
        Case("normal-access", make_event("normal-access"), ()),
        Case(
            "normal-delegation",
            make_event(
                "normal-delegation",
                "delegation",
                "governance",
                parent_scope={"read"},
                delegated_scope={"read"},
            ),
            (),
        ),
        Case(
            "current-credential",
            make_event(
                "current-credential",
                "credential",
                credential_version=2,
                current_credential_version=2,
            ),
            (),
        ),
        Case(
            "approved-breakglass",
            make_event(
                "approved-breakglass",
                actor_type="human",
                assumed_identity_type="workload",
                break_glass=True,
            ),
            (),
        ),
        Case(
            "healthy-telemetry",
            make_event("healthy-telemetry", "telemetry", "telemetry-control"),
            (),
        ),
        Case("valid-audience", make_event("valid-audience"), ()),
        Case("same-environment", make_event("same-environment"), ()),
        Case(
            "expected-workload",
            make_event("expected-workload", "workload", "workload-control"),
            (),
        ),
        Case(
            "ordinary-client-admin",
            make_event(
                "ordinary-client-admin",
                "admin",
                "governance",
                action="oauth_client.create",
                after_compromise=False,
            ),
            (),
        ),
        Case(
            "normal-kms",
            make_event(
                "normal-kms",
                source="kms",
                action="kms.sign",
                baseline_count=2,
                observed_count=5,
            ),
            (),
        ),
        Case(
            "revoked",
            make_event("revoked", identity_status="revoked", reported_risk=20),
            ("IDT-001",),
        ),
        Case(
            "delegation-widened",
            make_event(
                "delegation-widened",
                "delegation",
                "governance",
                parent_scope={"read"},
                delegated_scope={"read", "write"},
                reported_risk=20,
            ),
            ("IDT-002",),
        ),
        Case(
            "stale-credential",
            make_event(
                "stale-credential",
                "credential",
                credential_version=1,
                current_credential_version=2,
                reported_risk=20,
            ),
            ("IDT-003",),
        ),
        Case(
            "human-nhi",
            make_event(
                "human-nhi",
                actor_type="human",
                assumed_identity_type="workload",
                reported_risk=20,
            ),
            ("IDT-004",),
        ),
        Case(
            "telemetry-suppressed",
            make_event(
                "telemetry-suppressed",
                "telemetry",
                "telemetry-control",
                telemetry_healthy=False,
                reported_risk=20,
            ),
            ("IDT-005",),
        ),
        Case(
            "audience-mismatch",
            make_event("audience-mismatch", audience="vector-api", reported_risk=20),
            ("IDT-006",),
        ),
        Case(
            "cross-environment",
            make_event(
                "cross-environment",
                principal_env="dev",
                target_env="prod",
                reported_risk=20,
            ),
            ("IDT-007",),
        ),
        Case(
            "workload-mismatch",
            make_event(
                "workload-mismatch",
                "workload",
                "workload-control",
                workload_id="spiffe://northstar.example/prod/unknown",
                reported_risk=20,
            ),
            ("IDT-008",),
        ),
        Case(
            "oauth-persistence",
            make_event(
                "oauth-persistence",
                "admin",
                "governance",
                action="oauth_client.create",
                after_compromise=True,
                target="oauth:backdoor",
                reported_risk=20,
            ),
            ("IDT-009",),
        ),
        Case(
            "proof-replay",
            make_event(
                "proof-replay", proof_jti="proof:shared", sequence=2, reported_risk=20
            ),
            ("IDT-010",),
            prelude=(make_event("proof-first", proof_jti="proof:shared"),),
        ),
        Case(
            "kms-spike",
            make_event(
                "kms-spike",
                source="kms",
                action="kms.sign",
                baseline_count=2,
                observed_count=12,
                reported_risk=20,
            ),
            ("IDT-011",),
        ),
        Case(
            "revoked-audience",
            make_event(
                "revoked-audience",
                identity_status="revoked",
                audience="other",
                reported_risk=20,
            ),
            ("IDT-001", "IDT-006"),
        ),
        Case(
            "delegation-cross-env",
            make_event(
                "delegation-cross-env",
                "delegation",
                "governance",
                parent_scope={"read"},
                delegated_scope={"read", "write"},
                principal_env="dev",
                target_env="prod",
                reported_risk=20,
            ),
            ("IDT-002", "IDT-007"),
        ),
        Case(
            "telemetry-revoked",
            make_event(
                "telemetry-revoked",
                "telemetry",
                "telemetry-control",
                telemetry_healthy=False,
                identity_status="revoked",
                reported_risk=20,
            ),
            ("IDT-001", "IDT-005"),
        ),
        Case(
            "stale-workload",
            make_event(
                "stale-workload",
                "workload",
                "workload-control",
                credential_version=1,
                current_credential_version=2,
                workload_id="spiffe://northstar.example/prod/unknown",
                reported_risk=20,
            ),
            ("IDT-003", "IDT-008"),
        ),
        Case(
            "oauth-human",
            make_event(
                "oauth-human",
                "admin",
                "governance",
                action="oauth_client.create",
                after_compromise=True,
                actor_type="human",
                assumed_identity_type="workload",
                target="oauth:backdoor",
                reported_risk=20,
            ),
            ("IDT-004", "IDT-009"),
        ),
        Case(
            "replay-audience",
            make_event(
                "replay-audience",
                proof_jti="proof:shared",
                sequence=2,
                audience="other",
                reported_risk=20,
            ),
            ("IDT-006", "IDT-010"),
            prelude=(make_event("replay-first", proof_jti="proof:shared"),),
        ),
        Case(
            "high-risk-kms-spike",
            make_event(
                "high-risk-kms-spike",
                source="kms",
                action="kms.sign",
                baseline_count=2,
                observed_count=12,
                reported_risk=90,
            ),
            ("IDT-011",),
        ),
        Case(
            "high-risk-revoked",
            make_event(
                "high-risk-revoked", identity_status="revoked", reported_risk=90
            ),
            ("IDT-001",),
        ),
        Case(
            "benign-high-reported-risk",
            make_event("benign-high-reported-risk", reported_risk=95),
            (),
        ),
    ]
    return values


def run_case(case: Case) -> tuple[str, ...]:
    authority, engine = TelemetryAuthority(), DetectionEngine()
    ingestor = TelemetryIngestor(authority)
    for event in case.prelude:
        engine.detect(ingestor.ingest(authority.issue(event)))
    verified = ingestor.ingest(authority.issue(case.event))
    return tuple(sorted(finding.rule_id for finding in engine.detect(verified)))


def baseline_detect(event: IdentityEvent) -> bool:
    """Deliberately weak baseline: trust the producer's opaque risk number."""

    return event.reported_risk >= 80


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
            actual_detected = baseline_detect(case.event)
            actual_rules: tuple[str, ...] = (
                ("opaque-risk-threshold",) if actual_detected else ()
            )
            exact = actual_detected == case.expected_detected
        else:
            actual_rules = run_case(case)
            actual_detected = bool(actual_rules)
            exact = actual_rules == tuple(sorted(case.expected_rules))
        rows.append(
            {
                "case_id": case.case_id,
                "expected_detected": case.expected_detected,
                "expected_rules": case.expected_rules,
                "actual_detected": actual_detected,
                "actual_rules": actual_rules,
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


if __name__ == "__main__":
    hardened, _ = evaluate()
    baseline, _ = evaluate(True)
    print(
        canonical(
            {"hardened": asdict(hardened), "opaque_risk_baseline": asdict(baseline)}
        )
    )
    if hardened.exact != hardened.total:
        raise SystemExit(1)
