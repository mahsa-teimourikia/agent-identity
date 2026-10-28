"""Executable Course 11 lab: compliance, audit, and forensic readiness.

The module is deliberately offline and deterministic.  It models the trusted
application boundary that validates evidence and produces assurance decisions;
it does not claim that a teaching-sized OSCAL-shaped export is OSCAL conformant.
"""

from __future__ import annotations

import base64
import hashlib
import json
import random
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Literal

import networkx as nx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from pydantic import BaseModel, ConfigDict, Field, model_validator

NOW = datetime(2026, 10, 28, 12, 0, tzinfo=timezone.utc)
TENANT = "northstar-insurance"
ASSESSMENT_PERIOD = "2026-Q3"
CONTROL_CATALOG_VERSION = "northstar-agent-identity-2026.10"
MAPPING_VERSION = "2026.10"
OSCAL_MODEL_VERSION = "1.2.3"


def canonical(value: Any) -> bytes:
    """Return deterministic UTF-8 JSON for hashing and signatures."""

    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json")
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), default=str
    ).encode()


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def deterministic_private_key(label: str) -> Ed25519PrivateKey:
    seed = hashlib.sha256(f"course-11::{label}".encode()).digest()
    return Ed25519PrivateKey.from_private_bytes(seed)


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def from_b64(value: str) -> bytes:
    return base64.b64decode(value.encode(), validate=True)


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Control(StrictModel):
    control_id: str = Field(pattern=r"^[A-Z]{2}-\d{2}$")
    name: str = Field(min_length=3)
    domain: str
    critical: bool
    evidence_types: tuple[str, ...] = Field(min_length=1)
    max_age_hours: int = Field(gt=0)
    applicable_environments: frozenset[str] = frozenset({"prod"})


class FrameworkReference(StrictModel):
    framework: str
    version: str
    references: tuple[str, ...] = Field(min_length=1)
    source_url: str


class AgentRecord(StrictModel):
    tenant: str
    agent_id: str = Field(pattern=r"^agent:[a-z0-9-]+$")
    environment: Literal["dev", "test", "prod"]
    risk: Literal["low", "medium", "high", "critical"]
    registered: bool
    owner: str = ""
    active: bool = True
    credential_type: Literal["workload", "oauth_client", "static_api_key", "none"]
    credential_lifetime_minutes: int = Field(ge=0)
    granted_permissions: frozenset[str] = frozenset()
    used_permissions: frozenset[str] = frozenset()
    delegated_parent: frozenset[str] = frozenset()
    delegated_child: frozenset[str] = frozenset()
    offboarded_at: datetime | None = None
    credential_revoked: bool = False
    delegation_revoked: bool = False
    last_reviewed_at: datetime

    @model_validator(mode="after")
    def validate_scope(self) -> AgentRecord:
        if self.tenant != TENANT:
            raise ValueError("fixture tenant must match the assessment tenant")
        if self.credential_type == "none" and self.credential_lifetime_minutes:
            raise ValueError("credential lifetime requires a credential")
        return self


class EvidencePayload(StrictModel):
    control_id: str
    subject: str
    observed: dict[str, Any]
    event_ids: tuple[str, ...] = Field(default_factory=tuple)


class EvidenceArtifact(StrictModel):
    artifact_id: str = Field(pattern=r"^ev-[a-z0-9-]+$")
    tenant: str
    evidence_type: str
    source: str
    producer: str
    collected_at: datetime
    effective_at: datetime
    payload: EvidencePayload
    payload_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    signature: str


class ExceptionRecord(StrictModel):
    exception_id: str = Field(pattern=r"^EX-\d+$")
    tenant: str
    control_id: str
    subject: str
    approver: str
    approved_at: datetime
    expires_at: datetime
    compensating_controls: frozenset[str]
    rationale: str = Field(min_length=12)
    state: Literal["approved", "revoked", "consumed"] = "approved"


class ControlResult(StrictModel):
    control_id: str
    subject: str
    status: Literal["pass", "fail", "exception", "not_applicable", "indeterminate"]
    reason_code: str
    tested_at: datetime
    policy_version: str
    evidence_ids: tuple[str, ...]
    evidence_complete: bool
    critical: bool
    exception_id: str | None = None


class CustodyEntry(StrictModel):
    sequence: int = Field(gt=0)
    artifact_id: str
    actor: str
    action: Literal["collected", "transferred", "verified", "held", "released"]
    occurred_at: datetime
    previous_hash: str
    entry_hash: str


class LegalHold(StrictModel):
    hold_id: str
    tenant: str
    case_id: str
    artifact_ids: frozenset[str]
    issued_by: str
    issued_at: datetime
    released_at: datetime | None = None


class AuditPack(StrictModel):
    pack_id: str
    tenant: str
    period: str
    catalog_version: str
    mapping_version: str
    created_at: datetime
    scope_digest: str
    result_digest: str
    artifact_digests: tuple[tuple[str, str], ...]
    artifact_count: int
    custody_root: str
    legal_hold_ids: tuple[str, ...]
    manifest_digest: str
    signature: str


CONTROL_CATALOG = (
    Control(
        control_id="AG-01",
        name="Registered agent identity",
        domain="governance",
        critical=True,
        evidence_types=("registry_record",),
        max_age_hours=24,
    ),
    Control(
        control_id="AG-02",
        name="Named accountable owner",
        domain="governance",
        critical=True,
        evidence_types=("owner_record",),
        max_age_hours=24,
    ),
    Control(
        control_id="CR-01",
        name="Short-lived production credential",
        domain="credential",
        critical=True,
        evidence_types=("credential_config", "issuance_event"),
        max_age_hours=24,
    ),
    Control(
        control_id="AC-01",
        name="Least privilege",
        domain="authorization",
        critical=False,
        evidence_types=("entitlement_snapshot", "usage_window"),
        max_age_hours=168,
    ),
    Control(
        control_id="DG-01",
        name="Delegation attenuation",
        domain="delegation",
        critical=True,
        evidence_types=("delegation_record", "policy_decision"),
        max_age_hours=24,
    ),
    Control(
        control_id="LC-01",
        name="Complete offboarding",
        domain="lifecycle",
        critical=True,
        evidence_types=("lifecycle_event", "revocation_event"),
        max_age_hours=24,
    ),
    Control(
        control_id="AU-01",
        name="Critical action reconstruction",
        domain="audit",
        critical=True,
        evidence_types=("authorization_event", "enforcement_event", "action_event"),
        max_age_hours=24,
    ),
)

CONTROL_BY_ID = {control.control_id: control for control in CONTROL_CATALOG}

FRAMEWORK_MAPPINGS = {
    "AG-01": (
        FrameworkReference(
            framework="NIST SP 800-53",
            version="5.2.0",
            references=("IA-4", "CM-8"),
            source_url="https://csrc.nist.gov/projects/cprt/catalog",
        ),
        FrameworkReference(
            framework="CIS Controls",
            version="8.1",
            references=("5.1",),
            source_url="https://www.cisecurity.org/controls/v8-1",
        ),
    ),
    "CR-01": (
        FrameworkReference(
            framework="NIST SP 800-53",
            version="5.2.0",
            references=("IA-5", "AC-2"),
            source_url="https://csrc.nist.gov/projects/cprt/catalog",
        ),
    ),
    "AU-01": (
        FrameworkReference(
            framework="NIST SP 800-53",
            version="5.2.0",
            references=("AU-2", "AU-3", "AU-10", "AU-12"),
            source_url="https://csrc.nist.gov/projects/cprt/catalog",
        ),
        FrameworkReference(
            framework="EU AI Act",
            version="Regulation (EU) 2024/1689",
            references=("Article 12",),
            source_url="https://eur-lex.europa.eu/eli/reg/2024/1689/oj",
        ),
    ),
}

TRUSTED_SOURCES = {
    "registry": "registry-producer",
    "ownership": "governance-producer",
    "credential-broker": "credential-producer",
    "authorization": "pdp-producer",
    "enforcement": "pep-producer",
    "runtime": "runtime-producer",
    "lifecycle": "lifecycle-producer",
}

EVIDENCE_SOURCE = {
    "registry_record": "registry",
    "owner_record": "ownership",
    "credential_config": "credential-broker",
    "issuance_event": "credential-broker",
    "entitlement_snapshot": "authorization",
    "usage_window": "runtime",
    "delegation_record": "authorization",
    "policy_decision": "authorization",
    "lifecycle_event": "lifecycle",
    "revocation_event": "lifecycle",
    "authorization_event": "authorization",
    "enforcement_event": "enforcement",
    "action_event": "runtime",
}

PRODUCER_KEYS = {
    producer: deterministic_private_key(producer)
    for producer in TRUSTED_SOURCES.values()
}


def sign_artifact(
    *,
    artifact_id: str,
    evidence_type: str,
    source: str,
    collected_at: datetime,
    effective_at: datetime,
    payload: EvidencePayload,
    tenant: str = TENANT,
    producer: str | None = None,
) -> EvidenceArtifact:
    producer = producer or TRUSTED_SOURCES[source]
    payload_digest = digest(payload)
    fields = {
        "artifact_id": artifact_id,
        "tenant": tenant,
        "evidence_type": evidence_type,
        "source": source,
        "producer": producer,
        "collected_at": collected_at,
        "effective_at": effective_at,
        "payload": payload,
        "payload_digest": payload_digest,
    }
    key = PRODUCER_KEYS.get(producer, deterministic_private_key(producer))
    provisional = EvidenceArtifact(**fields, signature="")
    unsigned = provisional.model_dump(mode="json", exclude={"signature"})
    return provisional.model_copy(
        update={"signature": b64(key.sign(canonical(unsigned)))}
    )


class EvidenceStore:
    """Fail-closed evidence admission with source, signature, and freshness checks."""

    def __init__(self, now: datetime = NOW) -> None:
        self.now = now
        self.artifacts: dict[str, EvidenceArtifact] = {}
        self.rejections: list[tuple[str, str]] = []

    def admit(self, artifact: EvidenceArtifact) -> bool:
        reason = self._validate(artifact)
        if reason:
            self.rejections.append((artifact.artifact_id, reason))
            return False
        self.artifacts[artifact.artifact_id] = artifact
        return True

    def _validate(self, artifact: EvidenceArtifact) -> str | None:
        if artifact.artifact_id in self.artifacts:
            return "duplicate-artifact"
        if artifact.tenant != TENANT:
            return "wrong-tenant"
        if TRUSTED_SOURCES.get(artifact.source) != artifact.producer:
            return "untrusted-source-binding"
        if EVIDENCE_SOURCE.get(artifact.evidence_type) != artifact.source:
            return "untrusted-evidence-type-source"
        if artifact.payload_digest != digest(artifact.payload):
            return "payload-digest-mismatch"
        if artifact.effective_at > self.now + timedelta(minutes=5):
            return "future-evidence"
        if artifact.collected_at > self.now + timedelta(minutes=5):
            return "future-collection"
        if artifact.collected_at < artifact.effective_at:
            return "collection-before-observation"
        unsigned = artifact.model_dump(mode="json", exclude={"signature"})
        public_key = PRODUCER_KEYS[artifact.producer].public_key()
        try:
            public_key.verify(from_b64(artifact.signature), canonical(unsigned))
        except (InvalidSignature, ValueError):
            return "invalid-signature"
        return None

    def for_control(self, control_id: str, subject: str) -> list[EvidenceArtifact]:
        return [
            artifact
            for artifact in self.artifacts.values()
            if artifact.payload.control_id == control_id
            and artifact.payload.subject == subject
        ]


def required_evidence(
    control: Control,
    artifacts: Iterable[EvidenceArtifact],
    *,
    now: datetime = NOW,
) -> tuple[tuple[str, ...], bool, str | None]:
    usable = [
        artifact
        for artifact in artifacts
        if now - artifact.effective_at <= timedelta(hours=control.max_age_hours)
    ]
    types = {artifact.evidence_type for artifact in usable}
    missing = set(control.evidence_types) - types
    if missing:
        return tuple(sorted(a.artifact_id for a in usable)), False, "missing-evidence"
    return tuple(sorted(a.artifact_id for a in usable)), True, None


REQUIRED_COMPENSATING = frozenset(
    {"vault", "network-restriction", "enhanced-monitoring"}
)


def valid_exception(
    record: ExceptionRecord | None,
    *,
    control_id: str,
    subject: str,
    now: datetime = NOW,
) -> tuple[bool, str]:
    if record is None:
        return False, "no-exception"
    if (
        record.tenant != TENANT
        or record.control_id != control_id
        or record.subject != subject
    ):
        return False, "exception-scope-mismatch"
    if record.state != "approved":
        return False, "exception-not-approved"
    if not record.approver.startswith("risk:"):
        return False, "untrusted-exception-approver"
    if record.approved_at > now or record.expires_at <= now:
        return False, "exception-expired-or-not-yet-valid"
    if not REQUIRED_COMPENSATING <= record.compensating_controls:
        return False, "compensating-controls-incomplete"
    return True, "approved-bounded-exception"


def control_applicable(control: Control, agent: AgentRecord) -> bool:
    if agent.environment not in control.applicable_environments:
        return False
    if control.control_id == "LC-01":
        return not agent.active or agent.offboarded_at is not None
    if not agent.active:
        return False
    if control.control_id == "DG-01":
        return bool(agent.delegated_parent or agent.delegated_child)
    return True


def _control_observation(control_id: str, agent: AgentRecord) -> tuple[bool, str]:
    if control_id == "AG-01":
        return (
            agent.registered,
            "registered" if agent.registered else "identity-not-registered",
        )
    if control_id == "AG-02":
        return bool(
            agent.owner.strip()
        ), "owner-present" if agent.owner.strip() else "owner-missing"
    if control_id == "CR-01":
        ok = (
            agent.credential_type not in {"static_api_key", "none"}
            and agent.credential_lifetime_minutes <= 60
        )
        return ok, "credential-compliant" if ok else "credential-noncompliant"
    if control_id == "AC-01":
        excess = agent.granted_permissions - agent.used_permissions
        ok = len(excess) <= 1
        return ok, "least-privilege" if ok else "excess-unused-privilege"
    if control_id == "DG-01":
        ok = agent.delegated_child <= agent.delegated_parent
        return ok, "delegation-attenuated" if ok else "delegation-widened"
    if control_id == "LC-01":
        ok = not agent.active and agent.credential_revoked and agent.delegation_revoked
        return ok, "offboarding-complete" if ok else "offboarding-incomplete"
    if control_id == "AU-01":
        return True, "critical-action-recorded"
    raise KeyError(control_id)


def evaluate_control(
    control: Control,
    agent: AgentRecord,
    evidence: EvidenceStore,
    *,
    exception: ExceptionRecord | None = None,
    now: datetime = NOW,
) -> ControlResult:
    if not control_applicable(control, agent):
        return ControlResult(
            control_id=control.control_id,
            subject=agent.agent_id,
            status="not_applicable",
            reason_code="control-not-applicable",
            tested_at=now,
            policy_version=CONTROL_CATALOG_VERSION,
            evidence_ids=(),
            evidence_complete=True,
            critical=control.critical,
        )
    artifacts = evidence.for_control(control.control_id, agent.agent_id)
    evidence_ids, complete, evidence_reason = required_evidence(
        control, artifacts, now=now
    )
    if not complete:
        return ControlResult(
            control_id=control.control_id,
            subject=agent.agent_id,
            status="indeterminate",
            reason_code=evidence_reason or "evidence-incomplete",
            tested_at=now,
            policy_version=CONTROL_CATALOG_VERSION,
            evidence_ids=evidence_ids,
            evidence_complete=False,
            critical=control.critical,
        )
    passed, reason = _control_observation(control.control_id, agent)
    admitted_by_id = {artifact.artifact_id: artifact for artifact in artifacts}
    evidence_observations = {
        admitted_by_id[artifact_id].payload.observed.get("passed")
        for artifact_id in evidence_ids
    }
    if evidence_observations != {passed}:
        return ControlResult(
            control_id=control.control_id,
            subject=agent.agent_id,
            status="indeterminate",
            reason_code="evidence-state-mismatch",
            tested_at=now,
            policy_version=CONTROL_CATALOG_VERSION,
            evidence_ids=evidence_ids,
            evidence_complete=True,
            critical=control.critical,
        )
    if passed:
        status: Literal["pass", "fail", "exception"] = "pass"
        exception_id = None
    else:
        accepted, exception_reason = valid_exception(
            exception, control_id=control.control_id, subject=agent.agent_id, now=now
        )
        status = "exception" if accepted else "fail"
        reason = exception_reason if accepted else reason
        exception_id = exception.exception_id if accepted and exception else None
    return ControlResult(
        control_id=control.control_id,
        subject=agent.agent_id,
        status=status,
        reason_code=reason,
        tested_at=now,
        policy_version=CONTROL_CATALOG_VERSION,
        evidence_ids=evidence_ids,
        evidence_complete=True,
        critical=control.critical,
        exception_id=exception_id,
    )


def release_decision(
    results: Iterable[ControlResult],
) -> Literal["release", "block", "review"]:
    results = tuple(results)
    if any(result.critical and result.status == "fail" for result in results):
        return "block"
    if any(result.status in {"indeterminate", "exception"} for result in results):
        return "review"
    return "release"


def evidence_for_agent(
    agent: AgentRecord, *, now: datetime = NOW
) -> list[EvidenceArtifact]:
    """Build complete evidence for the controls applicable to one synthetic agent."""

    artifacts: list[EvidenceArtifact] = []
    ordinal = 0
    for control in CONTROL_CATALOG:
        if not control_applicable(control, agent):
            continue
        passed, reason = _control_observation(control.control_id, agent)
        for evidence_type in control.evidence_types:
            ordinal += 1
            source = EVIDENCE_SOURCE[evidence_type]
            artifacts.append(
                sign_artifact(
                    artifact_id=f"ev-{agent.agent_id.removeprefix('agent:')}-{ordinal}",
                    evidence_type=evidence_type,
                    source=source,
                    collected_at=now - timedelta(minutes=4),
                    effective_at=now - timedelta(minutes=5),
                    payload=EvidencePayload(
                        control_id=control.control_id,
                        subject=agent.agent_id,
                        observed={"passed": passed, "reason": reason},
                        event_ids=(f"evt-{ordinal}",),
                    ),
                )
            )
    return artifacts


def assess_agent(
    agent: AgentRecord,
    *,
    exceptions: Iterable[ExceptionRecord] = (),
    artifacts: Iterable[EvidenceArtifact] | None = None,
    now: datetime = NOW,
) -> tuple[list[ControlResult], EvidenceStore]:
    store = EvidenceStore(now)
    for artifact in (
        artifacts if artifacts is not None else evidence_for_agent(agent, now=now)
    ):
        store.admit(artifact)
    exception_by_control = {
        (item.control_id, item.subject): item for item in exceptions
    }
    results = [
        evaluate_control(
            control,
            agent,
            store,
            exception=exception_by_control.get((control.control_id, agent.agent_id)),
            now=now,
        )
        for control in CONTROL_CATALOG
    ]
    return results, store


def completeness(results: Iterable[ControlResult]) -> dict[str, float | int]:
    relevant = [result for result in results if result.status != "not_applicable"]
    complete = sum(result.evidence_complete for result in relevant)
    return {
        "complete": complete,
        "relevant": len(relevant),
        "ratio": complete / len(relevant) if relevant else 1.0,
    }


def build_custody(entries: Iterable[dict[str, Any]]) -> list[CustodyEntry]:
    chain: list[CustodyEntry] = []
    previous = "0" * 64
    for sequence, raw in enumerate(entries, start=1):
        fields = {"sequence": sequence, "previous_hash": previous, **raw}
        provisional = CustodyEntry(**fields, entry_hash="0" * 64)
        material = provisional.model_dump(mode="json", exclude={"entry_hash"})
        entry_hash = digest(material)
        entry = provisional.model_copy(update={"entry_hash": entry_hash})
        chain.append(entry)
        previous = entry_hash
    return chain


def verify_custody(chain: Iterable[CustodyEntry]) -> bool:
    previous = "0" * 64
    expected_sequence = 1
    for entry in chain:
        if entry.sequence != expected_sequence or entry.previous_hash != previous:
            return False
        material = entry.model_dump(mode="json", exclude={"entry_hash"})
        if digest(material) != entry.entry_hash:
            return False
        previous = entry.entry_hash
        expected_sequence += 1
    return expected_sequence > 1


def retention_action(
    artifact: EvidenceArtifact,
    *,
    retention_days: int,
    holds: Iterable[LegalHold],
    now: datetime = NOW,
) -> Literal["retain", "delete"]:
    active_hold_ids = {
        artifact_id
        for hold in holds
        if hold.released_at is None and hold.tenant == artifact.tenant
        for artifact_id in hold.artifact_ids
    }
    if artifact.artifact_id in active_hold_ids:
        return "retain"
    return (
        "delete"
        if now - artifact.effective_at > timedelta(days=retention_days)
        else "retain"
    )


def risk_sample(
    population: Iterable[AgentRecord],
    size: int,
    *,
    seed: int = 11,
) -> list[AgentRecord]:
    population = list(population)
    if size < 1 or size > len(population):
        raise ValueError("sample size must be within the population")
    weight = {"low": 1, "medium": 2, "high": 5, "critical": 8}
    rng = random.Random(seed)
    keys = [(rng.random() ** (1 / weight[item.risk]), item) for item in population]
    return [
        item for _, item in sorted(keys, key=lambda pair: pair[0], reverse=True)[:size]
    ]


def sample_coverage(
    population: Iterable[AgentRecord], sample: Iterable[AgentRecord]
) -> dict[str, Any]:
    population = list(population)
    sample = list(sample)
    population_risk = Counter(item.risk for item in population)
    sample_risk = Counter(item.risk for item in sample)
    critical_total = population_risk["critical"]
    critical_sampled = sample_risk["critical"]
    return {
        "population": len(population),
        "sample": len(sample),
        "population_by_risk": dict(population_risk),
        "sample_by_risk": dict(sample_risk),
        "critical_coverage": critical_sampled / critical_total
        if critical_total
        else 1.0,
    }


def segregation_of_duties(
    assignments: dict[str, set[str] | frozenset[str]],
    incompatible_pairs: Iterable[tuple[str, str]],
) -> dict[str, Any]:
    """Evaluate SoD conflicts using an inspectable principal-permission graph."""

    graph = nx.Graph()
    for principal, permissions in assignments.items():
        graph.add_node(principal, kind="principal")
        for permission in permissions:
            graph.add_node(permission, kind="permission")
            graph.add_edge(principal, permission)
    conflicts = []
    for principal in assignments:
        neighbors = set(graph.neighbors(principal))
        for left, right in incompatible_pairs:
            if {left, right} <= neighbors:
                conflicts.append(
                    {
                        "principal": principal,
                        "permissions": tuple(sorted((left, right))),
                    }
                )
    return {
        "conflicts": conflicts,
        "principals": sum(
            data["kind"] == "principal" for _, data in graph.nodes(data=True)
        ),
        "permissions": sum(
            data["kind"] == "permission" for _, data in graph.nodes(data=True)
        ),
        "edges": graph.number_of_edges(),
    }


def manifest_material(
    *,
    pack_id: str,
    tenant: str,
    period: str,
    scope_digest: str,
    result_digest: str,
    artifact_digests: tuple[tuple[str, str], ...],
    custody_root: str,
    legal_hold_ids: tuple[str, ...],
    created_at: datetime,
) -> dict[str, Any]:
    return {
        "pack_id": pack_id,
        "tenant": tenant,
        "period": period,
        "catalog_version": CONTROL_CATALOG_VERSION,
        "mapping_version": MAPPING_VERSION,
        "created_at": created_at.isoformat(),
        "scope_digest": scope_digest,
        "result_digest": result_digest,
        "artifact_digests": artifact_digests,
        "artifact_count": len(artifact_digests),
        "custody_root": custody_root,
        "legal_hold_ids": legal_hold_ids,
    }


def build_audit_pack(
    agents: Iterable[AgentRecord],
    results: Iterable[ControlResult],
    artifacts: Iterable[EvidenceArtifact],
    custody: Iterable[CustodyEntry],
    holds: Iterable[LegalHold],
    *,
    signer: Ed25519PrivateKey,
    created_at: datetime = NOW,
) -> AuditPack:
    agents = tuple(agents)
    results = tuple(results)
    artifacts = tuple(artifacts)
    custody = tuple(custody)
    holds = tuple(holds)
    artifact_digests = tuple(
        sorted((item.artifact_id, digest(item)) for item in artifacts)
    )
    material = manifest_material(
        pack_id="pack-2026-q3",
        tenant=TENANT,
        period=ASSESSMENT_PERIOD,
        scope_digest=digest([item.model_dump(mode="json") for item in agents]),
        result_digest=digest([item.model_dump(mode="json") for item in results]),
        artifact_digests=artifact_digests,
        custody_root=custody[-1].entry_hash if custody else "0" * 64,
        legal_hold_ids=tuple(
            sorted(item.hold_id for item in holds if item.released_at is None)
        ),
        created_at=created_at,
    )
    provisional = AuditPack(**material, manifest_digest="0" * 64, signature="")
    signed_material = provisional.model_dump(
        mode="json", exclude={"manifest_digest", "signature"}
    )
    manifest_digest = digest(signed_material)
    return provisional.model_copy(
        update={
            "manifest_digest": manifest_digest,
            "signature": b64(signer.sign(canonical(signed_material))),
        }
    )


def verify_audit_pack(
    pack: AuditPack,
    *,
    public_key: Ed25519PublicKey,
    agents: Iterable[AgentRecord],
    results: Iterable[ControlResult],
    artifacts: Iterable[EvidenceArtifact],
    custody: Iterable[CustodyEntry],
) -> tuple[bool, str]:
    artifact_digests = tuple(
        sorted((item.artifact_id, digest(item)) for item in artifacts)
    )
    custody = tuple(custody)
    if (
        len(artifact_digests) != pack.artifact_count
        or artifact_digests != pack.artifact_digests
    ):
        return False, "artifact-set-mismatch"
    if digest([item.model_dump(mode="json") for item in agents]) != pack.scope_digest:
        return False, "scope-mismatch"
    if digest([item.model_dump(mode="json") for item in results]) != pack.result_digest:
        return False, "result-mismatch"
    if not verify_custody(custody) or custody[-1].entry_hash != pack.custody_root:
        return False, "custody-mismatch"
    material = pack.model_dump(mode="json", exclude={"manifest_digest", "signature"})
    if digest(material) != pack.manifest_digest:
        return False, "manifest-digest-mismatch"
    try:
        public_key.verify(from_b64(pack.signature), canonical(material))
    except (InvalidSignature, ValueError):
        return False, "invalid-pack-signature"
    return True, "verified"


def oscal_assessment_results(
    pack: AuditPack, results: Iterable[ControlResult]
) -> dict[str, Any]:
    """Return an OSCAL-shaped teaching subset, not a conformance claim."""

    observations = [
        {
            "uuid": digest({"control": result.control_id, "subject": result.subject})[
                :32
            ],
            "description": result.reason_code,
            "methods": ["EXAMINE"],
            "collected": result.tested_at.isoformat(),
            "subjects": [{"subject-uuid": result.subject, "type": "component"}],
            "relevant-evidence": [
                {"href": f"urn:northstar:evidence:{evidence_id}"}
                for evidence_id in result.evidence_ids
            ],
            "props": [
                {"name": "status", "value": result.status},
                {"name": "policy-version", "value": result.policy_version},
            ],
        }
        for result in results
    ]
    return {
        "assessment-results": {
            "uuid": digest(pack.pack_id)[:32],
            "metadata": {
                "title": "Northstar agent identity assessment",
                "last-modified": pack.created_at.isoformat(),
                "version": pack.period,
                "oscal-version": OSCAL_MODEL_VERSION,
            },
            "import-ap": {"href": "urn:northstar:assessment-plan:agent-identity"},
            "results": [
                {
                    "uuid": digest({"pack": pack.pack_id, "period": pack.period})[:32],
                    "title": f"Agent identity controls {pack.period}",
                    "start": pack.created_at.isoformat(),
                    "end": pack.created_at.isoformat(),
                    "observations": observations,
                }
            ],
        }
    }


def baseline_decision(case: AssuranceCase) -> str:
    """Intentionally weak baseline: trusts self-reported posture and ignores evidence."""

    agent = case.agent
    if (
        not agent.registered
        or not agent.owner
        or agent.credential_type == "static_api_key"
    ):
        return "block"
    return "release"


@dataclass(frozen=True)
class AssuranceCase:
    case_id: str
    description: str
    expected: Literal["release", "block", "review"]
    agent: AgentRecord
    mutation: str = "none"
    exception: ExceptionRecord | None = None


def agent_fixture(
    agent_id: str = "agent:claims",
    **updates: Any,
) -> AgentRecord:
    data: dict[str, Any] = {
        "tenant": TENANT,
        "agent_id": agent_id,
        "environment": "prod",
        "risk": "high",
        "registered": True,
        "owner": "team:claims-ai",
        "active": True,
        "credential_type": "workload",
        "credential_lifetime_minutes": 10,
        "granted_permissions": frozenset({"claims.read", "documents.read"}),
        "used_permissions": frozenset({"claims.read", "documents.read"}),
        "delegated_parent": frozenset(),
        "delegated_child": frozenset(),
        "offboarded_at": None,
        "credential_revoked": False,
        "delegation_revoked": False,
        "last_reviewed_at": NOW - timedelta(days=20),
    }
    data.update(updates)
    return AgentRecord(**data)


def approved_exception(
    subject: str = "agent:legacy", **updates: Any
) -> ExceptionRecord:
    data: dict[str, Any] = {
        "exception_id": "EX-12",
        "tenant": TENANT,
        "control_id": "CR-01",
        "subject": subject,
        "approver": "risk:director",
        "approved_at": NOW - timedelta(days=10),
        "expires_at": NOW + timedelta(days=10),
        "compensating_controls": REQUIRED_COMPENSATING,
        "rationale": "Legacy claims migration requires a bounded transition.",
        "state": "approved",
    }
    data.update(updates)
    return ExceptionRecord(**data)


def assurance_cases() -> list[AssuranceCase]:
    normal = agent_fixture()
    delegated = agent_fixture(
        "agent:research",
        delegated_parent=frozenset({"documents.read", "claims.read"}),
        delegated_child=frozenset({"documents.read"}),
    )
    offboarded = agent_fixture(
        "agent:retired",
        active=False,
        credential_type="none",
        credential_lifetime_minutes=0,
        offboarded_at=NOW - timedelta(hours=2),
        credential_revoked=True,
        delegation_revoked=True,
    )
    legacy = agent_fixture(
        "agent:legacy",
        credential_type="static_api_key",
        credential_lifetime_minutes=1440,
    )
    return [
        AssuranceCase("C01", "compliant production agent", "release", normal),
        AssuranceCase("C02", "attenuated delegation", "release", delegated),
        AssuranceCase("C03", "complete offboarding", "release", offboarded),
        AssuranceCase(
            "C04", "missing registration", "block", agent_fixture(registered=False)
        ),
        AssuranceCase("C05", "missing owner", "block", agent_fixture(owner="")),
        AssuranceCase("C06", "static production credential", "block", legacy),
        AssuranceCase(
            "C07",
            "widened delegation",
            "block",
            agent_fixture(
                delegated_parent=frozenset({"documents.read"}),
                delegated_child=frozenset({"documents.read", "claims.write"}),
            ),
        ),
        AssuranceCase(
            "C08",
            "incomplete offboarding",
            "block",
            agent_fixture(
                active=False,
                offboarded_at=NOW - timedelta(hours=1),
                credential_revoked=False,
                delegation_revoked=True,
            ),
        ),
        AssuranceCase(
            "C09",
            "excess unused privilege",
            "release",
            agent_fixture(
                granted_permissions=frozenset(
                    {"claims.read", "claims.write", "payments.write"}
                ),
                used_permissions=frozenset({"claims.read"}),
            ),
        ),
        AssuranceCase("C10", "missing evidence", "review", normal, "drop-evidence"),
        AssuranceCase("C11", "stale evidence", "review", normal, "stale-evidence"),
        AssuranceCase("C12", "forged evidence", "review", normal, "forge-signature"),
        AssuranceCase("C13", "wrong-tenant evidence", "review", normal, "wrong-tenant"),
        AssuranceCase(
            "C14", "replayed evidence", "review", normal, "duplicate-evidence"
        ),
        AssuranceCase(
            "C15",
            "valid bounded exception",
            "review",
            legacy,
            "none",
            approved_exception(),
        ),
        AssuranceCase(
            "C16",
            "expired exception",
            "block",
            legacy,
            "none",
            approved_exception(expires_at=NOW - timedelta(seconds=1)),
        ),
        AssuranceCase(
            "C17",
            "undercompensated exception",
            "block",
            legacy,
            "none",
            approved_exception(compensating_controls=frozenset({"vault"})),
        ),
        AssuranceCase("C18", "tampered payload", "review", normal, "tamper-payload"),
    ]


def run_case(case: AssuranceCase) -> str:
    artifacts = evidence_for_agent(case.agent)
    if case.mutation == "drop-evidence":
        artifacts = artifacts[:-1]
    elif case.mutation == "stale-evidence":
        artifacts = [
            sign_artifact(
                artifact_id=artifact.artifact_id,
                evidence_type=artifact.evidence_type,
                source=artifact.source,
                producer=artifact.producer,
                tenant=artifact.tenant,
                collected_at=NOW - timedelta(days=30),
                effective_at=NOW - timedelta(days=30, minutes=1),
                payload=artifact.payload,
            )
            for artifact in artifacts
        ]
    elif case.mutation == "forge-signature":
        artifacts[0] = artifacts[0].model_copy(update={"signature": b64(b"x" * 64)})
    elif case.mutation == "wrong-tenant":
        artifacts[0] = artifacts[0].model_copy(update={"tenant": "other-tenant"})
    elif case.mutation == "duplicate-evidence":
        artifacts.append(artifacts[0])
    elif case.mutation == "tamper-payload":
        artifacts[0] = artifacts[0].model_copy(
            update={
                "payload": artifacts[0].payload.model_copy(
                    update={"observed": {"passed": True, "reason": "tampered"}}
                )
            }
        )
    results, store = assess_agent(
        case.agent,
        exceptions=([case.exception] if case.exception else []),
        artifacts=artifacts,
    )
    if store.rejections:
        return "review"
    return release_decision(results)


def evaluation() -> dict[str, Any]:
    cases = assurance_cases()
    rows = [
        {
            "case_id": case.case_id,
            "expected": case.expected,
            "baseline": baseline_decision(case),
            "hardened": run_case(case),
        }
        for case in cases
    ]

    def metrics(system: str) -> dict[str, float | int]:
        exact = sum(row[system] == row["expected"] for row in rows)
        false_passes = sum(
            row[system] == "release" and row["expected"] != "release" for row in rows
        )
        false_blocks = sum(
            row[system] == "block" and row["expected"] == "release" for row in rows
        )
        return {
            "exact": exact,
            "total": len(rows),
            "accuracy": exact / len(rows),
            "false_passes": false_passes,
            "false_blocks": false_blocks,
        }

    hardened = metrics("hardened")
    return {
        "rows": rows,
        "baseline": metrics("baseline"),
        "hardened": hardened,
        "release_gate": hardened["false_passes"] == 0 and hardened["accuracy"] >= 0.95,
    }


def demo() -> dict[str, Any]:
    agent = agent_fixture()
    results, store = assess_agent(agent)
    custody = build_custody(
        [
            {
                "artifact_id": artifact.artifact_id,
                "actor": "collector:assurance",
                "action": "collected",
                "occurred_at": NOW - timedelta(minutes=3),
            }
            for artifact in store.artifacts.values()
        ]
    )
    signer = deterministic_private_key("audit-office")
    pack = build_audit_pack(
        [agent], results, store.artifacts.values(), custody, [], signer=signer
    )
    verified = verify_audit_pack(
        pack,
        public_key=signer.public_key(),
        agents=[agent],
        results=results,
        artifacts=store.artifacts.values(),
        custody=custody,
    )
    return {
        "decision": release_decision(results),
        "completeness": completeness(results),
        "pack_verified": verified,
        "evaluation": evaluation(),
    }


if __name__ == "__main__":
    print(json.dumps(demo(), indent=2, default=str))
