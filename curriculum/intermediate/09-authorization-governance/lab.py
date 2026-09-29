"""Deterministic authorization-governance control-plane lab.

The lab models inventory, exact entitlements, attenuating delegation, toxic
combinations, reviews, exceptions, policy impact, and atomic offboarding.  It
does not let usage analytics or a model directly change authority.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass, is_dataclass, replace
from enum import Enum
from hashlib import sha256
from threading import RLock
from typing import Any, Literal

NOW = 1_800_000_000
TENANT = "tenant:northstar"
POLICY_VERSION = "policy:v20"
MODEL_VERSION = "authz-model:01K9GOVERNANCE"
INVENTORY_VERSION = 12
SUBJECT = "user:alice"
CLAIMS_AGENT = "agent:claims"
RESEARCH_AGENT = "agent:research"
FINANCE_AGENT = "agent:finance"
CLAIM = "claim:483"


class GovernanceError(RuntimeError):
    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


class Outcome(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    REVIEW = "review"
    REVOKE = "revoke"
    RECONCILED = "reconciled"


def canonical(value: Any) -> str:
    def convert(item: Any) -> Any:
        if is_dataclass(item) and not isinstance(item, type):
            return asdict(item)
        if isinstance(item, (set, frozenset)):
            return sorted(item)
        if isinstance(item, Enum):
            return item.value
        raise TypeError(f"cannot canonicalize {type(item).__name__}")

    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=convert)


def digest(value: Any) -> str:
    return sha256(canonical(value).encode()).hexdigest()


@dataclass(frozen=True)
class AgentRecord:
    agent_id: str
    tenant_id: str
    owner_id: str | None
    status: Literal["active", "disabled", "retired"]
    risk_tier: Literal["R1", "R2", "R3", "R4"]
    last_seen: int
    workload_id: str


@dataclass(frozen=True)
class Entitlement:
    entitlement_id: str
    principal_id: str
    tenant_id: str
    action: str
    resource: str
    source: Literal["policy", "role", "delegation", "exception", "task"]
    owner_id: str
    justification: str
    risk: Literal["low", "medium", "high", "critical"]
    created_at: int
    expires_at: int
    last_used: int | None
    version: int = 1

    def permission(self) -> tuple[str, str]:
        return self.action, self.resource


@dataclass(frozen=True)
class Delegation:
    delegation_id: str
    delegator: str
    delegatee: str
    tenant_id: str
    permissions: frozenset[tuple[str, str]]
    parent_id: str | None
    depth: int
    max_depth: int
    redelegable: bool
    issued_at: int
    expires_at: int
    task_id: str
    active: bool = True


@dataclass(frozen=True)
class ExceptionGrant:
    exception_id: str
    principal_id: str
    tenant_id: str
    permission: tuple[str, str]
    reason: str
    approver_ids: tuple[str, ...]
    controls: tuple[str, ...]
    ticket_id: str
    issued_at: int
    expires_at: int
    policy_version: str
    revoked: bool = False


@dataclass(frozen=True)
class Finding:
    code: str
    severity: Literal["low", "medium", "high", "critical"]
    subject_id: str
    evidence_ids: tuple[str, ...]


@dataclass(frozen=True)
class ReviewPacket:
    review_id: str
    principal_id: str
    entitlement_id: str
    snapshot_digest: str
    inventory_version: int
    policy_version: str
    risk: str
    usage_count_90d: int
    alternatives: tuple[str, ...]
    expires_at: int


@dataclass
class ReviewDecision:
    review_id: str
    reviewer_id: str
    outcome: Literal["renew", "reduce", "revoke", "escalate"]
    snapshot_digest: str
    reason: str
    decided_at: int
    used: bool = False


@dataclass(frozen=True)
class PolicyCandidate:
    version: str
    permissions: Mapping[str, frozenset[tuple[str, str]]]


@dataclass(frozen=True)
class PolicyImpact:
    newly_allowed: tuple[str, ...]
    newly_denied: tuple[str, ...]
    unchanged: int
    high_risk_expansions: tuple[str, ...]
    valid_work_blocked: int
    forbidden_allows: int


@dataclass(frozen=True)
class Decision:
    outcome: Outcome
    reasons: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    policy_version: str = POLICY_VERSION
    model_version: str = MODEL_VERSION


TOXIC_SETS = {
    "self_approved_payment": frozenset({"payment.create", "payment.approve"}),
    "vendor_and_payment": frozenset({"vendor.create", "payment.create"}),
    "policy_author_and_deployer": frozenset({"policy.write", "policy.deploy"}),
}
HIGH_RISK_ACTIONS = {
    "claim.delete",
    "claim.export",
    "payment.create",
    "payment.approve",
    "policy.deploy",
}


class GovernanceEngine:
    def __init__(self):
        self.inventory_version = INVENTORY_VERSION
        self.agents: dict[str, AgentRecord] = {
            CLAIMS_AGENT: AgentRecord(
                CLAIMS_AGENT,
                TENANT,
                "team:claims",
                "active",
                "R3",
                NOW - 60,
                "spiffe://northstar.example/prod/claims",
            ),
            RESEARCH_AGENT: AgentRecord(
                RESEARCH_AGENT,
                TENANT,
                "team:knowledge",
                "active",
                "R2",
                NOW - 3_600,
                "spiffe://northstar.example/prod/research",
            ),
            FINANCE_AGENT: AgentRecord(
                FINANCE_AGENT,
                TENANT,
                "team:finance",
                "active",
                "R4",
                NOW - 30,
                "spiffe://northstar.example/prod/finance",
            ),
            "agent:legacy": AgentRecord(
                "agent:legacy",
                TENANT,
                None,
                "active",
                "R3",
                NOW - 100 * 86_400,
                "spiffe://northstar.example/legacy",
            ),
        }
        self.entitlements: dict[str, Entitlement] = {
            "ent:claim-read": Entitlement(
                "ent:claim-read",
                CLAIMS_AGENT,
                TENANT,
                "claim.read",
                CLAIM,
                "policy",
                "team:claims",
                "assigned claim",
                "medium",
                NOW - 30 * 86_400,
                NOW + 180 * 86_400,
                NOW - 60,
            ),
            "ent:claim-update": Entitlement(
                "ent:claim-update",
                CLAIMS_AGENT,
                TENANT,
                "claim.update",
                CLAIM,
                "task",
                "team:claims",
                "active adjustment",
                "high",
                NOW - 5 * 86_400,
                NOW + 86_400,
                NOW - 600,
            ),
            "ent:legacy-export": Entitlement(
                "ent:legacy-export",
                "agent:legacy",
                TENANT,
                "claim.export",
                "claims/*",
                "role",
                "team:legacy",
                "migration",
                "critical",
                NOW - 400 * 86_400,
                NOW + 30 * 86_400,
                None,
            ),
            "ent:payment-create": Entitlement(
                "ent:payment-create",
                FINANCE_AGENT,
                TENANT,
                "payment.create",
                "payments/*",
                "role",
                "team:finance",
                "payments",
                "critical",
                NOW - 90 * 86_400,
                NOW + 90 * 86_400,
                NOW - 30,
            ),
            "ent:payment-approve": Entitlement(
                "ent:payment-approve",
                FINANCE_AGENT,
                TENANT,
                "payment.approve",
                "payments/*",
                "role",
                "team:finance",
                "legacy workflow",
                "critical",
                NOW - 90 * 86_400,
                NOW + 90 * 86_400,
                NOW - 20,
            ),
        }
        root_permissions = frozenset({("claim.read", CLAIM), ("claim.update", CLAIM)})
        self.delegations: dict[str, Delegation] = {
            "del:alice-claims": Delegation(
                "del:alice-claims",
                SUBJECT,
                CLAIMS_AGENT,
                TENANT,
                root_permissions,
                None,
                0,
                2,
                True,
                NOW - 600,
                NOW + 3_600,
                "task:483",
            ),
            "del:claims-research": Delegation(
                "del:claims-research",
                CLAIMS_AGENT,
                RESEARCH_AGENT,
                TENANT,
                frozenset({("claim.read", CLAIM)}),
                "del:alice-claims",
                1,
                2,
                False,
                NOW - 300,
                NOW + 1_800,
                "task:483",
            ),
        }
        self.exceptions: dict[str, ExceptionGrant] = {}
        self.reviews: dict[str, ReviewPacket] = {}
        self.review_decisions: dict[str, ReviewDecision] = {}
        self.offboarding_receipts: dict[str, Mapping[str, Any]] = {}
        self._lock = RLock()

    def direct_permissions(
        self, principal_id: str, now: int = NOW
    ) -> set[tuple[str, str]]:
        permissions = {
            entitlement.permission()
            for entitlement in self.entitlements.values()
            if entitlement.principal_id == principal_id
            and entitlement.tenant_id == TENANT
            and entitlement.expires_at > now
        }
        permissions |= {
            grant.permission
            for grant in self.exceptions.values()
            if grant.principal_id == principal_id
            and grant.tenant_id == TENANT
            and grant.expires_at > now
            and not grant.revoked
        }
        return permissions

    def validate_delegations(self, now: int = NOW) -> list[Finding]:
        findings: list[Finding] = []
        for delegation in self.delegations.values():
            if not delegation.active:
                continue
            if delegation.expires_at <= now:
                findings.append(
                    Finding(
                        "DELEGATION_EXPIRED",
                        "high",
                        delegation.delegatee,
                        (delegation.delegation_id,),
                    )
                )
                continue
            if (
                delegation.tenant_id != TENANT
                or delegation.delegator == delegation.delegatee
            ):
                findings.append(
                    Finding(
                        "DELEGATION_BINDING_INVALID",
                        "critical",
                        delegation.delegatee,
                        (delegation.delegation_id,),
                    )
                )
            if delegation.depth > delegation.max_depth:
                findings.append(
                    Finding(
                        "DELEGATION_DEPTH_EXCEEDED",
                        "critical",
                        delegation.delegatee,
                        (delegation.delegation_id,),
                    )
                )
            if delegation.parent_id:
                parent = self.delegations.get(delegation.parent_id)
                if not parent or not parent.active or not parent.redelegable:
                    findings.append(
                        Finding(
                            "REDELEGATION_NOT_ALLOWED",
                            "critical",
                            delegation.delegatee,
                            (delegation.delegation_id,),
                        )
                    )
                elif delegation.permissions - parent.permissions:
                    findings.append(
                        Finding(
                            "DELEGATION_WIDENED",
                            "critical",
                            delegation.delegatee,
                            (delegation.delegation_id, parent.delegation_id),
                        )
                    )
                elif (
                    delegation.depth != parent.depth + 1
                    or delegation.max_depth > parent.max_depth
                ):
                    findings.append(
                        Finding(
                            "DELEGATION_DEPTH_INVALID",
                            "critical",
                            delegation.delegatee,
                            (delegation.delegation_id, parent.delegation_id),
                        )
                    )
                seen = {delegation.delegation_id}
                ancestor_id = delegation.parent_id
                while ancestor_id:
                    if ancestor_id in seen:
                        findings.append(
                            Finding(
                                "DELEGATION_CYCLE",
                                "critical",
                                delegation.delegatee,
                                (delegation.delegation_id, ancestor_id),
                            )
                        )
                        break
                    seen.add(ancestor_id)
                    ancestor = self.delegations.get(ancestor_id)
                    ancestor_id = ancestor.parent_id if ancestor else None
        return findings

    def effective_permissions(
        self, principal_id: str, now: int = NOW
    ) -> set[tuple[str, str]]:
        invalid = {finding.subject_id for finding in self.validate_delegations(now)}
        permissions = self.direct_permissions(principal_id, now)
        if principal_id in invalid:
            return permissions
        for delegation in self.delegations.values():
            if (
                delegation.delegatee == principal_id
                and delegation.active
                and delegation.expires_at > now
            ):
                permissions |= set(delegation.permissions)
        return permissions

    def authorize(
        self,
        principal_id: str,
        action: str,
        resource: str,
        tenant_id: str = TENANT,
        now: int = NOW,
    ) -> Decision:
        agent = self.agents.get(principal_id)
        if tenant_id != TENANT or not agent or agent.tenant_id != tenant_id:
            return Decision(Outcome.DENY, ("principal_or_tenant_invalid",), ())
        if agent.status != "active" or not agent.owner_id:
            return Decision(Outcome.DENY, ("agent_lifecycle_invalid",), (principal_id,))
        permission = (action, resource)
        effective = self.effective_permissions(principal_id, now)
        wildcard = (action, resource.split(":", 1)[0] + "s/*")
        if permission not in effective and wildcard not in effective:
            return Decision(Outcome.DENY, ("permission_absent",), ())
        toxic = self.toxic_combinations(principal_id, now)
        if toxic:
            return Decision(Outcome.DENY, ("toxic_combination",), tuple(sorted(toxic)))
        evidence = tuple(
            sorted(
                ent.entitlement_id
                for ent in self.entitlements.values()
                if ent.principal_id == principal_id and ent.expires_at > now
            )
        )
        return Decision(Outcome.ALLOW, ("effective_permission_present",), evidence)

    def toxic_combinations(self, principal_id: str, now: int = NOW) -> set[str]:
        actions = {
            action for action, _ in self.effective_permissions(principal_id, now)
        }
        return {name for name, required in TOXIC_SETS.items() if required <= actions}

    def findings(
        self, usage_90d: Mapping[str, int] | None = None, now: int = NOW
    ) -> list[Finding]:
        usage_90d = usage_90d or {}
        results = self.validate_delegations(now)
        for agent in self.agents.values():
            if agent.status == "active" and not agent.owner_id:
                results.append(
                    Finding(
                        "ORPHANED_AGENT", "critical", agent.agent_id, (agent.agent_id,)
                    )
                )
            if agent.status == "active" and now - agent.last_seen > 30 * 86_400:
                results.append(
                    Finding("STALE_AGENT", "high", agent.agent_id, (agent.agent_id,))
                )
        for entitlement in self.entitlements.values():
            if entitlement.expires_at <= now:
                results.append(
                    Finding(
                        "ENTITLEMENT_EXPIRED",
                        "high",
                        entitlement.principal_id,
                        (entitlement.entitlement_id,),
                    )
                )
            if "*" in entitlement.resource and entitlement.risk in {"high", "critical"}:
                results.append(
                    Finding(
                        "HIGH_RISK_WILDCARD",
                        "critical",
                        entitlement.principal_id,
                        (entitlement.entitlement_id,),
                    )
                )
            if usage_90d.get(
                entitlement.entitlement_id, 0
            ) == 0 and entitlement.risk in {"high", "critical"}:
                results.append(
                    Finding(
                        "UNUSED_HIGH_RISK_PERMISSION",
                        "high",
                        entitlement.principal_id,
                        (entitlement.entitlement_id,),
                    )
                )
        for principal in self.agents:
            for toxic in self.toxic_combinations(principal, now):
                results.append(
                    Finding("TOXIC_COMBINATION", "critical", principal, (toxic,))
                )
        for grant in self.exceptions.values():
            if grant.expires_at <= now and not grant.revoked:
                results.append(
                    Finding(
                        "EXCEPTION_EXPIRED",
                        "critical",
                        grant.principal_id,
                        (grant.exception_id,),
                    )
                )
        return sorted(
            results, key=lambda item: (item.code, item.subject_id, item.evidence_ids)
        )

    def create_exception(self, grant: ExceptionGrant) -> None:
        prior = self.exceptions.get(grant.exception_id)
        if prior:
            if prior != grant:
                raise GovernanceError("exception_id_conflict")
            return
        if (
            grant.tenant_id != TENANT
            or grant.expires_at <= NOW
            or grant.expires_at - grant.issued_at > 86_400
        ):
            raise GovernanceError("exception_lifetime_invalid")
        if len(set(grant.approver_ids)) < 2 or grant.principal_id in grant.approver_ids:
            raise GovernanceError("exception_approval_invalid")
        if (
            not grant.reason
            or not grant.controls
            or not grant.ticket_id
            or grant.policy_version != POLICY_VERSION
        ):
            raise GovernanceError("exception_binding_invalid")
        self.exceptions[grant.exception_id] = grant

    def review_packet(self, entitlement_id: str, usage_count_90d: int) -> ReviewPacket:
        entitlement = self.entitlements[entitlement_id]
        snapshot = digest(
            {
                "entitlement": entitlement,
                "inventory_version": self.inventory_version,
                "policy_version": POLICY_VERSION,
            }
        )
        packet = ReviewPacket(
            "review:" + entitlement_id,
            entitlement.principal_id,
            entitlement_id,
            snapshot,
            self.inventory_version,
            POLICY_VERSION,
            entitlement.risk,
            usage_count_90d,
            ("renew", "reduce", "revoke", "escalate"),
            NOW + 900,
        )
        self.reviews[packet.review_id] = packet
        return packet

    def apply_review(
        self, decision: ReviewDecision, expected_inventory_version: int
    ) -> Mapping[str, Any]:
        with self._lock:
            prior = self.review_decisions.get(decision.review_id)
            if prior:
                if digest(replace(prior, used=False)) != digest(
                    replace(decision, used=False)
                ):
                    raise GovernanceError("review_replay_conflict")
                return {
                    "outcome": Outcome.RECONCILED.value,
                    "inventory_version": self.inventory_version,
                }
            packet = self.reviews.get(decision.review_id)
            if not packet or packet.expires_at <= decision.decided_at:
                raise GovernanceError("review_packet_invalid")
            entitlement = self.entitlements[packet.entitlement_id]
            current_snapshot = digest(
                {
                    "entitlement": entitlement,
                    "inventory_version": self.inventory_version,
                    "policy_version": POLICY_VERSION,
                }
            )
            if (
                expected_inventory_version != self.inventory_version
                or packet.inventory_version != self.inventory_version
            ):
                raise GovernanceError("inventory_version_conflict")
            if (
                decision.snapshot_digest != packet.snapshot_digest
                or packet.snapshot_digest != current_snapshot
                or decision.reviewer_id
                in {entitlement.principal_id, entitlement.owner_id}
                or not decision.reason.strip()
            ):
                raise GovernanceError("review_binding_invalid")
            if decision.outcome not in packet.alternatives:
                raise GovernanceError("review_outcome_invalid")
            if decision.outcome == "revoke":
                del self.entitlements[packet.entitlement_id]
            elif decision.outcome == "reduce":
                self.entitlements[packet.entitlement_id] = replace(
                    entitlement, resource=CLAIM, version=entitlement.version + 1
                )
            elif decision.outcome == "renew":
                self.entitlements[packet.entitlement_id] = replace(
                    entitlement,
                    expires_at=NOW + 90 * 86_400,
                    version=entitlement.version + 1,
                )
            self.inventory_version += 1
            decision.used = True
            self.review_decisions[decision.review_id] = decision
            return {
                "outcome": decision.outcome,
                "inventory_version": self.inventory_version,
            }

    def policy_impact(
        self,
        old: PolicyCandidate,
        new: PolicyCandidate,
        cases: Iterable[tuple[str, str, str, bool]],
    ) -> PolicyImpact:
        newly_allowed, newly_denied = [], []
        newly_allowed_actions: dict[str, str] = {}
        unchanged = valid_blocked = forbidden_allowed = 0
        for case_id, principal, permission_text, expected in cases:
            action, resource = permission_text.split("|", 1)
            permission = (action, resource)
            before = permission in old.permissions.get(principal, frozenset())
            after = permission in new.permissions.get(principal, frozenset())
            if not before and after:
                newly_allowed.append(case_id)
                newly_allowed_actions[case_id] = action
            elif before and not after:
                newly_denied.append(case_id)
            else:
                unchanged += 1
            valid_blocked += int(expected and not after)
            forbidden_allowed += int(not expected and after)
        high_risk = tuple(
            sorted(
                case
                for case in newly_allowed
                if newly_allowed_actions[case] in HIGH_RISK_ACTIONS
            )
        )
        return PolicyImpact(
            tuple(sorted(newly_allowed)),
            tuple(sorted(newly_denied)),
            unchanged,
            high_risk,
            valid_blocked,
            forbidden_allowed,
        )

    def evidence_bundle(
        self, usage_90d: Mapping[str, int] | None = None
    ) -> Mapping[str, Any]:
        findings = self.findings(usage_90d)
        counts = {
            code: sum(item.code == code for item in findings)
            for code in sorted({item.code for item in findings})
        }
        inventory_digest = digest(
            {
                "agents": self.agents,
                "entitlements": self.entitlements,
                "delegations": self.delegations,
                "exceptions": self.exceptions,
            }
        )
        return {
            "captured_at": NOW,
            "inventory_version": self.inventory_version,
            "policy_version": POLICY_VERSION,
            "model_version": MODEL_VERSION,
            "inventory_digest": inventory_digest,
            "agent_count": len(self.agents),
            "entitlement_count": len(self.entitlements),
            "finding_counts": counts,
        }

    def offboard(self, agent_id: str, operation_id: str) -> Mapping[str, Any]:
        with self._lock:
            if operation_id in self.offboarding_receipts:
                if self.offboarding_receipts[operation_id]["agent_id"] != agent_id:
                    raise GovernanceError("operation_id_conflict")
                return dict(self.offboarding_receipts[operation_id]) | {
                    "reconciled": True
                }
            if agent_id not in self.agents:
                raise GovernanceError("agent_unknown")
            self.agents[agent_id] = replace(self.agents[agent_id], status="retired")
            removed_entitlements = [
                key
                for key, value in self.entitlements.items()
                if value.principal_id == agent_id
            ]
            for key in removed_entitlements:
                del self.entitlements[key]
            removed_delegations = [
                key
                for key, value in self.delegations.items()
                if value.delegator == agent_id or value.delegatee == agent_id
            ]
            for key in removed_delegations:
                self.delegations[key] = replace(self.delegations[key], active=False)
            removed_exceptions = [
                key
                for key, value in self.exceptions.items()
                if value.principal_id == agent_id
            ]
            for key in removed_exceptions:
                self.exceptions[key] = replace(self.exceptions[key], revoked=True)
            self.inventory_version += 1
            receipt = {
                "operation_id": operation_id,
                "agent_id": agent_id,
                "entitlements_removed": tuple(sorted(removed_entitlements)),
                "delegations_disabled": tuple(sorted(removed_delegations)),
                "exceptions_revoked": tuple(sorted(removed_exceptions)),
                "surfaces": (
                    "oauth_grants",
                    "workload_identity",
                    "tool_access",
                    "mcp_registration",
                    "scheduled_jobs",
                ),
                "inventory_version": self.inventory_version,
            }
            self.offboarding_receipts[operation_id] = receipt
            return receipt


def valid_exception(**updates: Any) -> ExceptionGrant:
    values = {
        "exception_id": "exc:bulk-export",
        "principal_id": CLAIMS_AGENT,
        "tenant_id": TENANT,
        "permission": ("claim.export", CLAIM),
        "reason": "regulatory response",
        "approver_ids": ("security:bob", "data-owner:carol"),
        "controls": ("human approval", "export watermark"),
        "ticket_id": "GRC-1042",
        "issued_at": NOW,
        "expires_at": NOW + 3_600,
        "policy_version": POLICY_VERSION,
    }
    values.update(updates)
    return ExceptionGrant(**values)


@dataclass(frozen=True)
class Scenario:
    case_id: str
    expected: Outcome


def build_cases() -> list[Scenario]:
    return [
        Scenario("valid_claim_read", Outcome.ALLOW),
        Scenario("valid_claim_update", Outcome.ALLOW),
        Scenario("missing_permission", Outcome.DENY),
        Scenario("wrong_tenant", Outcome.DENY),
        Scenario("unknown_agent", Outcome.DENY),
        Scenario("orphaned_agent", Outcome.DENY),
        Scenario("disabled_agent", Outcome.DENY),
        Scenario("expired_entitlement", Outcome.DENY),
        Scenario("valid_delegation", Outcome.ALLOW),
        Scenario("expired_delegation", Outcome.DENY),
        Scenario("widened_delegation", Outcome.DENY),
        Scenario("redelegation_forbidden", Outcome.DENY),
        Scenario("depth_exceeded", Outcome.DENY),
        Scenario("toxic_finance", Outcome.DENY),
        Scenario("valid_exception", Outcome.ALLOW),
        Scenario("expired_exception", Outcome.DENY),
        Scenario("revoked_exception", Outcome.DENY),
        Scenario("retired_agent", Outcome.DENY),
    ]


def run_case(case: Scenario) -> Outcome:
    engine = GovernanceEngine()
    principal, action, resource, tenant, now = (
        CLAIMS_AGENT,
        "claim.read",
        CLAIM,
        TENANT,
        NOW,
    )
    if case.case_id == "valid_claim_update":
        action = "claim.update"
    elif case.case_id == "missing_permission":
        action = "claim.delete"
    elif case.case_id == "wrong_tenant":
        tenant = "tenant:evil"
    elif case.case_id == "unknown_agent":
        principal = "agent:unknown"
    elif case.case_id == "orphaned_agent":
        principal, action, resource = "agent:legacy", "claim.export", "claims/*"
    elif case.case_id == "disabled_agent":
        engine.agents[principal] = replace(engine.agents[principal], status="disabled")
    elif case.case_id == "expired_entitlement":
        now = NOW + 200 * 86_400
    elif case.case_id in {
        "valid_delegation",
        "expired_delegation",
        "widened_delegation",
        "redelegation_forbidden",
        "depth_exceeded",
    }:
        principal = RESEARCH_AGENT
        if case.case_id == "expired_delegation":
            now = NOW + 2_000
        elif case.case_id == "widened_delegation":
            engine.delegations["del:claims-research"] = replace(
                engine.delegations["del:claims-research"],
                permissions=frozenset({("claim.read", CLAIM), ("claim.delete", CLAIM)}),
            )
        elif case.case_id == "redelegation_forbidden":
            engine.delegations["del:alice-claims"] = replace(
                engine.delegations["del:alice-claims"], redelegable=False
            )
        elif case.case_id == "depth_exceeded":
            engine.delegations["del:claims-research"] = replace(
                engine.delegations["del:claims-research"], depth=3
            )
    elif case.case_id == "toxic_finance":
        principal, action, resource = FINANCE_AGENT, "payment.create", "payments/*"
    elif case.case_id in {"valid_exception", "expired_exception", "revoked_exception"}:
        action = "claim.export"
        grant = valid_exception()
        engine.create_exception(grant)
        if case.case_id == "expired_exception":
            now = grant.expires_at
        elif case.case_id == "revoked_exception":
            engine.exceptions[grant.exception_id] = replace(grant, revoked=True)
    elif case.case_id == "retired_agent":
        engine.agents[principal] = replace(engine.agents[principal], status="retired")
    return engine.authorize(principal, action, resource, tenant, now).outcome


def evaluate() -> tuple[dict[str, int], list[dict[str, str]]]:
    rows = [
        {
            "case_id": case.case_id,
            "expected": case.expected.value,
            "observed": run_case(case).value,
        }
        for case in build_cases()
    ]
    metrics = {
        "total": len(rows),
        "matches": sum(row["expected"] == row["observed"] for row in rows),
        "invalid_allows": sum(
            row["expected"] == "deny" and row["observed"] == "allow" for row in rows
        ),
        "valid_work_blocked": sum(
            row["expected"] == "allow" and row["observed"] == "deny" for row in rows
        ),
    }
    return metrics, rows


def main() -> None:
    metrics, _ = evaluate()
    print(canonical(metrics))
    print(
        "release_gate",
        "PASS"
        if metrics
        == {"total": 18, "matches": 18, "invalid_allows": 0, "valid_work_blocked": 0}
        else "FAIL",
    )


if __name__ == "__main__":
    main()
