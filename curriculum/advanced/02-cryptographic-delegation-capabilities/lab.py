"""Credential-free cryptographic delegation lab for autonomous agents.

The lab demonstrates portable proof of bounded authority, not a production token
format. It uses real Ed25519 signatures, PyJWT DPoP proofs, and PyMacaroons while
keeping current authorization and side effects in trusted application code.
"""

from __future__ import annotations

import base64
import json
from collections.abc import Callable, Iterable, Mapping
from dataclasses import asdict, dataclass, field, replace
from hashlib import sha256
from threading import Lock
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import jwt
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from pymacaroons import Macaroon, Verifier
from pymacaroons.exceptions import MacaroonException

NOW = 1_800_000_000
TENANT = "tenant:northstar"
TASK = "task:claim-483"
CLAIM = "claim:483"
ROOT_ISSUER = "authority:northstar"
CLAIMS_AGENT = "agent:claims"
RESEARCH_AGENT = "agent:research"
KNOWLEDGE_API = "https://knowledge.northstar.example"
CLAIMS_API = "https://claims.northstar.example"
WORKLOAD = "spiffe://northstar.example/agents/research"
POLICY_VERSION = "capability-policy-2026-10-07"
ACCESS_TOKEN = "synthetic-access-token-483"
DPoP_NONCE = "nonce:knowledge:1"


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def unb64url(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def canonical(value: Any) -> bytes:
    if hasattr(value, "__dataclass_fields__"):
        value = asdict(value)
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), default=list
    ).encode()


def digest(value: Any) -> str:
    return sha256(canonical(value)).hexdigest()


def deterministic_private_key(label: str) -> Ed25519PrivateKey:
    """Deterministic synthetic key for reproducible training only."""

    return Ed25519PrivateKey.from_private_bytes(sha256(label.encode()).digest())


def public_jwk(public_key: Ed25519PublicKey) -> dict[str, str]:
    raw = public_key.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return {"kty": "OKP", "crv": "Ed25519", "x": b64url(raw)}


def jwk_thumbprint(jwk: Mapping[str, str]) -> str:
    required = {"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"]}
    return b64url(sha256(canonical(required)).digest())


def public_from_jwk(jwk: Mapping[str, str]) -> Ed25519PublicKey:
    if set(jwk) != {"kty", "crv", "x"}:
        raise ValueError("dpop_jwk_not_public_or_minimal")
    if jwk["kty"] != "OKP" or jwk["crv"] != "Ed25519":
        raise ValueError("dpop_jwk_type_invalid")
    return Ed25519PublicKey.from_public_bytes(unb64url(jwk["x"]))


@dataclass(frozen=True)
class CapabilityClaims:
    jti: str
    issuer: str
    subject: str
    tenant_id: str
    task_id: str
    audiences: frozenset[str]
    actions: frozenset[str]
    resources: frozenset[str]
    tools: frozenset[str]
    purposes: frozenset[str]
    issued_at: int
    expires_at: int
    max_calls: int
    max_amount_cents: int
    depth: int
    parent_jti: str | None
    parent_digest: str | None
    confirmation_jkt: str
    policy_version: str = POLICY_VERSION


@dataclass(frozen=True)
class SignedCapability:
    claims: CapabilityClaims
    signature: str


def sign_capability(
    claims: CapabilityClaims, private_key: Ed25519PrivateKey
) -> SignedCapability:
    return SignedCapability(claims, b64url(private_key.sign(canonical(claims))))


def verify_signature(token: SignedCapability, public_key: Ed25519PublicKey) -> bool:
    try:
        public_key.verify(unb64url(token.signature), canonical(token.claims))
    except (InvalidSignature, ValueError):
        return False
    return True


def attenuation_violations(
    parent: CapabilityClaims, child: CapabilityClaims
) -> tuple[str, ...]:
    checks = {
        "issuer_not_parent_subject": child.issuer != parent.subject,
        "tenant_widened": child.tenant_id != parent.tenant_id,
        "task_widened": child.task_id != parent.task_id,
        "audience_widened": not child.audiences.issubset(parent.audiences),
        "action_widened": not child.actions.issubset(parent.actions),
        "resource_widened": not child.resources.issubset(parent.resources),
        "tool_widened": not child.tools.issubset(parent.tools),
        "purpose_widened": not child.purposes.issubset(parent.purposes),
        "issued_before_parent": child.issued_at < parent.issued_at,
        "expiry_widened": child.expires_at > parent.expires_at,
        "call_budget_widened": child.max_calls > parent.max_calls,
        "amount_widened": child.max_amount_cents > parent.max_amount_cents,
        "depth_invalid": child.depth != parent.depth + 1,
        "parent_jti_mismatch": child.parent_jti != parent.jti,
        "parent_digest_mismatch": child.parent_digest != digest(parent),
        "policy_version_changed": child.policy_version != parent.policy_version,
    }
    return tuple(code for code, failed in checks.items() if failed)


@dataclass(frozen=True)
class ChainResult:
    valid: bool
    reason_codes: tuple[str, ...]
    leaf: CapabilityClaims | None
    chain_digest: str


def verify_chain(
    chain: Iterable[SignedCapability],
    key_registry: Mapping[str, Ed25519PublicKey],
    *,
    revoked: frozenset[str] = frozenset(),
    now: int = NOW,
    max_depth: int = 2,
) -> ChainResult:
    tokens = tuple(chain)
    failures: list[str] = []
    if not tokens:
        return ChainResult(False, ("chain_empty",), None, digest([]))
    for index, token in enumerate(tokens):
        claims = token.claims
        public_key = key_registry.get(claims.issuer)
        if public_key is None or not verify_signature(token, public_key):
            failures.append(f"signature_invalid:{index}")
        if claims.jti in revoked:
            failures.append(f"capability_revoked:{index}")
        if not claims.issued_at <= now < claims.expires_at:
            failures.append(f"capability_not_current:{index}")
        if claims.policy_version != POLICY_VERSION:
            failures.append(f"policy_version_stale:{index}")
        if claims.depth > max_depth:
            failures.append(f"depth_exceeded:{index}")
        if index == 0:
            if claims.issuer != ROOT_ISSUER or claims.depth != 0:
                failures.append("root_not_trusted")
            if claims.parent_jti is not None or claims.parent_digest is not None:
                failures.append("root_has_parent")
        else:
            failures.extend(attenuation_violations(tokens[index - 1].claims, claims))
    failures = list(dict.fromkeys(failures))
    return ChainResult(
        not failures,
        tuple(failures or ["chain_valid"]),
        tokens[-1].claims,
        digest([asdict(token) for token in tokens]),
    )


def normalize_htu(uri: str) -> str:
    parts = urlsplit(uri)
    return urlunsplit((parts.scheme.lower(), parts.netloc.lower(), parts.path, "", ""))


def access_token_hash(access_token: str) -> str:
    return b64url(sha256(access_token.encode("ascii")).digest())


def create_dpop_proof(
    private_key: Ed25519PrivateKey,
    *,
    method: str,
    uri: str,
    access_token: str,
    jti: str,
    nonce: str,
    now: int = NOW,
) -> str:
    jwk = public_jwk(private_key.public_key())
    return jwt.encode(
        {
            "jti": jti,
            "htm": method.upper(),
            "htu": normalize_htu(uri),
            "iat": now,
            "ath": access_token_hash(access_token),
            "nonce": nonce,
        },
        private_key,
        algorithm="EdDSA",
        headers={"typ": "dpop+jwt", "jwk": jwk},
    )


@dataclass
class ReplayStore:
    seen: set[str] = field(default_factory=set)
    _lock: Lock = field(default_factory=Lock)

    def consume(self, value: str) -> bool:
        with self._lock:
            if value in self.seen:
                return False
            self.seen.add(value)
            return True


@dataclass
class CallBudgetStore:
    """Atomic, in-memory reservation model for the lab's call obligation."""

    remaining: dict[str, int] = field(default_factory=dict)
    operations: dict[tuple[str, str], str] = field(default_factory=dict)
    _lock: Lock = field(default_factory=Lock)

    def reserve(
        self,
        capability_jti: str,
        maximum: int,
        operation_id: str,
        request_digest: str,
    ) -> tuple[bool, str]:
        with self._lock:
            operation_key = (capability_jti, operation_id)
            existing = self.operations.get(operation_key)
            if existing is not None:
                if existing == request_digest:
                    return True, "call_budget_idempotent"
                return False, "operation_id_conflict"
            available = self.remaining.setdefault(capability_jti, maximum)
            if available <= 0:
                return False, "call_budget_exhausted"
            self.remaining[capability_jti] = available - 1
            self.operations[operation_key] = request_digest
            return True, "call_budget_reserved"


def verify_dpop_proof(
    proof: str,
    *,
    expected_jkt: str,
    method: str,
    uri: str,
    access_token: str,
    nonce: str,
    replay_store: ReplayStore,
    now: int = NOW,
    max_age: int = 60,
) -> tuple[bool, str]:
    try:
        header = jwt.get_unverified_header(proof)
        if header.get("typ") != "dpop+jwt" or header.get("alg") != "EdDSA":
            return False, "dpop_header_invalid"
        jwk = header.get("jwk", {})
        public_key = public_from_jwk(jwk)
        if jwk_thumbprint(jwk) != expected_jkt:
            return False, "dpop_key_binding_invalid"
        payload = jwt.decode(
            proof,
            public_key,
            algorithms=["EdDSA"],
            options={"verify_aud": False, "verify_iat": False},
        )
    except (jwt.PyJWTError, ValueError, KeyError):
        return False, "dpop_signature_or_shape_invalid"
    checks = {
        "dpop_method_mismatch": payload.get("htm") != method.upper(),
        "dpop_uri_mismatch": payload.get("htu") != normalize_htu(uri),
        "dpop_token_hash_mismatch": payload.get("ath")
        != access_token_hash(access_token),
        "dpop_nonce_mismatch": payload.get("nonce") != nonce,
        "dpop_time_invalid": not isinstance(payload.get("iat"), int)
        or not now - max_age <= payload.get("iat", 0) <= now + 5,
        "dpop_jti_invalid": not isinstance(payload.get("jti"), str)
        or not 1 <= len(payload.get("jti", "")) <= 200,
    }
    for code, failed in checks.items():
        if failed:
            return False, code
    if not replay_store.consume(digest(payload["jti"])):
        return False, "dpop_replayed"
    return True, "dpop_valid"


@dataclass(frozen=True)
class ActionRequest:
    operation_id: str
    agent_id: str
    workload_id: str
    tenant_id: str
    task_id: str
    audience: str
    action: str
    resource: str
    tool: str
    purpose: str
    amount_cents: int
    method: str
    uri: str


@dataclass(frozen=True)
class CurrentPolicy:
    version: str
    workload_approved: bool
    task_active: bool
    relationship_valid: bool
    risk_score: int


@dataclass(frozen=True)
class GatewayDecision:
    allowed: bool
    reason_code: str
    chain_digest: str
    capability_jti: str | None


class CapabilityGateway:
    """Verify proof and current policy; it performs no downstream effect."""

    def __init__(
        self,
        key_registry: Mapping[str, Ed25519PublicKey],
        *,
        revoked: frozenset[str] = frozenset(),
        call_budgets: CallBudgetStore | None = None,
    ) -> None:
        self.key_registry = key_registry
        self.revoked = revoked
        self.dpop_replays = ReplayStore()
        self.call_budgets = call_budgets or CallBudgetStore()
        self.evidence: list[dict[str, Any]] = []

    def authorize(
        self,
        chain: Iterable[SignedCapability],
        request: ActionRequest,
        policy: CurrentPolicy,
        *,
        proof: str,
        access_token: str = ACCESS_TOKEN,
        nonce: str = DPoP_NONCE,
        now: int = NOW,
    ) -> GatewayDecision:
        result = verify_chain(chain, self.key_registry, revoked=self.revoked, now=now)
        if not result.valid or result.leaf is None:
            return self._record(False, result.reason_codes[0], result, request)
        leaf = result.leaf
        checks = {
            "subject_mismatch": request.agent_id != leaf.subject,
            "workload_mismatch": request.workload_id != WORKLOAD,
            "tenant_mismatch": request.tenant_id != leaf.tenant_id,
            "task_mismatch": request.task_id != leaf.task_id,
            "audience_mismatch": request.audience not in leaf.audiences,
            "action_not_granted": request.action not in leaf.actions,
            "resource_not_granted": request.resource not in leaf.resources,
            "tool_not_granted": request.tool not in leaf.tools,
            "purpose_not_granted": request.purpose not in leaf.purposes,
            "amount_exceeds_capability": request.amount_cents > leaf.max_amount_cents,
            "policy_version_mismatch": policy.version != leaf.policy_version,
            "workload_not_approved": not policy.workload_approved,
            "task_inactive": not policy.task_active,
            "relationship_invalid": not policy.relationship_valid,
            "risk_too_high": policy.risk_score >= 50,
        }
        for code, failed in checks.items():
            if failed:
                return self._record(False, code, result, request)
        proof_ok, proof_reason = verify_dpop_proof(
            proof,
            expected_jkt=leaf.confirmation_jkt,
            method=request.method,
            uri=request.uri,
            access_token=access_token,
            nonce=nonce,
            replay_store=self.dpop_replays,
            now=now,
        )
        if not proof_ok:
            return self._record(False, proof_reason, result, request)
        budget_ok, budget_reason = self.call_budgets.reserve(
            leaf.jti, leaf.max_calls, request.operation_id, digest(request)
        )
        return self._record(
            budget_ok,
            "authorized" if budget_ok else budget_reason,
            result,
            request,
        )

    def _record(
        self,
        allowed: bool,
        reason: str,
        result: ChainResult,
        request: ActionRequest,
    ) -> GatewayDecision:
        leaf_jti = result.leaf.jti if result.leaf else None
        decision = GatewayDecision(allowed, reason, result.chain_digest, leaf_jti)
        self.evidence.append(
            {
                "operation_id": request.operation_id,
                "allowed": allowed,
                "reason_code": reason,
                "chain_digest": result.chain_digest,
                "capability_jti_hash": digest(leaf_jti) if leaf_jti else None,
                "policy_version": POLICY_VERSION,
            }
        )
        return decision


def create_macaroon(root_key: str = "synthetic-root-key") -> Macaroon:
    macaroon = Macaroon(
        location=KNOWLEDGE_API, identifier="knowledge-root-v1", key=root_key
    )
    for caveat in (
        f"tenant = {TENANT}",
        f"task = {TASK}",
        "action = knowledge.search",
        f"resource = {CLAIM}",
    ):
        macaroon.add_first_party_caveat(caveat)
    return macaroon


def attenuate_macaroon(macaroon: Macaroon, *caveats: str) -> Macaroon:
    child = Macaroon.deserialize(macaroon.serialize())
    for caveat in caveats:
        child.add_first_party_caveat(caveat)
    return child


def verify_macaroon(
    macaroon: Macaroon, satisfied: Iterable[str], root_key: str = "synthetic-root-key"
) -> bool:
    verifier = Verifier()
    for caveat in satisfied:
        verifier.satisfy_exact(caveat)
    try:
        return bool(verifier.verify(macaroon, root_key))
    except MacaroonException:
        return False


@dataclass(frozen=True)
class EvidenceEvent:
    event_id: str
    producer: str
    event_type: str
    subject_id: str
    object_digest: str
    previous_hash: str
    occurred_at: int
    signature: str


def evidence_payload(event: EvidenceEvent) -> dict[str, Any]:
    body = asdict(event)
    body.pop("signature")
    return body


def sign_evidence(
    *,
    event_id: str,
    producer: str,
    event_type: str,
    subject_id: str,
    object_digest: str,
    previous_hash: str,
    private_key: Ed25519PrivateKey,
    occurred_at: int = NOW,
) -> EvidenceEvent:
    unsigned = EvidenceEvent(
        event_id,
        producer,
        event_type,
        subject_id,
        object_digest,
        previous_hash,
        occurred_at,
        "",
    )
    signature = b64url(private_key.sign(canonical(evidence_payload(unsigned))))
    return replace(unsigned, signature=signature)


def evidence_hash(event: EvidenceEvent) -> str:
    return digest(asdict(event))


def verify_evidence_chain(
    events: Iterable[EvidenceEvent], keys: Mapping[str, Ed25519PublicKey]
) -> tuple[bool, str]:
    previous = ""
    seen: set[str] = set()
    for event in events:
        if event.event_id in seen:
            return False, "evidence_duplicate"
        seen.add(event.event_id)
        if event.previous_hash != previous:
            return False, "evidence_link_invalid"
        key = keys.get(event.producer)
        if key is None:
            return False, "evidence_producer_unknown"
        try:
            key.verify(unb64url(event.signature), canonical(evidence_payload(event)))
        except (InvalidSignature, ValueError):
            return False, "evidence_signature_invalid"
        previous = evidence_hash(event)
    return True, "evidence_valid"


def scenario() -> dict[str, Any]:
    authority_key = deterministic_private_key(ROOT_ISSUER)
    claims_key = deterministic_private_key(CLAIMS_AGENT)
    research_key = deterministic_private_key(RESEARCH_AGENT)
    dpop_key = deterministic_private_key("dpop:research")
    dpop_jkt = jwk_thumbprint(public_jwk(dpop_key.public_key()))
    root_claims = CapabilityClaims(
        "cap:root:483",
        ROOT_ISSUER,
        CLAIMS_AGENT,
        TENANT,
        TASK,
        frozenset({CLAIMS_API, KNOWLEDGE_API}),
        frozenset({"claim.read", "claim.update", "knowledge.search"}),
        frozenset({CLAIM}),
        frozenset({"tool:claims", "tool:knowledge"}),
        frozenset({"claims-processing", "fraud-research"}),
        NOW - 60,
        NOW + 600,
        5,
        50_000,
        0,
        None,
        None,
        dpop_jkt,
    )
    root = sign_capability(root_claims, authority_key)
    child_claims = CapabilityClaims(
        "cap:research:483",
        CLAIMS_AGENT,
        RESEARCH_AGENT,
        TENANT,
        TASK,
        frozenset({KNOWLEDGE_API}),
        frozenset({"knowledge.search"}),
        frozenset({CLAIM}),
        frozenset({"tool:knowledge"}),
        frozenset({"fraud-research"}),
        NOW - 30,
        NOW + 300,
        2,
        0,
        1,
        root_claims.jti,
        digest(root_claims),
        dpop_jkt,
    )
    child = sign_capability(child_claims, claims_key)
    request = ActionRequest(
        "operation:search:483",
        RESEARCH_AGENT,
        WORKLOAD,
        TENANT,
        TASK,
        KNOWLEDGE_API,
        "knowledge.search",
        CLAIM,
        "tool:knowledge",
        "fraud-research",
        0,
        "POST",
        f"{KNOWLEDGE_API}/search",
    )
    policy = CurrentPolicy(POLICY_VERSION, True, True, True, 20)
    proof = create_dpop_proof(
        dpop_key,
        method=request.method,
        uri=request.uri,
        access_token=ACCESS_TOKEN,
        jti="dpop:search:483:1",
        nonce=DPoP_NONCE,
    )
    return {
        "keys": {
            ROOT_ISSUER: authority_key.public_key(),
            CLAIMS_AGENT: claims_key.public_key(),
            RESEARCH_AGENT: research_key.public_key(),
        },
        "private_keys": {
            ROOT_ISSUER: authority_key,
            CLAIMS_AGENT: claims_key,
            RESEARCH_AGENT: research_key,
        },
        "dpop_key": dpop_key,
        "chain": (root, child),
        "request": request,
        "policy": policy,
        "proof": proof,
    }


@dataclass(frozen=True)
class Case:
    case_id: str
    expected_allowed: bool
    category: str
    run: Callable[[], bool]


def build_cases() -> list[Case]:
    def gateway_case(
        case_id: str,
        expected: bool,
        category: str,
        *,
        mutate_request: Callable[[ActionRequest], ActionRequest] | None = None,
        mutate_policy: Callable[[CurrentPolicy], CurrentPolicy] | None = None,
        mutate_chain: Callable[
            [tuple[SignedCapability, ...]], tuple[SignedCapability, ...]
        ]
        | None = None,
        proof_changes: Mapping[str, Any] | None = None,
        revoked: frozenset[str] = frozenset(),
    ) -> Case:
        def run() -> bool:
            value = scenario()
            request = value["request"]
            policy = value["policy"]
            chain = value["chain"]
            if mutate_request:
                request = mutate_request(request)
            if mutate_policy:
                policy = mutate_policy(policy)
            if mutate_chain:
                chain = mutate_chain(chain)
            proof = value["proof"]
            if proof_changes is not None:
                args = {
                    "method": request.method,
                    "uri": request.uri,
                    "access_token": ACCESS_TOKEN,
                    "jti": f"dpop:{case_id}",
                    "nonce": DPoP_NONCE,
                    "now": NOW,
                }
                args.update(proof_changes)
                proof = create_dpop_proof(value["dpop_key"], **args)
            return (
                CapabilityGateway(value["keys"], revoked=revoked)
                .authorize(chain, request, policy, proof=proof)
                .allowed
            )

        return Case(case_id, expected, category, run)

    def tamper_child(
        chain: tuple[SignedCapability, ...], **changes: Any
    ) -> tuple[SignedCapability, ...]:
        return (chain[0], replace(chain[1], claims=replace(chain[1].claims, **changes)))

    return [
        gateway_case("valid_chain", True, "valid"),
        gateway_case(
            "wrong_subject",
            False,
            "identity",
            mutate_request=lambda x: replace(x, agent_id="agent:evil"),
        ),
        gateway_case(
            "wrong_workload",
            False,
            "identity",
            mutate_request=lambda x: replace(x, workload_id="spiffe://evil"),
        ),
        gateway_case(
            "cross_tenant",
            False,
            "isolation",
            mutate_request=lambda x: replace(x, tenant_id="tenant:evil"),
        ),
        gateway_case(
            "wrong_task",
            False,
            "binding",
            mutate_request=lambda x: replace(x, task_id="task:999"),
        ),
        gateway_case(
            "wrong_audience",
            False,
            "binding",
            mutate_request=lambda x: replace(x, audience=CLAIMS_API),
        ),
        gateway_case(
            "action_escalation",
            False,
            "attenuation",
            mutate_request=lambda x: replace(x, action="claim.delete"),
        ),
        gateway_case(
            "resource_escalation",
            False,
            "attenuation",
            mutate_request=lambda x: replace(x, resource="claim:999"),
        ),
        gateway_case(
            "tool_escalation",
            False,
            "attenuation",
            mutate_request=lambda x: replace(x, tool="tool:wire"),
        ),
        gateway_case(
            "purpose_escalation",
            False,
            "attenuation",
            mutate_request=lambda x: replace(x, purpose="marketing"),
        ),
        gateway_case(
            "amount_escalation",
            False,
            "attenuation",
            mutate_request=lambda x: replace(x, amount_cents=1),
        ),
        gateway_case(
            "workload_revoked",
            False,
            "policy",
            mutate_policy=lambda x: replace(x, workload_approved=False),
        ),
        gateway_case(
            "task_revoked",
            False,
            "policy",
            mutate_policy=lambda x: replace(x, task_active=False),
        ),
        gateway_case(
            "relationship_revoked",
            False,
            "policy",
            mutate_policy=lambda x: replace(x, relationship_valid=False),
        ),
        gateway_case(
            "risk_high",
            False,
            "policy",
            mutate_policy=lambda x: replace(x, risk_score=50),
        ),
        gateway_case(
            "policy_changed",
            False,
            "policy",
            mutate_policy=lambda x: replace(x, version="new"),
        ),
        gateway_case(
            "parent_revoked", False, "revocation", revoked=frozenset({"cap:root:483"})
        ),
        gateway_case(
            "leaf_revoked", False, "revocation", revoked=frozenset({"cap:research:483"})
        ),
        gateway_case(
            "payload_tampered",
            False,
            "crypto",
            mutate_chain=lambda c: tamper_child(c, actions=frozenset({"claim.delete"})),
        ),
        gateway_case(
            "parent_digest_tampered",
            False,
            "crypto",
            mutate_chain=lambda c: tamper_child(c, parent_digest="wrong"),
        ),
        gateway_case(
            "depth_widened",
            False,
            "crypto",
            mutate_chain=lambda c: tamper_child(c, depth=3),
        ),
        gateway_case(
            "expired_child",
            False,
            "lifecycle",
            mutate_chain=lambda c: tamper_child(c, expires_at=NOW),
        ),
        gateway_case("dpop_method", False, "dpop", proof_changes={"method": "GET"}),
        gateway_case(
            "dpop_uri", False, "dpop", proof_changes={"uri": f"{KNOWLEDGE_API}/other"}
        ),
        gateway_case(
            "dpop_token", False, "dpop", proof_changes={"access_token": "other-token"}
        ),
        gateway_case("dpop_nonce", False, "dpop", proof_changes={"nonce": "wrong"}),
        gateway_case("dpop_old", False, "dpop", proof_changes={"now": NOW - 61}),
    ]


@dataclass(frozen=True)
class Metrics:
    total: int
    expected_allowed: int
    expected_blocked: int
    matches: int
    invalid_allows: int
    valid_blocked: int
    accuracy: float


def evaluate_cases(cases: Iterable[Case]) -> tuple[Metrics, list[dict[str, Any]]]:
    rows = []
    for case in cases:
        actual = case.run()
        rows.append(
            {
                "case_id": case.case_id,
                "category": case.category,
                "expected": case.expected_allowed,
                "actual": actual,
                "match": actual == case.expected_allowed,
            }
        )
    total = len(rows)
    matches = sum(row["match"] for row in rows)
    metrics = Metrics(
        total,
        sum(row["expected"] for row in rows),
        sum(not row["expected"] for row in rows),
        matches,
        sum(row["actual"] and not row["expected"] for row in rows),
        sum(not row["actual"] and row["expected"] for row in rows),
        matches / total if total else 0.0,
    )
    return metrics, rows


def release_gate(metrics: Metrics) -> bool:
    return (
        metrics.total >= 25
        and metrics.invalid_allows == 0
        and metrics.valid_blocked == 0
        and metrics.accuracy == 1.0
    )


def evaluate_cedar_context(
    context: Mapping[str, Any], course_dir: Any | None = None
) -> bool:
    """Execute the checked Cedar policy against trusted gateway facts."""

    from pathlib import Path

    import cedarpy

    root = Path(course_dir) if course_dir else Path(__file__).parent
    policy_dir = root / "policies/cedar"
    policies = (policy_dir / "capability.cedar").read_text()
    schema = json.loads((policy_dir / "schema.json").read_text())
    validation = cedarpy.validate_policies(policies, schema)
    if not validation.validation_passed:
        raise RuntimeError(f"Cedar validation failed: {validation}")
    request = {
        "principal": {"type": "Agent", "id": RESEARCH_AGENT},
        "action": {"type": "Action", "id": "SearchKnowledge"},
        "resource": {"type": "Claim", "id": CLAIM},
        "context": dict(context),
    }
    entities = [
        {
            "uid": {"type": "Agent", "id": RESEARCH_AGENT},
            "attrs": {"tenantId": TENANT},
            "parents": [],
        },
        {
            "uid": {"type": "Claim", "id": CLAIM},
            "attrs": {"tenantId": TENANT},
            "parents": [],
        },
    ]
    result = cedarpy.is_authorized(request, policies, entities, schema)
    return not result.diagnostics.errors and result.decision == cedarpy.Decision.Allow


def valid_cedar_context() -> dict[str, Any]:
    """Return synthetic facts after successful cryptographic verification."""

    return {
        "proofValid": True,
        "attenuationValid": True,
        "dpopValid": True,
        "replayConsumed": True,
        "capabilityCurrent": True,
        "policyVersionCurrent": True,
        "subjectBound": True,
        "tenantBound": True,
        "taskBound": True,
        "audienceBound": True,
        "actionBound": True,
        "resourceBound": True,
        "toolBound": True,
        "purposeBound": True,
        "workloadApproved": True,
        "relationshipValid": True,
        "riskScore": 20,
    }


if __name__ == "__main__":
    metrics, rows = evaluate_cases(build_cases())
    print(
        json.dumps(
            {
                "metrics": asdict(metrics),
                "release_gate": release_gate(metrics),
                "mismatches": [row for row in rows if not row["match"]],
            },
            indent=2,
        )
    )
