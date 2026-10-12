"""Credential-free cross-domain identity federation lab.

The implementation is a deliberately bounded teaching profile, not a complete
OpenID Federation, SPIFFE, OAuth, or MCP stack. It uses real Ed25519 signatures,
JWTs, and X.509 certificates while keeping trust selection and authorization in
deterministic local application code.
"""

from __future__ import annotations

import base64
import json
from collections.abc import Callable, Iterable, Mapping
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from itertools import pairwise
from pathlib import Path
from threading import Lock
from typing import Any
from urllib.parse import urlsplit

import jwt
import networkx as nx
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.x509.oid import NameOID

NOW = 1_800_000_000
CORP_DOMAIN = "corp.example"
PARTNER_DOMAIN = "partner.example"
VENDOR_DOMAIN = "vendor.example"
ANCHOR = "https://trust.corp.example"
INTERMEDIATE = "https://federation.partner.example"
PARTNER_ISSUER = "https://id.partner.example"
VENDOR_ISSUER = "https://identity.vendor.example"
RESOURCE = "https://mcp.corp.example"
PARTNER_AS = "https://id.partner.example"
AGENT_SUBJECT = "agent:research"
TENANT = "tenant:northstar"
TASK = "task:claim-483"
CLAIM = "claim:483"
SPIFFE_ID = "spiffe://partner.example/prod/research-agent"
POLICY_VERSION = "federation-policy-2026-10-12"


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
    """Create a reproducible training key. Never use this in production."""

    return Ed25519PrivateKey.from_private_bytes(sha256(label.encode()).digest())


def public_jwk(public_key: Ed25519PublicKey, kid: str) -> dict[str, str]:
    raw = public_key.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return {"kty": "OKP", "crv": "Ed25519", "x": b64url(raw), "kid": kid}


def jwk_thumbprint(jwk: Mapping[str, str]) -> str:
    required = {"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"]}
    return b64url(sha256(canonical(required)).digest())


def compound_principal_id(issuer: str, subject: str) -> str:
    """Map a verified compound identity without collapsing its namespace."""

    source = f"{issuer}|{subject}".encode()
    return f"federated:{b64url(sha256(source).digest())}"


@dataclass(frozen=True)
class FederationRelationship:
    foreign_domain: str
    status: str
    exact_issuers: frozenset[str]
    accepted_anchor: str
    accepted_audiences: frozenset[str]
    allowed_agent_types: frozenset[str]
    allowed_actions: frozenset[str]
    allowed_resources: frozenset[str]
    allowed_spiffe_ids: frozenset[str]
    bundle_fingerprint: str
    allowed_authorization_servers: frozenset[str]
    max_token_ttl_seconds: int
    max_delegation_depth: int
    max_chain_length: int
    metadata_max_age_seconds: int
    require_sender_constraint: bool
    policy_version: str


@dataclass(frozen=True)
class FederatedPrincipal:
    issuer: str
    subject: str
    trust_domain: str
    principal_type: str
    local_principal_id: str


@dataclass(frozen=True)
class TrustResult:
    valid: bool
    reason_codes: tuple[str, ...]
    subject: str | None
    anchor: str | None
    resolved_metadata: Mapping[str, Any]
    chain_digest: str


@dataclass(frozen=True)
class TokenResult:
    valid: bool
    reason_codes: tuple[str, ...]
    principal: FederatedPrincipal | None
    claims: Mapping[str, Any]


@dataclass(frozen=True)
class WorkloadResult:
    valid: bool
    reason_code: str
    spiffe_id: str | None


@dataclass(frozen=True)
class DelegationGrant:
    grant_id: str
    issuer: str
    subject_issuer: str
    subject: str
    tenant_id: str
    task_id: str
    audience: str
    actions: frozenset[str]
    resources: frozenset[str]
    purpose: str
    issued_at: int
    expires_at: int
    depth: int
    policy_version: str


@dataclass(frozen=True)
class SignedDelegation:
    grant: DelegationGrant
    signature: str


@dataclass(frozen=True)
class AccessRequest:
    trace_id: str
    operation_id: str
    issuer: str
    subject: str
    workload_id: str
    tenant_id: str
    task_id: str
    audience: str
    action: str
    resource: str
    purpose: str
    proof_jkt: str


@dataclass(frozen=True)
class CurrentPolicy:
    version: str
    partner_active: bool
    relationship_active: bool
    task_active: bool
    risk_score: int


@dataclass(frozen=True)
class OAuthTransaction:
    expected_issuer: str
    state_hash: str
    consumed: bool = False


@dataclass(frozen=True)
class FederationContext:
    chain: tuple[str, ...]
    access_token: str
    workload_certificate: x509.Certificate
    delegation: SignedDelegation
    request: AccessRequest
    current_policy: CurrentPolicy
    protected_resource_metadata: Mapping[str, Any]
    metadata_fetched_at: int
    oauth_transaction: OAuthTransaction
    oauth_response_issuer: str
    oauth_response_state: str


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason_code: str
    local_principal_id: str | None
    chain_digest: str


KeyRegistry = Mapping[str, Mapping[str, Ed25519PublicKey]]


def sign_entity_statement(
    private_key: Ed25519PrivateKey,
    *,
    kid: str,
    issuer: str,
    subject: str,
    issued_at: int = NOW - 30,
    expires_at: int = NOW + 600,
    authority_hints: Iterable[str] = (),
    metadata: Mapping[str, Any] | None = None,
    metadata_policy: Mapping[str, Any] | None = None,
    constraints: Mapping[str, Any] | None = None,
) -> str:
    claims: dict[str, Any] = {
        "iss": issuer,
        "sub": subject,
        "iat": issued_at,
        "exp": expires_at,
        "jti": f"es:{digest([issuer, subject, issued_at])[:20]}",
    }
    if authority_hints:
        claims["authority_hints"] = list(authority_hints)
    if metadata is not None:
        claims["metadata"] = dict(metadata)
    if metadata_policy is not None:
        claims["metadata_policy"] = dict(metadata_policy)
    if constraints is not None:
        claims["constraints"] = dict(constraints)
    return jwt.encode(
        claims,
        private_key,
        algorithm="EdDSA",
        headers={"typ": "entity-statement+jwt", "kid": kid},
    )


def _verified_jwt(
    token: str,
    keys: KeyRegistry,
    *,
    expected_type: str,
) -> tuple[Mapping[str, Any] | None, str | None]:
    try:
        header = jwt.get_unverified_header(token)
        claims = jwt.decode(token, options={"verify_signature": False})
        issuer = claims.get("iss")
        kid = header.get("kid")
        if header.get("typ") != expected_type or header.get("alg") != "EdDSA":
            return None, "jwt_header_invalid"
        if not isinstance(issuer, str) or not isinstance(kid, str):
            return None, "jwt_shape_invalid"
        public_key = keys.get(issuer, {}).get(kid)
        if public_key is None:
            return None, "jwt_key_unknown"
        verified = jwt.decode(
            token,
            public_key,
            algorithms=["EdDSA"],
            options={
                "verify_aud": False,
                "verify_exp": False,
                "verify_iat": False,
                "verify_nbf": False,
            },
        )
    except (jwt.PyJWTError, KeyError, TypeError, ValueError):
        return None, "jwt_signature_or_shape_invalid"
    return verified, None


def tamper_jwt(token: str, claim: str, value: Any) -> str:
    """Modify a compact JWT payload without re-signing it."""

    header, payload, signature = token.split(".")
    claims = json.loads(unb64url(payload))
    claims[claim] = value
    return f"{header}.{b64url(canonical(claims))}.{signature}"


def _as_string_set(value: Any) -> frozenset[str] | None:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        return None
    return frozenset(value)


def resolve_metadata(
    statements: tuple[Mapping[str, Any], ...], entity_type: str
) -> tuple[Mapping[str, Any] | None, tuple[str, ...]]:
    """Apply a safe teaching subset of OpenID Federation metadata policy.

    This supports ``essential``, ``subset_of``, and ``one_of``. A production
    implementation must implement the complete Final Specification.
    """

    leaf_metadata = statements[0].get("metadata", {}).get(entity_type)
    if not isinstance(leaf_metadata, dict):
        return None, ("metadata_missing",)
    resolved = dict(leaf_metadata)
    failures: list[str] = []
    allowed_sets: dict[str, frozenset[str]] = {}

    # Policy resolution proceeds from the most superior statement downward.
    for statement in reversed(statements[1:]):
        policy = statement.get("metadata_policy", {}).get(entity_type, {})
        if not isinstance(policy, dict):
            failures.append("metadata_policy_shape_invalid")
            continue
        for parameter, operators in policy.items():
            if not isinstance(operators, dict):
                failures.append(f"metadata_policy_shape_invalid:{parameter}")
                continue
            unknown = set(operators) - {"essential", "subset_of", "one_of"}
            if unknown:
                failures.append(f"metadata_policy_operator_unsupported:{parameter}")
                continue
            if operators.get("essential") is True and parameter not in resolved:
                failures.append(f"metadata_required:{parameter}")
            if "subset_of" in operators:
                constraint = _as_string_set(operators["subset_of"])
                actual = _as_string_set(resolved.get(parameter))
                if constraint is None or actual is None:
                    failures.append(f"metadata_set_invalid:{parameter}")
                    continue
                prior = allowed_sets.get(parameter, constraint)
                combined = prior & constraint
                allowed_sets[parameter] = combined
                if not combined:
                    failures.append(f"metadata_policy_conflict:{parameter}")
                if not actual.issubset(combined):
                    failures.append(f"metadata_not_subset:{parameter}")
            if "one_of" in operators:
                choices = _as_string_set(operators["one_of"])
                if choices is None or resolved.get(parameter) not in choices:
                    failures.append(f"metadata_not_one_of:{parameter}")

    return (resolved if not failures else None), tuple(dict.fromkeys(failures))


def verify_trust_chain(
    chain: Iterable[str],
    keys: KeyRegistry,
    relationship: FederationRelationship,
    *,
    now: int = NOW,
) -> TrustResult:
    tokens = tuple(chain)
    chain_hash = digest(tokens)
    if not tokens:
        return TrustResult(False, ("chain_empty",), None, None, {}, chain_hash)
    failures: list[str] = []
    if len(tokens) > relationship.max_chain_length:
        failures.append("chain_too_long")
    statements: list[Mapping[str, Any]] = []
    for index, token in enumerate(tokens):
        claims, error = _verified_jwt(token, keys, expected_type="entity-statement+jwt")
        if error or claims is None:
            failures.append(f"{error}:{index}")
            continue
        statements.append(claims)
        if not isinstance(claims.get("iat"), int) or not isinstance(
            claims.get("exp"), int
        ):
            failures.append(f"statement_time_shape_invalid:{index}")
        elif not claims["iat"] <= now < claims["exp"]:
            failures.append(f"statement_not_current:{index}")
        if claims.get("exp", 0) - claims.get("iat", 0) > 3600:
            failures.append(f"statement_ttl_excessive:{index}")
        constraint = claims.get("constraints", {})
        if isinstance(constraint, dict) and "max_path_length" in constraint:
            remaining = max(0, len(tokens) - index - 2)
            if remaining > constraint["max_path_length"]:
                failures.append(f"max_path_length_exceeded:{index}")

    if len(statements) != len(tokens):
        return TrustResult(
            False, tuple(dict.fromkeys(failures)), None, None, {}, chain_hash
        )
    if statements[0].get("iss") != statements[0].get("sub"):
        failures.append("leaf_not_self_issued")
    for index, (lower, superior) in enumerate(pairwise(statements)):
        if lower.get("iss") != superior.get("sub"):
            failures.append(f"chain_link_invalid:{index}")
        hints = lower.get("authority_hints", [])
        if index < len(statements) - 1 and superior.get("iss") not in hints:
            failures.append(f"authority_hint_missing:{index}")
    anchor = statements[-1].get("iss")
    if anchor != relationship.accepted_anchor:
        failures.append("anchor_not_accepted")
    if statements[0].get("sub") not in relationship.exact_issuers:
        failures.append("leaf_issuer_not_approved")
    statement_ids = [item.get("jti") for item in statements]
    if not all(isinstance(item, str) and item for item in statement_ids):
        failures.append("statement_id_missing")
    elif len(set(statement_ids)) != len(statements):
        failures.append("statement_replay_or_duplicate")

    metadata, metadata_failures = resolve_metadata(
        tuple(statements), "oauth_authorization_server"
    )
    failures.extend(metadata_failures)
    if metadata is not None:
        if metadata.get("issuer") != statements[0].get("sub"):
            failures.append("metadata_issuer_mismatch")
        for endpoint_name in ("authorization_endpoint", "token_endpoint"):
            endpoint = metadata.get(endpoint_name)
            if not isinstance(endpoint, str) or urlsplit(endpoint).scheme != "https":
                failures.append(f"metadata_endpoint_invalid:{endpoint_name}")
    return TrustResult(
        not failures,
        tuple(dict.fromkeys(failures or ["trust_chain_valid"])),
        statements[0].get("sub"),
        anchor,
        metadata or {},
        chain_hash,
    )


def sign_access_token(
    private_key: Ed25519PrivateKey,
    *,
    kid: str,
    issuer: str = PARTNER_ISSUER,
    subject: str = AGENT_SUBJECT,
    audience: str = RESOURCE,
    issued_at: int = NOW - 10,
    expires_at: int = NOW + 300,
    tenant_id: str = TENANT,
    task_id: str = TASK,
    agent_type: str = "research",
    actions: Iterable[str] = ("knowledge.search",),
    resources: Iterable[str] = (CLAIM,),
    confirmation_jkt: str,
) -> str:
    return jwt.encode(
        {
            "iss": issuer,
            "sub": subject,
            "aud": audience,
            "iat": issued_at,
            "exp": expires_at,
            "jti": f"token:{digest([issuer, subject, issued_at])[:20]}",
            "tenant_id": tenant_id,
            "task_id": task_id,
            "agent_type": agent_type,
            "actions": list(actions),
            "resources": list(resources),
            "cnf": {"jkt": confirmation_jkt},
        },
        private_key,
        algorithm="EdDSA",
        headers={"typ": "at+jwt", "kid": kid},
    )


def verify_access_token(
    token: str,
    keys: KeyRegistry,
    relationship: FederationRelationship,
    trust: TrustResult,
    *,
    expected_audience: str,
    expected_proof_jkt: str,
    now: int = NOW,
) -> TokenResult:
    claims, error = _verified_jwt(token, keys, expected_type="at+jwt")
    if error or claims is None:
        return TokenResult(False, (error or "token_invalid",), None, {})
    failures: list[str] = []
    issuer = claims.get("iss")
    if not trust.valid or issuer != trust.subject:
        failures.append("issuer_not_trust_chain_subject")
    if issuer not in relationship.exact_issuers:
        failures.append("issuer_not_approved")
    if claims.get("aud") != expected_audience:
        failures.append("audience_mismatch")
    if not isinstance(claims.get("iat"), int) or not isinstance(claims.get("exp"), int):
        failures.append("token_time_shape_invalid")
    else:
        if not claims["iat"] <= now < claims["exp"]:
            failures.append("token_not_current")
        if claims["exp"] - claims["iat"] > relationship.max_token_ttl_seconds:
            failures.append("token_ttl_excessive")
    if claims.get("agent_type") not in relationship.allowed_agent_types:
        failures.append("agent_type_not_allowed")
    actions = _as_string_set(claims.get("actions"))
    resources = _as_string_set(claims.get("resources"))
    if actions is None or not actions.issubset(relationship.allowed_actions):
        failures.append("token_actions_not_allowed")
    if resources is None or not resources.issubset(relationship.allowed_resources):
        failures.append("token_resources_not_allowed")
    jkt = claims.get("cnf", {}).get("jkt")
    if relationship.require_sender_constraint and jkt != expected_proof_jkt:
        failures.append("sender_constraint_mismatch")
    if not all(
        isinstance(claims.get(name), str) and claims.get(name)
        for name in ("sub", "jti", "tenant_id", "task_id")
    ):
        failures.append("token_required_claim_missing")
    principal = None
    if not failures:
        principal = FederatedPrincipal(
            str(issuer),
            str(claims["sub"]),
            relationship.foreign_domain,
            str(claims["agent_type"]),
            compound_principal_id(str(issuer), str(claims["sub"])),
        )
    return TokenResult(
        not failures,
        tuple(dict.fromkeys(failures or ["access_token_valid"])),
        principal,
        claims,
    )


def _name(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def create_ca(
    label: str, trust_domain: str
) -> tuple[Ed25519PrivateKey, x509.Certificate]:
    key = deterministic_private_key(f"ca:{label}")
    now = datetime.fromtimestamp(NOW, timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name(trust_domain))
        .issuer_name(_name(trust_domain))
        .public_key(key.public_key())
        .serial_number(int(digest([label, "ca"])[:30], 16))
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(key, algorithm=None)
    )
    return key, cert


def issue_x509_svid(
    ca_key: Ed25519PrivateKey,
    ca_cert: x509.Certificate,
    spiffe_id: str,
    *,
    label: str = "research-agent",
    issued_at: int = NOW - 30,
    expires_at: int = NOW + 300,
) -> x509.Certificate:
    leaf_key = deterministic_private_key(f"svid:{label}")
    return (
        x509.CertificateBuilder()
        .subject_name(x509.Name([]))
        .issuer_name(ca_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(int(digest([label, spiffe_id])[:30], 16))
        .not_valid_before(datetime.fromtimestamp(issued_at, timezone.utc))
        .not_valid_after(datetime.fromtimestamp(expires_at, timezone.utc))
        .add_extension(
            x509.SubjectAlternativeName([x509.UniformResourceIdentifier(spiffe_id)]),
            critical=True,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(ca_key, algorithm=None)
    )


def certificate_fingerprint(certificate: x509.Certificate) -> str:
    return certificate.fingerprint(hashes.SHA256()).hex()


def verify_x509_svid(
    certificate: x509.Certificate,
    bundle: x509.Certificate,
    relationship: FederationRelationship,
    *,
    expected_spiffe_id: str,
    now: int = NOW,
) -> WorkloadResult:
    if certificate_fingerprint(bundle) != relationship.bundle_fingerprint:
        return WorkloadResult(False, "bundle_binding_invalid", None)
    try:
        bundle.public_key().verify(
            certificate.signature, certificate.tbs_certificate_bytes
        )
    except (InvalidSignature, ValueError, TypeError):
        return WorkloadResult(False, "svid_signature_invalid", None)
    current = datetime.fromtimestamp(now, timezone.utc)
    if (
        not certificate.not_valid_before_utc
        <= current
        < certificate.not_valid_after_utc
    ):
        return WorkloadResult(False, "svid_not_current", None)
    if certificate.issuer != bundle.subject:
        return WorkloadResult(False, "svid_issuer_mismatch", None)
    try:
        sans = certificate.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value.get_values_for_type(x509.UniformResourceIdentifier)
    except x509.ExtensionNotFound:
        return WorkloadResult(False, "svid_uri_missing", None)
    if len(sans) != 1:
        return WorkloadResult(False, "svid_uri_ambiguous", None)
    spiffe_id = sans[0]
    parsed = urlsplit(spiffe_id)
    if parsed.scheme != "spiffe" or parsed.netloc != relationship.foreign_domain:
        return WorkloadResult(False, "svid_trust_domain_mismatch", spiffe_id)
    if (
        spiffe_id != expected_spiffe_id
        or spiffe_id not in relationship.allowed_spiffe_ids
    ):
        return WorkloadResult(False, "svid_identity_not_allowed", spiffe_id)
    return WorkloadResult(True, "svid_valid", spiffe_id)


def sign_delegation(
    grant: DelegationGrant, private_key: Ed25519PrivateKey
) -> SignedDelegation:
    return SignedDelegation(grant, b64url(private_key.sign(canonical(grant))))


def verify_delegation(
    signed: SignedDelegation,
    public_key: Ed25519PublicKey,
    token: TokenResult,
    relationship: FederationRelationship,
    *,
    now: int = NOW,
) -> tuple[bool, str]:
    try:
        public_key.verify(unb64url(signed.signature), canonical(signed.grant))
    except (InvalidSignature, ValueError):
        return False, "delegation_signature_invalid"
    grant = signed.grant
    claims = token.claims
    checks = {
        "delegation_issuer_invalid": grant.issuer != "authority:corp",
        "delegation_subject_issuer_mismatch": grant.subject_issuer != claims.get("iss"),
        "delegation_subject_mismatch": grant.subject != claims.get("sub"),
        "delegation_tenant_mismatch": grant.tenant_id != claims.get("tenant_id"),
        "delegation_task_mismatch": grant.task_id != claims.get("task_id"),
        "delegation_audience_mismatch": grant.audience
        not in relationship.accepted_audiences,
        "delegation_action_widened": not grant.actions.issubset(
            frozenset(claims.get("actions", [])) & relationship.allowed_actions
        ),
        "delegation_resource_widened": not grant.resources.issubset(
            frozenset(claims.get("resources", [])) & relationship.allowed_resources
        ),
        "delegation_not_current": not grant.issued_at <= now < grant.expires_at,
        "delegation_outlives_token": grant.expires_at > claims.get("exp", 0),
        "delegation_depth_exceeded": grant.depth > relationship.max_delegation_depth,
        "delegation_policy_stale": grant.policy_version != relationship.policy_version,
    }
    for reason, failed in checks.items():
        if failed:
            return False, reason
    return True, "delegation_valid"


def select_authorization_server(
    metadata: Mapping[str, Any],
    *,
    expected_resource: str,
    approved_servers: frozenset[str],
) -> tuple[str | None, str]:
    resource = metadata.get("resource")
    if resource != expected_resource or urlsplit(str(resource)).scheme != "https":
        return None, "protected_resource_mismatch"
    advertised = metadata.get("authorization_servers")
    if not isinstance(advertised, list) or not all(
        isinstance(item, str) for item in advertised
    ):
        return None, "authorization_server_metadata_invalid"
    accepted = [item for item in advertised if item in approved_servers]
    if len(accepted) != 1:
        return None, "authorization_server_not_unambiguous"
    return accepted[0], "authorization_server_selected"


@dataclass
class OAuthTransactionStore:
    transactions: dict[str, OAuthTransaction] = field(default_factory=dict)
    _lock: Lock = field(default_factory=Lock)

    def start(self, transaction_id: str, issuer: str, state: str) -> OAuthTransaction:
        transaction = OAuthTransaction(issuer, digest(state))
        with self._lock:
            if transaction_id in self.transactions:
                raise ValueError("oauth_transaction_duplicate")
            self.transactions[transaction_id] = transaction
        return transaction

    def complete(
        self, transaction_id: str, response_issuer: str, state: str
    ) -> tuple[bool, str]:
        with self._lock:
            transaction = self.transactions.get(transaction_id)
            if transaction is None:
                return False, "oauth_transaction_unknown"
            if transaction.consumed:
                return False, "oauth_response_replayed"
            if response_issuer != transaction.expected_issuer:
                return False, "oauth_issuer_mixup"
            if digest(state) != transaction.state_hash:
                return False, "oauth_state_mismatch"
            self.transactions[transaction_id] = replace(transaction, consumed=True)
            return True, "oauth_response_valid"


def build_trust_graph(relationships: Iterable[tuple[str, str]]) -> nx.DiGraph:
    graph = nx.DiGraph()
    graph.add_edges_from(relationships)
    return graph


class FederationGateway:
    def __init__(
        self,
        relationship: FederationRelationship,
        key_registry: KeyRegistry,
        bundle: x509.Certificate,
        delegation_key: Ed25519PublicKey,
    ) -> None:
        self.relationship = relationship
        self.key_registry = key_registry
        self.bundle = bundle
        self.delegation_key = delegation_key
        self.evidence: list[dict[str, Any]] = []

    def authorize(self, context: FederationContext, *, now: int = NOW) -> Decision:
        relationship = self.relationship
        if relationship.status != "active":
            return self._record(False, "federation_disabled", None, "", context)
        trust = verify_trust_chain(
            context.chain, self.key_registry, relationship, now=now
        )
        if not trust.valid:
            return self._record(
                False, trust.reason_codes[0], None, trust.chain_digest, context
            )
        selected_as, metadata_reason = select_authorization_server(
            context.protected_resource_metadata,
            expected_resource=RESOURCE,
            approved_servers=relationship.allowed_authorization_servers,
        )
        if selected_as is None:
            return self._record(
                False, metadata_reason, None, trust.chain_digest, context
            )
        if context.oauth_transaction.expected_issuer != selected_as:
            return self._record(
                False,
                "oauth_transaction_issuer_mismatch",
                None,
                trust.chain_digest,
                context,
            )
        if context.oauth_response_issuer != context.oauth_transaction.expected_issuer:
            return self._record(
                False, "oauth_issuer_mixup", None, trust.chain_digest, context
            )
        if digest(context.oauth_response_state) != context.oauth_transaction.state_hash:
            return self._record(
                False, "oauth_state_mismatch", None, trust.chain_digest, context
            )
        if context.oauth_transaction.consumed:
            return self._record(
                False, "oauth_response_replayed", None, trust.chain_digest, context
            )
        if now - context.metadata_fetched_at > relationship.metadata_max_age_seconds:
            return self._record(
                False, "federation_metadata_stale", None, trust.chain_digest, context
            )
        token = verify_access_token(
            context.access_token,
            self.key_registry,
            relationship,
            trust,
            expected_audience=context.request.audience,
            expected_proof_jkt=context.request.proof_jkt,
            now=now,
        )
        if not token.valid or token.principal is None:
            return self._record(
                False, token.reason_codes[0], None, trust.chain_digest, context
            )
        workload = verify_x509_svid(
            context.workload_certificate,
            self.bundle,
            relationship,
            expected_spiffe_id=context.request.workload_id,
            now=now,
        )
        if not workload.valid:
            return self._record(
                False,
                workload.reason_code,
                token.principal,
                trust.chain_digest,
                context,
            )
        delegated, delegation_reason = verify_delegation(
            context.delegation,
            self.delegation_key,
            token,
            relationship,
            now=now,
        )
        if not delegated:
            return self._record(
                False,
                delegation_reason,
                token.principal,
                trust.chain_digest,
                context,
            )
        request = context.request
        grant = context.delegation.grant
        policy = context.current_policy
        checks = {
            "request_issuer_mismatch": request.issuer != token.principal.issuer,
            "request_subject_mismatch": request.subject != token.principal.subject,
            "request_workload_mismatch": request.workload_id != workload.spiffe_id,
            "request_tenant_mismatch": request.tenant_id != grant.tenant_id,
            "request_task_mismatch": request.task_id != grant.task_id,
            "request_audience_mismatch": request.audience != grant.audience,
            "request_action_not_delegated": request.action not in grant.actions,
            "request_resource_not_delegated": request.resource not in grant.resources,
            "request_purpose_mismatch": request.purpose != grant.purpose,
            "policy_version_mismatch": policy.version != relationship.policy_version,
            "partner_not_current": not policy.partner_active,
            "relationship_not_current": not policy.relationship_active,
            "task_not_current": not policy.task_active,
            "risk_too_high": not 0 <= policy.risk_score < 50,
        }
        for reason, failed in checks.items():
            if failed:
                return self._record(
                    False,
                    reason,
                    token.principal,
                    trust.chain_digest,
                    context,
                )
        return self._record(
            True, "authorized", token.principal, trust.chain_digest, context
        )

    def _record(
        self,
        allowed: bool,
        reason: str,
        principal: FederatedPrincipal | None,
        chain_digest: str,
        context: FederationContext,
    ) -> Decision:
        decision = Decision(
            allowed,
            reason,
            principal.local_principal_id if principal else None,
            chain_digest,
        )
        self.evidence.append(
            {
                "trace_id": context.request.trace_id,
                "operation_id": context.request.operation_id,
                "allowed": allowed,
                "reason_code": reason,
                "foreign_issuer": context.request.issuer,
                "foreign_subject_hash": digest(context.request.subject),
                "workload_id": context.request.workload_id,
                "audience": context.request.audience,
                "resource": context.request.resource,
                "chain_digest": chain_digest,
                "policy_version": self.relationship.policy_version,
            }
        )
        return decision


def signature_only_baseline(context: FederationContext, keys: KeyRegistry) -> bool:
    """Deliberately unsafe baseline: verify only the access-token signature."""

    claims, error = _verified_jwt(context.access_token, keys, expected_type="at+jwt")
    return error is None and claims is not None


def relationship(
    bundle_fingerprint: str | None = None, course_dir: Path | None = None
) -> FederationRelationship:
    root = course_dir or Path(__file__).parent
    registry = json.loads((root / "data/trust_registry.json").read_text())
    record = registry[PARTNER_DOMAIN]
    return FederationRelationship(
        PARTNER_DOMAIN,
        record["status"],
        frozenset({record["oidc_issuer"]}),
        record["accepted_trust_anchor"],
        frozenset(record["accepted_audiences"]),
        frozenset(record["allowed_agent_types"]),
        frozenset(record["allowed_actions"]),
        frozenset(record["allowed_resources"]),
        frozenset(record["allowed_spiffe_ids"]),
        bundle_fingerprint or record["spiffe_bundle_sha256"],
        frozenset(record["allowed_authorization_servers"]),
        record["max_token_ttl_seconds"],
        record["max_delegation_depth"],
        record["max_chain_length"],
        record["metadata_max_age_seconds"],
        record["require_sender_constraint"],
        record["policy_version"],
    )


def protected_resource_metadata(course_dir: Path | None = None) -> Mapping[str, Any]:
    root = course_dir or Path(__file__).parent
    return json.loads(
        (root / "configs/mcp/protected-resource-metadata.json").read_text()
    )


def scenario() -> dict[str, Any]:
    anchor_key = deterministic_private_key(ANCHOR)
    intermediate_key = deterministic_private_key(INTERMEDIATE)
    issuer_key = deterministic_private_key(PARTNER_ISSUER)
    vendor_key = deterministic_private_key(VENDOR_ISSUER)
    proof_key = deterministic_private_key("dpop:partner-research")
    delegation_key = deterministic_private_key("authority:corp")
    key_registry = {
        ANCHOR: {"anchor-2026": anchor_key.public_key()},
        INTERMEDIATE: {"intermediate-2026": intermediate_key.public_key()},
        PARTNER_ISSUER: {"issuer-2026": issuer_key.public_key()},
        VENDOR_ISSUER: {"vendor-2026": vendor_key.public_key()},
    }
    metadata = {
        "issuer": PARTNER_ISSUER,
        "authorization_endpoint": f"{PARTNER_ISSUER}/authorize",
        "token_endpoint": f"{PARTNER_ISSUER}/token",
        "grant_types_supported": ["authorization_code"],
        "token_endpoint_auth_methods_supported": ["private_key_jwt"],
        "id_token_signing_alg_values_supported": ["EdDSA"],
    }
    anchor_policy = {
        "oauth_authorization_server": {
            "grant_types_supported": {
                "essential": True,
                "subset_of": ["authorization_code"],
            },
            "token_endpoint_auth_methods_supported": {
                "essential": True,
                "subset_of": ["private_key_jwt", "tls_client_auth"],
            },
            "id_token_signing_alg_values_supported": {
                "essential": True,
                "subset_of": ["EdDSA", "ES256"],
            },
        }
    }
    intermediate_policy = {
        "oauth_authorization_server": {
            "token_endpoint_auth_methods_supported": {"subset_of": ["private_key_jwt"]}
        }
    }
    chain = (
        sign_entity_statement(
            issuer_key,
            kid="issuer-2026",
            issuer=PARTNER_ISSUER,
            subject=PARTNER_ISSUER,
            authority_hints=(INTERMEDIATE,),
            metadata={"oauth_authorization_server": metadata},
        ),
        sign_entity_statement(
            intermediate_key,
            kid="intermediate-2026",
            issuer=INTERMEDIATE,
            subject=PARTNER_ISSUER,
            authority_hints=(ANCHOR,),
            metadata_policy=intermediate_policy,
            constraints={"max_path_length": 1},
        ),
        sign_entity_statement(
            anchor_key,
            kid="anchor-2026",
            issuer=ANCHOR,
            subject=INTERMEDIATE,
            metadata_policy=anchor_policy,
            constraints={"max_path_length": 2},
        ),
    )
    proof_jwk = public_jwk(proof_key.public_key(), "proof-2026")
    proof_jkt = jwk_thumbprint(proof_jwk)
    access_token = sign_access_token(
        issuer_key,
        kid="issuer-2026",
        confirmation_jkt=proof_jkt,
    )
    ca_key, ca_cert = create_ca("partner-2026", PARTNER_DOMAIN)
    workload_cert = issue_x509_svid(ca_key, ca_cert, SPIFFE_ID)
    grant = DelegationGrant(
        "delegation:claim-483",
        "authority:corp",
        PARTNER_ISSUER,
        AGENT_SUBJECT,
        TENANT,
        TASK,
        RESOURCE,
        frozenset({"knowledge.search"}),
        frozenset({CLAIM}),
        "fraud-research",
        NOW - 20,
        NOW + 180,
        1,
        POLICY_VERSION,
    )
    signed_grant = sign_delegation(grant, delegation_key)
    request = AccessRequest(
        "trace:federation:483",
        "operation:search:483",
        PARTNER_ISSUER,
        AGENT_SUBJECT,
        SPIFFE_ID,
        TENANT,
        TASK,
        RESOURCE,
        "knowledge.search",
        CLAIM,
        "fraud-research",
        proof_jkt,
    )
    oauth_state = "synthetic-oauth-state-483"
    oauth_transaction = OAuthTransaction(PARTNER_AS, digest(oauth_state))
    context = FederationContext(
        chain,
        access_token,
        workload_cert,
        signed_grant,
        request,
        CurrentPolicy(POLICY_VERSION, True, True, True, 20),
        protected_resource_metadata(),
        NOW - 10,
        oauth_transaction,
        PARTNER_AS,
        oauth_state,
    )
    return {
        "relationship": relationship(certificate_fingerprint(ca_cert)),
        "keys": key_registry,
        "private_keys": {
            ANCHOR: anchor_key,
            INTERMEDIATE: intermediate_key,
            PARTNER_ISSUER: issuer_key,
            VENDOR_ISSUER: vendor_key,
            "delegation": delegation_key,
            "proof": proof_key,
            "ca": ca_key,
        },
        "bundle": ca_cert,
        "delegation_key": delegation_key.public_key(),
        "context": context,
        "metadata": metadata,
        "policies": {
            "anchor": anchor_policy,
            "intermediate": intermediate_policy,
        },
    }


@dataclass(frozen=True)
class Case:
    case_id: str
    category: str
    expected_allowed: bool
    run: Callable[[], bool]
    baseline_run: Callable[[], bool]


def build_cases() -> list[Case]:
    def gateway_case(
        case_id: str,
        category: str,
        expected: bool = False,
        *,
        mutate_context: Callable[[FederationContext, dict[str, Any]], FederationContext]
        | None = None,
        mutate_relationship: Callable[[FederationRelationship], FederationRelationship]
        | None = None,
        mutate_bundle: Callable[[x509.Certificate, dict[str, Any]], x509.Certificate]
        | None = None,
    ) -> Case:
        def run() -> bool:
            value = scenario()
            context = value["context"]
            relation = value["relationship"]
            bundle = value["bundle"]
            if mutate_context:
                context = mutate_context(context, value)
            if mutate_relationship:
                relation = mutate_relationship(relation)
            if mutate_bundle:
                bundle = mutate_bundle(bundle, value)
            gateway = FederationGateway(
                relation,
                value["keys"],
                bundle,
                value["delegation_key"],
            )
            return gateway.authorize(context).allowed

        def baseline_run() -> bool:
            value = scenario()
            context = value["context"]
            if mutate_context:
                context = mutate_context(context, value)
            return signature_only_baseline(context, value["keys"])

        return Case(case_id, category, expected, run, baseline_run)

    def request(**changes: Any):
        return lambda context, _: replace(
            context, request=replace(context.request, **changes)
        )

    def policy(**changes: Any):
        return lambda context, _: replace(
            context, current_policy=replace(context.current_policy, **changes)
        )

    def token(**changes: Any):
        def mutate(
            context: FederationContext, value: dict[str, Any]
        ) -> FederationContext:
            args = {
                "kid": "issuer-2026",
                "confirmation_jkt": context.request.proof_jkt,
            }
            args.update(changes)
            signed = sign_access_token(
                value["private_keys"][args.pop("issuer", PARTNER_ISSUER)],
                issuer=changes.get("issuer", PARTNER_ISSUER),
                **args,
            )
            return replace(context, access_token=signed)

        return mutate

    def grant(**changes: Any):
        def mutate(
            context: FederationContext, value: dict[str, Any]
        ) -> FederationContext:
            changed = replace(context.delegation.grant, **changes)
            return replace(
                context,
                delegation=sign_delegation(
                    changed, value["private_keys"]["delegation"]
                ),
            )

        return mutate

    def chain_statement(index: int, **changes: Any):
        def mutate(
            context: FederationContext, value: dict[str, Any]
        ) -> FederationContext:
            chain = list(context.chain)
            claims = jwt.decode(chain[index], options={"verify_signature": False})
            claims.update(changes)
            issuer = claims["iss"]
            kid = {
                PARTNER_ISSUER: "issuer-2026",
                INTERMEDIATE: "intermediate-2026",
                ANCHOR: "anchor-2026",
            }[issuer]
            chain[index] = jwt.encode(
                claims,
                value["private_keys"][issuer],
                algorithm="EdDSA",
                headers={"typ": "entity-statement+jwt", "kid": kid},
            )
            return replace(context, chain=tuple(chain))

        return mutate

    return [
        gateway_case("valid_partner_agent", "valid", True),
        gateway_case(
            "tampered_entity_statement",
            "trust-chain",
            mutate_context=lambda c, _: replace(
                c, chain=(c.chain[0], tamper_jwt(c.chain[1], "sub", "evil"), c.chain[2])
            ),
        ),
        gateway_case(
            "unaccepted_anchor",
            "trust-chain",
            mutate_relationship=lambda r: replace(r, accepted_anchor="https://evil"),
        ),
        gateway_case(
            "broken_chain_link",
            "trust-chain",
            mutate_context=chain_statement(2, sub="https://other-intermediate"),
        ),
        gateway_case(
            "expired_entity_statement",
            "trust-chain",
            mutate_context=chain_statement(1, exp=NOW),
        ),
        gateway_case(
            "authority_hint_missing",
            "trust-chain",
            mutate_context=chain_statement(0, authority_hints=[]),
        ),
        gateway_case(
            "duplicate_statement_id",
            "trust-chain",
            mutate_context=lambda c, _: chain_statement(
                1,
                jti=jwt.decode(c.chain[0], options={"verify_signature": False})["jti"],
            )(c, _),
        ),
        gateway_case(
            "metadata_algorithm_downgrade",
            "metadata-policy",
            mutate_context=chain_statement(
                0,
                metadata={
                    "oauth_authorization_server": {
                        "issuer": PARTNER_ISSUER,
                        "grant_types_supported": ["authorization_code"],
                        "token_endpoint_auth_methods_supported": [
                            "client_secret_basic"
                        ],
                        "id_token_signing_alg_values_supported": ["RS256"],
                    }
                },
            ),
        ),
        gateway_case(
            "token_signature_tampered",
            "token",
            mutate_context=lambda c, _: replace(
                c, access_token=tamper_jwt(c.access_token, "sub", "agent:evil")
            ),
        ),
        gateway_case(
            "unapproved_issuer",
            "token",
            mutate_context=token(issuer=VENDOR_ISSUER),
        ),
        gateway_case(
            "wrong_audience", "token", mutate_context=token(audience="https://evil")
        ),
        gateway_case("expired_token", "token", mutate_context=token(expires_at=NOW)),
        gateway_case(
            "excessive_token_ttl",
            "token",
            mutate_context=token(issued_at=NOW - 10, expires_at=NOW + 700),
        ),
        gateway_case(
            "foreign_action_escalation",
            "token",
            mutate_context=token(actions=("knowledge.search", "claim.delete")),
        ),
        gateway_case(
            "foreign_resource_escalation",
            "token",
            mutate_context=token(resources=(CLAIM, "claim:999")),
        ),
        gateway_case(
            "unapproved_agent_type",
            "token",
            mutate_context=token(agent_type="administrator"),
        ),
        gateway_case(
            "token_cross_tenant",
            "token",
            mutate_context=token(tenant_id="tenant:contoso"),
        ),
        gateway_case(
            "token_wrong_task",
            "token",
            mutate_context=token(task_id="task:999"),
        ),
        gateway_case(
            "sender_key_substitution",
            "token",
            mutate_context=token(confirmation_jkt="wrong-thumbprint"),
        ),
        gateway_case(
            "workload_bundle_substitution",
            "workload",
            mutate_bundle=lambda _, __: create_ca("evil", PARTNER_DOMAIN)[1],
        ),
        gateway_case(
            "workload_identity_substitution",
            "workload",
            mutate_context=request(workload_id="spiffe://partner.example/prod/admin"),
        ),
        gateway_case(
            "expired_workload_svid",
            "workload",
            mutate_context=lambda c, v: replace(
                c,
                workload_certificate=issue_x509_svid(
                    v["private_keys"]["ca"],
                    v["bundle"],
                    SPIFFE_ID,
                    label="expired",
                    issued_at=NOW - 300,
                    expires_at=NOW,
                ),
            ),
        ),
        gateway_case(
            "workload_trust_domain_substitution",
            "workload",
            mutate_context=lambda c, v: replace(
                c,
                workload_certificate=issue_x509_svid(
                    v["private_keys"]["ca"],
                    v["bundle"],
                    "spiffe://vendor.example/prod/research-agent",
                    label="wrong-domain",
                ),
            ),
        ),
        gateway_case(
            "federation_disabled",
            "lifecycle",
            mutate_relationship=lambda r: replace(r, status="disabled"),
        ),
        gateway_case(
            "delegation_signature_tampered",
            "delegation",
            mutate_context=lambda c, _: replace(
                c,
                delegation=replace(
                    c.delegation,
                    grant=replace(c.delegation.grant, purpose="marketing"),
                ),
            ),
        ),
        gateway_case(
            "delegation_expired",
            "delegation",
            mutate_context=grant(expires_at=NOW),
        ),
        gateway_case(
            "delegation_action_widened",
            "delegation",
            mutate_context=grant(
                actions=frozenset({"knowledge.search", "claim.delete"})
            ),
        ),
        gateway_case(
            "delegation_depth_exceeded",
            "delegation",
            mutate_context=grant(depth=2),
        ),
        gateway_case(
            "cross_tenant_request",
            "local-policy",
            mutate_context=request(tenant_id="tenant:contoso"),
        ),
        gateway_case(
            "request_issuer_substitution",
            "local-policy",
            mutate_context=request(issuer="https://evil"),
        ),
        gateway_case(
            "request_subject_substitution",
            "local-policy",
            mutate_context=request(subject="agent:evil"),
        ),
        gateway_case(
            "wrong_task_request",
            "local-policy",
            mutate_context=request(task_id="task:999"),
        ),
        gateway_case(
            "action_escalation_request",
            "local-policy",
            mutate_context=request(action="claim.delete"),
        ),
        gateway_case(
            "resource_escalation_request",
            "local-policy",
            mutate_context=request(resource="claim:999"),
        ),
        gateway_case(
            "purpose_substitution_request",
            "local-policy",
            mutate_context=request(purpose="marketing"),
        ),
        gateway_case(
            "protected_resource_substitution",
            "mcp-oauth",
            mutate_context=lambda c, _: replace(
                c,
                protected_resource_metadata={
                    "resource": "https://evil",
                    "authorization_servers": [PARTNER_AS],
                },
            ),
        ),
        gateway_case(
            "unapproved_authorization_server",
            "mcp-oauth",
            mutate_context=lambda c, _: replace(
                c,
                protected_resource_metadata={
                    "resource": RESOURCE,
                    "authorization_servers": ["https://evil"],
                },
            ),
        ),
        gateway_case(
            "oauth_issuer_mixup",
            "mcp-oauth",
            mutate_context=lambda c, _: replace(
                c, oauth_response_issuer="https://evil"
            ),
        ),
        gateway_case(
            "oauth_state_mismatch",
            "mcp-oauth",
            mutate_context=lambda c, _: replace(c, oauth_response_state="wrong"),
        ),
        gateway_case(
            "oauth_response_replayed",
            "mcp-oauth",
            mutate_context=lambda c, _: replace(
                c, oauth_transaction=replace(c.oauth_transaction, consumed=True)
            ),
        ),
        gateway_case(
            "stale_federation_metadata",
            "lifecycle",
            mutate_context=lambda c, _: replace(c, metadata_fetched_at=NOW - 301),
        ),
        gateway_case(
            "partner_offboarded",
            "lifecycle",
            mutate_context=policy(partner_active=False),
        ),
        gateway_case(
            "relationship_revoked",
            "lifecycle",
            mutate_context=policy(relationship_active=False),
        ),
        gateway_case(
            "task_deactivated",
            "lifecycle",
            mutate_context=policy(task_active=False),
        ),
        gateway_case(
            "high_runtime_risk",
            "local-policy",
            mutate_context=policy(risk_score=50),
        ),
        gateway_case(
            "stale_local_policy",
            "local-policy",
            mutate_context=policy(version="federation-policy-next"),
        ),
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
    rows: list[dict[str, Any]] = []
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


def evaluate_baseline(cases: Iterable[Case]) -> tuple[Metrics, list[dict[str, Any]]]:
    rows: list[dict[str, Any]] = []
    for case in cases:
        actual = case.baseline_run()
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
    return (
        Metrics(
            total,
            sum(row["expected"] for row in rows),
            sum(not row["expected"] for row in rows),
            matches,
            sum(row["actual"] and not row["expected"] for row in rows),
            sum(not row["actual"] and row["expected"] for row in rows),
            matches / total if total else 0.0,
        ),
        rows,
    )


def release_gate(metrics: Metrics) -> bool:
    return (
        metrics.total >= 30
        and metrics.invalid_allows == 0
        and metrics.valid_blocked == 0
        and metrics.accuracy == 1.0
    )


if __name__ == "__main__":
    result, rows = evaluate_cases(build_cases())
    baseline, _ = evaluate_baseline(build_cases())
    print(
        json.dumps(
            {
                "metrics": asdict(result),
                "signature_only_baseline": asdict(baseline),
                "release_gate": release_gate(result),
                "mismatches": [row for row in rows if not row["match"]],
            },
            indent=2,
        )
    )
