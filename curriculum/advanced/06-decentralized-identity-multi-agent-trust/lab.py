"""Offline decentralized identity and multi-agent trust lab.

The implementation deliberately separates DID control from organizational trust
and authorization.  It uses Ed25519 signatures, standards-shaped DID documents,
safe fixture resolution, a signed registration credential, attenuated capability
chains, local trust policy, and a labelled adversarial corpus.  It is a teaching
profile, not a claim of DID, VC, or authorization-protocol conformance.
"""

from __future__ import annotations

import base64
import copy
import ipaddress
import json
import re
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass, field
from hashlib import sha256
from threading import RLock
from typing import Any
from urllib.parse import unquote, urlsplit

import jwt
import networkx as nx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

NOW = 1_800_000_000
AUDIENCE = "https://verifier.northstar.example/agent-access"
DOMAIN = "verifier.northstar.example"
TENANT = "tenant:northstar"
PURPOSE = "claim-review"
RESOURCE = "claim:483"
ACTION = "claim.read"

OWNER = "did:web:agents.northstar.example:claims"
PARTNER = "did:web:agents.partner.example:research"
WORKER = "did:web:agents.partner.example:investigator"
PARTNER_ORG = "did:web:partner.example"
GOVERNANCE = "did:web:governance.northstar.example"
VERIFIER = "did:web:verifier.northstar.example"

ALLOWED_HOSTS = frozenset(
    {
        "agents.northstar.example",
        "agents.partner.example",
        "partner.example",
        "governance.northstar.example",
        "verifier.northstar.example",
    }
)
ALLOWED_METHODS = frozenset({"web", "key"})
BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
DID_PATTERN = re.compile(r"^did:([a-z0-9]+):([^?#]+)$")
PERCENT_PATTERN = re.compile(r"%(?![0-9A-Fa-f]{2})")


class TrustError(ValueError):
    """Fail-closed validation result safe to expose in this lab."""


def canonical(value: Any) -> str:
    if hasattr(value, "__dataclass_fields__"):
        value = asdict(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def digest(value: Any) -> str:
    return sha256(canonical(value).encode()).hexdigest()


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b58encode(data: bytes) -> str:
    number = int.from_bytes(data, "big")
    encoded = ""
    while number:
        number, remainder = divmod(number, 58)
        encoded = BASE58[remainder] + encoded
    zeros = len(data) - len(data.lstrip(b"\x00"))
    return "1" * zeros + (encoded or ("1" if not zeros else ""))


def b58decode(value: str) -> bytes:
    if not value or any(character not in BASE58 for character in value):
        raise TrustError("multibase_invalid")
    number = 0
    for character in value:
        number = number * 58 + BASE58.index(character)
    raw = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    return b"\x00" * (len(value) - len(value.lstrip("1"))) + raw


def deterministic_key(label: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(sha256(label.encode()).digest())


def public_bytes(key: Ed25519PrivateKey | Ed25519PublicKey) -> bytes:
    public = key.public_key() if isinstance(key, Ed25519PrivateKey) else key
    return public.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def public_jwk(key: Ed25519PrivateKey | Ed25519PublicKey) -> dict[str, str]:
    return {"kty": "OKP", "crv": "Ed25519", "x": b64url(public_bytes(key))}


def parse_did(
    value: str, allowed_methods: frozenset[str] = ALLOWED_METHODS
) -> tuple[str, str]:
    if not isinstance(value, str) or not (match := DID_PATTERN.fullmatch(value)):
        raise TrustError("did_invalid")
    method, identifier = match.groups()
    if method not in allowed_methods:
        raise TrustError("did_method_not_allowed")
    if PERCENT_PATTERN.search(identifier) or any(ord(char) < 33 for char in identifier):
        raise TrustError("did_invalid")
    return method, identifier


def did_key_from_public(key: Ed25519PrivateKey | Ed25519PublicKey) -> str:
    # 0xed01 is the unsigned-varint multicodec prefix for ed25519-pub.
    fingerprint = "z" + b58encode(b"\xed\x01" + public_bytes(key))
    return f"did:key:{fingerprint}"


def did_key_document(did: str) -> dict[str, Any]:
    method, identifier = parse_did(did)
    if method != "key" or not identifier.startswith("z"):
        raise TrustError("did_key_invalid")
    decoded = b58decode(identifier[1:])
    if len(decoded) != 34 or decoded[:2] != b"\xed\x01":
        raise TrustError("did_key_codec_unsupported")
    key_id = f"{did}#{identifier}"
    verification = {
        "id": key_id,
        "type": "Multikey",
        "controller": did,
        "publicKeyMultibase": identifier,
    }
    return {
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": did,
        "verificationMethod": [verification],
        "authentication": [key_id],
        "assertionMethod": [key_id],
        "capabilityInvocation": [key_id],
    }


def did_web_url(did: str, allowed_hosts: frozenset[str] = ALLOWED_HOSTS) -> str:
    method, identifier = parse_did(did)
    if method != "web":
        raise TrustError("did_web_required")
    pieces = identifier.split(":")
    host = unquote(pieces[0]).lower()
    if not host or "@" in host or ":" in host or host.endswith("."):
        raise TrustError("did_web_host_invalid")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise TrustError("did_web_ip_forbidden")
    if host == "localhost" or host.endswith(".localhost") or host not in allowed_hosts:
        raise TrustError("did_web_host_not_allowed")
    path: list[str] = []
    for raw_piece in pieces[1:]:
        piece = unquote(raw_piece)
        if not piece or piece in {".", ".."} or "/" in piece or "\\" in piece:
            raise TrustError("did_web_path_invalid")
        path.append(piece)
    suffix = "/.well-known/did.json" if not path else f"/{'/'.join(path)}/did.json"
    url = f"https://{host}{suffix}"
    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or parsed.username
        or parsed.password
        or parsed.fragment
        or parsed.query
    ):
        raise TrustError("did_web_url_invalid")
    return url


def service_endpoint_safe(
    endpoint: Any, allowed_hosts: frozenset[str] = ALLOWED_HOSTS
) -> bool:
    if not isinstance(endpoint, str):
        return False
    parsed = urlsplit(endpoint)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
    ):
        return False
    host = parsed.hostname.lower()
    if host not in allowed_hosts or host == "localhost" or host.endswith(".localhost"):
        return False
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return True
    return False


def key_from_method(method: Mapping[str, Any]) -> Ed25519PublicKey:
    if "publicKeyJwk" in method:
        jwk = method["publicKeyJwk"]
        if not isinstance(jwk, dict) or set(jwk) - {
            "kty",
            "crv",
            "x",
            "kid",
            "alg",
            "use",
        }:
            raise TrustError("jwk_invalid")
        if "d" in jwk or jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
            raise TrustError("jwk_invalid")
        try:
            raw = base64.urlsafe_b64decode(jwk["x"] + "==")
        except (KeyError, TypeError, ValueError) as exc:
            raise TrustError("jwk_invalid") from exc
    elif "publicKeyMultibase" in method:
        value = method["publicKeyMultibase"]
        if not isinstance(value, str) or not value.startswith("z"):
            raise TrustError("multikey_invalid")
        raw_with_codec = b58decode(value[1:])
        if raw_with_codec[:2] != b"\xed\x01":
            raise TrustError("multikey_codec_unsupported")
        raw = raw_with_codec[2:]
    else:
        raise TrustError("verification_material_missing")
    if len(raw) != 32:
        raise TrustError("ed25519_key_invalid")
    return Ed25519PublicKey.from_public_bytes(raw)


def validate_did_document(
    requested_did: str,
    document: Mapping[str, Any],
    metadata: Mapping[str, Any],
) -> dict[str, Mapping[str, Any]]:
    if metadata.get("deactivated") is True:
        raise TrustError("did_deactivated")
    if document.get("id") != requested_did:
        raise TrustError("did_document_substitution")
    methods = document.get("verificationMethod")
    if not isinstance(methods, list) or not methods:
        raise TrustError("verification_methods_missing")
    indexed: dict[str, Mapping[str, Any]] = {}
    for method in methods:
        if not isinstance(method, dict):
            raise TrustError("verification_method_invalid")
        key_id = method.get("id")
        if (
            not isinstance(key_id, str)
            or not key_id.startswith(requested_did + "#")
            or method.get("controller") != requested_did
            or method.get("type") not in {"JsonWebKey2020", "Multikey"}
            or key_id in indexed
        ):
            raise TrustError("verification_method_invalid")
        key_from_method(method)
        indexed[key_id] = method
    for relationship in ("authentication", "assertionMethod", "capabilityInvocation"):
        references = document.get(relationship, [])
        if not isinstance(references, list):
            raise TrustError("verification_relationship_invalid")
        for reference in references:
            reference_id = (
                reference.get("id") if isinstance(reference, dict) else reference
            )
            if reference_id not in indexed:
                raise TrustError("verification_relationship_invalid")
    services = document.get("service", [])
    if not isinstance(services, list):
        raise TrustError("service_invalid")
    for service in services:
        if not isinstance(service, dict) or not service_endpoint_safe(
            service.get("serviceEndpoint")
        ):
            raise TrustError("service_endpoint_unsafe")
    return indexed


@dataclass(frozen=True)
class ResolutionResult:
    document: dict[str, Any]
    document_metadata: dict[str, Any]
    resolution_metadata: dict[str, Any]


@dataclass
class FixtureResolver:
    documents: dict[str, dict[str, Any]]
    metadata: dict[str, dict[str, Any]]
    allowed_hosts: frozenset[str] = ALLOWED_HOSTS
    cache_ttl: int = 120
    cache: dict[str, tuple[int, ResolutionResult]] = field(default_factory=dict)

    def resolve(
        self, did: str, *, now: int = NOW, refresh: bool = False
    ) -> ResolutionResult:
        method, _ = parse_did(did)
        if not refresh and did in self.cache and self.cache[did][0] > now:
            return copy.deepcopy(self.cache[did][1])
        if method == "key":
            document = did_key_document(did)
            document_metadata = {"versionId": digest(document)[:16]}
            source = "local:did-key"
        else:
            source = did_web_url(did, self.allowed_hosts)
            if did not in self.documents:
                raise TrustError("did_not_found")
            document = copy.deepcopy(self.documents[did])
            document_metadata = copy.deepcopy(self.metadata.get(did, {}))
        indexed = validate_did_document(did, document, document_metadata)
        del indexed
        result = ResolutionResult(
            document=document,
            document_metadata=document_metadata,
            resolution_metadata={
                "contentType": "application/did+json",
                "source": source,
            },
        )
        self.cache[did] = (now + self.cache_ttl, copy.deepcopy(result))
        return result

    def invalidate(self, did: str) -> None:
        self.cache.pop(did, None)


def resolve_quorum(
    primary: FixtureResolver, secondary: FixtureResolver, did: str, now: int
) -> ResolutionResult:
    first = primary.resolve(did, now=now)
    second = secondary.resolve(did, now=now)
    first_version = first.document_metadata.get("versionId")
    second_version = second.document_metadata.get("versionId")
    if (
        digest(first.document) != digest(second.document)
        or first_version != second_version
    ):
        raise TrustError("resolver_disagreement")
    return first


def did_document(
    did: str, key: Ed25519PrivateKey, *, version: str = "1"
) -> dict[str, Any]:
    key_id = f"{did}#controller-{version}"
    return {
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": did,
        "verificationMethod": [
            {
                "id": key_id,
                "type": "JsonWebKey2020",
                "controller": did,
                "publicKeyJwk": public_jwk(key),
            }
        ],
        "authentication": [key_id],
        "assertionMethod": [key_id],
        "capabilityInvocation": [key_id],
        "service": [
            {
                "id": f"{did}#agent-card",
                "type": "AgentCard",
                "serviceEndpoint": f"https://{did.split(':')[2]}/agents/card.json",
            }
        ],
    }


def relationship_key(
    result: ResolutionResult,
    kid: str,
    relationship: str,
) -> Ed25519PublicKey:
    indexed = validate_did_document(
        result.document["id"], result.document, result.document_metadata
    )
    references = result.document.get(relationship, [])
    ids = {item.get("id") if isinstance(item, dict) else item for item in references}
    if kid not in ids or kid not in indexed:
        raise TrustError("key_relationship_invalid")
    return key_from_method(indexed[kid])


def encode_envelope(
    payload: Mapping[str, Any],
    key: Ed25519PrivateKey,
    kid: str,
    typ: str,
) -> str:
    return jwt.encode(
        dict(payload), key, algorithm="EdDSA", headers={"kid": kid, "typ": typ}
    )


def unverified(token: str) -> tuple[dict[str, Any], dict[str, Any]]:
    try:
        return jwt.get_unverified_header(token), jwt.decode(
            token, options={"verify_signature": False}
        )
    except jwt.PyJWTError as exc:
        raise TrustError("token_malformed") from exc


def verify_envelope(
    token: str,
    *,
    expected_issuer: str,
    expected_audience: str,
    expected_typ: str,
    relationship: str,
    resolver: FixtureResolver,
    secondary_resolver: FixtureResolver | None,
    high_assurance: bool,
    now: int,
) -> dict[str, Any]:
    header, claims = unverified(token)
    if (
        set(header) - {"alg", "kid", "typ"}
        or header.get("alg") != "EdDSA"
        or header.get("typ") != expected_typ
    ):
        raise TrustError("token_profile_invalid")
    kid = header.get("kid")
    if not isinstance(kid, str) or claims.get("iss") != expected_issuer:
        raise TrustError("token_issuer_or_key_invalid")
    result = (
        resolve_quorum(resolver, secondary_resolver, expected_issuer, now)
        if high_assurance and secondary_resolver is not None
        else resolver.resolve(expected_issuer, now=now)
    )
    key = relationship_key(result, kid, relationship)
    try:
        verified = jwt.decode(
            token,
            key,
            algorithms=["EdDSA"],
            options={
                "verify_aud": False,
                "verify_exp": False,
                "verify_iat": False,
                "verify_nbf": False,
            },
        )
    except jwt.PyJWTError as exc:
        raise TrustError("token_signature_invalid") from exc
    if verified.get("aud") != expected_audience:
        raise TrustError("token_audience_invalid")
    for field_name in ("iat", "nbf", "exp"):
        if not isinstance(verified.get(field_name), int):
            raise TrustError("token_time_invalid")
    if verified["iat"] > now + 30 or verified["nbf"] > now or verified["exp"] <= now:
        raise TrustError("token_time_invalid")
    if verified["exp"] - verified["iat"] > 3600:
        raise TrustError("token_lifetime_excessive")
    return verified


@dataclass
class ReplayStore:
    seen: set[str] = field(default_factory=set)
    lock: RLock = field(default_factory=RLock)

    def consume(self, value: str) -> None:
        if not isinstance(value, str) or not value:
            raise TrustError("jti_invalid")
        with self.lock:
            if value in self.seen:
                raise TrustError("replay_detected")
            self.seen.add(value)


def issue_did_auth(
    did: str,
    key: Ed25519PrivateKey,
    *,
    kid: str | None = None,
    audience: str = AUDIENCE,
    domain: str = DOMAIN,
    nonce: str = "nonce:course06",
    now: int = NOW,
    jti: str = "auth:course06",
    subject: str | None = None,
    signing_key: Ed25519PrivateKey | None = None,
) -> str:
    payload = {
        "iss": did,
        "sub": subject or did,
        "aud": audience,
        "domain": domain,
        "nonce": nonce,
        "iat": now,
        "nbf": now,
        "exp": now + 120,
        "jti": jti,
    }
    return encode_envelope(
        payload, signing_key or key, kid or f"{did}#controller-1", "did-auth+jwt"
    )


def verify_did_auth(
    token: str,
    *,
    did: str,
    audience: str,
    domain: str,
    nonce: str,
    resolver: FixtureResolver,
    secondary_resolver: FixtureResolver | None,
    high_assurance: bool,
    replay_store: ReplayStore,
    now: int,
) -> dict[str, Any]:
    claims = verify_envelope(
        token,
        expected_issuer=did,
        expected_audience=audience,
        expected_typ="did-auth+jwt",
        relationship="authentication",
        resolver=resolver,
        secondary_resolver=secondary_resolver,
        high_assurance=high_assurance,
        now=now,
    )
    if (
        claims.get("sub") != did
        or claims.get("domain") != domain
        or claims.get("nonce") != nonce
    ):
        raise TrustError("did_auth_binding_invalid")
    replay_store.consume(claims.get("jti"))
    return claims


def issue_registration(
    subject: str,
    key: Ed25519PrivateKey,
    *,
    issuer: str = GOVERNANCE,
    organization: str = PARTNER_ORG,
    agent_class: str = "claims-investigator",
    audience: str = AUDIENCE,
    now: int = NOW,
    jti: str = "registration:worker:1",
    status: str = "active",
    kid: str | None = None,
) -> str:
    payload = {
        "iss": issuer,
        "sub": subject,
        "aud": audience,
        "iat": now,
        "nbf": now,
        "exp": now + 900,
        "jti": jti,
        "vc": {
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential", "AgentRegistrationCredential"],
            "credentialSubject": {
                "id": subject,
                "organization": organization,
                "agentClass": agent_class,
                "status": status,
            },
        },
    }
    return encode_envelope(payload, key, kid or f"{issuer}#controller-1", "vc+jwt")


def verify_registration(token: str, scenario: Scenario) -> dict[str, Any]:
    claims = verify_envelope(
        token,
        expected_issuer=scenario.registry["registrationIssuer"],
        expected_audience=scenario.request.audience,
        expected_typ="vc+jwt",
        relationship="assertionMethod",
        resolver=scenario.resolver,
        secondary_resolver=scenario.secondary_resolver,
        high_assurance=scenario.high_assurance,
        now=scenario.now,
    )
    vc = claims.get("vc")
    expected_types = {"VerifiableCredential", "AgentRegistrationCredential"}
    if not isinstance(vc, dict) or set(vc.get("type", [])) != expected_types:
        raise TrustError("registration_type_invalid")
    subject = vc.get("credentialSubject")
    if not isinstance(subject, dict) or set(subject) != {
        "id",
        "organization",
        "agentClass",
        "status",
    }:
        raise TrustError("registration_claims_invalid")
    if (
        claims.get("sub") != scenario.request.agent
        or subject.get("id") != scenario.request.agent
    ):
        raise TrustError("registration_subject_invalid")
    if (
        subject.get("organization") not in scenario.registry["trustedOrganizations"]
        or subject.get("agentClass") not in scenario.registry["allowedAgentClasses"]
        or subject.get("status") != "active"
        or claims.get("jti") in scenario.registry["revokedCredentials"]
    ):
        raise TrustError("registration_not_trusted")
    return claims


def issue_capability(
    issuer: str,
    subject: str,
    key: Ed25519PrivateKey,
    *,
    actions: tuple[str, ...],
    resources: tuple[str, ...],
    parent: str | None,
    depth: int,
    audience: str = AUDIENCE,
    tenant: str = TENANT,
    purpose: str = PURPOSE,
    now: int = NOW,
    lifetime: int = 600,
    jti: str,
    kid: str | None = None,
) -> str:
    payload = {
        "iss": issuer,
        "sub": subject,
        "aud": audience,
        "iat": now,
        "nbf": now,
        "exp": now + lifetime,
        "jti": jti,
        "capability": {
            "actions": list(actions),
            "resources": list(resources),
            "tenant": tenant,
            "purpose": purpose,
            "parent": parent,
            "depth": depth,
        },
    }
    return encode_envelope(
        payload, key, kid or f"{issuer}#controller-1", "capability+jwt"
    )


def verify_capability_chain(
    tokens: list[str], scenario: Scenario
) -> list[dict[str, Any]]:
    if not tokens or len(tokens) > scenario.registry["maxDelegationDepth"]:
        raise TrustError("capability_depth_invalid")
    verified: list[dict[str, Any]] = []
    seen: set[str] = set()
    expected_issuer = scenario.registry["capabilityRoot"]
    previous: dict[str, Any] | None = None
    previous_token: str | None = None
    for index, token in enumerate(tokens):
        header, untrusted = unverified(token)
        del header
        issuer = untrusted.get("iss")
        if issuer != expected_issuer or issuer in seen:
            raise TrustError("capability_continuity_invalid")
        current = verify_envelope(
            token,
            expected_issuer=issuer,
            expected_audience=scenario.request.audience,
            expected_typ="capability+jwt",
            relationship="capabilityInvocation",
            resolver=scenario.resolver,
            secondary_resolver=scenario.secondary_resolver,
            high_assurance=scenario.high_assurance,
            now=scenario.now,
        )
        body = current.get("capability")
        if not isinstance(body, dict) or set(body) != {
            "actions",
            "resources",
            "tenant",
            "purpose",
            "parent",
            "depth",
        }:
            raise TrustError("capability_claims_invalid")
        if current.get("jti") in scenario.registry["revokedCapabilities"]:
            raise TrustError("capability_revoked")
        if (
            body.get("depth") != index
            or body.get("tenant") != scenario.request.tenant
            or body.get("purpose") != scenario.request.purpose
        ):
            raise TrustError("capability_context_invalid")
        if previous is None:
            if body.get("parent") is not None:
                raise TrustError("capability_parent_invalid")
        else:
            prior_body = previous["capability"]
            if body.get("parent") != digest(previous_token):
                raise TrustError("capability_parent_invalid")
            if previous.get("sub") != issuer:
                raise TrustError("capability_continuity_invalid")
            if not set(body["actions"]).issubset(prior_body["actions"]) or not set(
                body["resources"]
            ).issubset(prior_body["resources"]):
                raise TrustError("capability_amplification")
            if current["nbf"] < previous["nbf"] or current["exp"] > previous["exp"]:
                raise TrustError("capability_lifetime_amplification")
        seen.add(issuer)
        expected_issuer = current.get("sub")
        previous = current
        previous_token = token
        verified.append(current)
    final = verified[-1]
    body = final["capability"]
    if final.get("sub") != scenario.request.agent:
        raise TrustError("capability_subject_invalid")
    if (
        scenario.request.action not in body["actions"]
        or scenario.request.resource not in body["resources"]
    ):
        raise TrustError("request_not_delegated")
    return verified


@dataclass
class TrustRequest:
    agent: str = WORKER
    action: str = ACTION
    resource: str = RESOURCE
    tenant: str = TENANT
    purpose: str = PURPOSE
    audience: str = AUDIENCE
    domain: str = DOMAIN
    nonce: str = "nonce:course06"


@dataclass
class Scenario:
    request: TrustRequest
    proof: str
    registration: str
    capabilities: list[str]
    resolver: FixtureResolver
    secondary_resolver: FixtureResolver
    replay_store: ReplayStore
    registry: dict[str, Any]
    state: dict[str, Any]
    keys: dict[str, Ed25519PrivateKey]
    now: int = NOW
    high_assurance: bool = True


def build_scenario(case_id: str = "default") -> Scenario:
    keys = {
        did: deterministic_key(did)
        for did in (OWNER, PARTNER, WORKER, PARTNER_ORG, GOVERNANCE, VERIFIER)
    }
    documents = {did: did_document(did, key) for did, key in keys.items()}
    metadata = {did: {"versionId": "1", "updated": NOW - 60} for did in documents}
    resolver = FixtureResolver(copy.deepcopy(documents), copy.deepcopy(metadata))
    secondary = FixtureResolver(copy.deepcopy(documents), copy.deepcopy(metadata))
    request = TrustRequest(nonce=f"nonce:{case_id}")
    proof = issue_did_auth(
        WORKER, keys[WORKER], nonce=request.nonce, jti=f"auth:{case_id}"
    )
    registration = issue_registration(
        WORKER, keys[GOVERNANCE], jti=f"registration:{case_id}"
    )
    root = issue_capability(
        OWNER,
        PARTNER,
        keys[OWNER],
        actions=(ACTION, "claim.comment"),
        resources=(RESOURCE, "claim:484"),
        parent=None,
        depth=0,
        lifetime=600,
        jti=f"cap:root:{case_id}",
    )
    child = issue_capability(
        PARTNER,
        WORKER,
        keys[PARTNER],
        actions=(ACTION,),
        resources=(RESOURCE,),
        parent=digest(root),
        depth=1,
        lifetime=300,
        jti=f"cap:child:{case_id}",
    )
    registry = {
        "registrationIssuer": GOVERNANCE,
        "capabilityRoot": OWNER,
        "trustedOrganizations": [PARTNER_ORG],
        "allowedAgentClasses": ["claims-investigator"],
        "allowedDidMethods": ["web", "key"],
        "revokedCredentials": [],
        "revokedCapabilities": [],
        "maxDelegationDepth": 3,
    }
    state = {
        "organizations": {PARTNER_ORG: "active"},
        "agents": {WORKER: "active"},
        "relationships": {f"{PARTNER_ORG}|{WORKER}": "active"},
    }
    return Scenario(
        request,
        proof,
        registration,
        [root, child],
        resolver,
        secondary,
        ReplayStore(),
        registry,
        state,
        keys,
    )


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    evidence: dict[str, Any] = field(default_factory=dict)


def authorize(scenario: Scenario) -> Decision:
    try:
        method, _ = parse_did(
            scenario.request.agent, frozenset(scenario.registry["allowedDidMethods"])
        )
        verify_did_auth(
            scenario.proof,
            did=scenario.request.agent,
            audience=scenario.request.audience,
            domain=scenario.request.domain,
            nonce=scenario.request.nonce,
            resolver=scenario.resolver,
            secondary_resolver=scenario.secondary_resolver,
            high_assurance=scenario.high_assurance,
            replay_store=scenario.replay_store,
            now=scenario.now,
        )
        registration = verify_registration(scenario.registration, scenario)
        chain = verify_capability_chain(scenario.capabilities, scenario)
        subject = registration["vc"]["credentialSubject"]
        organization = subject["organization"]
        if scenario.state["organizations"].get(organization) != "active":
            raise TrustError("organization_inactive")
        if scenario.state["agents"].get(scenario.request.agent) != "active":
            raise TrustError("agent_inactive")
        if (
            scenario.state["relationships"].get(
                f"{organization}|{scenario.request.agent}"
            )
            != "active"
        ):
            raise TrustError("relationship_inactive")
        return Decision(
            True,
            "allow",
            {
                "did": scenario.request.agent,
                "didMethod": method,
                "organization": organization,
                "credential": registration["jti"],
                "capabilities": [item["jti"] for item in chain],
                "requestDigest": digest(scenario.request),
            },
        )
    except (TrustError, KeyError, TypeError, ValueError) as exc:
        return Decision(False, str(exc))


def authentication_only(scenario: Scenario) -> Decision:
    """Intentionally unsafe baseline: proves current DID-key control only."""
    try:
        verify_did_auth(
            scenario.proof,
            did=scenario.request.agent,
            audience=scenario.request.audience,
            domain=scenario.request.domain,
            nonce=scenario.request.nonce,
            resolver=scenario.resolver,
            secondary_resolver=None,
            high_assurance=False,
            replay_store=scenario.replay_store,
            now=scenario.now,
        )
        return Decision(True, "authenticated_only")
    except (TrustError, KeyError, TypeError, ValueError) as exc:
        return Decision(False, str(exc))


def reissue_proof(scenario: Scenario, **changes: Any) -> None:
    values = {
        "did": scenario.request.agent,
        "key": scenario.keys[WORKER],
        "nonce": scenario.request.nonce,
        "audience": scenario.request.audience,
        "domain": scenario.request.domain,
        "now": scenario.now,
        "jti": "auth:mutated",
    }
    values.update(changes)
    scenario.proof = issue_did_auth(**values)


def reissue_registration(scenario: Scenario, **changes: Any) -> None:
    values = {
        "subject": scenario.request.agent,
        "key": scenario.keys[GOVERNANCE],
        "audience": scenario.request.audience,
        "now": scenario.now,
        "jti": "registration:mutated",
    }
    values.update(changes)
    scenario.registration = issue_registration(**values)


def rebuild_chain(
    scenario: Scenario,
    root_changes: Mapping[str, Any] | None = None,
    child_changes: Mapping[str, Any] | None = None,
) -> None:
    root_values: dict[str, Any] = {
        "issuer": OWNER,
        "subject": PARTNER,
        "key": scenario.keys[OWNER],
        "actions": (ACTION, "claim.comment"),
        "resources": (RESOURCE, "claim:484"),
        "parent": None,
        "depth": 0,
        "audience": scenario.request.audience,
        "tenant": scenario.request.tenant,
        "purpose": scenario.request.purpose,
        "now": scenario.now,
        "lifetime": 600,
        "jti": "cap:root:mutated",
    }
    root_values.update(root_changes or {})
    root = issue_capability(**root_values)
    child_values: dict[str, Any] = {
        "issuer": PARTNER,
        "subject": scenario.request.agent,
        "key": scenario.keys[PARTNER],
        "actions": (ACTION,),
        "resources": (RESOURCE,),
        "parent": digest(root),
        "depth": 1,
        "audience": scenario.request.audience,
        "tenant": scenario.request.tenant,
        "purpose": scenario.request.purpose,
        "now": scenario.now,
        "lifetime": 300,
        "jti": "cap:child:mutated",
    }
    child_values.update(child_changes or {})
    scenario.capabilities = [root, issue_capability(**child_values)]


Mutation = Callable[[Scenario], None]


@dataclass(frozen=True)
class Case:
    case_id: str
    category: str
    expected_allowed: bool
    mutate: Mutation = lambda scenario: None

    def run(self, *, baseline: bool = False) -> Decision:
        scenario = build_scenario(self.case_id)
        self.mutate(scenario)
        return authentication_only(scenario) if baseline else authorize(scenario)


def _setattr(name: str, value: Any) -> Mutation:
    return lambda scenario: setattr(scenario.request, name, value)


def _document_change(
    did: str, change: Callable[[dict[str, Any]], None], *, secondary: bool = False
) -> Mutation:
    def mutate(scenario: Scenario) -> None:
        resolver = scenario.secondary_resolver if secondary else scenario.resolver
        change(resolver.documents[did])

    return mutate


def build_cases() -> list[Case]:
    cases: list[Case] = [
        Case("valid-worker-read", "valid", True),
        Case(
            "valid-lower-assurance",
            "valid",
            True,
            lambda s: setattr(s, "high_assurance", False),
        ),
        Case(
            "auth-forged-signature",
            "authentication",
            False,
            lambda s: reissue_proof(s, signing_key=deterministic_key("attacker")),
        ),
        Case(
            "auth-wrong-kid",
            "authentication",
            False,
            lambda s: reissue_proof(s, kid=f"{WORKER}#missing"),
        ),
        Case(
            "auth-key-not-authentication",
            "authentication",
            False,
            _document_change(WORKER, lambda d: d.update(authentication=[])),
        ),
        Case(
            "auth-wrong-nonce",
            "authentication",
            False,
            lambda s: reissue_proof(s, nonce="nonce:attacker"),
        ),
        Case(
            "auth-wrong-audience",
            "authentication",
            False,
            lambda s: reissue_proof(s, audience="https://other.example"),
        ),
        Case(
            "auth-wrong-domain",
            "authentication",
            False,
            lambda s: reissue_proof(s, domain="other.example"),
        ),
        Case(
            "auth-expired",
            "authentication",
            False,
            lambda s: reissue_proof(s, now=s.now - 1000),
        ),
        Case(
            "auth-replay",
            "authentication",
            False,
            lambda s: verify_did_auth(
                s.proof,
                did=s.request.agent,
                audience=s.request.audience,
                domain=s.request.domain,
                nonce=s.request.nonce,
                resolver=s.resolver,
                secondary_resolver=s.secondary_resolver,
                high_assurance=s.high_assurance,
                replay_store=s.replay_store,
                now=s.now,
            ),
        ),
        Case(
            "auth-subject-substitution",
            "authentication",
            False,
            lambda s: reissue_proof(s, subject=PARTNER),
        ),
        Case(
            "resolution-unsupported-method",
            "resolution",
            False,
            _setattr("agent", "did:ion:EiUnsupported"),
        ),
        Case(
            "resolution-document-substitution",
            "resolution",
            False,
            _document_change(WORKER, lambda d: d.update(id=PARTNER)),
        ),
        Case(
            "resolution-deactivated",
            "resolution",
            False,
            lambda s: s.resolver.metadata[WORKER].update(deactivated=True),
        ),
        Case(
            "resolution-private-jwk",
            "resolution",
            False,
            _document_change(
                WORKER,
                lambda d: d["verificationMethod"][0]["publicKeyJwk"].update(d="secret"),
            ),
        ),
        Case(
            "resolution-unsafe-service",
            "resolution",
            False,
            _document_change(
                WORKER,
                lambda d: d["service"][0].update(
                    serviceEndpoint="http://169.254.169.254/latest/meta-data"
                ),
            ),
        ),
        Case(
            "resolution-stale-after-rotation",
            "resolution",
            False,
            lambda s: _stale_rotation(s),
        ),
        Case(
            "resolution-quorum-disagreement",
            "resolution",
            False,
            _document_change(
                WORKER,
                lambda d: d.update(alsoKnownAs=["did:web:evil.example"]),
                secondary=True,
            ),
        ),
        Case(
            "resolution-method-downgrade",
            "resolution",
            False,
            lambda s: s.registry.update(allowedDidMethods=["key"]),
        ),
        Case(
            "registration-untrusted-issuer",
            "credential",
            False,
            lambda s: _untrusted_registration(s),
        ),
        Case(
            "registration-wrong-subject",
            "credential",
            False,
            lambda s: reissue_registration(s, subject=PARTNER),
        ),
        Case(
            "registration-untrusted-org",
            "credential",
            False,
            lambda s: reissue_registration(s, organization="did:web:evil.example"),
        ),
        Case(
            "registration-wrong-class",
            "credential",
            False,
            lambda s: reissue_registration(s, agent_class="unbounded-admin"),
        ),
        Case(
            "registration-expired",
            "credential",
            False,
            lambda s: reissue_registration(s, now=s.now - 2000),
        ),
        Case(
            "registration-revoked",
            "credential",
            False,
            lambda s: s.registry["revokedCredentials"].append(
                unverified(s.registration)[1]["jti"]
            ),
        ),
        Case(
            "registration-inactive",
            "credential",
            False,
            lambda s: reissue_registration(s, status="suspended"),
        ),
        Case(
            "capability-wrong-root",
            "delegation",
            False,
            lambda s: s.registry.update(capabilityRoot=GOVERNANCE),
        ),
        Case(
            "capability-wrong-delegate",
            "delegation",
            False,
            lambda s: rebuild_chain(s, child_changes={"subject": PARTNER}),
        ),
        Case(
            "capability-action-amplification",
            "delegation",
            False,
            lambda s: rebuild_chain(
                s,
                root_changes={"actions": ("claim.comment",)},
                child_changes={"actions": (ACTION,)},
            ),
        ),
        Case(
            "capability-resource-amplification",
            "delegation",
            False,
            lambda s: rebuild_chain(s, root_changes={"resources": ("claim:484",)}),
        ),
        Case(
            "capability-purpose-change",
            "delegation",
            False,
            lambda s: rebuild_chain(s, child_changes={"purpose": "model-training"}),
        ),
        Case(
            "capability-tenant-change",
            "delegation",
            False,
            lambda s: rebuild_chain(s, child_changes={"tenant": "tenant:other"}),
        ),
        Case(
            "capability-audience-change",
            "delegation",
            False,
            lambda s: rebuild_chain(
                s, child_changes={"audience": "https://other.example"}
            ),
        ),
        Case(
            "capability-lifetime-amplification",
            "delegation",
            False,
            lambda s: rebuild_chain(
                s, root_changes={"lifetime": 200}, child_changes={"lifetime": 300}
            ),
        ),
        Case(
            "capability-parent-mismatch",
            "delegation",
            False,
            lambda s: rebuild_chain(s, child_changes={"parent": "sha256:attacker"}),
        ),
        Case(
            "capability-revoked",
            "delegation",
            False,
            lambda s: s.registry["revokedCapabilities"].append(
                f"cap:child:{s.request.nonce.removeprefix('nonce:')}"
            ),
        ),
        Case(
            "organization-suspended",
            "policy",
            False,
            lambda s: s.state["organizations"].update({PARTNER_ORG: "suspended"}),
        ),
        Case(
            "agent-quarantined",
            "policy",
            False,
            lambda s: s.state["agents"].update({WORKER: "quarantined"}),
        ),
        Case(
            "relationship-ended",
            "policy",
            False,
            lambda s: s.state["relationships"].update(
                {f"{PARTNER_ORG}|{WORKER}": "ended"}
            ),
        ),
        Case(
            "request-action-not-delegated",
            "request",
            False,
            _setattr("action", "claim.approve"),
        ),
        Case(
            "request-resource-not-delegated",
            "request",
            False,
            _setattr("resource", "claim:999"),
        ),
        Case(
            "request-tenant-not-delegated",
            "request",
            False,
            _setattr("tenant", "tenant:other"),
        ),
    ]
    return cases


def _stale_rotation(scenario: Scenario) -> None:
    scenario.resolver.resolve(WORKER, now=scenario.now)
    rotated = deterministic_key("worker-rotated")
    scenario.resolver.documents[WORKER] = did_document(WORKER, rotated, version="2")
    scenario.resolver.metadata[WORKER] = {"versionId": "2", "updated": scenario.now}
    reissue_proof(scenario, key=rotated, kid=f"{WORKER}#controller-2")


def _untrusted_registration(scenario: Scenario) -> None:
    attacker = deterministic_key("attacker-governance")
    reissue_registration(scenario, key=attacker)


@dataclass(frozen=True)
class Metrics:
    total: int
    correct: int
    invalid_allows: int
    valid_blocks: int

    @property
    def accuracy(self) -> float:
        return self.correct / self.total


def evaluate(
    cases: list[Case], *, baseline: bool = False
) -> tuple[Metrics, list[dict[str, Any]]]:
    rows: list[dict[str, Any]] = []
    for case in cases:
        decision = case.run(baseline=baseline)
        match = decision.allowed is case.expected_allowed
        rows.append(
            {
                "case_id": case.case_id,
                "category": case.category,
                "expected": case.expected_allowed,
                "allowed": decision.allowed,
                "reason": decision.reason,
                "match": match,
            }
        )
    metrics = Metrics(
        total=len(rows),
        correct=sum(row["match"] for row in rows),
        invalid_allows=sum(row["allowed"] and not row["expected"] for row in rows),
        valid_blocks=sum(not row["allowed"] and row["expected"] for row in rows),
    )
    return metrics, rows


def trust_graph() -> nx.DiGraph:
    graph = nx.DiGraph()
    graph.add_edge(VERIFIER, GOVERNANCE, relation="trusts-registration-issuer")
    graph.add_edge(VERIFIER, OWNER, relation="trusts-capability-root")
    graph.add_edge(GOVERNANCE, PARTNER_ORG, relation="registers-organization")
    graph.add_edge(PARTNER_ORG, WORKER, relation="operates-agent")
    graph.add_edge(OWNER, PARTNER, relation="delegates-to")
    graph.add_edge(PARTNER, WORKER, relation="delegates-to")
    return graph


def release_gate(metrics: Metrics) -> bool:
    return (
        metrics.correct == metrics.total
        and metrics.invalid_allows == 0
        and metrics.valid_blocks == 0
    )


def main() -> None:
    cases = build_cases()
    hardened, rows = evaluate(cases)
    baseline, _ = evaluate(cases, baseline=True)
    decision = authorize(build_scenario("demo"))
    print("Decentralized identity and multi-agent trust lab")
    print(f"valid decision: {decision.allowed} ({decision.reason})")
    print(
        f"hardened: {hardened.correct}/{hardened.total}; invalid allows={hardened.invalid_allows}"
    )
    print(f"authentication-only baseline invalid allows={baseline.invalid_allows}")
    print(f"release gate: {'PASS' if release_gate(hardened) else 'FAIL'}")
    print("categories:", sorted({row["category"] for row in rows}))


if __name__ == "__main__":
    main()
