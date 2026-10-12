"""Credential-free trust-evidence lab for an enterprise agent.

This is a deliberately bounded teaching profile.  It uses real Ed25519 JWS
verification, JSON Schema, a DSSE-style in-toto envelope, and EAT-shaped JWTs,
but it is not a conformant VC, OpenID4VC, EAT, or SLSA implementation.
Production systems should use conformant libraries and ecosystem profiles.
"""

from __future__ import annotations

import base64
import json
from collections.abc import Callable, Iterable, Mapping
from dataclasses import asdict, dataclass, field, replace
from hashlib import sha256
from pathlib import Path
from threading import Lock
from typing import Any

import jwt
import networkx as nx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from jsonschema import Draft202012Validator

NOW = 1_800_000_000
VERIFIER = "https://claims.corp.example/evidence"
AGENT = "urn:agent:claims-research"
HOLDER = "spiffe://corp.example/prod/claims-agent"
WORKLOAD = "spiffe://corp.example/prod/claims-agent"
TENANT = "tenant:northstar"
RESOURCE = "claim:483"
ACTION = "claim.update"
RELEASE = "sha256:" + "a" * 64
CONFIG = "sha256:" + "b" * 64
TOOL_MANIFEST = "sha256:" + "c" * 64
SOURCE = "https://github.com/example/claims-agent@refs/tags/v4.2.0"
POLICY_VERSION = "evidence-policy-2026-10-12"

REGISTRY_ISSUER = "https://registry.corp.example"
EVALUATOR_ISSUER = "https://evaluation.corp.example"
GOVERNANCE_ISSUER = "https://governance.corp.example"
ATTESTER_ISSUER = "https://attester.corp.example"
BUILDER_ID = "https://builder.corp.example/gha"

REGISTRATION = "AgentRegistrationCredential"
EVALUATION = "AgentEvaluationCredential"
GOVERNANCE = "AgentGovernanceCredential"


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
    """Return a reproducible training key. Never derive production keys this way."""

    return Ed25519PrivateKey.from_private_bytes(sha256(label.encode()).digest())


def public_jwk(public_key: Ed25519PublicKey) -> dict[str, str]:
    raw = public_key.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return {"kty": "OKP", "crv": "Ed25519", "x": b64url(raw)}


def jwk_thumbprint(public_key: Ed25519PublicKey) -> str:
    return b64url(sha256(canonical(public_jwk(public_key))).digest())


@dataclass(frozen=True)
class IssuerPolicy:
    issuer: str
    status: str
    allowed_types: frozenset[str]
    allowed_claims: frozenset[str]
    max_ttl_seconds: int
    schema_path: str
    status_uri: str


@dataclass(frozen=True)
class VerifiedCredential:
    credential_id: str
    credential_type: str
    issuer: str
    subject: str
    claims: Mapping[str, Any]
    expires_at: int


@dataclass(frozen=True)
class PresentationResult:
    valid: bool
    reason_code: str
    holder: str | None
    credentials: tuple[VerifiedCredential, ...]


@dataclass(frozen=True)
class AttestationResult:
    valid: bool
    reason_code: str
    claims: Mapping[str, Any]


@dataclass(frozen=True)
class ProvenanceResult:
    valid: bool
    reason_code: str
    statement: Mapping[str, Any]


@dataclass(frozen=True)
class AccessRequest:
    trace_id: str
    operation_id: str
    agent_id: str
    holder_id: str
    workload_id: str
    tenant_id: str
    action: str
    resource: str
    release_digest: str
    config_digest: str
    tool_manifest_digest: str
    verifier: str
    nonce: str


@dataclass(frozen=True)
class CurrentPolicy:
    version: str
    relationship_active: bool
    task_active: bool
    quarantined: bool
    risk_score: int


@dataclass(frozen=True)
class EvidenceContext:
    presentation: str
    status_lists: Mapping[str, str]
    workload_attestation: str
    provenance: Mapping[str, Any]
    request: AccessRequest
    current_policy: CurrentPolicy
    status_fetched_at: int


@dataclass(frozen=True)
class AssuranceProfile:
    identity: str
    workload: str
    supply_chain: str
    evaluation: str
    governance: str
    evidence_ids: tuple[str, ...]


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason_code: str
    profile: AssuranceProfile | None


KeyRegistry = Mapping[str, Mapping[str, Ed25519PublicKey]]


def load_issuer_policies(course_dir: Path | None = None) -> dict[str, IssuerPolicy]:
    root = course_dir or Path(__file__).parent
    records = json.loads((root / "data/trusted_issuers.json").read_text())
    return {
        issuer: IssuerPolicy(
            issuer,
            record["status"],
            frozenset(record["credential_types"]),
            frozenset(record["allowed_subject_claims"]),
            record["max_ttl_seconds"],
            record["schema"],
            record["status_uri"],
        )
        for issuer, record in records.items()
    }


def credential_document(
    *,
    issuer: str,
    subject: str,
    credential_type: str,
    credential_id: str,
    claims: Mapping[str, Any],
    issued_at: int,
    expires_at: int,
    status_uri: str,
    status_index: int,
    schema_id: str,
) -> dict[str, Any]:
    return {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "id": credential_id,
        "type": ["VerifiableCredential", credential_type],
        "issuer": issuer,
        "validFrom": issued_at,
        "validUntil": expires_at,
        "credentialSubject": {"id": subject, **dict(claims)},
        "credentialStatus": {
            "id": f"{status_uri}#{status_index}",
            "type": "BitstringStatusListEntry",
            "statusPurpose": "revocation",
            "statusListIndex": str(status_index),
            "statusListCredential": status_uri,
        },
        "credentialSchema": {
            "id": schema_id,
            "type": "JsonSchema",
        },
    }


def issue_credential(
    private_key: Ed25519PrivateKey,
    *,
    kid: str,
    issuer: str,
    subject: str = AGENT,
    credential_type: str,
    credential_id: str,
    claims: Mapping[str, Any],
    issued_at: int = NOW - 60,
    expires_at: int = NOW + 600,
    audience: str = VERIFIER,
    status_uri: str,
    status_index: int,
    schema_id: str,
) -> str:
    vc = credential_document(
        issuer=issuer,
        subject=subject,
        credential_type=credential_type,
        credential_id=credential_id,
        claims=claims,
        issued_at=issued_at,
        expires_at=expires_at,
        status_uri=status_uri,
        status_index=status_index,
        schema_id=schema_id,
    )
    return jwt.encode(
        {
            "iss": issuer,
            "sub": subject,
            "jti": credential_id,
            "iat": issued_at,
            "nbf": issued_at,
            "exp": expires_at,
            "aud": audience,
            "vc": vc,
        },
        private_key,
        algorithm="EdDSA",
        headers={"typ": "vc+jwt", "kid": kid},
    )


def issue_status_list(
    private_key: Ed25519PrivateKey,
    *,
    kid: str,
    issuer: str,
    status_uri: str,
    revoked_indices: Iterable[int] = (),
    issued_at: int = NOW - 30,
    expires_at: int = NOW + 300,
    size: int = 128,
) -> str:
    bits = bytearray((size + 7) // 8)
    for index in revoked_indices:
        if not 0 <= index < size:
            raise ValueError("status_index_out_of_range")
        bits[index // 8] |= 1 << (index % 8)
    return jwt.encode(
        {
            "iss": issuer,
            "sub": status_uri,
            "iat": issued_at,
            "exp": expires_at,
            "statusPurpose": "revocation",
            "size": size,
            "encodedList": b64url(bytes(bits)),
        },
        private_key,
        algorithm="EdDSA",
        headers={"typ": "statuslist+jwt", "kid": kid},
    )


def _unverified(token: str) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
    return jwt.get_unverified_header(token), jwt.decode(
        token, options={"verify_signature": False}
    )


def _verify_jws(
    token: str,
    keys: KeyRegistry,
    *,
    expected_type: str,
) -> tuple[Mapping[str, Any] | None, str | None]:
    try:
        header, claims = _unverified(token)
        issuer = claims.get("iss")
        kid = header.get("kid")
        if header.get("typ") != expected_type or header.get("alg") != "EdDSA":
            return None, "jws_header_invalid"
        if not isinstance(issuer, str) or not isinstance(kid, str):
            return None, "jws_shape_invalid"
        key = keys.get(issuer, {}).get(kid)
        if key is None:
            return None, "verification_key_untrusted"
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
    except (jwt.PyJWTError, KeyError, TypeError, ValueError):
        return None, "jws_signature_or_shape_invalid"
    return verified, None


def tamper_jwt(token: str, claim: str, value: Any) -> str:
    header, payload, signature = token.split(".")
    claims = json.loads(unb64url(payload))
    claims[claim] = value
    return f"{header}.{b64url(canonical(claims))}.{signature}"


def _validate_status(
    vc: Mapping[str, Any],
    status_lists: Mapping[str, str],
    keys: KeyRegistry,
    issuer: str,
    *,
    now: int,
) -> str | None:
    status = vc.get("credentialStatus")
    if not isinstance(status, dict):
        return "credential_status_missing"
    if (
        status.get("type") != "BitstringStatusListEntry"
        or status.get("statusPurpose") != "revocation"
    ):
        return "credential_status_profile_invalid"
    uri = status.get("statusListCredential")
    if not isinstance(uri, str) or uri not in status_lists:
        return "credential_status_list_unavailable"
    claims, error = _verify_jws(status_lists[uri], keys, expected_type="statuslist+jwt")
    if error or claims is None:
        return error or "credential_status_invalid"
    if claims.get("iss") != issuer or claims.get("sub") != uri:
        return "credential_status_binding_invalid"
    if not isinstance(claims.get("iat"), int) or not isinstance(claims.get("exp"), int):
        return "credential_status_time_invalid"
    if not claims["iat"] <= now < claims["exp"]:
        return "credential_status_stale"
    try:
        index = int(status["statusListIndex"])
        size = int(claims["size"])
        bits = unb64url(claims["encodedList"])
        if not 0 <= index < size or len(bits) * 8 < size:
            return "credential_status_index_invalid"
        if bits[index // 8] & (1 << (index % 8)):
            return "credential_revoked"
    except (KeyError, TypeError, ValueError):
        return "credential_status_shape_invalid"
    return None


def verify_credential(
    token: str,
    keys: KeyRegistry,
    policies: Mapping[str, IssuerPolicy],
    schemas: Mapping[str, Mapping[str, Any]],
    status_lists: Mapping[str, str],
    *,
    expected_audience: str,
    now: int = NOW,
) -> tuple[VerifiedCredential | None, str]:
    claims, error = _verify_jws(token, keys, expected_type="vc+jwt")
    if error or claims is None:
        return None, error or "credential_invalid"
    issuer = claims.get("iss")
    policy = policies.get(str(issuer))
    if policy is None or policy.status != "active":
        return None, "credential_issuer_untrusted"
    vc = claims.get("vc")
    if not isinstance(vc, dict):
        return None, "credential_document_missing"
    types = vc.get("type")
    if not isinstance(types, list) or not all(isinstance(item, str) for item in types):
        return None, "credential_type_invalid"
    credential_types = set(types) - {"VerifiableCredential"}
    if len(credential_types) != 1:
        return None, "credential_type_ambiguous"
    credential_type = next(iter(credential_types))
    if credential_type not in policy.allowed_types:
        return None, "credential_type_not_allowed_for_issuer"
    schema = schemas.get(credential_type)
    if schema is None:
        return None, "credential_schema_untrusted"
    errors = sorted(Draft202012Validator(schema).iter_errors(vc), key=lambda e: e.path)
    if errors:
        return None, "credential_schema_invalid"
    subject = vc.get("credentialSubject", {})
    if not isinstance(subject, dict):
        return None, "credential_subject_invalid"
    subject_claim_names = set(subject) - {"id"}
    if not subject_claim_names.issubset(policy.allowed_claims):
        return None, "credential_claim_not_allowed_for_issuer"
    if (
        vc.get("issuer") != issuer
        or subject.get("id") != claims.get("sub")
        or vc.get("id") != claims.get("jti")
    ):
        return None, "credential_envelope_binding_invalid"
    times = [claims.get(name) for name in ("iat", "nbf", "exp")]
    if not all(isinstance(value, int) for value in times):
        return None, "credential_time_shape_invalid"
    issued_at, not_before, expires_at = times
    if not issued_at <= now < expires_at or now < not_before:
        return None, "credential_not_current"
    if expires_at - issued_at > policy.max_ttl_seconds:
        return None, "credential_ttl_excessive"
    if vc.get("validFrom") != issued_at or vc.get("validUntil") != expires_at:
        return None, "credential_time_binding_invalid"
    if claims.get("aud") != expected_audience:
        return None, "credential_audience_mismatch"
    status_error = _validate_status(vc, status_lists, keys, str(issuer), now=now)
    if status_error:
        return None, status_error
    return (
        VerifiedCredential(
            str(claims["jti"]),
            credential_type,
            str(issuer),
            str(claims["sub"]),
            dict(subject),
            int(expires_at),
        ),
        "credential_valid",
    )


def create_presentation(
    credentials: Iterable[str],
    holder_key: Ed25519PrivateKey,
    *,
    kid: str,
    holder: str = HOLDER,
    subject: str = AGENT,
    audience: str = VERIFIER,
    nonce: str,
    issued_at: int = NOW - 5,
    expires_at: int = NOW + 90,
    presentation_id: str = "vp:claims-agent:483",
) -> str:
    return jwt.encode(
        {
            "iss": holder,
            "sub": subject,
            "aud": audience,
            "nonce": nonce,
            "iat": issued_at,
            "exp": expires_at,
            "jti": presentation_id,
            "vp": {
                "@context": ["https://www.w3.org/ns/credentials/v2"],
                "type": ["VerifiablePresentation"],
                "holder": holder,
                "verifiableCredential": list(credentials),
            },
        },
        holder_key,
        algorithm="EdDSA",
        headers={"typ": "vp+jwt", "kid": kid},
    )


@dataclass
class ReplayCache:
    consumed: set[str] = field(default_factory=set)
    _lock: Lock = field(default_factory=Lock)

    def consume(self, presentation_id: str) -> bool:
        with self._lock:
            if presentation_id in self.consumed:
                return False
            self.consumed.add(presentation_id)
            return True


def verify_presentation(
    token: str,
    keys: KeyRegistry,
    policies: Mapping[str, IssuerPolicy],
    schemas: Mapping[str, Mapping[str, Any]],
    status_lists: Mapping[str, str],
    replay_cache: ReplayCache,
    *,
    expected_holder: str,
    expected_subject: str,
    expected_audience: str,
    expected_nonce: str,
    now: int = NOW,
) -> PresentationResult:
    claims, error = _verify_jws(token, keys, expected_type="vp+jwt")
    if error or claims is None:
        return PresentationResult(False, error or "presentation_invalid", None, ())
    vp = claims.get("vp")
    if not isinstance(vp, dict):
        return PresentationResult(False, "presentation_document_missing", None, ())
    if vp.get("@context") != ["https://www.w3.org/ns/credentials/v2"] or vp.get(
        "type"
    ) != ["VerifiablePresentation"]:
        return PresentationResult(False, "presentation_profile_invalid", None, ())
    if (
        claims.get("iss") != expected_holder
        or vp.get("holder") != expected_holder
        or claims.get("sub") != expected_subject
    ):
        return PresentationResult(
            False, "presentation_holder_binding_invalid", None, ()
        )
    if claims.get("aud") != expected_audience:
        return PresentationResult(False, "presentation_audience_mismatch", None, ())
    if claims.get("nonce") != expected_nonce:
        return PresentationResult(False, "presentation_nonce_mismatch", None, ())
    if not isinstance(claims.get("iat"), int) or not isinstance(claims.get("exp"), int):
        return PresentationResult(False, "presentation_time_shape_invalid", None, ())
    if not claims["iat"] <= now < claims["exp"] or claims["exp"] - claims["iat"] > 120:
        return PresentationResult(False, "presentation_not_current", None, ())
    presentation_id = claims.get("jti")
    if not isinstance(presentation_id, str) or not replay_cache.consume(
        presentation_id
    ):
        return PresentationResult(False, "presentation_replayed", None, ())
    embedded = vp.get("verifiableCredential")
    if not isinstance(embedded, list) or not embedded:
        return PresentationResult(False, "presentation_credentials_missing", None, ())
    verified: list[VerifiedCredential] = []
    for credential in embedded:
        if not isinstance(credential, str):
            return PresentationResult(
                False, "presentation_credential_shape_invalid", None, ()
            )
        result, reason = verify_credential(
            credential,
            keys,
            policies,
            schemas,
            status_lists,
            expected_audience=expected_audience,
            now=now,
        )
        if result is None:
            return PresentationResult(False, reason, expected_holder, tuple(verified))
        if result.subject != expected_subject:
            return PresentationResult(
                False,
                "credential_subject_substitution",
                expected_holder,
                tuple(verified),
            )
        verified.append(result)
    by_type = {item.credential_type for item in verified}
    if (
        len(verified) != 3
        or len(by_type) != 3
        or by_type != {REGISTRATION, EVALUATION, GOVERNANCE}
    ):
        return PresentationResult(
            False,
            "required_credential_set_incomplete",
            expected_holder,
            tuple(verified),
        )
    return PresentationResult(
        True, "presentation_valid", expected_holder, tuple(verified)
    )


def issue_eat(
    private_key: Ed25519PrivateKey,
    *,
    kid: str,
    nonce: str,
    issuer: str = ATTESTER_ISSUER,
    workload: str = WORKLOAD,
    audience: str = VERIFIER,
    release_digest: str = RELEASE,
    config_digest: str = CONFIG,
    tool_manifest_digest: str = TOOL_MANIFEST,
    issued_at: int = NOW - 5,
    expires_at: int = NOW + 90,
) -> str:
    return jwt.encode(
        {
            "iss": issuer,
            "sub": workload,
            "aud": audience,
            "iat": issued_at,
            "exp": expires_at,
            "nonce": nonce,
            "ueid": b64url(sha256(workload.encode()).digest()[:16]),
            "measurements": {
                "releaseDigest": release_digest,
                "configDigest": config_digest,
                "toolManifestDigest": tool_manifest_digest,
            },
        },
        private_key,
        algorithm="EdDSA",
        headers={"typ": "eat+jwt", "kid": kid},
    )


def verify_eat(
    token: str,
    keys: KeyRegistry,
    request: AccessRequest,
    *,
    now: int = NOW,
) -> AttestationResult:
    claims, error = _verify_jws(token, keys, expected_type="eat+jwt")
    if error or claims is None:
        return AttestationResult(False, error or "eat_invalid", {})
    if claims.get("iss") != ATTESTER_ISSUER:
        return AttestationResult(False, "eat_attester_untrusted", claims)
    if (
        claims.get("sub") != request.workload_id
        or claims.get("aud") != request.verifier
    ):
        return AttestationResult(False, "eat_workload_or_audience_mismatch", claims)
    if claims.get("nonce") != request.nonce:
        return AttestationResult(False, "eat_nonce_mismatch", claims)
    if not isinstance(claims.get("iat"), int) or not isinstance(claims.get("exp"), int):
        return AttestationResult(False, "eat_time_shape_invalid", claims)
    if not claims["iat"] <= now < claims["exp"] or claims["exp"] - claims["iat"] > 120:
        return AttestationResult(False, "eat_not_current", claims)
    expected = {
        "releaseDigest": request.release_digest,
        "configDigest": request.config_digest,
        "toolManifestDigest": request.tool_manifest_digest,
    }
    if claims.get("measurements") != expected:
        return AttestationResult(False, "eat_measurement_mismatch", claims)
    return AttestationResult(True, "eat_valid", claims)


def dsse_pae(payload_type: str, payload: bytes) -> bytes:
    """DSSE pre-authentication encoding."""

    return b" ".join(
        [
            b"DSSEv1",
            str(len(payload_type.encode())).encode(),
            payload_type.encode(),
            str(len(payload)).encode(),
            payload,
        ]
    )


def sign_provenance(
    private_key: Ed25519PrivateKey,
    *,
    kid: str,
    builder_id: str = BUILDER_ID,
    release_digest: str = RELEASE,
    source: str = SOURCE,
) -> dict[str, Any]:
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [
            {
                "name": "claims-agent",
                "digest": {"sha256": release_digest.removeprefix("sha256:")},
            }
        ],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "builder": {"id": builder_id},
            "buildType": "https://corp.example/build/agent/v1",
            "externalParameters": {"source": source},
            "invocationId": "build:claims-agent:4.2.0",
        },
    }
    payload_type = "application/vnd.in-toto+json"
    payload = canonical(statement)
    signature = private_key.sign(dsse_pae(payload_type, payload))
    return {
        "payloadType": payload_type,
        "payload": b64url(payload),
        "signatures": [{"keyid": kid, "sig": b64url(signature)}],
    }


def verify_provenance(
    envelope: Mapping[str, Any],
    builder_keys: Mapping[str, Ed25519PublicKey],
    request: AccessRequest,
) -> ProvenanceResult:
    try:
        payload_type = envelope["payloadType"]
        payload = unb64url(envelope["payload"])
        signatures = envelope["signatures"]
        if payload_type != "application/vnd.in-toto+json" or len(signatures) != 1:
            return ProvenanceResult(False, "provenance_envelope_invalid", {})
        key_id = signatures[0]["keyid"]
        key = builder_keys.get(key_id)
        if key is None:
            return ProvenanceResult(False, "provenance_builder_key_untrusted", {})
        key.verify(unb64url(signatures[0]["sig"]), dsse_pae(payload_type, payload))
        statement = json.loads(payload)
    except (InvalidSignature, KeyError, TypeError, ValueError, json.JSONDecodeError):
        return ProvenanceResult(False, "provenance_signature_or_shape_invalid", {})
    if (
        statement.get("_type") != "https://in-toto.io/Statement/v1"
        or statement.get("predicateType") != "https://slsa.dev/provenance/v1"
    ):
        return ProvenanceResult(False, "provenance_profile_invalid", statement)
    subjects = statement.get("subject")
    expected_digest = request.release_digest.removeprefix("sha256:")
    if (
        not isinstance(subjects, list)
        or len(subjects) != 1
        or subjects[0].get("digest", {}).get("sha256") != expected_digest
    ):
        return ProvenanceResult(False, "provenance_subject_mismatch", statement)
    predicate = statement.get("predicate", {})
    if predicate.get("builder", {}).get("id") != BUILDER_ID:
        return ProvenanceResult(False, "provenance_builder_untrusted", statement)
    if predicate.get("externalParameters", {}).get("source") != SOURCE:
        return ProvenanceResult(False, "provenance_source_mismatch", statement)
    return ProvenanceResult(True, "provenance_valid", statement)


def build_evidence_graph(
    request: AccessRequest,
    credentials: Iterable[VerifiedCredential],
) -> nx.DiGraph:
    graph = nx.DiGraph()
    graph.add_edge(request.agent_id, request.release_digest, relation="runs-release")
    graph.add_edge(request.workload_id, request.release_digest, relation="measured-as")
    for credential in credentials:
        graph.add_edge(
            credential.issuer,
            credential.subject,
            relation=credential.credential_type,
            evidence_id=credential.credential_id,
        )
    return graph


def disclosure_state(claims: Mapping[str, Any], name: str) -> tuple[str, Any | None]:
    """Keep an undisclosed claim distinct from a verified false value."""

    if name not in claims:
        return "unknown", None
    return "verified", claims[name]


def build_dcql_query() -> dict[str, Any]:
    """Build the minimal OpenID4VP-style query needed by this scenario."""

    return {
        "credentials": [
            {
                "id": "registration",
                "format": "jwt_vc_json",
                "meta": {"type_values": [["VerifiableCredential", REGISTRATION]]},
                "claims": [
                    {"path": ["credentialSubject", "releaseDigest"]},
                    {"path": ["credentialSubject", "holderJkt"]},
                ],
            },
            {
                "id": "evaluation",
                "format": "jwt_vc_json",
                "meta": {"type_values": [["VerifiableCredential", EVALUATION]]},
                "claims": [
                    {"path": ["credentialSubject", "releaseDigest"]},
                    {"path": ["credentialSubject", "configDigest"]},
                    {"path": ["credentialSubject", "result"]},
                    {"path": ["credentialSubject", "criticalFailures"]},
                ],
            },
            {
                "id": "governance",
                "format": "jwt_vc_json",
                "meta": {"type_values": [["VerifiableCredential", GOVERNANCE]]},
                "claims": [
                    {"path": ["credentialSubject", "tenantId"]},
                    {"path": ["credentialSubject", "approvedActions"]},
                    {"path": ["credentialSubject", "approvedResources"]},
                    {"path": ["credentialSubject", "policyVersion"]},
                ],
            },
        ]
    }


class EvidenceGateway:
    def __init__(
        self,
        keys: KeyRegistry,
        policies: Mapping[str, IssuerPolicy],
        schemas: Mapping[str, Mapping[str, Any]],
        builder_keys: Mapping[str, Ed25519PublicKey],
    ) -> None:
        self.keys = keys
        self.policies = policies
        self.schemas = schemas
        self.builder_keys = builder_keys
        self.replay_cache = ReplayCache()
        self.evidence: list[dict[str, Any]] = []

    def authorize(self, context: EvidenceContext, *, now: int = NOW) -> Decision:
        request = context.request
        policy = context.current_policy
        if policy.quarantined:
            return self._record(False, "agent_quarantined", None, context)
        if policy.version != POLICY_VERSION:
            return self._record(False, "policy_version_stale", None, context)
        if not policy.relationship_active:
            return self._record(False, "relationship_inactive", None, context)
        if not policy.task_active:
            return self._record(False, "task_inactive", None, context)
        if not 0 <= policy.risk_score < 50:
            return self._record(False, "runtime_risk_too_high", None, context)
        if context.status_fetched_at > now or now - context.status_fetched_at > 120:
            return self._record(False, "status_evidence_stale", None, context)

        presentation = verify_presentation(
            context.presentation,
            self.keys,
            self.policies,
            self.schemas,
            context.status_lists,
            self.replay_cache,
            expected_holder=request.holder_id,
            expected_subject=request.agent_id,
            expected_audience=request.verifier,
            expected_nonce=request.nonce,
            now=now,
        )
        if not presentation.valid:
            return self._record(False, presentation.reason_code, None, context)
        by_type = {item.credential_type: item for item in presentation.credentials}
        registration = by_type[REGISTRATION].claims
        evaluation = by_type[EVALUATION].claims
        governance = by_type[GOVERNANCE].claims
        bindings = {
            "registration_release_mismatch": registration.get("releaseDigest")
            != request.release_digest,
            "registration_holder_mismatch": registration.get("holderJkt")
            != jwk_thumbprint(self.keys[request.holder_id]["holder-2026"]),
            "evaluation_release_mismatch": evaluation.get("releaseDigest")
            != request.release_digest,
            "evaluation_config_mismatch": evaluation.get("configDigest")
            != request.config_digest,
            "evaluation_not_passing": evaluation.get("result") != "pass"
            or evaluation.get("criticalFailures") != 0,
            "governance_tenant_mismatch": governance.get("tenantId")
            != request.tenant_id,
            "governance_action_not_approved": request.action
            not in governance.get("approvedActions", []),
            "governance_resource_not_approved": request.resource
            not in governance.get("approvedResources", []),
            "governance_policy_stale": governance.get("policyVersion")
            != policy.version,
        }
        for reason, failed in bindings.items():
            if failed:
                return self._record(False, reason, None, context)

        attestation = verify_eat(
            context.workload_attestation, self.keys, request, now=now
        )
        if not attestation.valid:
            return self._record(False, attestation.reason_code, None, context)
        provenance = verify_provenance(context.provenance, self.builder_keys, request)
        if not provenance.valid:
            return self._record(False, provenance.reason_code, None, context)

        profile = AssuranceProfile(
            "verified",
            "verified",
            "verified",
            "verified",
            "verified",
            tuple(sorted(item.credential_id for item in presentation.credentials)),
        )
        return self._record(True, "authorized", profile, context)

    def _record(
        self,
        allowed: bool,
        reason: str,
        profile: AssuranceProfile | None,
        context: EvidenceContext,
    ) -> Decision:
        self.evidence.append(
            {
                "trace_id": context.request.trace_id,
                "operation_id": context.request.operation_id,
                "allowed": allowed,
                "reason_code": reason,
                "agent_hash": digest(context.request.agent_id),
                "workload_id": context.request.workload_id,
                "release_digest": context.request.release_digest,
                "action": context.request.action,
                "resource": context.request.resource,
                "policy_version": context.current_policy.version,
                "evidence_ids": list(profile.evidence_ids) if profile else [],
            }
        )
        return Decision(allowed, reason, profile)


def load_schemas(course_dir: Path | None = None) -> dict[str, Mapping[str, Any]]:
    root = course_dir or Path(__file__).parent
    return {
        REGISTRATION: json.loads(
            (root / "schemas/agent-registration-vc.schema.json").read_text()
        ),
        EVALUATION: json.loads(
            (root / "schemas/agent-evaluation-vc.schema.json").read_text()
        ),
        GOVERNANCE: json.loads(
            (root / "schemas/agent-governance-vc.schema.json").read_text()
        ),
    }


def scenario() -> dict[str, Any]:
    policies = load_issuer_policies()
    schemas = load_schemas()
    private_keys = {
        REGISTRY_ISSUER: deterministic_private_key(REGISTRY_ISSUER),
        EVALUATOR_ISSUER: deterministic_private_key(EVALUATOR_ISSUER),
        GOVERNANCE_ISSUER: deterministic_private_key(GOVERNANCE_ISSUER),
        ATTESTER_ISSUER: deterministic_private_key(ATTESTER_ISSUER),
        HOLDER: deterministic_private_key(HOLDER),
        BUILDER_ID: deterministic_private_key(BUILDER_ID),
    }
    kid = {
        REGISTRY_ISSUER: "registry-2026",
        EVALUATOR_ISSUER: "evaluator-2026",
        GOVERNANCE_ISSUER: "governance-2026",
        ATTESTER_ISSUER: "attester-2026",
        HOLDER: "holder-2026",
        BUILDER_ID: "builder-2026",
    }
    keys = {
        issuer: {kid[issuer]: key.public_key()}
        for issuer, key in private_keys.items()
        if issuer != BUILDER_ID
    }
    status_lists = {
        policy.status_uri: issue_status_list(
            private_keys[issuer],
            kid=kid[issuer],
            issuer=issuer,
            status_uri=policy.status_uri,
        )
        for issuer, policy in policies.items()
        if policy.status == "active"
    }
    credentials = (
        issue_credential(
            private_keys[REGISTRY_ISSUER],
            kid=kid[REGISTRY_ISSUER],
            issuer=REGISTRY_ISSUER,
            credential_type=REGISTRATION,
            credential_id="urn:vc:registration:claims-agent:v4",
            claims={
                "owner": "claims-platform",
                "agentClass": "ClaimsResearchAgent",
                "releaseDigest": RELEASE,
                "holderJkt": jwk_thumbprint(private_keys[HOLDER].public_key()),
            },
            status_uri=policies[REGISTRY_ISSUER].status_uri,
            status_index=7,
            schema_id="https://schemas.corp.example/agent-registration-v1",
        ),
        issue_credential(
            private_keys[EVALUATOR_ISSUER],
            kid=kid[EVALUATOR_ISSUER],
            issuer=EVALUATOR_ISSUER,
            credential_type=EVALUATION,
            credential_id="urn:vc:evaluation:claims-agent:v4",
            claims={
                "releaseDigest": RELEASE,
                "configDigest": CONFIG,
                "suite": "agent-security-v7",
                "result": "pass",
                "criticalFailures": 0,
            },
            expires_at=NOW + 300,
            status_uri=policies[EVALUATOR_ISSUER].status_uri,
            status_index=11,
            schema_id="https://schemas.corp.example/agent-evaluation-v1",
        ),
        issue_credential(
            private_keys[GOVERNANCE_ISSUER],
            kid=kid[GOVERNANCE_ISSUER],
            issuer=GOVERNANCE_ISSUER,
            credential_type=GOVERNANCE,
            credential_id="urn:vc:governance:claims-agent:v4",
            claims={
                "tenantId": TENANT,
                "approvedActions": [ACTION],
                "approvedResources": [RESOURCE],
                "policyVersion": POLICY_VERSION,
            },
            status_uri=policies[GOVERNANCE_ISSUER].status_uri,
            status_index=19,
            schema_id="https://schemas.corp.example/agent-governance-v1",
        ),
    )
    nonce = "challenge:claim-483:01"
    request = AccessRequest(
        "trace:evidence:483",
        "operation:update:483",
        AGENT,
        HOLDER,
        WORKLOAD,
        TENANT,
        ACTION,
        RESOURCE,
        RELEASE,
        CONFIG,
        TOOL_MANIFEST,
        VERIFIER,
        nonce,
    )
    context = EvidenceContext(
        create_presentation(
            credentials,
            private_keys[HOLDER],
            kid=kid[HOLDER],
            nonce=nonce,
        ),
        status_lists,
        issue_eat(private_keys[ATTESTER_ISSUER], kid=kid[ATTESTER_ISSUER], nonce=nonce),
        sign_provenance(private_keys[BUILDER_ID], kid=kid[BUILDER_ID]),
        request,
        CurrentPolicy(POLICY_VERSION, True, True, False, 20),
        NOW - 10,
    )
    return {
        "policies": policies,
        "schemas": schemas,
        "private_keys": private_keys,
        "keys": keys,
        "kids": kid,
        "builder_keys": {kid[BUILDER_ID]: private_keys[BUILDER_ID].public_key()},
        "credentials": credentials,
        "context": context,
    }


@dataclass(frozen=True)
class Case:
    case_id: str
    category: str
    expected_allowed: bool
    run: Callable[[], bool]
    baseline_run: Callable[[], bool]


def _resign_presentation(
    context: EvidenceContext,
    value: Mapping[str, Any],
    credentials: Iterable[str],
    **changes: Any,
) -> EvidenceContext:
    args = {
        "kid": value["kids"][HOLDER],
        "nonce": context.request.nonce,
        "holder": context.request.holder_id,
        "subject": context.request.agent_id,
        "audience": context.request.verifier,
    }
    args.update(changes)
    return replace(
        context,
        presentation=create_presentation(
            credentials, value["private_keys"][HOLDER], **args
        ),
    )


def _resign_credential(
    token: str,
    value: Mapping[str, Any],
    *,
    issuer: str | None = None,
    update_claims: Mapping[str, Any] | None = None,
    update_subject: Mapping[str, Any] | None = None,
) -> str:
    _, claims = _unverified(token)
    changed = dict(claims)
    if update_claims:
        changed.update(update_claims)
    vc = dict(changed["vc"])
    subject = dict(vc["credentialSubject"])
    if update_subject:
        subject.update(update_subject)
    vc["credentialSubject"] = subject
    changed["vc"] = vc
    signer = issuer or str(changed["iss"])
    return jwt.encode(
        changed,
        value["private_keys"][signer],
        algorithm="EdDSA",
        headers={"typ": "vc+jwt", "kid": value["kids"][signer]},
    )


def build_cases() -> list[Case]:
    def gateway_case(
        case_id: str,
        category: str,
        expected: bool = False,
        mutate: Callable[[EvidenceContext, dict[str, Any]], EvidenceContext]
        | None = None,
        prepare: Callable[[EvidenceGateway, EvidenceContext], None] | None = None,
    ) -> Case:
        def run() -> bool:
            value = scenario()
            context = value["context"]
            if mutate:
                context = mutate(context, value)
            gateway = EvidenceGateway(
                value["keys"],
                value["policies"],
                value["schemas"],
                value["builder_keys"],
            )
            if prepare:
                prepare(gateway, context)
            return gateway.authorize(context).allowed

        def baseline() -> bool:
            value = scenario()
            context = value["context"]
            if mutate:
                context = mutate(context, value)
            claims, error = _verify_jws(
                context.presentation, value["keys"], expected_type="vp+jwt"
            )
            return error is None and claims is not None

        return Case(case_id, category, expected, run, baseline)

    def request(**changes: Any):
        return lambda c, _: replace(c, request=replace(c.request, **changes))

    def policy(**changes: Any):
        return lambda c, _: replace(
            c, current_policy=replace(c.current_policy, **changes)
        )

    def credential(index: int, **subject_changes: Any):
        def mutate(c: EvidenceContext, v: dict[str, Any]) -> EvidenceContext:
            items = list(v["credentials"])
            items[index] = _resign_credential(
                items[index], v, update_subject=subject_changes
            )
            return _resign_presentation(c, v, items)

        return mutate

    def status(index: int, revoked: bool = False, **time_changes: Any):
        def mutate(c: EvidenceContext, v: dict[str, Any]) -> EvidenceContext:
            issuer = [REGISTRY_ISSUER, EVALUATOR_ISSUER, GOVERNANCE_ISSUER][index]
            uri = v["policies"][issuer].status_uri
            list_token = issue_status_list(
                v["private_keys"][issuer],
                kid=v["kids"][issuer],
                issuer=issuer,
                status_uri=uri,
                revoked_indices=([7, 11, 19][index],) if revoked else (),
                **time_changes,
            )
            return replace(c, status_lists={**c.status_lists, uri: list_token})

        return mutate

    def eat(**changes: Any):
        def mutate(c: EvidenceContext, v: dict[str, Any]) -> EvidenceContext:
            args = {
                "kid": v["kids"][ATTESTER_ISSUER],
                "nonce": c.request.nonce,
            }
            args.update(changes)
            return replace(
                c,
                workload_attestation=issue_eat(
                    v["private_keys"][ATTESTER_ISSUER],
                    **args,
                ),
            )

        return mutate

    def provenance(**changes: Any):
        def mutate(c: EvidenceContext, v: dict[str, Any]) -> EvidenceContext:
            return replace(
                c,
                provenance=sign_provenance(
                    v["private_keys"][BUILDER_ID],
                    kid=v["kids"][BUILDER_ID],
                    **changes,
                ),
            )

        return mutate

    return [
        gateway_case("valid_complete_evidence", "valid", True),
        gateway_case(
            "presentation_signature_tampered",
            "presentation",
            mutate=lambda c, _: replace(
                c, presentation=tamper_jwt(c.presentation, "sub", "urn:agent:evil")
            ),
        ),
        gateway_case(
            "presentation_wrong_audience",
            "presentation",
            mutate=lambda c, v: _resign_presentation(
                c, v, v["credentials"], audience="https://evil.example"
            ),
        ),
        gateway_case(
            "presentation_wrong_nonce",
            "presentation",
            mutate=lambda c, v: _resign_presentation(
                c, v, v["credentials"], nonce="wrong"
            ),
        ),
        gateway_case(
            "presentation_expired",
            "presentation",
            mutate=lambda c, v: _resign_presentation(
                c, v, v["credentials"], expires_at=NOW
            ),
        ),
        gateway_case(
            "presentation_replayed",
            "presentation",
            prepare=lambda gate, c: gate.replay_cache.consume(
                _unverified(c.presentation)[1]["jti"]
            ),
        ),
        gateway_case(
            "registration_signature_tampered",
            "credential",
            mutate=lambda c, v: _resign_presentation(
                c,
                v,
                (
                    tamper_jwt(v["credentials"][0], "sub", "urn:agent:evil"),
                    *v["credentials"][1:],
                ),
            ),
        ),
        gateway_case(
            "credential_subject_substitution",
            "credential",
            mutate=lambda c, v: _resign_presentation(
                c,
                v,
                (
                    _resign_credential(
                        v["credentials"][0],
                        v,
                        update_claims={"sub": "urn:agent:other"},
                        update_subject={"id": "urn:agent:other"},
                    ),
                    *v["credentials"][1:],
                ),
            ),
        ),
        gateway_case(
            "credential_audience_substitution",
            "credential",
            mutate=lambda c, v: _resign_presentation(
                c,
                v,
                (
                    _resign_credential(
                        v["credentials"][0],
                        v,
                        update_claims={"aud": "https://evil.example"},
                    ),
                    *v["credentials"][1:],
                ),
            ),
        ),
        gateway_case(
            "credential_expired",
            "credential",
            mutate=lambda c, v: _resign_presentation(
                c,
                v,
                (
                    _resign_credential(
                        v["credentials"][0], v, update_claims={"exp": NOW}
                    ),
                    *v["credentials"][1:],
                ),
            ),
        ),
        gateway_case(
            "credential_ttl_excessive",
            "credential",
            mutate=lambda c, v: _resign_presentation(
                c,
                v,
                (
                    _resign_credential(
                        v["credentials"][0],
                        v,
                        update_claims={"exp": NOW + 10_000},
                    ),
                    *v["credentials"][1:],
                ),
            ),
        ),
        gateway_case(
            "credential_schema_invalid",
            "credential",
            mutate=credential(0, owner=7),
        ),
        gateway_case(
            "credential_claim_not_allowed",
            "credential",
            mutate=credential(0, administrator=True),
        ),
        gateway_case("registration_revoked", "status", mutate=status(0, revoked=True)),
        gateway_case("evaluation_revoked", "status", mutate=status(1, revoked=True)),
        gateway_case("governance_revoked", "status", mutate=status(2, revoked=True)),
        gateway_case(
            "signed_status_list_expired",
            "status",
            mutate=status(0, expires_at=NOW),
        ),
        gateway_case(
            "status_cache_stale",
            "status",
            mutate=lambda c, _: replace(c, status_fetched_at=NOW - 121),
        ),
        gateway_case(
            "registration_release_mismatch",
            "binding",
            mutate=credential(0, releaseDigest="sha256:" + "d" * 64),
        ),
        gateway_case(
            "registration_holder_mismatch",
            "binding",
            mutate=credential(0, holderJkt="wrong"),
        ),
        gateway_case(
            "evaluation_release_mismatch",
            "binding",
            mutate=credential(1, releaseDigest="sha256:" + "d" * 64),
        ),
        gateway_case(
            "evaluation_config_mismatch",
            "binding",
            mutate=credential(1, configDigest="sha256:" + "d" * 64),
        ),
        gateway_case(
            "evaluation_failed",
            "negative-evidence",
            mutate=credential(1, result="fail", criticalFailures=1),
        ),
        gateway_case(
            "governance_tenant_mismatch",
            "binding",
            mutate=credential(2, tenantId="tenant:other"),
        ),
        gateway_case(
            "governance_action_not_approved",
            "binding",
            mutate=credential(2, approvedActions=["claim.read"]),
        ),
        gateway_case(
            "governance_resource_not_approved",
            "binding",
            mutate=credential(2, approvedResources=["claim:999"]),
        ),
        gateway_case(
            "governance_policy_stale",
            "binding",
            mutate=credential(2, policyVersion="evidence-policy-old"),
        ),
        gateway_case(
            "eat_signature_tampered",
            "workload",
            mutate=lambda c, _: replace(
                c,
                workload_attestation=tamper_jwt(
                    c.workload_attestation, "sub", "spiffe://evil"
                ),
            ),
        ),
        gateway_case("eat_nonce_mismatch", "workload", mutate=eat(nonce="wrong")),
        gateway_case(
            "eat_workload_mismatch",
            "workload",
            mutate=eat(workload="spiffe://corp.example/prod/other"),
        ),
        gateway_case(
            "eat_release_mismatch",
            "workload",
            mutate=eat(release_digest="sha256:" + "d" * 64),
        ),
        gateway_case(
            "eat_config_mismatch",
            "workload",
            mutate=eat(config_digest="sha256:" + "d" * 64),
        ),
        gateway_case(
            "eat_tool_manifest_mismatch",
            "workload",
            mutate=eat(tool_manifest_digest="sha256:" + "d" * 64),
        ),
        gateway_case("eat_expired", "workload", mutate=eat(expires_at=NOW)),
        gateway_case(
            "provenance_release_mismatch",
            "supply-chain",
            mutate=provenance(release_digest="sha256:" + "d" * 64),
        ),
        gateway_case(
            "provenance_builder_mismatch",
            "supply-chain",
            mutate=provenance(builder_id="https://evil.example/builder"),
        ),
        gateway_case(
            "provenance_source_mismatch",
            "supply-chain",
            mutate=provenance(source="https://evil.example/repo"),
        ),
        gateway_case("agent_quarantined", "lifecycle", mutate=policy(quarantined=True)),
        gateway_case("runtime_risk_high", "lifecycle", mutate=policy(risk_score=50)),
        gateway_case(
            "relationship_inactive",
            "lifecycle",
            mutate=policy(relationship_active=False),
        ),
        gateway_case("task_inactive", "lifecycle", mutate=policy(task_active=False)),
        gateway_case(
            "local_policy_stale",
            "lifecycle",
            mutate=policy(version="evidence-policy-next"),
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


def _evaluate(
    cases: Iterable[Case], baseline: bool
) -> tuple[Metrics, list[dict[str, Any]]]:
    rows = []
    for case in cases:
        actual = case.baseline_run() if baseline else case.run()
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


def evaluate_cases(cases: Iterable[Case]) -> tuple[Metrics, list[dict[str, Any]]]:
    return _evaluate(cases, False)


def evaluate_baseline(cases: Iterable[Case]) -> tuple[Metrics, list[dict[str, Any]]]:
    return _evaluate(cases, True)


def release_gate(metrics: Metrics) -> bool:
    return (
        metrics.total >= 40
        and metrics.invalid_allows == 0
        and metrics.valid_blocked == 0
        and metrics.accuracy == 1.0
    )


if __name__ == "__main__":
    metrics, rows = evaluate_cases(build_cases())
    baseline, _ = evaluate_baseline(build_cases())
    print(
        json.dumps(
            {
                "metrics": asdict(metrics),
                "signature_only_baseline": asdict(baseline),
                "release_gate": release_gate(metrics),
                "mismatches": [row for row in rows if not row["match"]],
            },
            indent=2,
        )
    )
