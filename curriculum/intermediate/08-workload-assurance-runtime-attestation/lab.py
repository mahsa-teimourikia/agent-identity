"""Deterministic workload identity, attestation, provenance, and authorization lab.

The implementation deliberately separates an identity document, attestation
evidence, verifier-issued attestation results, artifact provenance, runtime
posture, and business authorization.  It is a local reference model, not a
replacement for SPIRE, a hardware attester, or Cosign.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from enum import Enum
from hashlib import sha256
import base64
import json
import posixpath
from typing import Any, Mapping
from urllib.parse import urlsplit

import jwt
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


NOW = 1_800_000_000
TRUST_DOMAIN = "northstar.example"
SPIFFE_ID = "spiffe://northstar.example/prod/agents/claims-adjuster"
API_SPIFFE_ID = "spiffe://northstar.example/prod/apis/claims"
WORKLOAD_AUDIENCE = "https://claims-api.northstar.example"
ATTESTATION_AUDIENCE = "https://posture.northstar.example"
ARTIFACT_DIGEST = "sha256:" + "a7" * 32
BUILDER_ID = "https://github.com/northstar/secure-builders/claims@v4"
SOURCE_REPOSITORY = "https://github.com/northstar/claims-agent"
BUILD_TYPE = "https://northstar.example/build/container/v2"
SIGNER_IDENTITY = "https://github.com/northstar/claims-agent/.github/workflows/release.yml@refs/tags/v4.3.1"
SUBJECT = "user:alice"
AGENT = "agent:claims-adjuster"
TASK = "task:clm-100-review"
RESOURCE = "claim:clm-100"
POLICY_VERSION = 15
POSTURE_SCHEMA_VERSION = 3


class LabError(RuntimeError):
    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


class Outcome(str, Enum):
    ALLOW = "allow"
    REATTEST = "reattest"
    QUARANTINE = "quarantine"
    DENY = "deny"


def canonical(value: Any) -> bytes:
    if hasattr(value, "__dataclass_fields__"):
        value = asdict(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def digest(value: Any) -> str:
    return sha256(canonical(value)).hexdigest()


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def dsse_pae(payload_type: str, payload: bytes) -> bytes:
    """DSSE pre-authentication encoding binds type and payload."""

    type_bytes = payload_type.encode()
    return (
        b"DSSEv1 "
        + str(len(type_bytes)).encode()
        + b" "
        + type_bytes
        + b" "
        + str(len(payload)).encode()
        + b" "
        + payload
    )


@dataclass(frozen=True)
class SpiffeId:
    trust_domain: str
    path: str

    @classmethod
    def parse(cls, value: str) -> "SpiffeId":
        if not isinstance(value, str) or not value:
            raise LabError("spiffe_id_invalid")
        parsed = urlsplit(value)
        if (
            parsed.scheme != "spiffe"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.port
            or parsed.query
            or parsed.fragment
        ):
            raise LabError("spiffe_id_invalid")
        if (
            parsed.hostname != parsed.hostname.lower()
            or parsed.netloc != parsed.hostname
        ):
            raise LabError("spiffe_id_noncanonical")
        if not parsed.path.startswith("/") or parsed.path in {"", "/"}:
            raise LabError("spiffe_path_invalid")
        if (
            "//" in parsed.path
            or posixpath.normpath(parsed.path) != parsed.path
            or any(part in {".", ".."} for part in parsed.path.split("/"))
            or any(ord(char) < 0x21 or ord(char) > 0x7E for char in value)
        ):
            raise LabError("spiffe_id_noncanonical")
        return cls(parsed.hostname, parsed.path)

    def __str__(self) -> str:
        return f"spiffe://{self.trust_domain}{self.path}"


@dataclass(frozen=True)
class X509Identity:
    spiffe_id: str
    serial: int
    issued_at: int
    expires_at: int
    certificate_pem: bytes
    private_key_pem: bytes


@dataclass(frozen=True)
class WorkloadSession:
    spiffe_id: str
    format: str
    issued_at: int
    expires_at: int
    credential_id: str


class WorkloadAuthority:
    """Small CA/JWT issuer illustrating SVID validation and bundle rotation."""

    def __init__(self, seed: bytes = b"\x41" * 32, kid: str = "bundle-2026-09"):
        self.key = Ed25519PrivateKey.from_private_bytes(seed)
        self.kid = kid
        self.bundle = {kid: self.key.public_key()}

    def issue_x509(self, spiffe_id: str = SPIFFE_ID, ttl: int = 600) -> X509Identity:
        identity = SpiffeId.parse(spiffe_id)
        if identity.trust_domain != TRUST_DOMAIN:
            raise LabError("trust_domain_untrusted")
        leaf_key = Ed25519PrivateKey.from_private_bytes(
            sha256((spiffe_id + str(NOW)).encode()).digest()
        )
        import datetime

        start = datetime.datetime.fromtimestamp(NOW - 5, datetime.timezone.utc)
        end = datetime.datetime.fromtimestamp(NOW + ttl, datetime.timezone.utc)
        issuer_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, TRUST_DOMAIN)])
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([]))
            .issuer_name(issuer_name)
            .public_key(leaf_key.public_key())
            .serial_number(int(digest({"id": spiffe_id, "now": NOW})[:30], 16))
            .not_valid_before(start)
            .not_valid_after(end)
            .add_extension(
                x509.SubjectAlternativeName(
                    [x509.UniformResourceIdentifier(str(identity))]
                ),
                critical=False,
            )
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True
            )
            .add_extension(
                x509.KeyUsage(
                    True, False, False, False, False, False, False, None, None
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage(
                    [ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH]
                ),
                critical=False,
            )
            .sign(self.key, algorithm=None)
        )
        return X509Identity(
            str(identity),
            cert.serial_number,
            NOW - 5,
            NOW + ttl,
            cert.public_bytes(serialization.Encoding.PEM),
            leaf_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ),
        )

    def verify_x509(
        self, identity: X509Identity, expected_id: str = SPIFFE_ID, now: int = NOW
    ) -> WorkloadSession:
        try:
            cert = x509.load_pem_x509_certificate(identity.certificate_pem)
            self.key.public_key().verify(cert.signature, cert.tbs_certificate_bytes)
            sans = cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            ).value.get_values_for_type(x509.UniformResourceIdentifier)
        except Exception as exc:
            raise LabError("x509_svid_invalid") from exc
        if len(sans) != 1 or sans[0] != expected_id:
            raise LabError("x509_spiffe_id_mismatch")
        parsed = SpiffeId.parse(sans[0])
        if parsed.trust_domain != TRUST_DOMAIN:
            raise LabError("trust_domain_untrusted")
        issued_at = int(cert.not_valid_before_utc.timestamp())
        expires_at = int(cert.not_valid_after_utc.timestamp())
        if not issued_at <= now < expires_at:
            raise LabError("x509_svid_expired")
        return WorkloadSession(
            sans[0],
            "x509-svid",
            issued_at,
            expires_at,
            str(cert.serial_number),
        )

    def issue_jwt(
        self,
        spiffe_id: str = SPIFFE_ID,
        audience: str = WORKLOAD_AUDIENCE,
        ttl: int = 120,
        jti: str = "jwt-svid-001",
    ) -> str:
        SpiffeId.parse(spiffe_id)
        return jwt.encode(
            {
                "iss": f"https://{TRUST_DOMAIN}",
                "sub": spiffe_id,
                "aud": [audience],
                "iat": NOW - 1,
                "exp": NOW + ttl,
                "jti": jti,
            },
            self.key,
            algorithm="EdDSA",
            headers={"alg": "EdDSA", "kid": self.kid, "typ": "JWT"},
        )

    def verify_jwt(
        self, token: str, audience: str = WORKLOAD_AUDIENCE, now: int = NOW
    ) -> WorkloadSession:
        try:
            header = jwt.get_unverified_header(token)
            key = self.bundle[header["kid"]]
            if header.get("alg") != "EdDSA" or header.get("typ") != "JWT":
                raise LabError("jwt_svid_profile_invalid")
            claims = jwt.decode(
                token,
                key,
                algorithms=["EdDSA"],
                issuer=f"https://{TRUST_DOMAIN}",
                audience=audience,
                options={
                    "verify_exp": False,
                    "verify_iat": False,
                    "require": ["iss", "sub", "aud", "iat", "exp", "jti"],
                },
            )
        except LabError:
            raise
        except Exception as exc:
            raise LabError("jwt_svid_invalid") from exc
        parsed = SpiffeId.parse(claims["sub"])
        if parsed.trust_domain != TRUST_DOMAIN:
            raise LabError("trust_domain_untrusted")
        if (
            claims["iat"] > now + 30
            or claims["exp"] <= now
            or claims["exp"] - claims["iat"] > 300
        ):
            raise LabError("jwt_svid_not_current")
        return WorkloadSession(
            claims["sub"], "jwt-svid", claims["iat"], claims["exp"], claims["jti"]
        )

    def rotate(self, seed: bytes = b"\x42" * 32, kid: str = "bundle-2026-10") -> None:
        self.key = Ed25519PrivateKey.from_private_bytes(seed)
        self.kid = kid
        self.bundle[kid] = self.key.public_key()


@dataclass(frozen=True)
class RegistrationEntry:
    spiffe_id: str
    parent_node: str
    required_selectors: frozenset[str]

    def matches(self, node_id: str, selectors: frozenset[str]) -> bool:
        return node_id == self.parent_node and self.required_selectors <= selectors


REGISTRATION = RegistrationEntry(
    SPIFFE_ID,
    "spiffe://northstar.example/spire/agent/prod-node-17",
    frozenset(
        {
            "k8s:ns:claims",
            "k8s:sa:claims-adjuster",
            "container:image:" + ARTIFACT_DIGEST,
        }
    ),
)


@dataclass(frozen=True)
class AttestationResult:
    result_id: str
    spiffe_id: str
    node_id: str
    selectors: tuple[str, ...]
    artifact_digest: str
    verifier_id: str
    policy_id: str
    issued_at: int
    expires_at: int
    token: str


class AttestationVerifier:
    def __init__(self, seed: bytes = b"\x51" * 32):
        self.key = Ed25519PrivateKey.from_private_bytes(seed)
        self.public_key = self.key.public_key()
        self.verifier_id = "verifier:northstar-runtime-v3"

    def appraise(
        self, evidence: Mapping[str, Any], expected_nonce: str
    ) -> AttestationResult:
        required = {
            "nonce",
            "node_id",
            "selectors",
            "artifact_digest",
            "observed_at",
            "evidence_id",
        }
        if set(evidence) != required or evidence["nonce"] != expected_nonce:
            raise LabError("attestation_evidence_invalid")
        selectors = frozenset(evidence["selectors"])
        if NOW - evidence["observed_at"] > 120 or evidence["observed_at"] > NOW + 30:
            raise LabError("attestation_evidence_stale")
        if evidence["artifact_digest"] != ARTIFACT_DIGEST:
            raise LabError("measurement_unapproved")
        if not REGISTRATION.matches(evidence["node_id"], selectors):
            raise LabError("workload_attestation_failed")
        claims = {
            "iss": self.verifier_id,
            "aud": ATTESTATION_AUDIENCE,
            "sub": SPIFFE_ID,
            "iat": NOW,
            "exp": NOW + 300,
            "jti": "result-" + digest(evidence)[:16],
            "node_id": evidence["node_id"],
            "selectors": sorted(selectors),
            "artifact_digest": evidence["artifact_digest"],
            "policy_id": "runtime-baseline-v7",
            "nonce_hash": sha256(expected_nonce.encode()).hexdigest(),
        }
        token = jwt.encode(
            claims,
            self.key,
            algorithm="EdDSA",
            headers={
                "alg": "EdDSA",
                "typ": "attestation-result+jwt",
                "kid": "verifier-2026-09",
            },
        )
        return AttestationResult(
            claims["jti"],
            SPIFFE_ID,
            evidence["node_id"],
            tuple(sorted(selectors)),
            ARTIFACT_DIGEST,
            self.verifier_id,
            claims["policy_id"],
            NOW,
            NOW + 300,
            token,
        )

    def verify(
        self, token: str, expected_nonce: str, now: int = NOW
    ) -> AttestationResult:
        try:
            header = jwt.get_unverified_header(token)
            if header != {
                "alg": "EdDSA",
                "kid": "verifier-2026-09",
                "typ": "attestation-result+jwt",
            }:
                raise LabError("attestation_result_profile_invalid")
            claims = jwt.decode(
                token,
                self.public_key,
                algorithms=["EdDSA"],
                issuer=self.verifier_id,
                audience=ATTESTATION_AUDIENCE,
                options={"verify_exp": False, "verify_iat": False},
            )
        except LabError:
            raise
        except Exception as exc:
            raise LabError("attestation_result_invalid") from exc
        if claims["exp"] <= now or claims["iat"] > now + 30:
            raise LabError("attestation_result_stale")
        if claims["nonce_hash"] != sha256(expected_nonce.encode()).hexdigest():
            raise LabError("attestation_nonce_mismatch")
        return AttestationResult(
            claims["jti"],
            claims["sub"],
            claims["node_id"],
            tuple(claims["selectors"]),
            claims["artifact_digest"],
            claims["iss"],
            claims["policy_id"],
            claims["iat"],
            claims["exp"],
            token,
        )


def default_evidence(**updates: Any) -> dict[str, Any]:
    value = {
        "nonce": "nonce-8f13",
        "node_id": REGISTRATION.parent_node,
        "selectors": sorted(REGISTRATION.required_selectors),
        "artifact_digest": ARTIFACT_DIGEST,
        "observed_at": NOW - 5,
        "evidence_id": "evidence-001",
    }
    value.update(updates)
    return value


@dataclass(frozen=True)
class ProvenanceResult:
    artifact_digest: str
    builder_id: str
    source_repository: str
    build_type: str
    signer_identity: str
    verified_at: int
    envelope_digest: str


class ProvenanceVerifier:
    def __init__(self, seed: bytes = b"\x61" * 32):
        self.key = Ed25519PrivateKey.from_private_bytes(seed)

    def sign(self, **updates: Any) -> dict[str, Any]:
        statement = {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [
                {
                    "name": "claims-agent",
                    "digest": {"sha256": ARTIFACT_DIGEST.split(":", 1)[1]},
                }
            ],
            "predicateType": "https://slsa.dev/provenance/v1",
            "predicate": {
                "buildDefinition": {
                    "buildType": BUILD_TYPE,
                    "externalParameters": {"source": SOURCE_REPOSITORY},
                },
                "runDetails": {"builder": {"id": BUILDER_ID}},
            },
            "signer_identity": SIGNER_IDENTITY,
        }
        for dotted, value in updates.items():
            if dotted == "artifact_digest":
                statement["subject"][0]["digest"]["sha256"] = value.removeprefix(
                    "sha256:"
                )
            elif dotted == "builder_id":
                statement["predicate"]["runDetails"]["builder"]["id"] = value
            elif dotted == "source_repository":
                statement["predicate"]["buildDefinition"]["externalParameters"][
                    "source"
                ] = value
            elif dotted == "build_type":
                statement["predicate"]["buildDefinition"]["buildType"] = value
            elif dotted == "signer_identity":
                statement["signer_identity"] = value
        payload_type = "application/vnd.in-toto+json"
        payload = canonical(statement)
        return {
            "payloadType": payload_type,
            "payload": b64url(payload),
            "signature": b64url(self.key.sign(dsse_pae(payload_type, payload))),
        }

    def verify(self, envelope: Mapping[str, str]) -> ProvenanceResult:
        try:
            if (
                set(envelope) != {"payloadType", "payload", "signature"}
                or envelope["payloadType"] != "application/vnd.in-toto+json"
            ):
                raise LabError("provenance_envelope_invalid")
            payload = base64.urlsafe_b64decode(envelope["payload"] + "==")
            signature = base64.urlsafe_b64decode(envelope["signature"] + "==")
            self.key.public_key().verify(
                signature, dsse_pae(envelope["payloadType"], payload)
            )
            statement = json.loads(payload)
            artifact = "sha256:" + statement["subject"][0]["digest"]["sha256"]
            predicate = statement["predicate"]
            builder = predicate["runDetails"]["builder"]["id"]
            build_type = predicate["buildDefinition"]["buildType"]
            source = predicate["buildDefinition"]["externalParameters"]["source"]
        except LabError:
            raise
        except Exception as exc:
            raise LabError("provenance_invalid") from exc
        expected = (
            statement.get("_type") == "https://in-toto.io/Statement/v1"
            and statement.get("predicateType") == "https://slsa.dev/provenance/v1"
            and artifact == ARTIFACT_DIGEST
            and builder == BUILDER_ID
            and source == SOURCE_REPOSITORY
            and build_type == BUILD_TYPE
            and statement.get("signer_identity") == SIGNER_IDENTITY
        )
        if not expected:
            raise LabError("provenance_policy_failed")
        return ProvenanceResult(
            artifact,
            builder,
            source,
            build_type,
            statement["signer_identity"],
            NOW,
            digest(envelope),
        )


@dataclass(frozen=True)
class RuntimePosture:
    spiffe_id: str
    artifact_digest: str
    node_id: str
    attestation_result_id: str
    attestation_expires_at: int
    provenance_digest: str
    status: str
    schema_version: int = POSTURE_SCHEMA_VERSION


@dataclass(frozen=True)
class Decision:
    outcome: Outcome
    reasons: tuple[str, ...]
    evidence_digest: str
    policy_version: int = POLICY_VERSION


class AssuranceEngine:
    def __init__(self):
        self.authority = WorkloadAuthority()
        self.attestation = AttestationVerifier()
        self.provenance = ProvenanceVerifier()
        self.allowed_spiffe_ids = {AGENT: {SPIFFE_ID}}
        self.task = {
            "id": TASK,
            "subject": SUBJECT,
            "resource": RESOURCE,
            "actions": {"claim.read", "claim.update"},
            "active": True,
        }
        self.status = "active"

    def posture(
        self,
        session: WorkloadSession,
        result: AttestationResult,
        provenance: ProvenanceResult,
    ) -> RuntimePosture:
        if session.spiffe_id != result.spiffe_id:
            raise LabError("identity_attestation_binding_invalid")
        if result.artifact_digest != provenance.artifact_digest:
            raise LabError("attestation_provenance_binding_invalid")
        return RuntimePosture(
            session.spiffe_id,
            result.artifact_digest,
            result.node_id,
            result.result_id,
            result.expires_at,
            provenance.envelope_digest,
            self.status,
        )

    def authorize(
        self,
        posture: RuntimePosture,
        action: str = "claim.update",
        resource: str = RESOURCE,
        now: int = NOW,
    ) -> Decision:
        reasons = []
        if posture.schema_version != POSTURE_SCHEMA_VERSION:
            reasons.append("posture_schema_untrusted")
        if posture.spiffe_id not in self.allowed_spiffe_ids.get(AGENT, set()):
            reasons.append("agent_workload_binding_invalid")
        if posture.artifact_digest != ARTIFACT_DIGEST:
            reasons.append("artifact_unapproved")
        if posture.status == "quarantined" or self.status == "quarantined":
            return Decision(
                Outcome.QUARANTINE, ("workload_quarantined",), digest(posture)
            )
        if reasons:
            return Decision(Outcome.DENY, tuple(sorted(reasons)), digest(posture))
        if posture.attestation_expires_at <= now:
            return Decision(
                Outcome.REATTEST, ("attestation_result_stale",), digest(posture)
            )
        if (
            not self.task["active"]
            or action not in self.task["actions"]
            or resource != self.task["resource"]
        ):
            return Decision(
                Outcome.DENY, ("business_authority_invalid",), digest(posture)
            )
        return Decision(Outcome.ALLOW, ("requirements_satisfied",), digest(posture))


def fixture() -> tuple[
    AssuranceEngine,
    WorkloadSession,
    AttestationResult,
    ProvenanceResult,
    RuntimePosture,
]:
    engine = AssuranceEngine()
    session = engine.authority.verify_x509(engine.authority.issue_x509())
    result = engine.attestation.verify(
        engine.attestation.appraise(default_evidence(), "nonce-8f13").token,
        "nonce-8f13",
    )
    provenance = engine.provenance.verify(engine.provenance.sign())
    posture = engine.posture(session, result, provenance)
    return engine, session, result, provenance, posture


@dataclass(frozen=True)
class Scenario:
    name: str
    expected: Outcome


def build_cases() -> list[Scenario]:
    return [
        Scenario("valid", Outcome.ALLOW),
        Scenario("wrong_action", Outcome.DENY),
        Scenario("wrong_resource", Outcome.DENY),
        Scenario("inactive_task", Outcome.DENY),
        Scenario("stale_attestation", Outcome.REATTEST),
        Scenario("quarantined", Outcome.QUARANTINE),
        Scenario("wrong_spiffe", Outcome.DENY),
        Scenario("wrong_artifact", Outcome.DENY),
        Scenario("wrong_schema", Outcome.DENY),
    ]


def run_case(case: Scenario) -> Outcome:
    engine, _, _, _, posture = fixture()
    action, resource, now = "claim.update", RESOURCE, NOW
    if case.name == "wrong_action":
        action = "payment.create"
    elif case.name == "wrong_resource":
        resource = "claim:clm-999"
    elif case.name == "inactive_task":
        engine.task["active"] = False
    elif case.name == "stale_attestation":
        now = posture.attestation_expires_at
    elif case.name == "quarantined":
        engine.status = "quarantined"
    elif case.name == "wrong_spiffe":
        posture = replace(
            posture, spiffe_id="spiffe://northstar.example/prod/agents/evil"
        )
    elif case.name == "wrong_artifact":
        posture = replace(posture, artifact_digest="sha256:" + "00" * 32)
    elif case.name == "wrong_schema":
        posture = replace(posture, schema_version=999)
    return engine.authorize(posture, action, resource, now).outcome


def main() -> None:
    rows = [
        {"case": c.name, "expected": c.expected.value, "observed": run_case(c).value}
        for c in build_cases()
    ]
    print(json.dumps(rows, indent=2))
    print(
        "release_gate",
        "PASS" if all(r["expected"] == r["observed"] for r in rows) else "FAIL",
    )


if __name__ == "__main__":
    main()
