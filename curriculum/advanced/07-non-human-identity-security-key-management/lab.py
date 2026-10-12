"""Deterministic non-human identity and key-management teaching lab."""

from __future__ import annotations

import base64
import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from threading import RLock
from typing import Any

import jwt
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.x509.oid import NameOID

NOW = 1_800_000_000
SPIFFE_ID = "spiffe://northstar.example/agent/claims-investigator"
TRUST_DOMAIN = "northstar.example"
AUDIENCE = "https://claims-api.northstar.example"
RESOURCE_URI = AUDIENCE + "/claims/483"
ACTION = "claim.read"
TOKEN_ISSUER = "https://sts.northstar.example"
DPoP_TYP = "dpop+jwt"


class SecurityError(ValueError):
    pass


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def digest(value: Any) -> str:
    if isinstance(value, str):
        value = value.encode()
    elif not isinstance(value, bytes):
        value = canonical(value).encode()
    return b64url(sha256(value).digest())


def deterministic_key(label: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(sha256(label.encode()).digest())


def public_jwk(key: Ed25519PrivateKey) -> dict[str, str]:
    raw = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return {"crv": "Ed25519", "kty": "OKP", "x": b64url(raw)}


def jwk_thumbprint(jwk: dict[str, str]) -> str:
    if (
        set(jwk) != {"crv", "kty", "x"}
        or jwk["crv"] != "Ed25519"
        or jwk["kty"] != "OKP"
    ):
        raise SecurityError("jwk_invalid")
    return digest(jwk)


def issue_ca(label: str = "northstar-ca") -> tuple[Ed25519PrivateKey, x509.Certificate]:
    key = deterministic_key(label)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Northstar SPIFFE CA")])
    start = datetime.fromtimestamp(NOW - 3600, timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(start)
        .not_valid_after(start + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(key, algorithm=None)
    )
    return key, cert


def issue_svid(
    ca_key: Ed25519PrivateKey,
    ca_cert: x509.Certificate,
    workload_key: Ed25519PrivateKey,
    *,
    spiffe_id: str = SPIFFE_ID,
    now: int = NOW,
    lifetime: int = 600,
    serial: int = 100,
) -> x509.Certificate:
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SPIFFE Workload")])
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(workload_key.public_key())
        .serial_number(serial)
        .not_valid_before(datetime.fromtimestamp(now - 5, timezone.utc))
        .not_valid_after(datetime.fromtimestamp(now + lifetime, timezone.utc))
        .add_extension(
            x509.SubjectAlternativeName([x509.UniformResourceIdentifier(spiffe_id)]),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(True, False, False, False, False, False, False, False, False),
            critical=True,
        )
        .sign(ca_key, algorithm=None)
    )


def validate_svid(
    cert: x509.Certificate,
    bundle: x509.Certificate,
    *,
    expected_id: str = SPIFFE_ID,
    now: int = NOW,
) -> str:
    try:
        bundle.public_key().verify(cert.signature, cert.tbs_certificate_bytes)
        uris = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value.get_values_for_type(x509.UniformResourceIdentifier)
        constraints = cert.extensions.get_extension_for_class(
            x509.BasicConstraints
        ).value
        usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    except (InvalidSignature, ValueError, x509.ExtensionNotFound) as exc:
        raise SecurityError("svid_invalid") from exc
    current = datetime.fromtimestamp(now, timezone.utc)
    if not (cert.not_valid_before_utc <= current < cert.not_valid_after_utc):
        raise SecurityError("svid_time_invalid")
    if uris != [expected_id] or constraints.ca or not usage.digital_signature:
        raise SecurityError("svid_profile_invalid")
    if not expected_id.startswith(f"spiffe://{TRUST_DOMAIN}/"):
        raise SecurityError("trust_domain_invalid")
    return expected_id


@dataclass(frozen=True)
class KeyRecord:
    key_id: str
    purpose: str
    version: int
    state: str
    created_at: int
    retire_at: int | None = None


@dataclass
class KeyInventory:
    records: dict[str, KeyRecord] = field(default_factory=dict)
    materials: dict[str, Ed25519PrivateKey] = field(default_factory=dict)

    def create(self, purpose: str, version: int, now: int = NOW) -> KeyRecord:
        key_id = f"{purpose}:v{version}"
        if key_id in self.records:
            raise SecurityError("key_exists")
        record = KeyRecord(key_id, purpose, version, "active", now)
        self.records[key_id] = record
        self.materials[key_id] = deterministic_key(key_id)
        return record

    def rotate(self, key_id: str, *, overlap: int = 120, now: int = NOW) -> KeyRecord:
        current = self.records[key_id]
        if current.state != "active" or overlap < 0 or overlap > 300:
            raise SecurityError("rotation_invalid")
        self.records[key_id] = replace(
            current, state="retiring", retire_at=now + overlap
        )
        return self.create(current.purpose, current.version + 1, now)

    def key_for(self, key_id: str, purpose: str, now: int = NOW) -> Ed25519PrivateKey:
        record = self.records.get(key_id)
        if record is None or record.purpose != purpose or record.state == "revoked":
            raise SecurityError("key_not_usable")
        if record.state == "retiring" and (
            record.retire_at is None or now >= record.retire_at
        ):
            raise SecurityError("key_not_usable")
        return self.materials[key_id]

    def revoke(self, key_id: str) -> None:
        self.records[key_id] = replace(
            self.records[key_id], state="revoked", retire_at=None
        )


@dataclass
class ReplayCache:
    values: set[str] = field(default_factory=set)
    lock: RLock = field(default_factory=RLock)

    def consume(self, value: str) -> None:
        with self.lock:
            if not value or value in self.values:
                raise SecurityError("replay_detected")
            self.values.add(value)


def issue_access_token(
    issuer_key: Ed25519PrivateKey,
    *,
    subject: str = SPIFFE_ID,
    audience: str = AUDIENCE,
    scopes: tuple[str, ...] = (ACTION,),
    confirmation_jwk: dict[str, str],
    now: int = NOW,
    lifetime: int = 300,
    jti: str = "access:001",
) -> str:
    claims = {
        "iss": TOKEN_ISSUER,
        "sub": subject,
        "aud": audience,
        "scope": " ".join(scopes),
        "iat": now,
        "nbf": now,
        "exp": now + lifetime,
        "jti": jti,
        "cnf": {"jkt": jwk_thumbprint(confirmation_jwk)},
    }
    return jwt.encode(
        claims,
        issuer_key,
        algorithm="EdDSA",
        headers={"typ": "at+jwt", "kid": "sts:v1"},
    )


def issue_dpop(
    key: Ed25519PrivateKey,
    token: str,
    *,
    method: str = "GET",
    uri: str = RESOURCE_URI,
    now: int = NOW,
    jti: str = "dpop:001",
    nonce: str = "resource-nonce",
) -> str:
    claims = {
        "htm": method,
        "htu": uri,
        "iat": now,
        "jti": jti,
        "ath": digest(token),
        "nonce": nonce,
    }
    return jwt.encode(
        claims,
        key,
        algorithm="EdDSA",
        headers={"typ": DPoP_TYP, "jwk": public_jwk(key)},
    )


def public_key_from_jwk(jwk: dict[str, str]):
    try:
        raw = base64.urlsafe_b64decode(jwk["x"] + "==")
        return Ed25519PublicKey.from_public_bytes(raw)
    except (KeyError, ValueError) as exc:
        raise SecurityError("jwk_invalid") from exc


def authorize_request(
    token: str,
    proof: str,
    issuer_public_key,
    *,
    method: str = "GET",
    uri: str = RESOURCE_URI,
    action: str = ACTION,
    nonce: str = "resource-nonce",
    now: int = NOW,
    replay: ReplayCache | None = None,
    identity_state: str = "active",
) -> dict[str, Any]:
    try:
        header = jwt.get_unverified_header(token)
        if header != {"alg": "EdDSA", "kid": "sts:v1", "typ": "at+jwt"}:
            raise SecurityError("access_profile_invalid")
        claims = jwt.decode(
            token,
            issuer_public_key,
            algorithms=["EdDSA"],
            audience=AUDIENCE,
            issuer=TOKEN_ISSUER,
            options={"verify_exp": False, "verify_iat": False, "verify_nbf": False},
        )
    except jwt.PyJWTError as exc:
        raise SecurityError("access_token_invalid") from exc
    if (
        claims["iat"] > now + 30
        or claims["nbf"] > now
        or claims["exp"] <= now
        or claims["exp"] - claims["iat"] > 600
    ):
        raise SecurityError("access_time_invalid")
    if (
        claims["sub"] != SPIFFE_ID
        or action not in claims["scope"].split()
        or identity_state != "active"
    ):
        raise SecurityError("access_policy_denied")
    proof_header = jwt.get_unverified_header(proof)
    if (
        proof_header.get("typ") != DPoP_TYP
        or proof_header.get("alg") != "EdDSA"
        or "jwk" not in proof_header
    ):
        raise SecurityError("dpop_profile_invalid")
    proof_jwk = proof_header["jwk"]
    try:
        proof_claims = jwt.decode(
            proof,
            public_key_from_jwk(proof_jwk),
            algorithms=["EdDSA"],
            options={"verify_aud": False, "verify_iat": False},
        )
    except jwt.PyJWTError as exc:
        raise SecurityError("dpop_signature_invalid") from exc
    if claims.get("cnf", {}).get("jkt") != jwk_thumbprint(proof_jwk):
        raise SecurityError("dpop_binding_invalid")
    if (
        proof_claims.get("htm") != method
        or proof_claims.get("htu") != uri
        or proof_claims.get("ath") != digest(token)
        or proof_claims.get("nonce") != nonce
        or abs(now - proof_claims.get("iat", 0)) > 60
    ):
        raise SecurityError("dpop_request_invalid")
    (replay or ReplayCache()).consume(proof_claims.get("jti"))
    return {
        "allowed": True,
        "subject": claims["sub"],
        "action": action,
        "resource": uri,
        "token_id": claims["jti"],
    }


SECRET_PATTERNS = (
    re.compile(r"(?i)authorization:\s*(?:bearer|dpop)\s+[A-Za-z0-9._~-]+"),
    re.compile(r"AKIA[A-Z0-9]{16}"),
    re.compile(
        r"-----BEGIN (?:RSA |EC |OPENSSH |)PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |)PRIVATE KEY-----"
    ),
)


def redact(value: str) -> str:
    for pattern in SECRET_PATTERNS:
        value = pattern.sub("[REDACTED]", value)
    return value


@dataclass
class Scenario:
    ca_key: Ed25519PrivateKey
    ca_cert: x509.Certificate
    workload_key: Ed25519PrivateKey
    svid: x509.Certificate
    issuer_key: Ed25519PrivateKey
    dpop_key: Ed25519PrivateKey
    token: str
    proof: str
    replay: ReplayCache = field(default_factory=ReplayCache)
    identity_state: str = "active"


def scenario(case_id: str = "default") -> Scenario:
    ca_key, ca_cert = issue_ca()
    workload_key = deterministic_key("workload:v1")
    svid = issue_svid(ca_key, ca_cert, workload_key)
    issuer_key = deterministic_key("sts:v1")
    dpop_key = deterministic_key(f"dpop:{case_id}")
    token = issue_access_token(
        issuer_key, confirmation_jwk=public_jwk(dpop_key), jti=f"access:{case_id}"
    )
    proof = issue_dpop(dpop_key, token, jti=f"dpop:{case_id}")
    return Scenario(
        ca_key, ca_cert, workload_key, svid, issuer_key, dpop_key, token, proof
    )


def hardened(value: Scenario, **request: Any) -> bool:
    try:
        validate_svid(value.svid, value.ca_cert)
        authorize_request(
            value.token,
            value.proof,
            value.issuer_key.public_key(),
            replay=value.replay,
            identity_state=value.identity_state,
            **request,
        )
        return True
    except (SecurityError, KeyError, TypeError, ValueError):
        return False


def bearer_baseline(value: Scenario, **request: Any) -> bool:
    try:
        claims = jwt.decode(value.token, options={"verify_signature": False})
        return claims.get("exp", 0) > NOW
    except jwt.PyJWTError:
        return False


Mutation = Callable[[Scenario], dict[str, Any] | None]


@dataclass(frozen=True)
class Case:
    case_id: str
    category: str
    expected: bool
    mutate: Mutation = lambda value: None

    def run(self, baseline: bool = False) -> bool:
        value = scenario(self.case_id)
        request = self.mutate(value) or {}
        return (bearer_baseline if baseline else hardened)(value, **request)


def _token(value: Scenario, **changes: Any) -> None:
    args = {
        "subject": SPIFFE_ID,
        "audience": AUDIENCE,
        "scopes": (ACTION,),
        "confirmation_jwk": public_jwk(value.dpop_key),
        "now": NOW,
        "lifetime": 300,
        "jti": "access:mutated",
    }
    args.update(changes)
    value.token = issue_access_token(value.issuer_key, **args)
    value.proof = issue_dpop(value.dpop_key, value.token, jti="dpop:mutated")


def _proof(value: Scenario, **changes: Any) -> None:
    args = {"key": value.dpop_key, "token": value.token, "jti": "dpop:mutated"}
    args.update(changes)
    value.proof = issue_dpop(**args)


def cases() -> list[Case]:
    attacker = deterministic_key("attacker")
    return [
        Case("valid", "valid", True),
        Case("valid-rotated-dpop", "valid", True, lambda v: _rotate_dpop(v)),
        Case(
            "svid-wrong-id",
            "svid",
            False,
            lambda v: setattr(
                v,
                "svid",
                issue_svid(
                    v.ca_key,
                    v.ca_cert,
                    v.workload_key,
                    spiffe_id="spiffe://northstar.example/agent/evil",
                ),
            ),
        ),
        Case(
            "svid-expired",
            "svid",
            False,
            lambda v: setattr(
                v,
                "svid",
                issue_svid(
                    v.ca_key, v.ca_cert, v.workload_key, now=NOW - 1000, lifetime=100
                ),
            ),
        ),
        Case(
            "svid-untrusted-ca",
            "svid",
            False,
            lambda v: setattr(v, "svid", issue_svid(*issue_ca("evil"), v.workload_key)),
        ),
        Case(
            "token-forged",
            "token",
            False,
            lambda v: setattr(
                v,
                "token",
                issue_access_token(attacker, confirmation_jwk=public_jwk(v.dpop_key)),
            ),
        ),
        Case(
            "token-wrong-subject",
            "token",
            False,
            lambda v: _token(v, subject="spiffe://northstar.example/agent/evil"),
        ),
        Case(
            "token-wrong-audience",
            "token",
            False,
            lambda v: _token(v, audience="https://payments.example"),
        ),
        Case(
            "token-expired",
            "token",
            False,
            lambda v: _token(v, now=NOW - 1000, lifetime=100),
        ),
        Case("token-long-lived", "token", False, lambda v: _token(v, lifetime=3600)),
        Case(
            "token-scope-escalation",
            "token",
            False,
            lambda v: {"action": "claim.approve"},
        ),
        Case(
            "identity-quarantined",
            "lifecycle",
            False,
            lambda v: setattr(v, "identity_state", "quarantined"),
        ),
        Case(
            "identity-retired",
            "lifecycle",
            False,
            lambda v: setattr(v, "identity_state", "retired"),
        ),
        Case("dpop-wrong-key", "sender", False, lambda v: _proof(v, key=attacker)),
        Case("dpop-wrong-method", "sender", False, lambda v: _proof(v, method="POST")),
        Case(
            "dpop-wrong-uri",
            "sender",
            False,
            lambda v: _proof(v, uri=AUDIENCE + "/claims/999"),
        ),
        Case("dpop-wrong-token", "sender", False, lambda v: _proof(v, token="stolen")),
        Case(
            "dpop-wrong-nonce", "sender", False, lambda v: _proof(v, nonce="attacker")
        ),
        Case("dpop-stale", "sender", False, lambda v: _proof(v, now=NOW - 100)),
        Case("dpop-replay", "sender", False, _replay),
        Case("request-wrong-method", "request", False, lambda v: {"method": "POST"}),
        Case(
            "request-wrong-uri",
            "request",
            False,
            lambda v: {"uri": AUDIENCE + "/claims/999"},
        ),
        Case("request-wrong-nonce", "request", False, lambda v: {"nonce": "other"}),
        Case(
            "request-wrong-action",
            "request",
            False,
            lambda v: {"action": "claim.delete"},
        ),
    ]


def _rotate_dpop(value: Scenario) -> None:
    value.dpop_key = deterministic_key("dpop:rotated")
    _token(value, confirmation_jwk=public_jwk(value.dpop_key))


def _replay(value: Scenario) -> None:
    authorize_request(
        value.token, value.proof, value.issuer_key.public_key(), replay=value.replay
    )


@dataclass(frozen=True)
class Metrics:
    total: int
    correct: int
    invalid_allows: int
    valid_blocks: int


def evaluate(baseline: bool = False) -> tuple[Metrics, list[dict[str, Any]]]:
    rows = []
    for case in cases():
        allowed = case.run(baseline)
        rows.append(
            {
                "case_id": case.case_id,
                "category": case.category,
                "expected": case.expected,
                "allowed": allowed,
                "match": allowed is case.expected,
            }
        )
    return Metrics(
        len(rows),
        sum(r["match"] for r in rows),
        sum(r["allowed"] and not r["expected"] for r in rows),
        sum(not r["allowed"] and r["expected"] for r in rows),
    ), rows


def main() -> None:
    secure, _ = evaluate()
    baseline, _ = evaluate(True)
    print(
        f"hardened: {secure.correct}/{secure.total}; invalid allows={secure.invalid_allows}"
    )
    print(f"bearer baseline invalid allows={baseline.invalid_allows}")
    print("release gate:", "PASS" if secure.correct == secure.total else "FAIL")


if __name__ == "__main__":
    main()
