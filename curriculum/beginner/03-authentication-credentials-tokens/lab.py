"""Deterministic credential-verification lab for Beginner 03.

The lab defines a synthetic, single-use agent action-token profile and compares
signature-only JWT handling with explicit header, key, claim, lifetime, subject,
and replay validation. It uses maintained PyJWT and cryptography primitives,
performs no network calls, and never exposes token values in decision records.

This is a teaching profile, not a replacement for OAuth, DPoP, mTLS, SPIFFE, or
an identity provider. Production access tokens are not generally single-use;
the replay rule here is specific to consequential action assertions.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from enum import Enum
import hashlib
import json
import re
from typing import Callable, Iterable

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


NOW = datetime(2026, 9, 20, 12, 0, tzinfo=timezone.utc)
NOW_TS = int(NOW.timestamp())
ISSUER = "https://identity.corp.example"
AUDIENCE = "purchasing-api"
TOKEN_TYPE = "agent-action+jwt"
ALGORITHM = "EdDSA"
POLICY_VERSION = "agent-action-token/v1"
MAX_LIFETIME_SECONDS = 300
KID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
REQUIRED_CLAIMS = ("iss", "sub", "aud", "iat", "nbf", "exp", "jti", "action")


class KeyStatus(str, Enum):
    ACTIVE = "active"
    RETIRING = "retiring"
    REVOKED = "revoked"


@dataclass(frozen=True)
class SigningKey:
    key_id: str
    algorithm: str
    public_key: Ed25519PublicKey
    status: KeyStatus


@dataclass(frozen=True)
class TrustedKeySet:
    issuer: str
    keys: dict[str, SigningKey]


@dataclass(frozen=True)
class TokenProfile:
    issuer: str
    audience: str
    token_type: str
    algorithm: str
    max_lifetime_seconds: int
    allowed_subjects: frozenset[str]
    allowed_actions: frozenset[str]
    clock_skew_seconds: int = 0


@dataclass(frozen=True)
class VerificationDecision:
    accepted: bool
    reason_code: str
    decision_id: str
    token_digest: str
    key_id: str | None
    subject: str | None = None
    token_id: str | None = None
    action: str | None = None
    checks: tuple[str, ...] = ()
    policy_version: str = POLICY_VERSION

    @property
    def evidence_complete(self) -> bool:
        return bool(
            self.decision_id
            and self.token_digest
            and self.reason_code
            and self.policy_version
            and self.checks
        )


@dataclass(frozen=True)
class TokenCase:
    case_id: str
    token: str
    expected_accepts: tuple[bool, ...]
    expected_reasons: tuple[str, ...]


@dataclass(frozen=True)
class EvaluationReport:
    attempts: int
    expected_valid_attempts: int
    expected_invalid_attempts: int
    valid_attempt_success_rate: float
    invalid_acceptance_rate: float
    invalid_block_rate: float
    replay_block_rate: float
    evidence_completeness_rate: float

    def as_dict(self) -> dict[str, float | int]:
        return {
            "attempts": self.attempts,
            "expected_valid_attempts": self.expected_valid_attempts,
            "expected_invalid_attempts": self.expected_invalid_attempts,
            "valid_attempt_success_rate": self.valid_attempt_success_rate,
            "invalid_acceptance_rate": self.invalid_acceptance_rate,
            "invalid_block_rate": self.invalid_block_rate,
            "replay_block_rate": self.replay_block_rate,
            "evidence_completeness_rate": self.evidence_completeness_rate,
        }


class ReplayCache:
    """Small deterministic stand-in for an atomic, expiring replay store."""

    def __init__(self) -> None:
        self._consumed: dict[tuple[str, str], int] = {}

    def consume(self, issuer: str, token_id: str, expires_at: int, now: int) -> bool:
        self._consumed = {
            key: expiry for key, expiry in self._consumed.items() if expiry > now
        }
        key = (issuer, token_id)
        if key in self._consumed:
            return False
        self._consumed[key] = expires_at
        return True


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _private_key(label: str) -> Ed25519PrivateKey:
    """Derive deterministic synthetic fixture material; never use this in production."""
    seed = hashlib.sha256(f"course03-fixture:{label}".encode()).digest()
    return Ed25519PrivateKey.from_private_bytes(seed)


def public_jwk(key: SigningKey) -> dict[str, str]:
    return {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": _b64url(key.public_key.public_bytes_raw()),
        "kid": key.key_id,
        "alg": key.algorithm,
        "use": "sig",
    }


def build_key_material() -> tuple[dict[str, Ed25519PrivateKey], TrustedKeySet]:
    private_keys = {
        "sig-2026-08": _private_key("retiring"),
        "sig-2026-09": _private_key("active"),
        "sig-2026-07-revoked": _private_key("revoked"),
        "attacker-key": _private_key("attacker"),
    }
    records = {
        "sig-2026-08": SigningKey(
            "sig-2026-08", ALGORITHM, private_keys["sig-2026-08"].public_key(), KeyStatus.RETIRING
        ),
        "sig-2026-09": SigningKey(
            "sig-2026-09", ALGORITHM, private_keys["sig-2026-09"].public_key(), KeyStatus.ACTIVE
        ),
        "sig-2026-07-revoked": SigningKey(
            "sig-2026-07-revoked",
            ALGORITHM,
            private_keys["sig-2026-07-revoked"].public_key(),
            KeyStatus.REVOKED,
        ),
    }
    return private_keys, TrustedKeySet(ISSUER, records)


def build_profile() -> TokenProfile:
    return TokenProfile(
        issuer=ISSUER,
        audience=AUDIENCE,
        token_type=TOKEN_TYPE,
        algorithm=ALGORITHM,
        max_lifetime_seconds=MAX_LIFETIME_SECONDS,
        allowed_subjects=frozenset({"agent:procurement"}),
        allowed_actions=frozenset({"purchase:create"}),
    )


def base_claims(**overrides: object) -> dict[str, object]:
    claims: dict[str, object] = {
        "iss": ISSUER,
        "sub": "agent:procurement",
        "aud": AUDIENCE,
        "iat": NOW_TS - 10,
        "nbf": NOW_TS - 10,
        "exp": NOW_TS + 110,
        "jti": "action-483-valid",
        "action": "purchase:create",
    }
    claims.update(overrides)
    return claims


def mint_token(
    private_key: Ed25519PrivateKey,
    key_id: str,
    claims: dict[str, object],
    *,
    token_type: str | None = TOKEN_TYPE,
) -> str:
    headers: dict[str, str] = {"kid": key_id}
    if token_type is not None:
        headers["typ"] = token_type
    return jwt.encode(claims, private_key, algorithm=ALGORITHM, headers=headers)


def _token_digest(token: str) -> str:
    return f"sha256:{hashlib.sha256(token.encode()).hexdigest()}"


def _decision_id(token: str, attempt: int) -> str:
    digest = hashlib.sha256(f"{_token_digest(token)}:{attempt}".encode()).hexdigest()[:16]
    return f"decision:{digest}"


def _decision(
    token: str,
    attempt: int,
    *,
    accepted: bool,
    reason: str,
    key_id: str | None,
    subject: str | None = None,
    token_id: str | None = None,
    action: str | None = None,
    checks: tuple[str, ...],
) -> VerificationDecision:
    return VerificationDecision(
        accepted=accepted,
        reason_code=reason,
        decision_id=_decision_id(token, attempt),
        token_digest=_token_digest(token),
        key_id=key_id,
        subject=subject,
        token_id=token_id,
        action=action,
        checks=checks,
    )


def _header(token: str) -> tuple[dict[str, object] | None, str | None]:
    try:
        header = jwt.get_unverified_header(token)
    except jwt.PyJWTError:
        return None, "malformed_token"
    return header, None


def signature_only_baseline(
    token: str,
    key_set: TrustedKeySet,
    profile: TokenProfile,
    replay_cache: ReplayCache,
    attempt: int,
) -> VerificationDecision:
    """Unsafe baseline: verify a known signature but ignore token semantics."""
    del profile, replay_cache
    header, error = _header(token)
    if error or header is None:
        return _decision(token, attempt, accepted=False, reason=error or "malformed_token", key_id=None, checks=("header_parsed",))
    key_id = header.get("kid")
    key = key_set.keys.get(key_id) if isinstance(key_id, str) else None
    if not key:
        return _decision(token, attempt, accepted=False, reason="unknown_key", key_id=None, checks=("header_parsed", "key_lookup"))
    try:
        claims = jwt.decode(
            token,
            key.public_key,
            algorithms=[key.algorithm],
            options={
                "verify_aud": False,
                "verify_exp": False,
                "verify_iat": False,
                "verify_iss": False,
                "verify_nbf": False,
            },
        )
    except jwt.PyJWTError:
        return _decision(token, attempt, accepted=False, reason="signature_invalid", key_id=key.key_id, checks=("header_parsed", "key_lookup", "signature_verified"))
    return _decision(
        token,
        attempt,
        accepted=True,
        reason="signature_only_accept",
        key_id=key.key_id,
        subject=claims.get("sub") if isinstance(claims.get("sub"), str) else None,
        token_id=claims.get("jti") if isinstance(claims.get("jti"), str) else None,
        action=claims.get("action") if isinstance(claims.get("action"), str) else None,
        checks=("header_parsed", "key_lookup", "signature_verified"),
    )


def hardened_verifier(
    token: str,
    key_set: TrustedKeySet,
    profile: TokenProfile,
    replay_cache: ReplayCache,
    attempt: int,
) -> VerificationDecision:
    """Verify a token against an explicit, application-owned profile."""
    checks: list[str] = []

    def deny(reason: str, key_id: str | None = None) -> VerificationDecision:
        return _decision(
            token,
            attempt,
            accepted=False,
            reason=reason,
            key_id=key_id,
            checks=tuple(checks) or ("request_received",),
        )

    if key_set.issuer != profile.issuer:
        return deny("keyset_issuer_mismatch")
    checks.append("issuer_keyset_bound")

    header, error = _header(token)
    if error or header is None:
        return deny(error or "malformed_token")
    checks.append("header_parsed")

    if any(name in header for name in ("jku", "x5u")):
        return deny("remote_key_reference_forbidden")
    if header.get("alg") != profile.algorithm:
        return deny("algorithm_not_allowed")
    if header.get("typ") != profile.token_type:
        return deny("token_type_mismatch")
    key_id = header.get("kid")
    if not isinstance(key_id, str) or not KID_PATTERN.fullmatch(key_id):
        return deny("invalid_key_id")
    checks.append("header_profile_valid")

    key = key_set.keys.get(key_id)
    if not key:
        return deny("unknown_key", key_id)
    if key.algorithm != profile.algorithm:
        return deny("key_algorithm_mismatch", key_id)
    if key.status is KeyStatus.REVOKED:
        return deny("key_revoked", key_id)
    checks.append("trusted_key_selected")

    try:
        claims = jwt.decode(
            token,
            key.public_key,
            algorithms=[profile.algorithm],
            issuer=profile.issuer,
            audience=profile.audience,
            options={
                "require": list(REQUIRED_CLAIMS),
                "verify_exp": False,
                "verify_iat": False,
                "verify_nbf": False,
            },
        )
    except jwt.InvalidSignatureError:
        return deny("signature_invalid", key_id)
    except jwt.InvalidIssuerError:
        return deny("issuer_mismatch", key_id)
    except jwt.InvalidAudienceError:
        return deny("audience_mismatch", key_id)
    except jwt.MissingRequiredClaimError:
        return deny("required_claim_missing", key_id)
    except jwt.PyJWTError:
        return deny("token_invalid", key_id)
    checks.append("signature_issuer_audience_valid")

    numeric_dates = (claims.get("iat"), claims.get("nbf"), claims.get("exp"))
    if any(isinstance(value, bool) or not isinstance(value, int) for value in numeric_dates):
        return deny("invalid_time_claim", key_id)
    issued_at, not_before, expires_at = numeric_dates
    assert isinstance(issued_at, int) and isinstance(not_before, int) and isinstance(expires_at, int)
    skew = profile.clock_skew_seconds
    if issued_at > NOW_TS + skew or not_before > NOW_TS + skew:
        return deny("token_not_yet_valid", key_id)
    if expires_at <= NOW_TS - skew:
        return deny("token_expired", key_id)
    if expires_at <= issued_at or expires_at - issued_at > profile.max_lifetime_seconds:
        return deny("token_lifetime_invalid", key_id)
    checks.append("time_window_valid")

    subject = claims.get("sub")
    token_id = claims.get("jti")
    action = claims.get("action")
    if not isinstance(subject, str) or subject not in profile.allowed_subjects:
        return deny("subject_not_allowed", key_id)
    if not isinstance(action, str) or action not in profile.allowed_actions:
        return deny("action_not_allowed", key_id)
    if not isinstance(token_id, str) or not token_id or len(token_id) > 128:
        return deny("token_id_invalid", key_id)
    checks.append("subject_action_profile_valid")

    if not replay_cache.consume(profile.issuer, token_id, expires_at, NOW_TS):
        return deny("replay_detected", key_id)
    checks.append("single_use_consumed")

    return _decision(
        token,
        attempt,
        accepted=True,
        reason="token_profile_valid",
        key_id=key_id,
        subject=subject,
        token_id=token_id,
        action=action,
        checks=tuple(checks),
    )


def _tamper_payload(token: str) -> str:
    header, payload, signature = token.split(".")
    padded = payload + "=" * (-len(payload) % 4)
    claims = json.loads(base64.urlsafe_b64decode(padded))
    claims["sub"] = "agent:admin"
    changed = _b64url(json.dumps(claims, separators=(",", ":"), sort_keys=True).encode())
    return ".".join((header, changed, signature))


def build_cases() -> tuple[TokenCase, ...]:
    private_keys, _ = build_key_material()

    def token(
        case_id: str,
        *,
        key_id: str = "sig-2026-09",
        claims: dict[str, object] | None = None,
        token_type: str | None = TOKEN_TYPE,
        expected: bool = False,
        reason: str,
    ) -> TokenCase:
        value = mint_token(private_keys[key_id], key_id, claims or base_claims(jti=f"action-483-{case_id}"), token_type=token_type)
        return TokenCase(case_id, value, (expected,), (reason,))

    valid = token("valid_active_key", expected=True, reason="token_profile_valid")
    retiring = token(
        "valid_retiring_key",
        key_id="sig-2026-08",
        expected=True,
        reason="token_profile_valid",
    )
    replay_token = mint_token(
        private_keys["sig-2026-09"],
        "sig-2026-09",
        base_claims(jti="action-483-replay"),
    )
    replay = TokenCase(
        "replayed_action_token",
        replay_token,
        (True, False),
        ("token_profile_valid", "replay_detected"),
    )
    missing_jti_claims = base_claims()
    missing_jti_claims.pop("jti")

    tampered_source = mint_token(
        private_keys["sig-2026-09"],
        "sig-2026-09",
        base_claims(jti="action-483-tampered"),
    )

    return (
        valid,
        retiring,
        replay,
        token("wrong_audience", claims=base_claims(aud="payroll-api"), reason="audience_mismatch"),
        token("wrong_issuer", claims=base_claims(iss="https://attacker.example"), reason="issuer_mismatch"),
        token("expired", claims=base_claims(iat=NOW_TS - 400, nbf=NOW_TS - 400, exp=NOW_TS - 1), reason="token_expired"),
        token("future_not_before", claims=base_claims(iat=NOW_TS + 60, nbf=NOW_TS + 60, exp=NOW_TS + 180), reason="token_not_yet_valid"),
        token("excessive_lifetime", claims=base_claims(iat=NOW_TS - 10, nbf=NOW_TS - 10, exp=NOW_TS + 900), reason="token_lifetime_invalid"),
        token("missing_type", token_type=None, reason="token_type_mismatch"),
        token("id_token_confusion", token_type="JWT", reason="token_type_mismatch"),
        token("unknown_key", key_id="attacker-key", reason="unknown_key"),
        token("revoked_key", key_id="sig-2026-07-revoked", reason="key_revoked"),
        TokenCase("tampered_payload", _tamper_payload(tampered_source), (False,), ("signature_invalid",)),
        token("missing_token_id", claims=missing_jti_claims, reason="required_claim_missing"),
        token("unknown_subject", claims=base_claims(sub="agent:admin"), reason="subject_not_allowed"),
        token("wrong_action", claims=base_claims(action="purchase:delete"), reason="action_not_allowed"),
    )


Verifier = Callable[[str, TrustedKeySet, TokenProfile, ReplayCache, int], VerificationDecision]


def evaluate(cases: Iterable[TokenCase], verifier: Verifier) -> tuple[EvaluationReport, tuple[tuple[str, int, bool, bool, VerificationDecision], ...]]:
    case_list = tuple(cases)
    _, key_set = build_key_material()
    profile = build_profile()
    replay_cache = ReplayCache()
    rows: list[tuple[str, int, bool, bool, VerificationDecision]] = []
    for case in case_list:
        for attempt, (expected, expected_reason) in enumerate(
            zip(case.expected_accepts, case.expected_reasons), start=1
        ):
            decision = verifier(case.token, key_set, profile, replay_cache, attempt)
            rows.append((case.case_id, attempt, expected, expected_reason == decision.reason_code, decision))

    valid = [row for row in rows if row[2]]
    invalid = [row for row in rows if not row[2]]
    replay_rows = [row for row in rows if row[0] == "replayed_action_token" and not row[2]]

    def rate(numerator: int, denominator: int) -> float:
        return numerator / denominator if denominator else 0.0

    report = EvaluationReport(
        attempts=len(rows),
        expected_valid_attempts=len(valid),
        expected_invalid_attempts=len(invalid),
        valid_attempt_success_rate=rate(sum(row[4].accepted for row in valid), len(valid)),
        invalid_acceptance_rate=rate(sum(row[4].accepted for row in invalid), len(invalid)),
        invalid_block_rate=rate(sum(not row[4].accepted for row in invalid), len(invalid)),
        replay_block_rate=rate(sum(not row[4].accepted for row in replay_rows), len(replay_rows)),
        evidence_completeness_rate=rate(sum(row[4].evidence_complete for row in rows), len(rows)),
    )
    return report, tuple(rows)


def decision_rows(rows: Iterable[tuple[str, int, bool, bool, VerificationDecision]]) -> tuple[dict[str, object], ...]:
    return tuple(
        {
            "case": case_id,
            "attempt": attempt,
            "expected_accept": expected,
            "accepted": decision.accepted,
            "reason": decision.reason_code,
            "reason_matches": reason_matches,
            "key_id": decision.key_id,
        }
        for case_id, attempt, expected, reason_matches, decision in rows
    )


def run_demo() -> None:
    cases = build_cases()
    baseline_report, _ = evaluate(cases, signature_only_baseline)
    controlled_report, controlled_rows = evaluate(cases, hardened_verifier)

    print("Signature-only baseline")
    print(json.dumps(baseline_report.as_dict(), indent=2, sort_keys=True))
    print("\nHardened action-token verifier")
    print(json.dumps(controlled_report.as_dict(), indent=2, sort_keys=True))
    print("\nControlled decisions")
    for row in decision_rows(controlled_rows):
        print(row)

    assert baseline_report.invalid_acceptance_rate > 0.5
    assert controlled_report.valid_attempt_success_rate == 1.0
    assert controlled_report.invalid_acceptance_rate == 0.0
    assert controlled_report.invalid_block_rate == 1.0
    assert controlled_report.replay_block_rate == 1.0
    assert controlled_report.evidence_completeness_rate == 1.0
    assert all(row[3] for row in controlled_rows)


if __name__ == "__main__":
    run_demo()
