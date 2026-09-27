"""Deterministic SPIFFE/SPIRE workload-identity lab for Intermediate 01.

The Northstar Travel scenario models a booking agent that calls an internal
payment tool and a federated partner research service.  It compares an unsafe
"certificate present" baseline with an application-owned control plane that:

* maps trusted workload-attestor selectors to exactly one registration entry;
* issues short-lived X.509-SVID and JWT-SVID teaching profiles;
* validates bundle, time, profile, exact peer, lifecycle, and audience state;
* keeps authentication separate from resource authorization;
* models full-state Workload API updates, rotation, and identity redaction; and
* records public evidence without private keys, raw certificates, or JWTs.

This is a credential-free teaching simulator, not a SPIFFE conformance suite or
a replacement for SPIRE.  It deliberately implements a narrow subset so that
learners can inspect the trust decisions hidden behind production SDKs.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from enum import Enum
import hashlib
import json
import re
from typing import Iterable, Mapping
from urllib.parse import urlsplit

import jwt
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import ExtensionOID


NOW = datetime(2026, 9, 27, 16, 0, tzinfo=timezone.utc)
POLICY_VERSION = "workload-identity/2026-09-27.1"
CORP_DOMAIN = "corp.example"
PARTNER_DOMAIN = "partner.example"
AGENT_ID = "spiffe://corp.example/ns/travel/sa/booking-agent"
PAYMENT_ID = "spiffe://corp.example/ns/payments/sa/payment-api"
RESEARCH_ID = "spiffe://partner.example/ns/research/sa/travel-data"
JWT_AUDIENCE = "https://payments.corp.example"


class Outcome(str, Enum):
    ALLOW = "allow"
    DENY = "deny"


class CredentialKind(str, Enum):
    X509 = "x509-svid"
    JWT = "jwt-svid"


class Lifecycle(str, Enum):
    ACTIVE = "active"
    REMOVED = "removed"


@dataclass(frozen=True)
class SpiffeID:
    uri: str
    trust_domain: str
    path: str


@dataclass(frozen=True)
class Selector:
    selector_type: str
    value: str


@dataclass(frozen=True)
class ObservedWorkload:
    """Evidence supplied by a trusted node/workload attestor, not the caller."""

    workload_handle: str
    node_id: str
    selectors: frozenset[Selector]
    endpoint_local: bool = True
    evidence_id: str = "attestation:unknown"


@dataclass(frozen=True)
class RegistrationEntry:
    entry_id: str
    parent_id: str
    spiffe_id: str
    selectors: frozenset[Selector]
    x509_ttl_seconds: int = 300
    jwt_ttl_seconds: int = 180
    active: bool = True
    version: int = 1


@dataclass(frozen=True)
class TrustBundle:
    trust_domain: str
    version: int
    roots: tuple[x509.Certificate, ...]
    jwt_keys: Mapping[str, ed25519.Ed25519PublicKey]


@dataclass(frozen=True)
class X509SVID:
    spiffe_id: str
    certificate: x509.Certificate
    private_key: ed25519.Ed25519PrivateKey
    bundle_version: int
    entry_version: int


@dataclass(frozen=True)
class JWTSVID:
    spiffe_id: str
    token: str
    kid: str
    bundle_version: int
    entry_version: int


@dataclass(frozen=True)
class WorkloadUpdate:
    sequence: int
    full_state: bool
    x509_svids: tuple[X509SVID, ...]
    jwt_svids: tuple[JWTSVID, ...]
    bundles: tuple[TrustBundle, ...]
    reason: str


@dataclass(frozen=True)
class AccessRule:
    principal_id: str
    action: str
    resource: str


@dataclass(frozen=True)
class VerificationRequest:
    request_id: str
    action: str
    resource: str
    expected_peer_id: str
    credential_kind: CredentialKind
    x509_svid: X509SVID | None = None
    jwt_svid: JWTSVID | None = None
    audience: str | None = None


@dataclass(frozen=True)
class Decision:
    request_id: str
    outcome: Outcome
    reason_code: str
    authenticated_id: str | None
    expected_peer_id: str
    action: str
    resource: str
    policy_version: str
    bundle_version: int | None
    entry_version: int | None
    credential_digest: str | None
    evidence_ids: tuple[str, ...]


@dataclass(frozen=True)
class IssueDecision:
    outcome: Outcome
    reason_code: str
    selected_entry_id: str | None
    issued_id: str | None
    evidence_id: str


@dataclass(frozen=True)
class ScenarioCase:
    case_id: str
    expected: Outcome
    description: str
    credential_kind: CredentialKind = CredentialKind.X509


@dataclass(frozen=True)
class Metrics:
    attempts: int
    expected_allowed: int
    expected_blocked: int
    outcome_matches: int
    invalid_acceptances: int
    valid_work_blocked: int
    authorization_violations: int
    stale_credential_acceptances: int

    @property
    def accuracy(self) -> float:
        return self.outcome_matches / self.attempts if self.attempts else 0.0


_TRUST_DOMAIN = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)
_PATH = re.compile(r"^/(?:[A-Za-z0-9._~-]+(?:/[A-Za-z0-9._~-]+)*)?$")


def parse_spiffe_id(value: str) -> SpiffeID:
    """Parse the course's strict canonical SPIFFE ID subset.

    SPIFFE IDs are URIs, but generic URL parsing is not sufficient.  This
    rejects user info, ports, query strings, fragments, empty paths, encoded
    separators, non-canonical trust-domain case, and dot path segments.
    """

    if not isinstance(value, str) or len(value) > 2048 or "%" in value:
        raise ValueError("spiffe_id_invalid_encoding")
    parts = urlsplit(value)
    if parts.scheme != "spiffe":
        raise ValueError("spiffe_id_scheme_invalid")
    if parts.username or parts.password or parts.port is not None:
        raise ValueError("spiffe_id_authority_invalid")
    if not parts.hostname or parts.hostname != parts.netloc:
        raise ValueError("spiffe_id_authority_invalid")
    if parts.query or parts.fragment:
        raise ValueError("spiffe_id_suffix_invalid")
    if not _TRUST_DOMAIN.fullmatch(parts.hostname):
        raise ValueError("spiffe_trust_domain_invalid")
    if not parts.path or not _PATH.fullmatch(parts.path):
        raise ValueError("spiffe_path_invalid")
    if any(segment in {".", ".."} for segment in parts.path.split("/")):
        raise ValueError("spiffe_path_not_canonical")
    return SpiffeID(value, parts.hostname, parts.path)


def digest_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def certificate_digest(certificate: x509.Certificate) -> str:
    return digest_bytes(certificate.public_bytes(serialization.Encoding.DER))


def token_digest(token: str) -> str:
    return digest_bytes(token.encode())


def _stable_key(label: str) -> ed25519.Ed25519PrivateKey:
    return ed25519.Ed25519PrivateKey.from_private_bytes(
        hashlib.sha256(label.encode()).digest()
    )


class DeterministicIssuer:
    """Small deterministic issuer that makes the trust mechanics inspectable."""

    def __init__(self, trust_domain: str, generation: int = 1):
        self.trust_domain = trust_domain
        self.generation = generation
        self.root_key = _stable_key(f"root:{trust_domain}:{generation}")
        self.jwt_key = _stable_key(f"jwt:{trust_domain}:{generation}")
        self.kid = f"{trust_domain}-jwt-v{generation}"
        self.root_certificate = self._root_certificate()

    def _root_certificate(self) -> x509.Certificate:
        name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, f"{self.trust_domain} root v{self.generation}")])
        return (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(self.root_key.public_key())
            .serial_number(1000 + self.generation)
            .not_valid_before(NOW - timedelta(days=30))
            .not_valid_after(NOW + timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=None,
                    decipher_only=None,
                ),
                critical=True,
            )
            .sign(self.root_key, algorithm=None)
        )

    def bundle(self, *, version: int | None = None, extra_roots: Iterable[x509.Certificate] = ()) -> TrustBundle:
        return TrustBundle(
            trust_domain=self.trust_domain,
            version=version or self.generation,
            roots=(self.root_certificate, *tuple(extra_roots)),
            jwt_keys={self.kid: self.jwt_key.public_key()},
        )

    def issue_x509(
        self,
        spiffe_id: str,
        *,
        issued_at: datetime = NOW - timedelta(seconds=10),
        ttl_seconds: int = 300,
        entry_version: int = 1,
        extra_uri_sans: tuple[str, ...] = (),
    ) -> X509SVID:
        parse_spiffe_id(spiffe_id)
        key = _stable_key(
            f"workload:{self.trust_domain}:{self.generation}:{spiffe_id}:{issued_at.isoformat()}:{ttl_seconds}"
        )
        sans = [x509.UniformResourceIdentifier(spiffe_id)]
        sans.extend(x509.UniformResourceIdentifier(value) for value in extra_uri_sans)
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([]))
            .issuer_name(self.root_certificate.subject)
            .public_key(key.public_key())
            .serial_number(int.from_bytes(hashlib.sha256(f"{spiffe_id}:{issued_at}:{ttl_seconds}".encode()).digest()[:19], "big"))
            .not_valid_before(issued_at)
            .not_valid_after(issued_at + timedelta(seconds=ttl_seconds))
            .add_extension(x509.SubjectAlternativeName(sans), critical=True)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=None,
                    decipher_only=None,
                ),
                critical=True,
            )
            .sign(self.root_key, algorithm=None)
        )
        return X509SVID(spiffe_id, cert, key, self.generation, entry_version)

    def issue_jwt(
        self,
        spiffe_id: str,
        audience: str,
        *,
        issued_at: datetime = NOW - timedelta(seconds=10),
        ttl_seconds: int = 180,
        entry_version: int = 1,
        kid: str | None = None,
    ) -> JWTSVID:
        parse_spiffe_id(spiffe_id)
        claims = {
            "sub": spiffe_id,
            "aud": [audience],
            "iat": int(issued_at.timestamp()),
            "exp": int((issued_at + timedelta(seconds=ttl_seconds)).timestamp()),
        }
        token = jwt.encode(
            claims,
            self.jwt_key,
            algorithm="EdDSA",
            headers={"typ": "JWT", "kid": kid or self.kid},
        )
        return JWTSVID(spiffe_id, token, kid or self.kid, self.generation, entry_version)


class WorkloadAPI:
    """A narrow SPIRE-like issuance and full-state streaming simulator."""

    def __init__(
        self,
        issuer: DeterministicIssuer,
        entries: Iterable[RegistrationEntry],
    ):
        self.issuer = issuer
        self.entries = tuple(entries)
        self.sequence = 0
        self.lifecycle: dict[str, Lifecycle] = {
            entry.spiffe_id: Lifecycle.ACTIVE for entry in self.entries
        }

    def match(self, workload: ObservedWorkload) -> tuple[RegistrationEntry, ...]:
        return tuple(
            entry
            for entry in self.entries
            if entry.active
            and entry.parent_id == workload.node_id
            and entry.selectors.issubset(workload.selectors)
        )

    def fetch(
        self,
        workload: ObservedWorkload,
        *,
        audience: str = JWT_AUDIENCE,
        requested_id: str | None = None,
    ) -> tuple[IssueDecision, WorkloadUpdate | None]:
        # requested_id is intentionally ignored as an authority input.
        if not workload.endpoint_local:
            return self._issue_denial("workload_endpoint_not_local", workload), None
        matches = self.match(workload)
        if not matches:
            return self._issue_denial("registration_not_found", workload), None
        if len(matches) != 1:
            return self._issue_denial("registration_ambiguous", workload), None
        entry = matches[0]
        if self.lifecycle.get(entry.spiffe_id) is not Lifecycle.ACTIVE:
            return self._issue_denial("identity_removed", workload), None
        x509_svid = self.issuer.issue_x509(
            entry.spiffe_id,
            ttl_seconds=entry.x509_ttl_seconds,
            entry_version=entry.version,
        )
        jwt_svid = self.issuer.issue_jwt(
            entry.spiffe_id,
            audience,
            ttl_seconds=entry.jwt_ttl_seconds,
            entry_version=entry.version,
        )
        self.sequence += 1
        update = WorkloadUpdate(
            sequence=self.sequence,
            full_state=True,
            x509_svids=(x509_svid,),
            jwt_svids=(jwt_svid,),
            bundles=(self.issuer.bundle(),),
            reason="initial_or_rotated_state",
        )
        return (
            IssueDecision(
                Outcome.ALLOW,
                "svids_issued",
                entry.entry_id,
                entry.spiffe_id,
                workload.evidence_id,
            ),
            update,
        )

    def remove(self, spiffe_id: str) -> WorkloadUpdate:
        """Publish a full-state update with the removed SVID absent."""

        self.lifecycle[spiffe_id] = Lifecycle.REMOVED
        self.sequence += 1
        return WorkloadUpdate(
            sequence=self.sequence,
            full_state=True,
            x509_svids=(),
            jwt_svids=(),
            bundles=(self.issuer.bundle(),),
            reason="identity_removed_stop_using_previous_svids",
        )

    @staticmethod
    def _issue_denial(reason: str, workload: ObservedWorkload) -> IssueDecision:
        return IssueDecision(Outcome.DENY, reason, None, None, workload.evidence_id)


class WorkloadClientCache:
    """Consumes complete snapshots; omission removes previously cached state."""

    def __init__(self):
        self.last_sequence = 0
        self.x509_svids: dict[str, X509SVID] = {}
        self.jwt_svids: dict[str, JWTSVID] = {}
        self.bundles: dict[str, TrustBundle] = {}

    def apply(self, update: WorkloadUpdate) -> None:
        if not update.full_state:
            raise ValueError("partial_update_not_supported")
        if update.sequence <= self.last_sequence:
            raise ValueError("stale_update")
        self.x509_svids = {item.spiffe_id: item for item in update.x509_svids}
        self.jwt_svids = {item.spiffe_id: item for item in update.jwt_svids}
        self.bundles = {item.trust_domain: item for item in update.bundles}
        self.last_sequence = update.sequence


class WorkloadGateway:
    """Verifies authentication, then independently authorizes the resource."""

    def __init__(
        self,
        bundles: Mapping[str, TrustBundle],
        access_rules: Iterable[AccessRule],
        lifecycle: Mapping[str, Lifecycle],
        *,
        now: datetime = NOW,
        max_x509_ttl_seconds: int = 600,
        max_jwt_ttl_seconds: int = 300,
    ):
        self.bundles = dict(bundles)
        self.access_rules = frozenset(access_rules)
        self.lifecycle = dict(lifecycle)
        self.now = now
        self.max_x509_ttl_seconds = max_x509_ttl_seconds
        self.max_jwt_ttl_seconds = max_jwt_ttl_seconds

    def verify(self, request: VerificationRequest) -> Decision:
        try:
            expected = parse_spiffe_id(request.expected_peer_id)
        except ValueError:
            return self._deny(request, "expected_peer_id_invalid")
        bundle = self.bundles.get(expected.trust_domain)
        if bundle is None:
            return self._deny(request, "trust_bundle_unavailable")

        if request.credential_kind is CredentialKind.X509:
            identity, reason, digest, entry_version = self._verify_x509(
                request.x509_svid, bundle
            )
        else:
            identity, reason, digest, entry_version = self._verify_jwt(
                request.jwt_svid, bundle, request.audience
            )
        if reason:
            return self._deny(
                request,
                reason,
                digest=digest,
                bundle_version=bundle.version,
                entry_version=entry_version,
            )
        assert identity is not None
        if identity != request.expected_peer_id:
            return self._deny(
                request,
                "peer_identity_mismatch",
                authenticated_id=identity,
                digest=digest,
                bundle_version=bundle.version,
                entry_version=entry_version,
            )
        if self.lifecycle.get(identity) is not Lifecycle.ACTIVE:
            return self._deny(
                request,
                "identity_not_active",
                authenticated_id=identity,
                digest=digest,
                bundle_version=bundle.version,
                entry_version=entry_version,
            )
        rule = AccessRule(identity, request.action, request.resource)
        if rule not in self.access_rules:
            return self._deny(
                request,
                "resource_not_authorized",
                authenticated_id=identity,
                digest=digest,
                bundle_version=bundle.version,
                entry_version=entry_version,
            )
        return Decision(
            request.request_id,
            Outcome.ALLOW,
            "authenticated_and_authorized",
            identity,
            request.expected_peer_id,
            request.action,
            request.resource,
            POLICY_VERSION,
            bundle.version,
            entry_version,
            digest,
            (f"bundle:{expected.trust_domain}:v{bundle.version}",),
        )

    def _verify_x509(
        self, svid: X509SVID | None, bundle: TrustBundle
    ) -> tuple[str | None, str | None, str | None, int | None]:
        if svid is None:
            return None, "x509_svid_missing", None, None
        cert = svid.certificate
        digest = certificate_digest(cert)
        verified = False
        for root in bundle.roots:
            if cert.issuer != root.subject:
                continue
            try:
                root.public_key().verify(cert.signature, cert.tbs_certificate_bytes)
                verified = True
                break
            except Exception:
                continue
        if not verified:
            return None, "x509_chain_untrusted", digest, svid.entry_version
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
        if self.now < not_before:
            return None, "x509_not_yet_valid", digest, svid.entry_version
        if self.now >= not_after:
            return None, "x509_expired", digest, svid.entry_version
        if (not_after - not_before).total_seconds() > self.max_x509_ttl_seconds:
            return None, "x509_lifetime_exceeds_policy", digest, svid.entry_version
        try:
            basic = cert.extensions.get_extension_for_oid(
                ExtensionOID.BASIC_CONSTRAINTS
            ).value
            usage = cert.extensions.get_extension_for_oid(
                ExtensionOID.KEY_USAGE
            ).value
            sans = cert.extensions.get_extension_for_oid(
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            ).value
        except x509.ExtensionNotFound:
            return None, "x509_profile_incomplete", digest, svid.entry_version
        if basic.ca or not usage.digital_signature or usage.key_cert_sign:
            return None, "x509_profile_invalid", digest, svid.entry_version
        uri_sans = sans.get_values_for_type(x509.UniformResourceIdentifier)
        dns_sans = sans.get_values_for_type(x509.DNSName)
        if len(uri_sans) != 1 or dns_sans:
            return None, "x509_san_profile_invalid", digest, svid.entry_version
        try:
            identity = parse_spiffe_id(uri_sans[0]).uri
        except ValueError:
            return None, "x509_spiffe_id_invalid", digest, svid.entry_version
        if parse_spiffe_id(identity).trust_domain != bundle.trust_domain:
            return None, "x509_trust_domain_mismatch", digest, svid.entry_version
        return identity, None, digest, svid.entry_version

    def _verify_jwt(
        self,
        svid: JWTSVID | None,
        bundle: TrustBundle,
        audience: str | None,
    ) -> tuple[str | None, str | None, str | None, int | None]:
        if svid is None:
            return None, "jwt_svid_missing", None, None
        digest = token_digest(svid.token)
        if not audience:
            return None, "jwt_audience_missing", digest, svid.entry_version
        try:
            header = jwt.get_unverified_header(svid.token)
        except jwt.PyJWTError:
            return None, "jwt_malformed", digest, svid.entry_version
        if header.get("alg") != "EdDSA" or header.get("typ") != "JWT":
            return None, "jwt_header_invalid", digest, svid.entry_version
        kid = header.get("kid")
        key = bundle.jwt_keys.get(kid) if isinstance(kid, str) else None
        if key is None:
            return None, "jwt_key_untrusted", digest, svid.entry_version
        try:
            claims = jwt.decode(
                svid.token,
                key,
                algorithms=["EdDSA"],
                audience=audience,
                options={
                    "require": ["sub", "aud", "iat", "exp"],
                    "verify_exp": False,
                    "verify_iat": False,
                },
                leeway=0,
            )
        except jwt.ExpiredSignatureError:
            return None, "jwt_expired", digest, svid.entry_version
        except jwt.InvalidAudienceError:
            return None, "jwt_audience_mismatch", digest, svid.entry_version
        except jwt.PyJWTError:
            return None, "jwt_invalid", digest, svid.entry_version
        issued_at = datetime.fromtimestamp(claims["iat"], tz=timezone.utc)
        expires_at = datetime.fromtimestamp(claims["exp"], tz=timezone.utc)
        if self.now < issued_at:
            return None, "jwt_not_yet_valid", digest, svid.entry_version
        if self.now >= expires_at:
            return None, "jwt_expired", digest, svid.entry_version
        if (expires_at - issued_at).total_seconds() > self.max_jwt_ttl_seconds:
            return None, "jwt_lifetime_exceeds_policy", digest, svid.entry_version
        try:
            identity = parse_spiffe_id(claims["sub"]).uri
        except (KeyError, TypeError, ValueError):
            return None, "jwt_subject_invalid", digest, svid.entry_version
        if parse_spiffe_id(identity).trust_domain != bundle.trust_domain:
            return None, "jwt_trust_domain_mismatch", digest, svid.entry_version
        return identity, None, digest, svid.entry_version

    @staticmethod
    def _deny(
        request: VerificationRequest,
        reason: str,
        *,
        authenticated_id: str | None = None,
        digest: str | None = None,
        bundle_version: int | None = None,
        entry_version: int | None = None,
    ) -> Decision:
        return Decision(
            request.request_id,
            Outcome.DENY,
            reason,
            authenticated_id,
            request.expected_peer_id,
            request.action,
            request.resource,
            POLICY_VERSION,
            bundle_version,
            entry_version,
            digest,
            tuple(
                item
                for item in (
                    f"bundle:{bundle_version}" if bundle_version else None,
                    f"entry:v{entry_version}" if entry_version else None,
                )
                if item
            ),
        )


def unsafe_certificate_present_baseline(request: VerificationRequest) -> Decision:
    """Explicit anti-pattern: trust presence/claims and skip exact policy checks."""

    identity: str | None = None
    digest: str | None = None
    try:
        if request.credential_kind is CredentialKind.X509 and request.x509_svid:
            cert = request.x509_svid.certificate
            digest = certificate_digest(cert)
            sans = cert.extensions.get_extension_for_oid(
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            ).value
            values = sans.get_values_for_type(x509.UniformResourceIdentifier)
            identity = values[0] if values else None
        elif request.jwt_svid:
            digest = token_digest(request.jwt_svid.token)
            identity = jwt.decode(
                request.jwt_svid.token,
                options={"verify_signature": False, "verify_exp": False},
            ).get("sub")
    except Exception:
        identity = None
    outcome = Outcome.ALLOW if identity else Outcome.DENY
    return Decision(
        request.request_id,
        outcome,
        "credential_present" if identity else "credential_unreadable",
        identity,
        request.expected_peer_id,
        request.action,
        request.resource,
        "unsafe-baseline",
        None,
        None,
        digest,
        (),
    )


def registration_entries() -> tuple[RegistrationEntry, ...]:
    return (
        RegistrationEntry(
            "entry:booking-agent:v3",
            "spiffe://corp.example/spire/agent/node-a",
            AGENT_ID,
            frozenset(
                {
                    Selector("k8s", "ns:travel"),
                    Selector("k8s", "sa:booking-agent"),
                    Selector("k8s", "container-image:sha256:approved-v3"),
                }
            ),
            version=3,
        ),
        RegistrationEntry(
            "entry:payment-api:v7",
            "spiffe://corp.example/spire/agent/node-b",
            PAYMENT_ID,
            frozenset(
                {
                    Selector("k8s", "ns:payments"),
                    Selector("k8s", "sa:payment-api"),
                }
            ),
            version=7,
        ),
    )


def booking_workload(**changes: object) -> ObservedWorkload:
    base = ObservedWorkload(
        "pod:booking-agent-7d9f",
        "spiffe://corp.example/spire/agent/node-a",
        frozenset(
            {
                Selector("k8s", "ns:travel"),
                Selector("k8s", "sa:booking-agent"),
                Selector("k8s", "container-image:sha256:approved-v3"),
            }
        ),
        True,
        "attestation:k8s:booking-agent-7d9f:rv8421",
    )
    return replace(base, **changes)


def default_gateway(
    *,
    corp_bundle: TrustBundle | None = None,
    partner_bundle: TrustBundle | None = None,
    lifecycle: Mapping[str, Lifecycle] | None = None,
) -> WorkloadGateway:
    corp = DeterministicIssuer(CORP_DOMAIN)
    partner = DeterministicIssuer(PARTNER_DOMAIN)
    bundles = {
        CORP_DOMAIN: corp_bundle or corp.bundle(),
        PARTNER_DOMAIN: partner_bundle or partner.bundle(),
    }
    rules = (
        AccessRule(AGENT_ID, "charge", "payment:booking-1042"),
        AccessRule(PAYMENT_ID, "settle", "ledger:northstar"),
    )
    state = {AGENT_ID: Lifecycle.ACTIVE, PAYMENT_ID: Lifecycle.ACTIVE, RESEARCH_ID: Lifecycle.ACTIVE}
    state.update(lifecycle or {})
    return WorkloadGateway(bundles, rules, state)


def build_cases() -> tuple[ScenarioCase, ...]:
    return (
        ScenarioCase("valid_agent_x509", Outcome.ALLOW, "attested booking agent charges its booking"),
        ScenarioCase("valid_agent_jwt", Outcome.ALLOW, "JWT-SVID has exact audience and resource authority", CredentialKind.JWT),
        ScenarioCase("unknown_workload", Outcome.DENY, "selectors match no registration entry"),
        ScenarioCase("ambiguous_selectors", Outcome.DENY, "selectors match multiple registrations"),
        ScenarioCase("caller_supplied_identity", Outcome.DENY, "caller asks to become the payment API"),
        ScenarioCase("remote_workload_endpoint", Outcome.DENY, "Workload API endpoint is shared across hosts"),
        ScenarioCase("wrong_namespace", Outcome.DENY, "service account is replayed from another namespace"),
        ScenarioCase("expired_x509", Outcome.DENY, "X.509-SVID is expired"),
        ScenarioCase("future_x509", Outcome.DENY, "X.509-SVID is not yet valid"),
        ScenarioCase("overlong_x509", Outcome.DENY, "X.509-SVID exceeds local maximum lifetime"),
        ScenarioCase("wrong_bundle", Outcome.DENY, "credential chains to an untrusted authority"),
        ScenarioCase("wrong_peer_id", Outcome.DENY, "valid credential identifies a different workload"),
        ScenarioCase("multiple_uri_sans", Outcome.DENY, "certificate has ambiguous URI SAN identity"),
        ScenarioCase("stale_bundle_after_rotation", Outcome.DENY, "new SVID is checked with the retired root only"),
        ScenarioCase("removed_identity", Outcome.DENY, "redacted identity remains in a stale application cache"),
        ScenarioCase("jwt_wrong_audience", Outcome.DENY, "JWT-SVID is replayed to another audience", CredentialKind.JWT),
        ScenarioCase("jwt_expired", Outcome.DENY, "JWT-SVID is expired", CredentialKind.JWT),
        ScenarioCase("jwt_unknown_key", Outcome.DENY, "JWT key ID is not in the trust-domain bundle", CredentialKind.JWT),
        ScenarioCase("federated_but_unauthorized", Outcome.DENY, "partner authenticates but lacks local payment authority"),
        ScenarioCase("resource_scope_violation", Outcome.DENY, "agent is authenticated for a different booking"),
    )


def run_case(case: ScenarioCase, *, hardened: bool) -> Decision:
    corp = DeterministicIssuer(CORP_DOMAIN)
    partner = DeterministicIssuer(PARTNER_DOMAIN)
    request = VerificationRequest(
        f"request:{case.case_id}",
        "charge",
        "payment:booking-1042",
        AGENT_ID,
        case.credential_kind,
    )

    if case.case_id in {
        "unknown_workload",
        "ambiguous_selectors",
        "caller_supplied_identity",
        "remote_workload_endpoint",
        "wrong_namespace",
    }:
        entries = list(registration_entries())
        workload = booking_workload()
        requested_id = None
        if case.case_id == "unknown_workload":
            workload = booking_workload(selectors=frozenset({Selector("unix", "uid:65534")}))
        elif case.case_id == "ambiguous_selectors":
            entries.append(replace(entries[0], entry_id="entry:collision", spiffe_id=PAYMENT_ID))
        elif case.case_id == "caller_supplied_identity":
            requested_id = PAYMENT_ID
        elif case.case_id == "remote_workload_endpoint":
            workload = booking_workload(endpoint_local=False)
        elif case.case_id == "wrong_namespace":
            workload = booking_workload(
                selectors=frozenset(
                    {
                        Selector("k8s", "ns:attacker"),
                        Selector("k8s", "sa:booking-agent"),
                        Selector("k8s", "container-image:sha256:approved-v3"),
                    }
                )
            )
        api = WorkloadAPI(corp, entries)
        issue, update = api.fetch(workload, requested_id=requested_id)
        if update is None:
            return Decision(
                request.request_id,
                Outcome.DENY if hardened else Outcome.ALLOW,
                issue.reason_code if hardened else "declared_identity_accepted",
                None if hardened else requested_id or AGENT_ID,
                request.expected_peer_id,
                request.action,
                request.resource,
                POLICY_VERSION if hardened else "unsafe-baseline",
                None,
                None,
                None,
                (issue.evidence_id,),
            )
        request = replace(request, x509_svid=update.x509_svids[0])
        if case.case_id == "caller_supplied_identity":
            request = replace(request, expected_peer_id=PAYMENT_ID)
    else:
        x509_svid = corp.issue_x509(AGENT_ID, entry_version=3)
        jwt_svid = corp.issue_jwt(AGENT_ID, JWT_AUDIENCE, entry_version=3)
        gateway = default_gateway()
        if case.case_id == "expired_x509":
            x509_svid = corp.issue_x509(AGENT_ID, issued_at=NOW - timedelta(minutes=10), ttl_seconds=60, entry_version=3)
        elif case.case_id == "future_x509":
            x509_svid = corp.issue_x509(AGENT_ID, issued_at=NOW + timedelta(minutes=1), entry_version=3)
        elif case.case_id == "overlong_x509":
            x509_svid = corp.issue_x509(AGENT_ID, issued_at=NOW - timedelta(seconds=10), ttl_seconds=3600, entry_version=3)
        elif case.case_id == "wrong_bundle":
            x509_svid = partner.issue_x509(RESEARCH_ID)
            request = replace(request, expected_peer_id=RESEARCH_ID)
            gateway = WorkloadGateway(
                {PARTNER_DOMAIN: TrustBundle(PARTNER_DOMAIN, 99, (corp.root_certificate,), {})},
                (AccessRule(RESEARCH_ID, "charge", "payment:booking-1042"),),
                {RESEARCH_ID: Lifecycle.ACTIVE},
            )
        elif case.case_id == "wrong_peer_id":
            x509_svid = corp.issue_x509(PAYMENT_ID, entry_version=7)
        elif case.case_id == "multiple_uri_sans":
            x509_svid = corp.issue_x509(AGENT_ID, entry_version=3, extra_uri_sans=(PAYMENT_ID,))
        elif case.case_id == "stale_bundle_after_rotation":
            rotated = DeterministicIssuer(CORP_DOMAIN, generation=2)
            x509_svid = rotated.issue_x509(AGENT_ID, entry_version=4)
            gateway = default_gateway(corp_bundle=corp.bundle())
        elif case.case_id == "removed_identity":
            gateway = default_gateway(lifecycle={AGENT_ID: Lifecycle.REMOVED})
        elif case.case_id == "jwt_wrong_audience":
            request = replace(request, audience="https://reports.corp.example")
        elif case.case_id == "jwt_expired":
            jwt_svid = corp.issue_jwt(
                AGENT_ID,
                JWT_AUDIENCE,
                issued_at=NOW - timedelta(minutes=10),
                ttl_seconds=60,
                entry_version=3,
            )
        elif case.case_id == "jwt_unknown_key":
            rotated = DeterministicIssuer(CORP_DOMAIN, generation=2)
            jwt_svid = rotated.issue_jwt(AGENT_ID, JWT_AUDIENCE, entry_version=4)
        elif case.case_id == "federated_but_unauthorized":
            x509_svid = partner.issue_x509(RESEARCH_ID)
            request = replace(request, expected_peer_id=RESEARCH_ID)
        elif case.case_id == "resource_scope_violation":
            request = replace(request, resource="payment:booking-9999")
        request = replace(request, x509_svid=x509_svid, jwt_svid=jwt_svid, audience=request.audience or JWT_AUDIENCE)
        return gateway.verify(request) if hardened else unsafe_certificate_present_baseline(request)

    gateway = default_gateway()
    return gateway.verify(request) if hardened else unsafe_certificate_present_baseline(request)


def evaluate(cases: Iterable[ScenarioCase], *, hardened: bool) -> tuple[Metrics, tuple[tuple[ScenarioCase, Decision], ...]]:
    rows = tuple((case, run_case(case, hardened=hardened)) for case in cases)
    expected_allowed = sum(case.expected is Outcome.ALLOW for case, _ in rows)
    expected_blocked = len(rows) - expected_allowed
    outcome_matches = sum(case.expected is decision.outcome for case, decision in rows)
    invalid_acceptances = sum(
        case.expected is Outcome.DENY and decision.outcome is Outcome.ALLOW
        for case, decision in rows
    )
    valid_work_blocked = sum(
        case.expected is Outcome.ALLOW and decision.outcome is Outcome.DENY
        for case, decision in rows
    )
    authorization_cases = {"federated_but_unauthorized", "resource_scope_violation"}
    stale_cases = {"expired_x509", "stale_bundle_after_rotation", "removed_identity", "jwt_expired"}
    metrics = Metrics(
        attempts=len(rows),
        expected_allowed=expected_allowed,
        expected_blocked=expected_blocked,
        outcome_matches=outcome_matches,
        invalid_acceptances=invalid_acceptances,
        valid_work_blocked=valid_work_blocked,
        authorization_violations=sum(
            case.case_id in authorization_cases and decision.outcome is Outcome.ALLOW
            for case, decision in rows
        ),
        stale_credential_acceptances=sum(
            case.case_id in stale_cases and decision.outcome is Outcome.ALLOW
            for case, decision in rows
        ),
    )
    return metrics, rows


def release_gate(metrics: Metrics) -> bool:
    return (
        metrics.attempts == 20
        and metrics.outcome_matches == metrics.attempts
        and metrics.invalid_acceptances == 0
        and metrics.valid_work_blocked == 0
        and metrics.authorization_violations == 0
        and metrics.stale_credential_acceptances == 0
    )


def decision_record(decision: Decision) -> dict[str, object]:
    return {
        "request_id": decision.request_id,
        "outcome": decision.outcome.value,
        "reason_code": decision.reason_code,
        "authenticated_id": decision.authenticated_id,
        "expected_peer_id": decision.expected_peer_id,
        "action": decision.action,
        "resource": decision.resource,
        "policy_version": decision.policy_version,
        "bundle_version": decision.bundle_version,
        "entry_version": decision.entry_version,
        "credential_digest": decision.credential_digest,
        "evidence_ids": list(decision.evidence_ids),
    }


def demo() -> None:
    baseline, _ = evaluate(build_cases(), hardened=False)
    hardened, rows = evaluate(build_cases(), hardened=True)
    print("Northstar Travel workload-identity evaluation")
    print(json.dumps({"baseline": baseline.__dict__, "hardened": hardened.__dict__, "release_gate": release_gate(hardened)}, indent=2))
    print("\nHardened decisions")
    for case, decision in rows:
        print(f"{case.case_id:31} expected={case.expected.value:5} actual={decision.outcome.value:5} reason={decision.reason_code}")


if __name__ == "__main__":
    demo()
