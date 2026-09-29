"""Executable invariants for Intermediate 08 workload assurance."""

import importlib.util
from pathlib import Path
import sys

import pytest


LAB_PATH = Path(__file__).parents[1] / "lab.py"
SPEC = importlib.util.spec_from_file_location("intermediate08_lab", LAB_PATH)
lab = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = lab
SPEC.loader.exec_module(lab)


@pytest.mark.parametrize("case", lab.build_cases(), ids=lambda case: case.name)
def test_authorization_scenario_matrix(case):
    assert lab.run_case(case) is case.expected


@pytest.mark.parametrize(
    "value,reason",
    [
        ("https://northstar.example/prod/a", "spiffe_id_invalid"),
        ("spiffe:///prod/a", "spiffe_id_invalid"),
        ("spiffe://user@northstar.example/prod/a", "spiffe_id_invalid"),
        ("spiffe://northstar.example:443/prod/a", "spiffe_id_invalid"),
        ("spiffe://northstar.example/prod/a?x=1", "spiffe_id_invalid"),
        ("spiffe://northstar.example/prod/a#x", "spiffe_id_invalid"),
        ("spiffe://NORTHSTAR.example/prod/a", "spiffe_id_noncanonical"),
        ("spiffe://northstar.example/", "spiffe_path_invalid"),
        ("spiffe://northstar.example/prod//a", "spiffe_id_noncanonical"),
        ("spiffe://northstar.example/prod/../a", "spiffe_id_noncanonical"),
    ],
)
def test_spiffe_id_parser_rejects_ambiguous_or_noncanonical_values(value, reason):
    with pytest.raises(lab.LabError, match=reason):
        lab.SpiffeId.parse(value)


def test_spiffe_id_round_trip_preserves_trust_domain_and_path():
    value = lab.SpiffeId.parse(lab.SPIFFE_ID)
    assert value.trust_domain == lab.TRUST_DOMAIN
    assert value.path == "/prod/agents/claims-adjuster"
    assert str(value) == lab.SPIFFE_ID


def test_registration_requires_node_and_every_selector():
    assert lab.REGISTRATION.matches(
        lab.REGISTRATION.parent_node, lab.REGISTRATION.required_selectors
    )
    weak = frozenset({"k8s:ns:claims"})
    assert not lab.REGISTRATION.matches(lab.REGISTRATION.parent_node, weak)
    assert not lab.REGISTRATION.matches(
        "spiffe://northstar.example/spire/agent/evil",
        lab.REGISTRATION.required_selectors,
    )


def test_x509_svid_has_one_uri_san_and_verifies_to_expected_identity():
    authority = lab.WorkloadAuthority()
    identity = authority.issue_x509()
    session = authority.verify_x509(identity)
    assert session.spiffe_id == lab.SPIFFE_ID
    assert session.format == "x509-svid"
    assert session.expires_at - session.issued_at <= 605
    assert b"PRIVATE KEY" in identity.private_key_pem


def test_x509_svid_cannot_be_substituted_for_another_expected_identity():
    authority = lab.WorkloadAuthority()
    identity = authority.issue_x509()
    with pytest.raises(lab.LabError, match="x509_spiffe_id_mismatch"):
        authority.verify_x509(identity, expected_id=lab.API_SPIFFE_ID)


def test_x509_svid_expires_and_tampering_fails_closed():
    authority = lab.WorkloadAuthority()
    identity = authority.issue_x509(ttl=30)
    with pytest.raises(lab.LabError, match="x509_svid_expired"):
        authority.verify_x509(identity, now=lab.NOW + 31)
    tampered = lab.replace(identity, certificate_pem=identity.certificate_pem[:-10])
    with pytest.raises(lab.LabError, match="x509_svid_invalid"):
        authority.verify_x509(tampered)


def test_jwt_svid_validates_signature_issuer_subject_and_audience():
    authority = lab.WorkloadAuthority()
    token = authority.issue_jwt()
    session = authority.verify_jwt(token)
    assert session.spiffe_id == lab.SPIFFE_ID
    assert session.format == "jwt-svid"
    with pytest.raises(lab.LabError, match="jwt_svid_invalid"):
        authority.verify_jwt(token, audience="https://payments.example")


def test_jwt_svid_ttl_is_bounded():
    authority = lab.WorkloadAuthority()
    token = authority.issue_jwt(ttl=301)
    with pytest.raises(lab.LabError, match="jwt_svid_not_current"):
        authority.verify_jwt(token)


def test_bundle_rotation_accepts_overlap_then_can_remove_old_key():
    authority = lab.WorkloadAuthority()
    old = authority.issue_jwt(jti="old")
    old_kid = authority.kid
    authority.rotate()
    new = authority.issue_jwt(jti="new")
    assert authority.verify_jwt(old).credential_id == "old"
    assert authority.verify_jwt(new).credential_id == "new"
    del authority.bundle[old_kid]
    with pytest.raises(lab.LabError, match="jwt_svid_invalid"):
        authority.verify_jwt(old)


@pytest.mark.parametrize(
    "changes,reason",
    [
        ({"nonce": "attacker"}, "attestation_evidence_invalid"),
        ({"observed_at": lab.NOW - 121}, "attestation_evidence_stale"),
        ({"observed_at": lab.NOW + 31}, "attestation_evidence_stale"),
        ({"artifact_digest": "sha256:" + "00" * 32}, "measurement_unapproved"),
        (
            {"node_id": "spiffe://northstar.example/spire/agent/evil"},
            "workload_attestation_failed",
        ),
        ({"selectors": ["k8s:ns:claims"]}, "workload_attestation_failed"),
    ],
)
def test_attestation_appraisal_rejects_replay_stale_or_unapproved_evidence(
    changes, reason
):
    verifier = lab.AttestationVerifier()
    with pytest.raises(lab.LabError, match=reason):
        verifier.appraise(lab.default_evidence(**changes), "nonce-8f13")


def test_relying_party_verifies_signed_nonce_bound_attestation_result():
    verifier = lab.AttestationVerifier()
    result = verifier.appraise(lab.default_evidence(), "nonce-8f13")
    verified = verifier.verify(result.token, "nonce-8f13")
    assert verified.spiffe_id == lab.SPIFFE_ID
    assert verified.policy_id == "runtime-baseline-v7"
    with pytest.raises(lab.LabError, match="attestation_nonce_mismatch"):
        verifier.verify(result.token, "nonce-other")
    with pytest.raises(lab.LabError, match="attestation_result_stale"):
        verifier.verify(result.token, "nonce-8f13", now=lab.NOW + 301)


def test_provenance_verification_binds_signature_digest_builder_source_and_signer():
    verifier = lab.ProvenanceVerifier()
    result = verifier.verify(verifier.sign())
    assert result.artifact_digest == lab.ARTIFACT_DIGEST
    assert result.builder_id == lab.BUILDER_ID
    assert result.source_repository == lab.SOURCE_REPOSITORY
    assert result.build_type == lab.BUILD_TYPE
    assert result.signer_identity == lab.SIGNER_IDENTITY


@pytest.mark.parametrize(
    "field,value",
    [
        ("artifact_digest", "sha256:" + "00" * 32),
        ("builder_id", "https://attacker.example/builder"),
        ("source_repository", "https://github.com/attacker/repo"),
        ("build_type", "https://attacker.example/build"),
        ("signer_identity", "attacker@example.com"),
    ],
)
def test_valid_signature_does_not_override_provenance_policy(field, value):
    verifier = lab.ProvenanceVerifier()
    with pytest.raises(lab.LabError, match="provenance_policy_failed"):
        verifier.verify(verifier.sign(**{field: value}))


def test_provenance_payload_tampering_fails_signature_verification():
    verifier = lab.ProvenanceVerifier()
    envelope = verifier.sign()
    envelope["payload"] = envelope["payload"][:-2] + "AA"
    with pytest.raises(lab.LabError, match="provenance_invalid"):
        verifier.verify(envelope)


def test_runtime_posture_binds_identity_attestation_and_provenance():
    engine, session, result, provenance, _ = lab.fixture()
    with pytest.raises(lab.LabError, match="identity_attestation_binding_invalid"):
        engine.posture(
            lab.replace(session, spiffe_id=lab.API_SPIFFE_ID), result, provenance
        )
    with pytest.raises(lab.LabError, match="attestation_provenance_binding_invalid"):
        engine.posture(
            session,
            lab.replace(result, artifact_digest="sha256:" + "00" * 32),
            provenance,
        )


def test_workload_authentication_never_replaces_business_authorization():
    engine, _, _, _, posture = lab.fixture()
    decision = engine.authorize(posture, action="payment.create")
    assert decision.outcome is lab.Outcome.DENY
    assert decision.reasons == ("business_authority_invalid",)


def test_quarantine_overrides_an_otherwise_valid_identity():
    engine, _, _, _, posture = lab.fixture()
    engine.status = "quarantined"
    assert engine.authorize(posture).outcome is lab.Outcome.QUARANTINE


def test_decision_evidence_is_versioned_and_privacy_minimized():
    engine, _, _, _, posture = lab.fixture()
    decision = engine.authorize(posture)
    assert decision.policy_version == lab.POLICY_VERSION
    assert len(decision.evidence_digest) == 64
    assert "PRIVATE KEY" not in lab.canonical(decision).decode()
