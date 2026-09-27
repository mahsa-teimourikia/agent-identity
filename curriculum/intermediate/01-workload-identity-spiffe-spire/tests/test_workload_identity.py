"""Invariant tests for Intermediate 01 workload identity."""

from dataclasses import replace
import importlib.util
from pathlib import Path
import sys

import pytest


LAB_PATH = Path(__file__).parents[1] / "lab.py"
SPEC = importlib.util.spec_from_file_location("intermediate01_lab", LAB_PATH)
lab = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = lab
SPEC.loader.exec_module(lab)


def hardened_rows():
    return lab.evaluate(lab.build_cases(), hardened=True)[1]


def row_map():
    return {case.case_id: decision for case, decision in hardened_rows()}


def test_all_labelled_outcomes_match_and_release_gate_passes():
    metrics, rows = lab.evaluate(lab.build_cases(), hardened=True)

    assert len(rows) == 20
    assert metrics.expected_allowed == 2
    assert metrics.expected_blocked == 18
    assert metrics.outcome_matches == 20
    assert metrics.invalid_acceptances == 0
    assert metrics.authorization_violations == 0
    assert metrics.stale_credential_acceptances == 0
    assert lab.release_gate(metrics)


def test_baseline_exposes_the_expected_security_failures():
    metrics, _ = lab.evaluate(lab.build_cases(), hardened=False)

    assert metrics.invalid_acceptances == 18
    assert metrics.authorization_violations == 2
    assert metrics.stale_credential_acceptances == 4


@pytest.mark.parametrize(
    "value",
    [
        "https://corp.example/ns/travel",
        "spiffe://user@corp.example/ns/travel",
        "spiffe://corp.example:443/ns/travel",
        "spiffe://Corp.example/ns/travel",
        "spiffe://corp.example/ns/../payments",
        "spiffe://corp.example/ns%2fpayments",
        "spiffe://corp.example/ns/travel?role=admin",
    ],
)
def test_spiffe_id_parser_rejects_noncanonical_or_ambiguous_forms(value):
    with pytest.raises(ValueError):
        lab.parse_spiffe_id(value)


def test_spiffe_id_parser_preserves_trust_domain_and_path():
    identity = lab.parse_spiffe_id(lab.AGENT_ID)

    assert identity.trust_domain == lab.CORP_DOMAIN
    assert identity.path == "/ns/travel/sa/booking-agent"


def test_caller_requested_identity_is_not_an_issuance_authority():
    api = lab.WorkloadAPI(lab.DeterministicIssuer(lab.CORP_DOMAIN), lab.registration_entries())
    decision, update = api.fetch(lab.booking_workload(), requested_id=lab.PAYMENT_ID)

    assert decision.outcome is lab.Outcome.ALLOW
    assert decision.issued_id == lab.AGENT_ID
    assert update and update.x509_svids[0].spiffe_id == lab.AGENT_ID


def test_attestation_must_match_exactly_one_registration():
    entries = list(lab.registration_entries())
    entries.append(replace(entries[0], entry_id="entry:duplicate"))
    api = lab.WorkloadAPI(lab.DeterministicIssuer(lab.CORP_DOMAIN), entries)

    decision, update = api.fetch(lab.booking_workload())

    assert decision.reason_code == "registration_ambiguous"
    assert update is None


def test_selector_matching_requires_parent_and_every_registered_selector():
    api = lab.WorkloadAPI(lab.DeterministicIssuer(lab.CORP_DOMAIN), lab.registration_entries())
    wrong_parent = lab.booking_workload(node_id="spiffe://corp.example/spire/agent/node-z")
    incomplete = lab.booking_workload(
        selectors=frozenset(
            {
                lab.Selector("k8s", "ns:travel"),
                lab.Selector("k8s", "sa:booking-agent"),
            }
        )
    )

    assert api.fetch(wrong_parent)[0].reason_code == "registration_not_found"
    assert api.fetch(incomplete)[0].reason_code == "registration_not_found"


def test_workload_endpoint_must_be_local_to_the_attested_node():
    api = lab.WorkloadAPI(lab.DeterministicIssuer(lab.CORP_DOMAIN), lab.registration_entries())
    decision, update = api.fetch(lab.booking_workload(endpoint_local=False))

    assert decision.reason_code == "workload_endpoint_not_local"
    assert update is None


def test_issued_svids_are_deterministic_and_short_lived():
    issuer = lab.DeterministicIssuer(lab.CORP_DOMAIN)
    first = issuer.issue_x509(lab.AGENT_ID)
    second = issuer.issue_x509(lab.AGENT_ID)

    assert lab.certificate_digest(first.certificate) == lab.certificate_digest(second.certificate)
    lifetime = first.certificate.not_valid_after_utc - first.certificate.not_valid_before_utc
    assert lifetime.total_seconds() == 300


def test_x509_verification_checks_chain_profile_time_exact_peer_and_lifecycle():
    rows = row_map()

    assert rows["valid_agent_x509"].reason_code == "authenticated_and_authorized"
    assert rows["wrong_bundle"].reason_code == "x509_chain_untrusted"
    assert rows["expired_x509"].reason_code == "x509_expired"
    assert rows["future_x509"].reason_code == "x509_not_yet_valid"
    assert rows["overlong_x509"].reason_code == "x509_lifetime_exceeds_policy"
    assert rows["wrong_peer_id"].reason_code == "peer_identity_mismatch"
    assert rows["multiple_uri_sans"].reason_code == "x509_san_profile_invalid"
    assert rows["removed_identity"].reason_code == "identity_not_active"


def test_jwt_verification_checks_trusted_key_audience_time_and_subject():
    rows = row_map()

    assert rows["valid_agent_jwt"].reason_code == "authenticated_and_authorized"
    assert rows["jwt_wrong_audience"].reason_code == "jwt_audience_mismatch"
    assert rows["jwt_expired"].reason_code == "jwt_expired"
    assert rows["jwt_unknown_key"].reason_code == "jwt_key_untrusted"


def test_bundle_rotation_requires_overlap_then_new_root_distribution():
    old = lab.DeterministicIssuer(lab.CORP_DOMAIN, generation=1)
    new = lab.DeterministicIssuer(lab.CORP_DOMAIN, generation=2)
    new_svid = new.issue_x509(lab.AGENT_ID, entry_version=4)
    request = lab.VerificationRequest(
        "request:rotation",
        "charge",
        "payment:booking-1042",
        lab.AGENT_ID,
        lab.CredentialKind.X509,
        x509_svid=new_svid,
    )

    stale = lab.default_gateway(corp_bundle=old.bundle()).verify(request)
    overlap = lab.default_gateway(
        corp_bundle=new.bundle(version=2, extra_roots=(old.root_certificate,))
    ).verify(request)

    assert stale.reason_code == "x509_chain_untrusted"
    assert overlap.outcome is lab.Outcome.ALLOW


def test_full_state_update_redaction_removes_cached_credentials():
    api = lab.WorkloadAPI(lab.DeterministicIssuer(lab.CORP_DOMAIN), lab.registration_entries())
    decision, update = api.fetch(lab.booking_workload())
    cache = lab.WorkloadClientCache()
    assert update
    cache.apply(update)
    assert decision.outcome is lab.Outcome.ALLOW
    assert lab.AGENT_ID in cache.x509_svids

    cache.apply(api.remove(lab.AGENT_ID))

    assert cache.x509_svids == {}
    assert cache.jwt_svids == {}


def test_client_rejects_partial_and_replayed_workload_api_updates():
    api = lab.WorkloadAPI(lab.DeterministicIssuer(lab.CORP_DOMAIN), lab.registration_entries())
    _, update = api.fetch(lab.booking_workload())
    assert update
    cache = lab.WorkloadClientCache()
    cache.apply(update)

    with pytest.raises(ValueError, match="stale_update"):
        cache.apply(update)
    with pytest.raises(ValueError, match="partial_update_not_supported"):
        cache.apply(replace(update, sequence=2, full_state=False))


def test_federation_authenticates_a_domain_but_does_not_grant_resource_access():
    decision = row_map()["federated_but_unauthorized"]

    assert decision.authenticated_id == lab.RESEARCH_ID
    assert decision.reason_code == "resource_not_authorized"
    assert decision.outcome is lab.Outcome.DENY


def test_authorization_is_bound_to_exact_action_and_resource():
    assert row_map()["resource_scope_violation"].reason_code == "resource_not_authorized"


def test_decision_evidence_is_public_and_contains_no_credential_material():
    decision = row_map()["valid_agent_jwt"]
    record = lab.decision_record(decision)

    assert record["credential_digest"].startswith("sha256:")
    assert "token" not in record
    assert "certificate" not in record
    assert "private_key" not in record
    assert record["bundle_version"] == 1
    assert record["entry_version"] == 3


def test_issue_request_has_no_caller_controlled_identity_or_roles():
    fields = set(lab.ObservedWorkload.__dataclass_fields__)

    assert "requested_id" not in fields
    assert "roles" not in fields
    assert "permissions" not in fields
