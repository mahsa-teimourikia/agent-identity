from __future__ import annotations

import json
import sys
from dataclasses import FrozenInstanceError, replace
from pathlib import Path

import jwt
import pytest
from hypothesis import given
from hypothesis import strategies as st

COURSE = Path(__file__).parents[1]
sys.path.insert(0, str(COURSE))

from advanced_federation_runtime import (
    AGENT_SUBJECT,
    ANCHOR,
    CLAIM,
    INTERMEDIATE,
    NOW,
    PARTNER_AS,
    PARTNER_DOMAIN,
    PARTNER_ISSUER,
    RESOURCE,
    SPIFFE_ID,
    AccessRequest,
    FederationGateway,
    OAuthTransactionStore,
    build_cases,
    build_trust_graph,
    certificate_fingerprint,
    compound_principal_id,
    create_ca,
    evaluate_baseline,
    evaluate_cases,
    issue_x509_svid,
    relationship,
    release_gate,
    resolve_metadata,
    scenario,
    select_authorization_server,
    sign_delegation,
    sign_entity_statement,
    verify_access_token,
    verify_delegation,
    verify_trust_chain,
    verify_x509_svid,
)


def test_labelled_corpus_has_broad_slices_and_exact_results():
    cases = build_cases()
    metrics, rows = evaluate_cases(cases)
    assert len(cases) == 46
    assert {case.category for case in cases} >= {
        "trust-chain",
        "metadata-policy",
        "token",
        "workload",
        "delegation",
        "mcp-oauth",
        "lifecycle",
        "local-policy",
    }
    assert all(row["match"] for row in rows)
    assert release_gate(metrics)


def test_signature_only_baseline_demonstrates_why_federation_policy_is_required():
    metrics, _ = evaluate_baseline(build_cases())
    assert metrics.invalid_allows >= 40
    assert metrics.valid_blocked == 0


@pytest.mark.parametrize("case", build_cases(), ids=lambda case: case.case_id)
def test_every_labelled_case(case):
    assert case.run() is case.expected_allowed


def test_chain_terminates_at_final_issuer_not_final_subject():
    value = scenario()
    result = verify_trust_chain(
        value["context"].chain, value["keys"], value["relationship"]
    )
    final_claims = jwt.decode(
        value["context"].chain[-1], options={"verify_signature": False}
    )
    assert result.valid
    assert final_claims["iss"] == ANCHOR
    assert final_claims["sub"] == INTERMEDIATE
    assert result.anchor == final_claims["iss"]
    assert result.subject == PARTNER_ISSUER


def test_resolved_metadata_obeys_superior_and_intermediate_policy():
    value = scenario()
    result = verify_trust_chain(
        value["context"].chain, value["keys"], value["relationship"]
    )
    assert result.resolved_metadata["grant_types_supported"] == ["authorization_code"]
    assert result.resolved_metadata["token_endpoint_auth_methods_supported"] == [
        "private_key_jwt"
    ]


def test_conflicting_metadata_policy_invalidates_resolution():
    statements = (
        {
            "metadata": {
                "oauth_authorization_server": {
                    "id_token_signing_alg_values_supported": ["EdDSA"]
                }
            }
        },
        {
            "metadata_policy": {
                "oauth_authorization_server": {
                    "id_token_signing_alg_values_supported": {"subset_of": ["EdDSA"]}
                }
            }
        },
        {
            "metadata_policy": {
                "oauth_authorization_server": {
                    "id_token_signing_alg_values_supported": {"subset_of": ["ES256"]}
                }
            }
        },
    )
    metadata, failures = resolve_metadata(statements, "oauth_authorization_server")
    assert metadata is None
    assert "metadata_policy_conflict:id_token_signing_alg_values_supported" in failures


def test_chain_requires_unique_nonempty_statement_ids_and_bound_metadata_issuer():
    value = scenario()
    claims = jwt.decode(value["context"].chain[0], options={"verify_signature": False})
    claims.pop("jti")
    missing_id = jwt.encode(
        claims,
        value["private_keys"][PARTNER_ISSUER],
        algorithm="EdDSA",
        headers={"typ": "entity-statement+jwt", "kid": "issuer-2026"},
    )
    result = verify_trust_chain(
        (missing_id, *value["context"].chain[1:]),
        value["keys"],
        value["relationship"],
    )
    assert not result.valid
    assert "statement_id_missing" in result.reason_codes

    changed_metadata = dict(claims["metadata"])
    changed_metadata["oauth_authorization_server"] = {
        **changed_metadata["oauth_authorization_server"],
        "issuer": "https://evil.example",
    }
    claims["jti"] = "es:metadata-issuer-substitution"
    claims["metadata"] = changed_metadata
    mismatched_issuer = jwt.encode(
        claims,
        value["private_keys"][PARTNER_ISSUER],
        algorithm="EdDSA",
        headers={"typ": "entity-statement+jwt", "kid": "issuer-2026"},
    )
    result = verify_trust_chain(
        (mismatched_issuer, *value["context"].chain[1:]),
        value["keys"],
        value["relationship"],
    )
    assert not result.valid
    assert "metadata_issuer_mismatch" in result.reason_codes


def test_key_rotation_accepts_explicit_new_kid_without_algorithm_agility_loss():
    value = scenario()
    new_key = value["private_keys"][PARTNER_ISSUER]
    keys = {issuer: dict(records) for issuer, records in value["keys"].items()}
    keys[PARTNER_ISSUER]["issuer-next"] = new_key.public_key()
    original = jwt.decode(
        value["context"].chain[0], options={"verify_signature": False}
    )
    rotated = sign_entity_statement(
        new_key,
        kid="issuer-next",
        issuer=original["iss"],
        subject=original["sub"],
        issued_at=original["iat"],
        expires_at=original["exp"],
        authority_hints=original["authority_hints"],
        metadata=original["metadata"],
    )
    chain = (rotated, *value["context"].chain[1:])
    assert verify_trust_chain(chain, keys, value["relationship"]).valid


def test_same_subject_from_two_issuers_never_collides_locally():
    assert compound_principal_id(
        PARTNER_ISSUER, AGENT_SUBJECT
    ) != compound_principal_id("https://id.other.example", AGENT_SUBJECT)


@given(
    st.text(min_size=1, max_size=40),
    st.text(min_size=1, max_size=40),
)
def test_compound_mapping_is_deterministic(issuer, subject):
    assert compound_principal_id(issuer, subject) == compound_principal_id(
        issuer, subject
    )


def test_real_x509_svid_is_bound_to_exact_domain_identity_and_bundle():
    value = scenario()
    result = verify_x509_svid(
        value["context"].workload_certificate,
        value["bundle"],
        value["relationship"],
        expected_spiffe_id=SPIFFE_ID,
    )
    assert (result.valid, result.reason_code) == (True, "svid_valid")
    _, evil_bundle = create_ca("evil-partner", PARTNER_DOMAIN)
    substituted = verify_x509_svid(
        value["context"].workload_certificate,
        evil_bundle,
        value["relationship"],
        expected_spiffe_id=SPIFFE_ID,
    )
    assert (substituted.valid, substituted.reason_code) == (
        False,
        "bundle_binding_invalid",
    )


def test_bundle_rotation_requires_explicit_fingerprint_update():
    ca_key, ca_cert = create_ca("partner-next", PARTNER_DOMAIN)
    cert = issue_x509_svid(ca_key, ca_cert, SPIFFE_ID, label="rotated")
    old_relationship = relationship()
    assert not verify_x509_svid(
        cert, ca_cert, old_relationship, expected_spiffe_id=SPIFFE_ID
    ).valid
    updated = replace(
        old_relationship, bundle_fingerprint=certificate_fingerprint(ca_cert)
    )
    assert verify_x509_svid(cert, ca_cert, updated, expected_spiffe_id=SPIFFE_ID).valid


def test_access_token_is_bound_to_verified_chain_and_sender_key():
    value = scenario()
    trust = verify_trust_chain(
        value["context"].chain, value["keys"], value["relationship"]
    )
    token = verify_access_token(
        value["context"].access_token,
        value["keys"],
        value["relationship"],
        trust,
        expected_audience=RESOURCE,
        expected_proof_jkt=value["context"].request.proof_jkt,
    )
    assert token.valid
    assert token.principal is not None
    assert token.principal.issuer == PARTNER_ISSUER
    assert token.principal.subject == AGENT_SUBJECT


@pytest.mark.parametrize(
    "field,value,reason",
    [
        ("issuer", "evil", "delegation_issuer_invalid"),
        ("subject_issuer", "https://evil", "delegation_subject_issuer_mismatch"),
        ("subject", "agent:evil", "delegation_subject_mismatch"),
        ("tenant_id", "tenant:evil", "delegation_tenant_mismatch"),
        ("task_id", "task:evil", "delegation_task_mismatch"),
        ("audience", "https://evil", "delegation_audience_mismatch"),
        (
            "actions",
            frozenset({"knowledge.search", "claim.delete"}),
            "delegation_action_widened",
        ),
        (
            "resources",
            frozenset({CLAIM, "claim:999"}),
            "delegation_resource_widened",
        ),
        ("expires_at", NOW, "delegation_not_current"),
        ("expires_at", NOW + 400, "delegation_outlives_token"),
        ("depth", 2, "delegation_depth_exceeded"),
        ("policy_version", "old", "delegation_policy_stale"),
    ],
)
def test_delegation_dimensions_are_independently_enforced(field, value, reason):
    scenario_value = scenario()
    context = scenario_value["context"]
    trust = verify_trust_chain(
        context.chain, scenario_value["keys"], scenario_value["relationship"]
    )
    token = verify_access_token(
        context.access_token,
        scenario_value["keys"],
        scenario_value["relationship"],
        trust,
        expected_audience=RESOURCE,
        expected_proof_jkt=context.request.proof_jkt,
    )
    changed = replace(context.delegation.grant, **{field: value})
    signed = sign_delegation(changed, scenario_value["private_keys"]["delegation"])
    assert verify_delegation(
        signed,
        scenario_value["delegation_key"],
        token,
        scenario_value["relationship"],
    ) == (False, reason)


def test_protected_resource_metadata_never_selects_an_unapproved_server():
    metadata = {
        "resource": RESOURCE,
        "authorization_servers": [PARTNER_AS, "https://evil"],
    }
    assert select_authorization_server(
        metadata,
        expected_resource=RESOURCE,
        approved_servers=frozenset({PARTNER_AS}),
    ) == (PARTNER_AS, "authorization_server_selected")
    assert select_authorization_server(
        metadata,
        expected_resource=RESOURCE,
        approved_servers=frozenset({PARTNER_AS, "https://evil"}),
    ) == (None, "authorization_server_not_unambiguous")


def test_oauth_transaction_rejects_mixup_state_swap_and_replay():
    store = OAuthTransactionStore()
    store.start("tx:1", PARTNER_AS, "state:1")
    assert store.complete("tx:1", "https://evil", "state:1") == (
        False,
        "oauth_issuer_mixup",
    )
    assert store.complete("tx:1", PARTNER_AS, "wrong") == (
        False,
        "oauth_state_mismatch",
    )
    assert store.complete("tx:1", PARTNER_AS, "state:1") == (
        True,
        "oauth_response_valid",
    )
    assert store.complete("tx:1", PARTNER_AS, "state:1") == (
        False,
        "oauth_response_replayed",
    )


def test_gateway_binds_selected_server_to_transaction_expected_issuer():
    value = scenario()
    context = replace(
        value["context"],
        oauth_transaction=replace(
            value["context"].oauth_transaction,
            expected_issuer="https://evil.example",
        ),
    )
    gateway = FederationGateway(
        value["relationship"],
        value["keys"],
        value["bundle"],
        value["delegation_key"],
    )
    decision = gateway.authorize(context)
    assert not decision.allowed
    assert decision.reason_code == "oauth_transaction_issuer_mismatch"


def test_directed_graph_does_not_invent_transitive_trust():
    graph = build_trust_graph([("corp", "partner"), ("partner", "vendor")])
    assert graph.has_edge("corp", "partner")
    assert nx_has_path(graph, "corp", "vendor")
    assert not graph.has_edge("corp", "vendor")


def nx_has_path(graph, source, target):
    # A path is useful for risk analysis; it is not an implicit trust edge.
    import networkx as nx

    return nx.has_path(graph, source, target)


def test_gateway_evidence_contains_hashes_and_no_credentials():
    value = scenario()
    gateway = FederationGateway(
        value["relationship"],
        value["keys"],
        value["bundle"],
        value["delegation_key"],
    )
    assert gateway.authorize(value["context"]).allowed
    evidence = json.dumps(gateway.evidence)
    assert value["context"].access_token not in evidence
    assert value["context"].delegation.signature not in evidence
    assert value["context"].request.subject not in evidence
    assert "foreign_subject_hash" in gateway.evidence[0]


def test_config_examples_and_primary_sources_match_the_runtime():
    registry = json.loads((COURSE / "data/trust_registry.json").read_text())
    mcp = json.loads(
        (COURSE / "configs/mcp/protected-resource-metadata.json").read_text()
    )
    readme = (COURSE / "README.md").read_text()
    assert registry[PARTNER_DOMAIN]["oidc_issuer"] == PARTNER_ISSUER
    assert mcp["resource"] == RESOURCE
    for source in (
        "openid.net/specs/openid-federation",
        "spiffe.io/docs/latest/spiffe-specs",
        "rfc-editor.org/rfc/rfc9700",
        "modelcontextprotocol.io",
    ):
        assert source in readme


def test_request_contract_is_immutable_and_domain_qualified():
    request = scenario()["context"].request
    assert isinstance(request, AccessRequest)
    assert request.issuer == PARTNER_ISSUER
    assert request.workload_id.startswith("spiffe://partner.example/")
    with pytest.raises(FrozenInstanceError):
        request.subject = "agent:evil"
