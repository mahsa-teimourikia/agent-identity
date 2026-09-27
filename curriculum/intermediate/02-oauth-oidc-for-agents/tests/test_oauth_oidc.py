"""Invariant tests for Intermediate 02 OAuth/OIDC security."""

from dataclasses import replace
import importlib.util
from pathlib import Path
import sys
from threading import Thread

import pytest


LAB_PATH = Path(__file__).parents[1] / "lab.py"
SPEC = importlib.util.spec_from_file_location("intermediate02_lab", LAB_PATH)
lab = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = lab
SPEC.loader.exec_module(lab)


def row_map():
    return {
        case.case_id: decision
        for case, decision in lab.evaluate(lab.build_cases(), hardened=True)[1]
    }


def transaction_fixture(transaction_id="transaction:test"):
    keys = lab.IssuerKeyRing.default()
    token_issuer = lab.TokenIssuer(keys)
    server = lab.AuthorizationServer(lab.default_client(), token_issuer)
    start = server.begin(
        transaction_id=transaction_id,
        redirect_uri="https://agent.northstar.example/oauth/callback",
        resource=lab.TRAVEL_API,
        scopes={"openid", "profile", "trips:read", "trips:book"},
        subject=lab.USER_ID,
        task_id="task:book-trip-1042",
    )
    response = server.authorize(start)
    return keys, server, start, response


def redeem(server, start, response, **changes):
    values = {
        "code_verifier": start.code_verifier,
        "redirect_uri": "https://agent.northstar.example/oauth/callback",
        "workload": lab.default_workload(),
        "grant": lab.default_grant(),
        "dpop_jkt": lab.DPoPClient().jkt,
    }
    values.update(changes)
    return server.redeem(response, **values)


def test_all_labelled_outcomes_match_and_release_gate_passes():
    metrics, rows = lab.evaluate(lab.build_cases(), hardened=True)

    assert len(rows) == 25
    assert metrics.expected_allowed == 2
    assert metrics.expected_blocked == 23
    assert metrics.outcome_matches == 25
    assert metrics.invalid_acceptances == 0
    assert metrics.authority_amplifications == 0
    assert metrics.replay_acceptances == 0
    assert metrics.cross_resource_acceptances == 0
    assert lab.release_gate(metrics)


def test_baseline_exposes_claims_only_security_failures():
    metrics, _ = lab.evaluate(lab.build_cases(), hardened=False)

    assert metrics.invalid_acceptances == 19
    assert metrics.authority_amplifications == 6
    assert metrics.replay_acceptances == 5
    assert metrics.cross_resource_acceptances == 3


def test_authorization_start_rejects_unregistered_redirect_resource_and_scope():
    server = lab.AuthorizationServer(lab.default_client(), lab.TokenIssuer(lab.IssuerKeyRing.default()))
    base = dict(transaction_id="transaction:bad", redirect_uri="https://agent.northstar.example/oauth/callback", resource=lab.TRAVEL_API, scopes={"openid"}, subject=lab.USER_ID, task_id="task:book-trip-1042")

    for field, value, reason in (
        ("redirect_uri", "https://evil.example/callback", "redirect_uri_unregistered"),
        ("resource", "https://evil.example/api", "resource_not_registered"),
        ("scopes", {"admin"}, "scope_not_registered"),
        ("scopes", {"trips:read"}, "openid_scope_required"),
    ):
        with pytest.raises(lab.ProtocolError, match=reason):
            server.begin(**{**base, field: value})


def test_authorization_transaction_binds_state_issuer_redirect_and_pkce():
    _, server, start, response = transaction_fixture()
    failures = (
        ({"response": replace(response, state="attacker")}, "authorization_state_mismatch"),
        ({"response": replace(response, issuer="https://evil.example")}, "authorization_issuer_mismatch"),
        ({"redirect_uri": "https://evil.example/callback"}, "redirect_uri_mismatch"),
        ({"code_verifier": "wrong"}, "pkce_verification_failed"),
    )
    for changes, reason in failures:
        local_response = changes.pop("response", response)
        with pytest.raises(lab.ProtocolError, match=reason):
            redeem(server, start, local_response, **changes)


def test_authorization_code_is_single_use_and_exact_retry_is_not_success():
    _, server, start, response = transaction_fixture()

    token_set = redeem(server, start, response)
    assert token_set.token_type == "DPoP"
    with pytest.raises(lab.ProtocolError, match="authorization_code_replayed"):
        redeem(server, start, response)


def test_concurrent_authorization_code_redemption_allows_one_consumer():
    _, server, start, response = transaction_fixture("transaction:concurrent")
    outcomes = []

    def attempt():
        try:
            redeem(server, start, response)
            outcomes.append("issued")
        except lab.ProtocolError as exc:
            outcomes.append(exc.reason_code)

    threads = [Thread(target=attempt) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert sorted(outcomes) == ["authorization_code_replayed", "issued"]


def test_authorization_code_binds_verified_workload_and_delegation():
    _, server, start, response = transaction_fixture()
    with pytest.raises(lab.ProtocolError, match="workload_client_binding_invalid"):
        redeem(server, start, response, workload=lab.default_workload(agent_id="agent:attacker"))

    _, server, start, response = transaction_fixture("transaction:grant")
    with pytest.raises(lab.ProtocolError, match="delegation_binding_invalid"):
        redeem(server, start, response, grant=lab.default_grant(task_id="task:other"))


def test_id_token_is_for_client_and_validates_nonce_and_time():
    keys, server, start, response = transaction_fixture()
    token_set = redeem(server, start, response)

    claims = lab.validate_id_token(
        token_set.id_token,
        keys=keys,
        expected_client_id=lab.CLIENT_ID,
        expected_nonce=start.nonce,
    )
    assert claims["sub"] == lab.USER_ID
    with pytest.raises(lab.ProtocolError, match="id_token_nonce_mismatch"):
        lab.validate_id_token(token_set.id_token, keys=keys, expected_client_id=lab.CLIENT_ID, expected_nonce="wrong")


def test_api_rejects_id_token_even_when_signature_is_valid():
    assert row_map()["id_token_at_api"].reason_code == "access_token_header_invalid"


def test_token_broker_intersects_user_client_agent_task_and_resource_authority():
    broker = lab.TokenBroker(lab.default_client(), lab.TokenIssuer(lab.IssuerKeyRing.default()))
    dpop = lab.DPoPClient()
    request = lab.BrokerRequest(
        "broker:valid",
        lab.USER_ID,
        lab.CLIENT_ID,
        lab.AGENT_ID,
        "task:book-trip-1042",
        lab.PAYMENT_API,
        frozenset({"payments:create"}),
        dpop.jkt,
    )

    token = broker.issue(lab.default_workload(), lab.default_grant(), request)
    assert token and lab.digest_text(token).startswith("sha256:")

    for changed, reason in (
        (replace(request, request_id="broker:scope", requested_scopes=frozenset({"admin"})), "scope_amplification"),
        (replace(request, request_id="broker:resource", resource=lab.MCP_RESOURCE), "resource_not_delegated"),
        (replace(request, request_id="broker:task", task_id="task:other"), "delegation_binding_invalid"),
        (replace(request, request_id="broker:actor", agent_id="agent:attacker"), "request_actor_binding_invalid"),
    ):
        with pytest.raises(lab.ProtocolError, match=reason):
            broker.issue(lab.default_workload(), lab.default_grant(), changed)


def test_broker_operation_id_cannot_be_reused_for_changed_request():
    broker = lab.TokenBroker(lab.default_client(), lab.TokenIssuer(lab.IssuerKeyRing.default()))
    request = lab.BrokerRequest("broker:stable", lab.USER_ID, lab.CLIENT_ID, lab.AGENT_ID, "task:book-trip-1042", lab.TRAVEL_API, frozenset({"trips:read"}))
    broker.issue(lab.default_workload(), lab.default_grant(), request)

    with pytest.raises(lab.ProtocolError, match="broker_idempotency_conflict"):
        broker.issue(lab.default_workload(), lab.default_grant(), replace(request, requested_scopes=frozenset({"trips:book"})))


def test_client_credentials_never_implies_a_human_subject():
    keys = lab.IssuerKeyRing.default()
    broker = lab.TokenBroker(lab.default_client(), lab.TokenIssuer(keys))
    token = broker.client_credentials(lab.default_workload(), resource=lab.TRAVEL_API, scopes=frozenset({"inventory:read"}))
    claims = jwt_decode_without_authority(token)

    assert claims["sub"] == lab.CLIENT_ID
    assert "act" not in claims
    assert "task_id" not in claims
    with pytest.raises(lab.ProtocolError, match="client_credentials_authority_exceeded"):
        broker.client_credentials(lab.default_workload(), resource=lab.PAYMENT_API, scopes=frozenset({"payments:create"}))


def jwt_decode_without_authority(token):
    import jwt

    return jwt.decode(token, options={"verify_signature": False})


def test_access_token_profile_checks_key_audience_time_type_scope_and_actor():
    rows = row_map()

    expected = {
        "wrong_audience": "token_audience_mismatch",
        "expired_token": "token_expired",
        "future_token": "token_not_yet_valid",
        "overlong_token": "token_lifetime_exceeds_policy",
        "unknown_key": "token_key_untrusted",
        "revoked_key": "token_key_revoked",
        "missing_scope": "scope_insufficient",
        "malformed_actor": "token_actor_invalid",
        "empty_scope": "token_scope_empty",
    }
    assert {case: rows[case].reason_code for case in expected} == expected


def test_resource_authorization_is_independent_of_token_signature_and_scope():
    rows = row_map()

    assert rows["cross_subject_resource"].reason_code == "subject_not_resource_owner"
    assert rows["cross_tenant_resource"].reason_code == "tenant_mismatch"
    assert rows["wrong_client_binding"].reason_code == "client_not_authorized"
    assert rows["wrong_actor_binding"].reason_code == "actor_not_authorized"
    assert rows["wrong_workload_binding"].reason_code == "workload_not_authorized"
    assert rows["unsupported_action"].outcome is lab.Outcome.DENY


def test_dpop_is_bound_to_token_key_method_uri_time_and_jti():
    rows = row_map()

    expected = {
        "dpop_missing": "dpop_proof_required",
        "dpop_wrong_key": "dpop_key_binding_mismatch",
        "dpop_wrong_method": "dpop_method_mismatch",
        "dpop_wrong_uri": "dpop_uri_mismatch",
        "dpop_wrong_token": "dpop_access_token_mismatch",
        "dpop_stale": "dpop_proof_stale",
        "dpop_replay": "dpop_replay",
    }
    assert {case: rows[case].reason_code for case in expected} == expected


def test_public_jwks_excludes_private_and_revoked_key_material():
    jwks = lab.IssuerKeyRing.default().public_jwks()

    assert all("d" not in key for key in jwks["keys"])
    assert {key["kid"] for key in jwks["keys"]} == {"northstar-2026-09", "northstar-2026-08"}


@pytest.mark.parametrize(
    ("metadata", "expected"),
    [
        ({"resource": lab.MCP_RESOURCE, "authorization_servers": [lab.ISSUER]}, True),
        ({"resource": "http://mcp.northstar.example/mcp", "authorization_servers": [lab.ISSUER]}, False),
        ({"resource": lab.MCP_RESOURCE + "#fragment", "authorization_servers": [lab.ISSUER]}, False),
        ({"resource": lab.MCP_RESOURCE, "authorization_servers": ["https://evil.example"]}, False),
    ],
)
def test_protected_resource_metadata_requires_exact_https_resource_and_trusted_issuer(metadata, expected):
    assert lab.trusted_protected_resource_metadata(metadata) is expected


def test_decision_evidence_contains_digests_not_credentials():
    record = lab.decision_record(row_map()["valid_dpop_booking"])

    assert record["token_digest"].startswith("sha256:")
    assert "access_token" not in record
    assert "dpop_proof" not in record
    assert record["subject"] == lab.USER_ID
    assert record["actor"] == lab.AGENT_ID
    assert record["workload_id"] == lab.WORKLOAD_ID


def test_untrusted_requests_cannot_supply_verified_workload_or_tenant_authority():
    fields = set(lab.BrokerRequest.__dataclass_fields__)

    assert "workload_id" not in fields
    assert "tenant_id" not in fields
    assert "roles" not in fields
