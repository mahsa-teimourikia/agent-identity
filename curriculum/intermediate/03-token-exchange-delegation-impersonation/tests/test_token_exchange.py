"""Invariant tests for Intermediate 03 token exchange and delegation."""

from dataclasses import replace
import importlib.util
from pathlib import Path
import sys
from threading import Thread

import jwt
import pytest


LAB_PATH = Path(__file__).parents[1] / "lab.py"
SPEC = importlib.util.spec_from_file_location("intermediate03_lab", LAB_PATH)
lab = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = lab
SPEC.loader.exec_module(lab)


def claims(env, response, audience=lab.TRAVEL_API):
    return env.codec.validate(
        response.access_token,
        issuer=lab.BROKER_ISSUER,
        audience=audience,
        token_typ="at+jwt",
        max_lifetime=300,
    )


def test_hardened_matrix_matches_every_label_and_release_gate():
    cases = lab.build_cases()
    metrics, rows = lab.evaluate(cases, hardened=True)
    assert len(rows) == 33
    assert sum(case.category == "authority" for case in cases) == 11
    assert sum(case.category == "identity" for case in cases) == 10
    assert sum(case.category in {"replay", "lifecycle"} for case in cases) == 5
    assert metrics.expected_allowed == 4
    assert metrics.expected_blocked == 29
    assert metrics.outcome_matches == 33
    assert metrics.invalid_acceptances == 0
    assert metrics.valid_work_blocked == 0
    assert lab.release_gate(metrics)


def test_scope_only_baseline_exposes_material_failures():
    metrics, _ = lab.evaluate(lab.build_cases(), hardened=False)
    assert metrics.invalid_acceptances == 28
    assert metrics.authority_amplifications == 10
    assert metrics.identity_substitutions == 10
    assert metrics.replay_or_lifecycle_acceptances == 5


def test_exchange_returns_rfc_8693_response_shape_and_narrow_token():
    env = lab.Environment()
    request = env.request()
    response = env.broker.exchange(request, env.caller())
    token = claims(env, response)

    assert response.issued_token_type == lab.ACCESS_TOKEN_TYPE
    assert response.token_type == "Bearer"
    assert response.expires_in == 240
    assert response.scope == "flights:search travel:book"
    assert token["sub"] == lab.USER_ID
    assert token["aud"] == lab.TRAVEL_API
    assert token["resource_ids"] == ["trip:483"]


def test_delegation_preserves_subject_and_issuer_qualified_current_actor():
    env = lab.Environment()
    response = env.broker.exchange(env.request(), env.caller())
    token = claims(env, response)

    assert token["sub"] == lab.USER_ID
    assert token["act"] == {"iss": lab.ACTOR_ISSUER, "sub": lab.SUPERVISOR}
    assert token["workload_id"] == lab.SUPERVISOR_WORKLOAD


def test_child_exchange_derives_real_nested_chain_without_subject_change():
    env = lab.Environment()
    request, caller = lab.child_attempt(env)
    response = env.broker.exchange(request, caller)
    token = claims(env, response, lab.FLIGHT_API)

    assert token["sub"] == lab.USER_ID
    assert lab.actor_chain(token) == (lab.SPECIALIST, lab.SUPERVISOR)
    assert token["scope"] == "flights:search"
    assert token["delegation_depth"] == 2
    assert not token["redelegation"]


def test_impersonation_is_separate_approved_policy_and_omits_act():
    env = lab.Environment()
    request, caller = lab.impersonation_attempt(env)
    response = env.broker.exchange(request, caller)
    token = claims(env, response, lab.LEGACY_API)

    assert "act" not in token
    assert token["sub"] == lab.USER_ID
    assert env.broker.audit[-1].current_actor == lab.SUPERVISOR
    assert env.broker.audit[-1].approval_id == request.approval_id


@pytest.mark.parametrize(
    "case_id,reason",
    [
        ("wrong_grant_type", "grant_type_invalid"),
        ("wrong_subject_token_type", "subject_token_type_unsupported"),
        ("wrong_requested_token_type", "requested_token_type_unsupported"),
        ("id_token_substitution", "token_profile_invalid"),
        ("tampered_subject_token", "token_signature_or_claim_invalid"),
        ("expired_subject_token", "token_expired"),
    ],
)
def test_protocol_and_input_token_profiles_fail_closed(case_id, reason):
    env, request, caller, _ = lab.prepare_case(case_id)
    with pytest.raises(lab.ProtocolError, match=reason):
        env.broker.exchange(request, caller)


@pytest.mark.parametrize(
    "case_id",
    [
        "missing_actor_token",
        "wrong_actor_token_type",
        "actor_substitution",
        "caller_unverified",
        "caller_workload_mismatch",
        "caller_tenant_mismatch",
        "presenter_substitution",
    ],
)
def test_actor_client_workload_and_presenter_substitutions_are_denied(case_id):
    env, request, caller, _ = lab.prepare_case(case_id)
    with pytest.raises(lab.ProtocolError):
        env.broker.exchange(request, caller)


@pytest.mark.parametrize(
    "case_id,reason",
    [
        ("scope_amplification", "scope_amplification"),
        ("audience_amplification", "audience_amplification"),
        ("resource_amplification", "resource_amplification"),
        ("action_amplification", "action_amplification"),
        ("amount_amplification", "amount_amplification"),
        ("purpose_substitution", "purpose_mismatch"),
    ],
)
def test_every_authority_dimension_is_attenuated(case_id, reason):
    env, request, caller, _ = lab.prepare_case(case_id)
    with pytest.raises(lab.ProtocolError, match=reason):
        env.broker.exchange(request, caller)


def test_redelegation_and_depth_are_enforced_before_child_issuance():
    for case_id in ("redelegation_forbidden", "delegation_depth_exceeded"):
        env, request, caller, _ = lab.prepare_case(case_id)
        with pytest.raises(lab.ProtocolError, match="subject_not_exchangeable"):
            env.broker.exchange(request, caller)


def test_revoked_family_stops_new_exchange_and_existing_token_use():
    env = lab.Environment()
    response = env.broker.exchange(env.request(), env.caller())
    env.broker.revoked_families.add(lab.FAMILY_ID)

    with pytest.raises(lab.ProtocolError, match="delegation_family_revoked"):
        env.broker.exchange(replace(env.request(), operation_id="operation:new"), env.caller())
    with pytest.raises(lab.ProtocolError, match="delegation_family_revoked"):
        lab.ResourceServer(env.codec, lab.TRAVEL_API, env.broker.revoked_families).authorize(
            response.access_token,
            sender_jkt=lab.stable_value("supervisor:dpop", 32),
            resource="trip:483",
            action="book",
            amount=900,
            purpose="book-trip-483",
        )


def test_exact_retry_reconciles_and_changed_request_conflicts():
    env = lab.Environment()
    request = env.request()
    first = env.broker.exchange(request, env.caller())
    assert env.broker.exchange(request, env.caller()) == first

    with pytest.raises(lab.ProtocolError, match="operation_id_conflict"):
        env.broker.exchange(replace(request, requested_scopes=frozenset({"travel:read"})), env.caller())


def test_approval_is_exact_role_bound_and_atomically_single_use():
    env = lab.Environment()
    request, _ = lab.impersonation_attempt(env)
    outcomes = []

    def consume():
        try:
            env.approvals.consume(request.approval_id, request, lab.NOW)
            outcomes.append("ok")
        except lab.ProtocolError as exc:
            outcomes.append(exc.reason_code)

    threads = [Thread(target=consume), Thread(target=consume)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sorted(outcomes) == ["approval_replayed", "ok"]


def test_approval_missing_altered_and_wrong_role_are_denied():
    for case_id in ("approval_missing", "approval_wrong_request", "approval_wrong_role"):
        env, request, caller, _ = lab.prepare_case(case_id)
        with pytest.raises(lab.ProtocolError):
            env.broker.exchange(request, caller)


def test_actor_chain_rejects_cycle_malformed_identity_and_excess_depth():
    cycle = {"iss": lab.ACTOR_ISSUER, "sub": "a"}
    cycle["act"] = cycle
    with pytest.raises(lab.ProtocolError, match="actor_chain_cycle"):
        lab.actor_chain({"act": cycle})
    with pytest.raises(lab.ProtocolError, match="actor_chain_invalid"):
        lab.actor_chain({"act": {"sub": "a"}})
    chain = None
    for index in range(10):
        chain = {"iss": lab.ACTOR_ISSUER, "sub": f"actor:{index}", "act": chain}
    with pytest.raises(lab.ProtocolError, match="actor_chain_too_deep"):
        lab.actor_chain({"act": chain})


def test_resource_server_requires_bound_sender_and_object_constraints():
    env = lab.Environment()
    response = env.broker.exchange(env.request(), env.caller())
    server = lab.ResourceServer(env.codec, lab.TRAVEL_API, env.broker.revoked_families)

    accepted = server.authorize(
        response.access_token,
        sender_jkt=lab.stable_value("supervisor:dpop", 32),
        resource="trip:483",
        action="book",
        amount=900,
        purpose="book-trip-483",
    )
    assert accepted["sub"] == lab.USER_ID
    for changes, reason in (
        ({"sender_jkt": "attacker"}, "sender_binding_mismatch"),
        ({"resource": "trip:999"}, "resource_not_authorized"),
        ({"action": "refund"}, "action_not_authorized"),
        ({"amount": 901}, "amount_not_authorized"),
        ({"purpose": "export"}, "purpose_not_authorized"),
    ):
        values = dict(sender_jkt=lab.stable_value("supervisor:dpop", 32), resource="trip:483", action="book", amount=900, purpose="book-trip-483")
        values.update(changes)
        with pytest.raises(lab.ProtocolError, match=reason):
            server.authorize(response.access_token, **values)


def test_public_jwks_excludes_private_material_and_revoked_keys():
    jwks = lab.Environment().rings[lab.BROKER_ISSUER].jwks()
    assert len(jwks["keys"]) == 2
    assert all("d" not in key and "private" not in key for key in jwks["keys"])
    assert all("revoked" not in key["kid"] for key in jwks["keys"])


def test_decision_evidence_contains_digests_not_raw_credentials():
    env = lab.Environment()
    request = env.request()
    env.broker.exchange(request, env.caller())
    record = lab.public_decision(env.broker.audit[-1])
    serialized = str(record)

    assert request.subject_token not in serialized
    assert request.actor_token not in serialized
    assert record["subject_token_digest"] == lab.digest(request.subject_token)
    assert record["current_actor"] == lab.SUPERVISOR


def test_request_fields_never_supply_subject_actor_tenant_or_family():
    fields = set(lab.ExchangeRequest.__dataclass_fields__)
    assert fields.isdisjoint({"subject", "actor", "tenant_id", "delegation_family", "workload_id", "client_id"})


def test_broker_key_profile_rejects_revoked_signing_key():
    env = lab.Environment()
    bad = env.codec.issue(
        lab.USER_ISSUER,
        lab.USER_ID,
        lab.BROKER_AUDIENCE,
        "at+jwt",
        300,
        {"scope": "travel:book", "allowed_audiences": [lab.TRAVEL_API], "resource_ids": ["trip:483"], "actions": ["book"], "max_amount": 900, "purpose": "book-trip-483", "may_act": {"iss": lab.ACTOR_ISSUER, "sub": lab.SUPERVISOR}},
        kid="user-revoked",
    )
    request = replace(env.request(), subject_token=bad)
    with pytest.raises(lab.ProtocolError, match="token_key_revoked"):
        env.broker.exchange(request, env.caller())
