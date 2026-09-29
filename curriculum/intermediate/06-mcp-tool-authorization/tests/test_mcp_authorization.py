"""Executable invariants for Intermediate 06 MCP tool authorization."""

import asyncio
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import importlib.util
import json
from pathlib import Path
import sys

import cedarpy
from mcp.server import MCPServer
import pytest


LAB_PATH = Path(__file__).parents[1] / "lab.py"
SPEC = importlib.util.spec_from_file_location("intermediate06_lab", LAB_PATH)
lab = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = lab
SPEC.loader.exec_module(lab)


def payment_args(**overrides):
    value = {
        "claim_id": lab.CLAIM,
        "amount_cents": 12_500,
        "currency": "CAD",
        "payee_id": "vendor:clinic",
        "approval_id": "approval-001",
        "operation_id": "op-payment",
    }
    value.update(overrides)
    return value


def approve(engine, token, args=None, approval_id="approval-001"):
    value = dict(args or payment_args())
    value.pop("approval_id", None)
    return engine.prepare_approval(token, value, approval_id=approval_id)


def test_hardened_matrix_matches_every_label_and_release_gate():
    metrics, rows = lab.evaluate(lab.build_cases())
    assert len(rows) == 44
    assert metrics.expected_allowed == 5
    assert metrics.expected_blocked == 39
    assert metrics.invalid_acceptances == 0
    assert metrics.valid_work_blocked == 0
    assert metrics.outcome_matches == 44
    assert lab.release_gate(metrics)


def test_decode_only_baseline_exposes_many_invalid_acceptances():
    metrics, _ = lab.evaluate(lab.build_cases(), hardened=False)
    assert metrics.invalid_acceptances >= 30
    assert not lab.release_gate(metrics)


@pytest.mark.parametrize("case", lab.build_cases(), ids=lambda case: case.case_id)
def test_each_scenario_matches_its_security_label(case):
    assert lab.run_case(case) is case.expected_allowed


def test_official_sdk_server_uses_token_verifier_and_resource_validation():
    issuer, engine, _ = lab.fixture()
    server = lab.build_sdk_server(engine.verifier)
    assert isinstance(server, MCPServer)
    assert server.name == "northstar-claims"
    assert server.settings.auth.resource_server_url.unicode_string() == lab.MCP_RESOURCE
    assert server.settings.auth.validate_token_resource is True


def test_sdk_token_verifier_returns_access_token_or_none():
    issuer, engine, token = lab.fixture()
    access = asyncio.run(engine.verifier.verify_token(token))
    assert access.subject == lab.SUBJECT
    assert access.resource == lab.MCP_RESOURCE
    assert "claims:read" in access.scopes
    attacker = lab.TrainingIssuer(seed=b"\x44" * 32)
    assert asyncio.run(engine.verifier.verify_token(attacker.issue())) is None


def test_protected_resource_metadata_is_canonical_and_header_only():
    metadata = lab.protected_resource_metadata()
    assert metadata["resource"] == lab.MCP_RESOURCE
    assert metadata["authorization_servers"] == [lab.ISSUER]
    assert metadata["bearer_methods_supported"] == ["header"]
    assert "payments:create" in metadata["scopes_supported"]


def test_bad_token_returns_http_401_with_resource_metadata_challenge():
    issuer, engine, _ = lab.fixture()
    with pytest.raises(lab.AuthorizationFailure) as caught:
        engine.invoke(
            lab.TrainingIssuer(seed=b"\x55" * 32).issue(),
            "claim.read",
            {"claim_id": lab.CLAIM},
        )
    assert caught.value.status == 401
    assert "resource_metadata=" in caught.value.headers["WWW-Authenticate"]


def test_unknown_key_id_is_not_a_trust_anchor_even_with_same_key_material():
    issuer, engine, _ = lab.fixture()
    with pytest.raises(lab.AuthorizationFailure, match="token_profile_invalid"):
        engine.authenticate(issuer.issue(header_kid="caller-selected-key"))


def test_insufficient_scope_returns_http_403_stepup_challenge():
    issuer, engine, _ = lab.fixture()
    token = issuer.issue(scopes=("claims:search",))
    with pytest.raises(lab.AuthorizationFailure) as caught:
        engine.invoke(token, "claim.read", {"claim_id": lab.CLAIM})
    assert caught.value.status == 403
    assert caught.value.required_scopes == ("claims:read",)
    assert 'error="insufficient_scope"' in caught.value.headers["WWW-Authenticate"]


def test_policy_denial_is_403_without_oauth_scope_escalation():
    issuer, engine, token = lab.fixture()
    engine.task.active = False
    with pytest.raises(lab.AuthorizationFailure) as caught:
        engine.invoke(token, "claim.read", {"claim_id": lab.CLAIM})
    assert caught.value.status == 403
    assert "WWW-Authenticate" not in caught.value.headers


def test_discovery_is_filtered_but_invocation_still_reauthorizes():
    issuer, engine, _ = lab.fixture()
    token = issuer.issue(scopes=("claims:read",))
    assert engine.discover(token) == ["claim.read"]
    engine.task.tools = frozenset()
    with pytest.raises(lab.AuthorizationFailure, match="tool_not_delegated"):
        engine.invoke(token, "claim.read", {"claim_id": lab.CLAIM})


@pytest.mark.parametrize(
    "bad_args",
    [
        {"claim_id": lab.CLAIM, "admin": True},
        {"claim_id": 100},
        {"claim_id": "../../../etc/passwd"},
        {},
    ],
)
def test_input_models_reject_extra_wrong_typed_malformed_or_missing_fields(bad_args):
    _, engine, token = lab.fixture()
    with pytest.raises(lab.AuthorizationFailure) as caught:
        engine.invoke(token, "claim.read", bad_args)
    assert caught.value.status == 400
    assert caught.value.reason_code == "arguments_invalid"


def test_search_returns_only_task_and_subject_authorized_resources():
    _, engine, token = lab.fixture()
    result = engine.invoke(token, "claim.search", {"status": "open", "limit": 10})
    assert result["claim_ids"] == [lab.CLAIM]
    assert lab.OTHER_CLAIM not in result["claim_ids"]


def test_state_handle_is_bound_to_query_subject_tenant_and_task():
    _, engine, token = lab.fixture()
    first = engine.invoke(token, "claim.search", {"status": "open", "limit": 5})
    handle = first["next_state_handle"]
    engine.state_handles[handle] = replace(
        engine.state_handles[handle], task_id="task:other"
    )
    with pytest.raises(lab.AuthorizationFailure, match="state_handle_binding_invalid"):
        engine.invoke(
            token,
            "claim.search",
            {"status": "open", "limit": 5, "state_handle": handle},
        )


def test_expired_state_handle_fails_closed():
    _, engine, token = lab.fixture()
    first = engine.invoke(token, "claim.search", {"status": "open", "limit": 5})
    handle = first["next_state_handle"]
    engine.state_handles[handle] = replace(
        engine.state_handles[handle], expires_at=lab.NOW
    )
    with pytest.raises(lab.AuthorizationFailure, match="state_handle_invalid"):
        engine.invoke(
            token,
            "claim.search",
            {"status": "open", "limit": 5, "state_handle": handle},
        )


def test_approval_binds_exact_effect_and_current_versions():
    _, engine, token = lab.fixture()
    args = payment_args()
    receipt = approve(engine, token, args)
    assert receipt.policy_version == lab.POLICY_VERSION
    assert receipt.resource_version == lab.RESOURCE_VERSION
    args["amount_cents"] += 1
    with pytest.raises(lab.AuthorizationFailure, match="approval_binding_invalid"):
        engine.invoke(token, "payment.create", args)


def test_approval_is_consumed_only_after_successful_effect():
    _, engine, token = lab.fixture()
    args = payment_args()
    approve(engine, token, args)
    engine.force_bad_output = True
    with pytest.raises(lab.AuthorizationFailure, match="tool_output_invalid"):
        engine.invoke(token, "payment.create", args)
    assert not engine.approvals["approval-001"].used
    assert engine.effect_count == 0


def test_single_use_approval_cannot_authorize_a_second_operation():
    _, engine, token = lab.fixture()
    args = payment_args()
    approve(engine, token, args)
    engine.invoke(token, "payment.create", args)
    args["operation_id"] = "op-second"
    with pytest.raises(lab.AuthorizationFailure, match="approval_consumed"):
        engine.invoke(token, "payment.create", args)
    assert engine.effect_count == 1


def test_commit_time_reauthorization_closes_revocation_race():
    _, engine, token = lab.fixture()
    with pytest.raises(lab.AuthorizationFailure, match="task_inactive"):
        engine.invoke(
            token,
            "claim.update",
            {
                "claim_id": lab.CLAIM,
                "expected_version": 4,
                "status": "approved",
                "operation_id": "op-update",
            },
            before_commit=lambda value: setattr(value.task, "active", False),
        )
    assert engine.effect_count == 0
    assert engine.claims[lab.CLAIM].status == "open"


def test_unknown_outcome_reconciles_same_operation_without_duplicate_effect():
    _, engine, token = lab.fixture()
    args = {
        "claim_id": lab.CLAIM,
        "expected_version": 4,
        "status": "approved",
        "operation_id": "op-update",
    }
    with pytest.raises(lab.UnknownOutcome):
        engine.invoke(token, "claim.update", args, lose_response_after_commit=True)
    # The business state changed, but exact retry is resolved from the operation ledger
    # before a stale resource-version check can trigger another execution.
    result = engine.invoke(token, "claim.update", args)
    assert result["reconciled"] is True
    assert engine.effect_count == 1


def test_changed_retry_conflicts_instead_of_reusing_operation_id():
    _, engine, token = lab.fixture()
    args = {
        "claim_id": lab.CLAIM,
        "expected_version": 4,
        "status": "approved",
        "operation_id": "op-update",
    }
    engine.invoke(token, "claim.update", args)
    args["status"] = "closed"
    with pytest.raises(lab.AuthorizationFailure) as caught:
        engine.invoke(token, "claim.update", args)
    assert caught.value.status == 409
    assert caught.value.reason_code == "operation_id_conflict"
    assert engine.effect_count == 1


def test_concurrent_exact_retries_create_one_effect_and_reconcile_the_rest():
    _, engine, token = lab.fixture()
    args = {
        "claim_id": lab.CLAIM,
        "expected_version": 4,
        "status": "approved",
        "operation_id": "op-race",
    }
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(
            pool.map(lambda _: engine.invoke(token, "claim.update", args), range(8))
        )
    assert engine.effect_count == 1
    assert sum(result.get("reconciled", False) for result in results) == 7


def test_downstream_exchange_attenuates_and_preserves_actor_identity():
    _, engine, token = lab.fixture()
    child = engine.exchange_downstream(
        token,
        audience="https://payments-api.northstar.example",
        scopes=("payments:create",),
    )
    assert child["aud"] == "https://payments-api.northstar.example"
    assert child["sub"] == lab.SUBJECT
    assert child["act"]["sub"] == lab.AGENT
    assert child["source_token_forwarded"] is False
    assert child["expires_at"] - lab.NOW == 60


@pytest.mark.parametrize(
    "audience,scopes,reason",
    [
        ("https://evil.example", ("claims:read",), "downstream_audience_not_allowed"),
        (
            "https://claims-api.northstar.example",
            ("payments:create",),
            "downstream_scope_not_attenuated",
        ),
        ("https://claims-api.northstar.example", (), "downstream_scope_not_attenuated"),
    ],
)
def test_downstream_exchange_rejects_audience_or_scope_growth(audience, scopes, reason):
    _, engine, token = lab.fixture()
    with pytest.raises(lab.AuthorizationFailure, match=reason):
        engine.exchange_downstream(token, audience=audience, scopes=scopes)


def test_mcp_routing_headers_must_match_the_json_rpc_body():
    _, engine, token = lab.fixture()
    with pytest.raises(lab.AuthorizationFailure) as caught:
        engine.invoke(
            token, "claim.read", {"claim_id": lab.CLAIM}, mcp_name="payment.create"
        )
    assert caught.value.status == 400
    assert caught.value.reason_code == "routing_metadata_mismatch"


def test_untrusted_tool_output_is_schema_validated_before_release():
    _, engine, token = lab.fixture()
    engine.force_bad_output = True
    with pytest.raises(lab.AuthorizationFailure) as caught:
        engine.invoke(token, "claim.read", {"claim_id": lab.CLAIM})
    assert caught.value.status == 502
    assert caught.value.reason_code == "tool_output_invalid"


def test_audit_evidence_has_versions_and_token_fingerprint_not_raw_token():
    _, engine, token = lab.fixture()
    engine.invoke(token, "claim.read", {"claim_id": lab.CLAIM})
    event = engine.audit[-1]
    assert event["policy_version"] == lab.POLICY_VERSION
    assert event["toolset_version"] == lab.TOOLSET_VERSION
    assert event["resource_version"] == lab.RESOURCE_VERSION
    assert len(event["token_fingerprint"]) == 16
    assert token not in lab.canonical(event)


def test_tool_annotations_are_only_metadata_and_do_not_override_policy():
    _, engine, token = lab.fixture()
    assert lab.TOOLS["claim.read"].destructive_hint is False
    engine.task.tools = frozenset()
    with pytest.raises(lab.AuthorizationFailure, match="tool_not_delegated"):
        engine.invoke(token, "claim.read", {"claim_id": lab.CLAIM})


def test_cedar_policy_parses_and_validates_against_its_schema():
    policy_dir = LAB_PATH.parent / "policies" / "cedar"
    policies = (policy_dir / "mcp.cedar").read_text()
    schema = json.loads((policy_dir / "schema.json").read_text())
    assert len(cedarpy.PolicySet.from_str(policies)) == 4
    result = cedarpy.validate_policies(policies, schema)
    assert result.validation_passed, result.errors
