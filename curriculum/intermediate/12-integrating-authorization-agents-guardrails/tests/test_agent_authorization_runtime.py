from __future__ import annotations

import importlib.util
import json
import sys
from dataclasses import replace
from pathlib import Path

import pytest
from cedarpy import is_authorized

COURSE = Path(__file__).parents[1]
sys.path.insert(0, str(COURSE))

from lab import (
    NOW,
    SecureAgentRuntime,
    SecurityError,
    SignedApproval,
    TerminalState,
    build_scenarios,
    evaluate,
    intent,
    proposal_digest,
    release_gate,
    valid_context,
)


def load_module(name: str, relative_path: str):
    spec = importlib.util.spec_from_file_location(name, COURSE / relative_path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    "extra",
    [
        {"tenant_id": "tenant:evil"},
        {"principal_id": "user:mallory"},
        {"approved": True},
    ],
)
def test_model_cannot_supply_trusted_security_fields(extra):
    result = SecureAgentRuntime().run(valid_context(), {**intent("extra"), **extra})
    assert result.terminal_state is TerminalState.INVALID_INTENT


@pytest.mark.parametrize(
    "field,value",
    [
        ("principal_id", "user:mallory"),
        ("tenant_id", "tenant:evil"),
        ("agent_id", "agent:other"),
        ("workload_id", "spiffe://evil/workload"),
        ("task_id", "task:other"),
        ("delegation_id", "delegation:other"),
        ("authenticated", False),
    ],
)
def test_every_trusted_context_binding_is_enforced(field, value):
    context = replace(valid_context(), **{field: value})
    result = SecureAgentRuntime().run(context, intent("bad-context"))
    assert (result.terminal_state, result.reason_code) == (
        TerminalState.DENIED,
        "TRUSTED_CONTEXT_INVALID",
    )


def test_discovery_reduces_exposure_but_invocation_reauthorizes():
    runtime = SecureAgentRuntime()
    assert "claims.get" in runtime.discover_tools(valid_context())
    bad = replace(valid_context(), workload_id="spiffe://evil")
    assert runtime.discover_tools(bad) == ()
    assert runtime.run(bad, intent("hidden")).terminal_state is TerminalState.DENIED


@pytest.mark.parametrize(
    "payload,reason",
    [
        (intent("cross", resource="claim:evil"), "CROSS_TENANT_RESOURCE"),
        (intent("unknown", "admin.export"), "TOOL_UNKNOWN"),
        (intent("wrong-type", "claims.get", "account:42"), "RESOURCE_TYPE_INVALID"),
        (intent("read-args", arguments={"all": True}), "PARAMETER_CONSTRAINT_INVALID"),
        (
            intent("field", "claims.update", arguments={"payout": 100}),
            "FIELD_NOT_AUTHORIZED",
        ),
        (
            intent("query", "knowledge.search", "kb:claims", {"query": ""}),
            "PARAMETER_CONSTRAINT_INVALID",
        ),
        (
            intent(
                "currency",
                "payments.create",
                "account:42",
                {"amount_cents": 100, "currency": "USD", "payee": "vendor:7"},
            ),
            "PAYMENT_CONSTRAINT_INVALID",
        ),
    ],
)
def test_policy_denies_invalid_invocations(payload, reason):
    result = SecureAgentRuntime().run(valid_context(), payload)
    assert (result.terminal_state, result.reason_code) == (TerminalState.DENIED, reason)


def test_guardrail_is_content_validation_not_authorization():
    result = SecureAgentRuntime().run(
        valid_context(), intent("secret", arguments={"password": "secret-token"})
    )
    assert result.terminal_state is TerminalState.GUARDRAIL_BLOCKED


def test_policy_dependency_failure_is_retryable_and_fail_closed():
    runtime = SecureAgentRuntime()
    runtime.policy_available = False
    result = runtime.run_with_retry(valid_context(), intent("outage"), max_attempts=3)
    assert result.terminal_state is TerminalState.RETRYABLE_ERROR
    assert result.attempts == 3
    assert not runtime.receipts


def payment_request(operation="payment", amount=75_000):
    return intent(
        operation,
        "payments.create",
        "account:42",
        {"amount_cents": amount, "currency": "CAD", "payee": "vendor:7"},
    )


def issue_payment_approval(runtime, request=None):
    request = request or payment_request()
    pending = runtime.run(valid_context(), request)
    assert pending.terminal_state is TerminalState.APPROVAL_REQUIRED
    assert pending.decision is not None
    return runtime.approvals.issue(valid_context(), pending.decision), pending.decision


def test_high_risk_payment_requires_signed_approval():
    runtime = SecureAgentRuntime()
    request = payment_request()
    approval, _ = issue_payment_approval(runtime, request)
    executed = runtime.run(valid_context(), request, approval=approval)
    assert executed.terminal_state is TerminalState.EXECUTED
    assert executed.receipt and executed.receipt.approval_id


def test_ineligible_approver_cannot_issue_approval():
    runtime = SecureAgentRuntime()
    _, decision = issue_payment_approval(runtime)
    with pytest.raises(SecurityError, match="APPROVER_NOT_ELIGIBLE"):
        runtime.approvals.issue(valid_context(), decision, approver_role="viewer")


def test_parameter_change_invalidates_exact_approval_binding():
    runtime = SecureAgentRuntime()
    approval, _ = issue_payment_approval(runtime)
    changed = runtime.run(
        valid_context(), payment_request(amount=90_000), approval=approval
    )
    assert (changed.terminal_state, changed.reason_code) == (
        TerminalState.DENIED,
        "APPROVAL_BINDING_INVALID",
    )


def test_tampered_approval_signature_fails_closed():
    runtime = SecureAgentRuntime()
    approval, _ = issue_payment_approval(runtime)
    tampered = SignedApproval(approval.manifest, "00" * 64)
    result = runtime.run(valid_context(), payment_request(), approval=tampered)
    assert result.reason_code == "APPROVAL_SIGNATURE_INVALID"


def test_expired_approval_fails_closed():
    runtime = SecureAgentRuntime()
    request = payment_request()
    _, decision = issue_payment_approval(runtime, request)
    expired = runtime.approvals.issue(valid_context(), decision, expires_at=NOW + 1)
    result = runtime.run(valid_context(), request, approval=expired, now=NOW + 1)
    assert result.reason_code == "APPROVAL_EXPIRED"


def test_approval_is_atomic_and_single_use():
    runtime = SecureAgentRuntime()
    request = payment_request()
    approval, _ = issue_payment_approval(runtime, request)
    assert (
        runtime.run(valid_context(), request, approval=approval).terminal_state
        is TerminalState.EXECUTED
    )
    # Exact delivery retry reconciles the persisted receipt; it does not execute again.
    retry = runtime.run(valid_context(), request, approval=approval)
    assert retry.terminal_state is TerminalState.RECONCILED
    with pytest.raises(SecurityError, match="APPROVAL_REPLAYED"):
        runtime.approvals.consume(approval)


def test_resource_version_change_invalidates_approval():
    runtime = SecureAgentRuntime()
    request = payment_request()
    approval, _ = issue_payment_approval(runtime, request)
    account = runtime.resources["account:42"]
    runtime.resources["account:42"] = replace(account, version=account.version + 1)
    result = runtime.run(valid_context(), request, approval=approval)
    assert result.reason_code == "APPROVAL_BINDING_INVALID"


def test_commit_time_reauthorization_detects_revocation(monkeypatch):
    runtime = SecureAgentRuntime()
    original = runtime.authorize
    calls = 0

    def authorize_then_revoke(context, model_intent):
        nonlocal calls
        calls += 1
        if calls == 2:
            runtime.delegation = replace(runtime.delegation, revoked=True)
        return original(context, model_intent)

    monkeypatch.setattr(runtime, "authorize", authorize_then_revoke)
    result = runtime.run(valid_context(), intent("toctou"))
    assert result.reason_code == "COMMIT_REAUTHORIZATION_DENIED"
    assert not runtime.receipts


def test_exact_retry_reconciles_but_changed_retry_conflicts():
    runtime = SecureAgentRuntime()
    request = intent("idem", "claims.update", arguments={"status": "reviewed"})
    first = runtime.run(valid_context(), request)
    assert first.terminal_state is TerminalState.EXECUTED
    assert (
        runtime.run(valid_context(), request).terminal_state is TerminalState.RECONCILED
    )
    changed = runtime.run(
        valid_context(),
        {**request, "arguments": {"status": "closed"}},
    )
    assert changed.reason_code == "IDEMPOTENCY_CONFLICT"


def test_unknown_transport_outcome_is_reconciled_without_duplicate_effect():
    runtime = SecureAgentRuntime()
    request = intent("lost", "claims.update", arguments={"status": "reviewed"})
    lost = runtime.run(valid_context(), request, inject_unknown_outcome=True)
    assert lost.terminal_state is TerminalState.UNKNOWN_OUTCOME
    assert runtime.resources["claim:483"].version == 8
    recovered = runtime.run(valid_context(), request)
    assert recovered.terminal_state is TerminalState.RECONCILED
    assert runtime.resources["claim:483"].version == 8


def test_invalid_tool_result_does_not_commit_state():
    runtime = SecureAgentRuntime()
    result = runtime.run(
        valid_context(),
        intent("bad-result", "claims.update", arguments={"status": "reviewed"}),
        inject_invalid_result=True,
    )
    assert result.terminal_state is TerminalState.RESULT_INVALID
    assert runtime.resources["claim:483"].version == 7
    assert not runtime.receipts


def test_evidence_is_minimal_and_excludes_arguments():
    runtime = SecureAgentRuntime()
    runtime.run(valid_context(), intent("evidence"))
    encoded = json.dumps(runtime.evidence)
    assert "arguments" not in encoded
    assert "synthetic" not in encoded
    assert runtime.evidence[0]["decision_id"].startswith("decision:")


def test_evaluation_has_explicit_denominators_and_release_gate():
    metrics, rows = evaluate()
    assert metrics.total_cases == len(build_scenarios()) == len(rows)
    assert metrics.valid_cases == 3
    assert metrics.invalid_cases == 9
    assert release_gate(metrics)
    insecure, _ = evaluate(secure=False)
    assert insecure.invalid_execution_rate > 0
    assert not release_gate(insecure)


def test_proposal_digest_binds_context_tool_schema_arguments_and_version():
    runtime = SecureAgentRuntime()
    parsed = runtime.parse_intent(intent("digest"))
    tool = runtime.tools["claims.get"]
    base = proposal_digest(valid_context(), parsed, tool, 7)
    assert base != proposal_digest(
        replace(valid_context(), task_id="task:other"), parsed, tool, 7
    )
    assert base != proposal_digest(
        valid_context(), parsed, replace(tool, schema_hash="changed"), 7
    )
    assert base != proposal_digest(valid_context(), parsed, tool, 8)


def test_langgraph_routes_execution_approval_and_denial():
    module = load_module("course12_graph", "langgraph/secure_agent_graph.py")
    assert module.GRAPH.invoke({"intent": intent("graph")})["route"] == "executed"
    assert (
        module.GRAPH.invoke({"intent": payment_request("graph-pay")})["route"]
        == "approval"
    )
    assert (
        module.GRAPH.invoke({"intent": intent("graph-deny", "admin.export")})["route"]
        == "blocked"
    )


def test_agents_sdk_tools_expose_strict_schemas_without_api_call():
    module = load_module("course12_agents_sdk", "agents_sdk/secure_tools.py")
    names = {tool.name for tool in module.TOOLS}
    assert names == {"claims_get", "payments_create"}
    for tool in module.TOOLS:
        assert tool.strict_json_schema is True
        assert tool.params_json_schema["additionalProperties"] is False
    payment = next(tool for tool in module.TOOLS if tool.name == "payments_create")
    assert payment.needs_approval is True


def mcp_request(**changes):
    module = load_module("course12_mcp_fixture", "mcp/mock_server.py")
    values = {
        "server_id": "mcp://claims-prod",
        "audience": "https://claims-prod",
        "tool_name": "claims.get",
        "operation_id": "operation:mcp",
        "resource_id": "claim:483",
        "arguments": {},
        "purpose": "handle assigned synthetic claim",
    }
    values.update(changes)
    return module, module.MCPRequest(**values)


@pytest.mark.parametrize(
    "changes,reason",
    [
        ({"server_id": "mcp://evil"}, "UNTRUSTED_MCP_SERVER"),
        ({"audience": "https://evil"}, "TOKEN_AUDIENCE_INVALID"),
        ({"bearer_token": "do-not-forward"}, "TOKEN_PASSTHROUGH_FORBIDDEN"),
    ],
)
def test_mcp_boundary_rejects_server_audience_and_token_passthrough(changes, reason):
    module, request = mcp_request(**changes)
    result = module.SecureMCPBoundary(SecureAgentRuntime()).invoke(
        valid_context(), request
    )
    assert result.reason_code == reason


def test_mcp_boundary_invokes_same_policy_runtime():
    module, request = mcp_request()
    result = module.SecureMCPBoundary(SecureAgentRuntime()).invoke(
        valid_context(), request
    )
    assert result.terminal_state is TerminalState.EXECUTED


def test_scenario_dataset_matches_executable_cases():
    dataset = json.loads((COURSE / "data/scenarios.json").read_text())
    assert {row["case_id"] for row in dataset["evaluation_cases"]} == {
        scenario.case_id for scenario in build_scenarios()
    }
    assert len(dataset["threat_scenarios"]) >= 8


def cedar_request(**context_changes):
    context = {
        "expectedWorkload": "spiffe://northstar.example/prod/claims",
        "taskId": "task:483",
        "toolName": "claims.get",
        "toolServer": "mcp://claims-prod",
        "policyVersion": "agent-tools/2026-10-04",
        "workloadApproved": True,
        "delegationActive": True,
        "taskResource": "claim:483",
        "requestTenant": "tenant:northstar",
    }
    context.update(context_changes)
    request = {
        "principal": {"type": "Agent", "id": "claims"},
        "action": {"type": "Action", "id": "ReadClaim"},
        "resource": {"type": "Claim", "id": "483"},
        "context": context,
    }
    entities = [
        {
            "uid": {"type": "Agent", "id": "claims"},
            "attrs": {
                "tenant": "tenant:northstar",
                "workload": "spiffe://northstar.example/prod/claims",
                "task": "task:483",
            },
            "parents": [],
        },
        {
            "uid": {"type": "Claim", "id": "483"},
            "attrs": {"tenant": "tenant:northstar", "id": "claim:483"},
            "parents": [],
        },
    ]
    policies = (COURSE / "policies/cedar/agent_tools.cedar").read_text()
    return is_authorized(request, policies, entities)


def test_cedar_policy_executes_valid_read():
    result = cedar_request()
    assert result.allowed
    assert not result.diagnostics.errors


@pytest.mark.parametrize(
    "change",
    [
        {"delegationActive": False},
        {"workloadApproved": False},
        {"requestTenant": "tenant:evil"},
        {"toolServer": "mcp://evil"},
    ],
)
def test_cedar_forbid_and_context_bindings_deny(change):
    assert not cedar_request(**change).allowed
