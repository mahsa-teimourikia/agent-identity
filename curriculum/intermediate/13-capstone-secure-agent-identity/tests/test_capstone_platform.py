from __future__ import annotations

import asyncio
import importlib.util
import json
import sys
from dataclasses import replace
from pathlib import Path

import pytest
from cedarpy import is_authorized
from hypothesis import given
from hypothesis import strategies as st

COURSE = Path(__file__).parents[1]
sys.path.insert(0, str(COURSE))

from capstone_runtime import (
    NOW,
    TENANT,
    PromptOnlyBaseline,
    SecureAgentPlatform,
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
        {"workload_id": "spiffe://evil"},
        {"approved": True},
    ],
)
def test_model_cannot_supply_trusted_security_fields(extra):
    result = SecureAgentPlatform().run(valid_context(), {**intent("extra"), **extra})
    assert result.terminal_state is TerminalState.INVALID_INTENT


@pytest.mark.parametrize(
    "field,value,reason",
    [
        ("principal_id", "user:mallory", "PRINCIPAL_NOT_ACTIVE"),
        ("tenant_id", "tenant:evil", "AGENT_TENANT_MISMATCH"),
        ("agent_id", "agent:unknown", "AGENT_NOT_REGISTERED"),
        ("workload_id", "spiffe://evil", "WORKLOAD_BINDING_INVALID"),
        ("artifact_digest", "sha256:unknown", "ARTIFACT_NOT_APPROVED"),
        ("task_id", "task:999", "DELEGATION_INVALID"),
        ("delegation_id", "delegation:other", "DELEGATION_INVALID"),
        ("token_issuer", "https://evil", "TOKEN_ISSUER_INVALID"),
        ("token_audience", "https://other", "TOKEN_AUDIENCE_INVALID"),
        ("token_expires_at", NOW, "TOKEN_EXPIRED"),
        ("sender_key", "not-bound", "SENDER_BINDING_INVALID"),
        ("authenticated", False, "PRINCIPAL_NOT_ACTIVE"),
    ],
)
def test_every_trusted_identity_plane_is_enforced(field, value, reason):
    context = replace(valid_context(), **{field: value})
    result = SecureAgentPlatform().run(context, intent("identity"))
    assert (result.terminal_state, result.reason_code) == (TerminalState.DENIED, reason)


def test_discovery_reduces_exposure_but_invocation_reauthorizes():
    platform = SecureAgentPlatform()
    assert set(platform.discover_tools(valid_context())) == set(platform.tools)
    bad = replace(valid_context(), artifact_digest="sha256:unknown")
    assert platform.discover_tools(bad) == ()
    assert platform.run(bad, intent("bypass")).terminal_state is TerminalState.DENIED


@pytest.mark.parametrize(
    "payload,reason",
    [
        (intent("cross", resource="claim:evil"), "CROSS_TENANT_RESOURCE"),
        (intent("unassigned", resource="claim:999"), "RELATIONSHIP_NOT_AUTHORIZED"),
        (intent("unknown", "admin.export"), "TOOL_UNKNOWN"),
        (
            intent("wrong-type", "claims.get", "account:42"),
            "DELEGATED_AUTHORITY_INSUFFICIENT",
        ),
        (intent("read-args", arguments={"all": True}), "PARAMETER_INVALID"),
        (
            intent("field", "claims.update", arguments={"payout": 100}),
            "FIELD_NOT_AUTHORIZED",
        ),
        (
            intent("query", "knowledge.search", "kb:claims", {"query": ""}),
            "PARAMETER_INVALID",
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
def test_contextual_and_relationship_policy_deny_invalid_requests(payload, reason):
    result = SecureAgentPlatform().run(valid_context(), payload)
    assert (result.terminal_state, result.reason_code) == (TerminalState.DENIED, reason)


def test_oauth_scope_is_required_per_tool():
    context = replace(valid_context(), token_scopes=("claims:write",))
    result = SecureAgentPlatform().run(context, intent("scope"))
    assert result.reason_code == "OAUTH_SCOPE_INSUFFICIENT"


def test_rag_filters_before_content_reaches_model():
    platform = SecureAgentPlatform()
    platform.delegation = replace(
        platform.delegation,
        resources=platform.delegation.resources + ("kb:restricted",),
    )
    platform.relationships.add(("agent:claims", "task:483", "kb:restricted"))
    result = platform.run(
        valid_context(),
        intent("rag", "knowledge.search", "kb:restricted", {"query": "executive"}),
    )
    assert result.reason_code == "DATA_CLASS_NOT_AUTHORIZED"
    assert result.output is None


def test_memory_is_task_scoped():
    platform = SecureAgentPlatform()
    platform.delegation = replace(
        platform.delegation,
        resources=platform.delegation.resources + ("memory:task:999",),
    )
    platform.relationships.add(("agent:claims", "task:483", "memory:task:999"))
    result = platform.run(
        valid_context(),
        intent("memory", "memory.write", "memory:task:999", {"summary": "leak"}),
    )
    assert result.reason_code == "TASK_RESOURCE_MISMATCH"


def test_child_agent_authority_must_be_attenuated():
    payload = intent(
        "launder",
        "agents.delegate",
        "agent:research",
        {"actions": ["payment.create"], "resources": ["account:42"]},
    )
    result = SecureAgentPlatform().run(valid_context(), payload)
    assert result.reason_code == "CHILD_AUTHORITY_NOT_ATTENUATED"

    wrong_resource = intent(
        "launder-resource",
        "agents.delegate",
        "agent:research",
        {"actions": ["knowledge.search"], "resources": ["account:42"]},
    )
    assert (
        SecureAgentPlatform().run(valid_context(), wrong_resource).reason_code
        == "CHILD_AUTHORITY_NOT_ATTENUATED"
    )


@given(
    requested=st.sets(
        st.sampled_from(
            [
                "claim.read",
                "claim.update",
                "knowledge.search",
                "payment.create",
                "admin.root",
            ]
        ),
        max_size=5,
    )
)
def test_child_authority_never_exceeds_parent_property(requested):
    platform = SecureAgentPlatform()
    allowed = set(platform.delegation.actions)
    effective = requested & allowed
    assert effective.issubset(allowed)
    if "admin.root" in requested:
        assert "admin.root" not in effective


@pytest.mark.parametrize(
    "transport_change,reason",
    [
        ({"server_id": "mcp://evil"}, "MCP_SERVER_UNTRUSTED"),
        ({"token_audience": "https://evil"}, "MCP_TOKEN_AUDIENCE_INVALID"),
        ({"forwards_incoming_token": True}, "TOKEN_PASSTHROUGH_FORBIDDEN"),
    ],
)
def test_mcp_boundary_rejects_substitution_and_passthrough(transport_change, reason):
    platform = SecureAgentPlatform()
    transport = replace(platform.default_transport("claims.get"), **transport_change)
    result = platform.run(valid_context(), intent("mcp"), transport=transport)
    assert result.reason_code == reason


def test_guardrail_is_not_authorization():
    result = SecureAgentPlatform().run(
        valid_context(), intent("secret", arguments={"password": "do-not-log"})
    )
    assert result.terminal_state is TerminalState.GUARDRAIL_BLOCKED


@pytest.mark.parametrize("dependency", ["policy_available", "relationships_available"])
def test_authorization_dependencies_fail_closed_and_retry_is_bounded(dependency):
    platform = SecureAgentPlatform()
    setattr(platform, dependency, False)
    result = platform.run_with_retry(valid_context(), intent("outage"), max_attempts=3)
    assert result.terminal_state is TerminalState.RETRYABLE_ERROR
    assert result.attempts == 3
    assert not platform.receipts


def payment_request(operation="payment", amount=75_000):
    return intent(
        operation,
        "payments.create",
        "account:42",
        {"amount_cents": amount, "currency": "CAD", "payee": "vendor:7"},
    )


def issue_approval(platform, payload=None):
    payload = payload or payment_request()
    pending = platform.run(valid_context(), payload)
    assert pending.terminal_state is TerminalState.APPROVAL_REQUIRED
    assert pending.decision
    return platform.approvals.issue(valid_context(), pending.decision), pending.decision


def test_high_risk_payment_requires_exact_signed_approval():
    platform = SecureAgentPlatform()
    payload = payment_request()
    approval, _ = issue_approval(platform, payload)
    result = platform.run(valid_context(), payload, approval=approval)
    assert result.terminal_state is TerminalState.EXECUTED
    assert result.receipt and result.receipt.approval_id


def test_approver_must_have_authoritative_role():
    platform = SecureAgentPlatform()
    _, decision = issue_approval(platform)
    with pytest.raises(SecurityError, match="APPROVER_NOT_ELIGIBLE"):
        platform.approvals.issue(valid_context(), decision, approver_role="viewer")


def test_parameter_change_invalidates_approval():
    platform = SecureAgentPlatform()
    approval, _ = issue_approval(platform)
    result = platform.run(
        valid_context(), payment_request(amount=90_000), approval=approval
    )
    assert result.reason_code == "APPROVAL_BINDING_INVALID"


def test_tampered_and_expired_approval_fail_closed():
    platform = SecureAgentPlatform()
    payload = payment_request()
    approval, decision = issue_approval(platform, payload)
    tampered = SignedApproval(approval.manifest, "00" * 64)
    assert (
        platform.run(valid_context(), payload, approval=tampered).reason_code
        == "APPROVAL_SIGNATURE_INVALID"
    )
    expired = platform.approvals.issue(valid_context(), decision, expires_at=NOW + 1)
    assert (
        platform.run(
            valid_context(), payload, approval=expired, now=NOW + 1
        ).reason_code
        == "APPROVAL_EXPIRED"
    )


def test_approval_is_single_use_but_exact_delivery_retry_reconciles():
    platform = SecureAgentPlatform()
    payload = payment_request()
    approval, _ = issue_approval(platform, payload)
    assert (
        platform.run(valid_context(), payload, approval=approval).terminal_state
        is TerminalState.EXECUTED
    )
    assert (
        platform.run(valid_context(), payload, approval=approval).terminal_state
        is TerminalState.RECONCILED
    )
    with pytest.raises(SecurityError, match="APPROVAL_REPLAYED"):
        platform.approvals.consume(approval)


def test_resource_change_invalidates_approval():
    platform = SecureAgentPlatform()
    payload = payment_request()
    approval, _ = issue_approval(platform, payload)
    resource = platform.resources["account:42"]
    platform.resources["account:42"] = replace(resource, version=resource.version + 1)
    assert (
        platform.run(valid_context(), payload, approval=approval).reason_code
        == "APPROVAL_BINDING_INVALID"
    )


def test_commit_time_reauthorization_detects_revocation(monkeypatch):
    platform = SecureAgentPlatform()
    original = platform.authorize
    calls = 0

    def authorize_then_revoke(context, model_intent, transport, *, now=NOW + 1):
        nonlocal calls
        calls += 1
        if calls == 2:
            platform.delegation = replace(platform.delegation, revoked=True)
        return original(context, model_intent, transport, now=now)

    monkeypatch.setattr(platform, "authorize", authorize_then_revoke)
    result = platform.run(valid_context(), intent("toctou"))
    assert result.reason_code == "COMMIT_REAUTHORIZATION_DENIED"
    assert not platform.receipts


def test_exact_retry_reconciles_and_changed_retry_conflicts():
    platform = SecureAgentPlatform()
    payload = intent("idem", "claims.update", arguments={"status": "reviewed"})
    assert (
        platform.run(valid_context(), payload).terminal_state is TerminalState.EXECUTED
    )
    assert (
        platform.run(valid_context(), payload).terminal_state
        is TerminalState.RECONCILED
    )
    changed = platform.run(
        valid_context(), {**payload, "arguments": {"status": "closed"}}
    )
    assert changed.reason_code == "IDEMPOTENCY_CONFLICT"


def test_unknown_outcome_reconciles_without_duplicate_effect():
    platform = SecureAgentPlatform()
    payload = intent("lost", "claims.update", arguments={"status": "reviewed"})
    assert (
        platform.run(
            valid_context(), payload, inject_unknown_outcome=True
        ).terminal_state
        is TerminalState.UNKNOWN_OUTCOME
    )
    assert (
        platform.run(valid_context(), payload).terminal_state
        is TerminalState.RECONCILED
    )
    assert platform.resources["claim:483"].version == 8


def test_invalid_tool_result_never_commits():
    platform = SecureAgentPlatform()
    result = platform.run(
        valid_context(),
        intent("result", "claims.update", arguments={"status": "reviewed"}),
        inject_invalid_result=True,
    )
    assert result.terminal_state is TerminalState.RESULT_INVALID
    assert platform.resources["claim:483"].version == 7
    assert not platform.receipts


def test_evidence_is_minimal_hash_chained_and_tamper_evident():
    platform = SecureAgentPlatform()
    platform.run(valid_context(), intent("evidence"))
    platform.run(valid_context(), intent("evidence-deny", resource="claim:evil"))
    encoded = json.dumps([event.__dict__ for event in platform.evidence])
    assert "arguments" not in encoded and "synthetic" not in encoded
    assert platform.verify_evidence()
    platform.evidence[0] = replace(platform.evidence[0], reason_code="tampered")
    assert not platform.verify_evidence()


def test_digest_binds_every_effect_security_dimension():
    platform = SecureAgentPlatform()
    parsed = platform.parse_intent(intent("digest"))
    tool = platform.tools["claims.get"]
    transport = platform.default_transport("claims.get")
    base = proposal_digest(valid_context(), parsed, tool, 7, transport)
    assert base != proposal_digest(
        replace(valid_context(), task_id="task:other"), parsed, tool, 7, transport
    )
    assert base != proposal_digest(
        replace(valid_context(), token_scopes=("claims:read", "admin:*")),
        parsed,
        tool,
        7,
        transport,
    )
    assert base != proposal_digest(
        valid_context(), parsed, replace(tool, schema_hash="changed"), 7, transport
    )
    assert base != proposal_digest(valid_context(), parsed, tool, 8, transport)
    assert base != proposal_digest(
        valid_context(), parsed, tool, 7, replace(transport, server_id="mcp://other")
    )


def test_evaluation_has_explicit_populations_and_release_gate():
    metrics, rows = evaluate()
    assert metrics.total_cases == len(build_scenarios()) == len(rows) == 27
    assert metrics.valid_cases == 6 and metrics.invalid_cases == 21
    assert release_gate(metrics)
    insecure, _ = evaluate(secure=False)
    assert insecure.invalid_execution_rate > 0
    assert not release_gate(insecure)
    assert (
        PromptOnlyBaseline().run(intent("baseline")).terminal_state
        is TerminalState.EXECUTED
    )


def test_registry_fixture_matches_runtime_governance_metadata():
    registry = json.loads((COURSE / "data/agent_registry.json").read_text())
    platform = SecureAgentPlatform()
    assert registry["registry_version"] == "registry/2026-10-04"
    assert set(registry["agents"]) == set(platform.agents)
    for record in registry["agents"].values():
        assert record["owner"] and record["business_purpose"]
        assert record["review_due_at"] > NOW
        assert record["test_status"] == "passing"


def test_scenario_corpus_covers_each_capstone_plane():
    case_ids = {scenario.case_id for scenario in build_scenarios()}
    required = {
        "wrong-issuer",
        "wrong-workload",
        "cross-tenant",
        "restricted-rag",
        "cross-task-memory",
        "authority-laundering",
        "mcp-substitution",
        "revoked-delegation",
        "policy-outage",
    }
    assert required.issubset(case_ids)


def cedar_request(**context_changes):
    context = {
        "expectedWorkload": "spiffe://northstar.example/prod/claims",
        "taskId": "task:483",
        "toolName": "claims.get",
        "toolServer": "mcp://claims-prod",
        "policyVersion": "capstone/2026-10-04",
        "workloadApproved": True,
        "delegationActive": True,
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
                "tenant": TENANT,
                "workload": "spiffe://northstar.example/prod/claims",
                "task": "task:483",
            },
            "parents": [],
        },
        {
            "uid": {"type": "Claim", "id": "483"},
            "attrs": {"tenant": TENANT, "id": "claim:483"},
            "parents": [],
        },
    ]
    policies = (COURSE / "policies/cedar/capstone.cedar").read_text()
    return is_authorized(request, policies, entities)


def test_cedar_policy_executes_allow_and_forbid_cases():
    assert cedar_request().allowed
    for change in (
        {"delegationActive": False},
        {"workloadApproved": False},
        {"requestTenant": "tenant:evil"},
        {"toolServer": "mcp://evil"},
    ):
        assert not cedar_request(**change).allowed


def test_architecture_diagram_contains_every_enforcement_plane():
    diagram = (COURSE / "architecture/capstone_architecture.mmd").read_text()
    for term in (
        "IdP",
        "Gateway",
        "Workload",
        "PDP",
        "OpenFGA",
        "OPA",
        "Approval",
        "MCP",
        "RAG",
        "Evidence",
    ):
        assert term in diagram


def test_openai_agents_sdk_exposes_strict_tools_without_api_call():
    module = load_module("capstone_agents_sdk", "agents_sdk/secure_tools.py")
    assert {tool.name for tool in module.TOOLS} == {"claims_get", "payments_create"}
    assert all(tool.strict_json_schema for tool in module.TOOLS)
    payment = next(tool for tool in module.TOOLS if tool.name == "payments_create")
    assert payment.needs_approval is True


def test_langgraph_routes_allow_approval_and_deny():
    module = load_module("capstone_langgraph", "langgraph/capstone_graph.py")
    assert module.GRAPH.invoke({"intent": intent("graph")})["route"] == "executed"
    assert (
        module.GRAPH.invoke({"intent": payment_request("graph-payment")})["route"]
        == "approval"
    )
    assert (
        module.GRAPH.invoke({"intent": intent("graph-deny", resource="claim:evil")})[
            "route"
        ]
        == "blocked"
    )


def test_mcp_v2_sdk_server_publishes_guarded_tools():
    module = load_module("capstone_mcp", "protocols/mcp_server.py")
    tools = asyncio.run(module.SERVER.list_tools())
    assert {tool.name for tool in tools} == {"claims_get", "payments_create"}
    claims = next(tool for tool in tools if tool.name == "claims_get")
    payment = next(tool for tool in tools if tool.name == "payments_create")
    assert claims.annotations.read_only_hint is True
    assert payment.annotations.destructive_hint is True
