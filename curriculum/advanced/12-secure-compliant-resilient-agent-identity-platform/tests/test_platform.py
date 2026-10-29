from __future__ import annotations

import copy
import json
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jsonschema import Draft202012Validator
from pydantic import ValidationError

sys.path.insert(0, str(Path(__file__).parents[1]))

from lab import (
    CASES,
    NOW,
    AgentRecord,
    ApprovalAuthority,
    AuthorizationEngine,
    CapabilityToken,
    ContainmentAction,
    DecisionOutcome,
    Delegation,
    EffectStore,
    FederationEvidence,
    IncidentResponder,
    Intent,
    Registry,
    SecurityAlert,
    SecurityContext,
    TokenBroker,
    attenuate,
    build_evidence_chain,
    compliance_gate,
    containment_plan,
    evaluate,
    evaluate_baseline,
    fixture,
    recovery_ready,
    redact,
    run_case,
    sign_checkpoint,
    telemetry_event,
    verify_evidence,
)


@pytest.mark.parametrize(("case_id", "expected"), CASES.items())
def test_adversarial_matrix(case_id: str, expected: str) -> None:
    assert run_case(case_id) == expected


def test_strict_context_rejects_unknown_identity_claim() -> None:
    values = fixture()["context"].model_dump()
    values["is_admin_from_prompt"] = True
    with pytest.raises(ValidationError):
        SecurityContext(**values)


def test_intent_digest_changes_with_parameter_swap() -> None:
    one = Intent(
        action="claim.update",
        resource="claim:1",
        tool="mcp:claims",
        purpose="p",
        parameters={"status": "a"},
    )
    two = one.model_copy(update={"parameters": {"status": "b"}})
    assert one.request_digest != two.request_digest


def test_registry_requires_optimistic_version() -> None:
    record = fixture()["agent"]
    registry = Registry(record)
    with pytest.raises(RuntimeError, match="VERSION_CONFLICT"):
        registry.transition("suspended", expected_version=3, proposal_digest="wrong")


def test_registry_binds_exact_proposal() -> None:
    record = fixture()["agent"]
    registry = Registry(record)
    with pytest.raises(PermissionError, match="PROPOSAL_MISMATCH"):
        registry.transition("suspended", expected_version=4, proposal_digest="wrong")


def test_registry_transition_increments_version() -> None:
    from lab import digest

    record = fixture()["agent"]
    registry = Registry(record)
    proposal = digest([record.agent_id, record.version, "suspended"])
    updated = registry.transition(
        "suspended", expected_version=4, proposal_digest=proposal
    )
    assert (updated.state, updated.version) == ("suspended", 5)


def parent_delegation() -> Delegation:
    return Delegation(
        delegation_id="parent",
        tenant_id="northstar",
        delegator="user:alice",
        delegatee="agent:orchestrator",
        actions=frozenset({"claim.read", "knowledge.search"}),
        resources=frozenset({"claim:8842", "knowledge:policy"}),
        purposes=frozenset({"claims_adjustment"}),
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=30),
        depth=0,
        max_depth=1,
    )


def child_delegation(**updates: object) -> Delegation:
    child = Delegation(
        delegation_id="child",
        tenant_id="northstar",
        delegator="agent:orchestrator",
        delegatee="agent:research",
        actions=frozenset({"knowledge.search"}),
        resources=frozenset({"knowledge:policy"}),
        purposes=frozenset({"claims_adjustment"}),
        issued_at=NOW + timedelta(seconds=1),
        expires_at=NOW + timedelta(minutes=5),
        depth=1,
        max_depth=1,
        parent_id="parent",
    )
    return child.model_copy(update=updates)


def test_valid_delegation_attenuates() -> None:
    assert attenuate(parent_delegation(), child_delegation()) is None


@pytest.mark.parametrize(
    "updates",
    [
        {"tenant_id": "other"},
        {"parent_id": "wrong"},
        {"actions": frozenset({"claim.delete"})},
        {"resources": frozenset({"claim:other"})},
        {"purposes": frozenset({"marketing"})},
        {"expires_at": NOW + timedelta(hours=1)},
        {"depth": 2},
    ],
)
def test_delegation_widening_is_rejected(updates: dict[str, object]) -> None:
    with pytest.raises(PermissionError, match="widening"):
        attenuate(parent_delegation(), child_delegation(**updates))


def root_token() -> CapabilityToken:
    return CapabilityToken(
        token_id="root",
        tenant_id="northstar",
        subject="user:alice",
        actor_chain=("agent:claims",),
        audience="mcp:claims",
        scopes=frozenset({"claim.read", "claim.update"}),
        sender_key_thumbprint="key:root",
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=10),
    )


def test_token_exchange_attenuates_scope_and_lifetime() -> None:
    child = TokenBroker().exchange(
        root_token(),
        actor="agent:research",
        audience="mcp:policy-search",
        scopes={"claim.read"},
        sender_key_thumbprint="key:research",
        expires_at=NOW + timedelta(minutes=3),
    )
    assert child.parent_token_id == "root"
    assert child.actor_chain[-1] == "agent:research"


def test_token_exchange_rejects_scope_escalation() -> None:
    with pytest.raises(PermissionError, match="scope escalation"):
        TokenBroker().exchange(
            root_token(),
            actor="agent:research",
            audience="api",
            scopes={"claim.delete"},
            sender_key_thumbprint="key",
            expires_at=NOW + timedelta(minutes=3),
        )


def test_token_exchange_rejects_lifetime_extension() -> None:
    with pytest.raises(PermissionError, match="lifetime"):
        TokenBroker().exchange(
            root_token(),
            actor="agent:research",
            audience="api",
            scopes={"claim.read"},
            sender_key_thumbprint="key",
            expires_at=NOW + timedelta(hours=1),
        )


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    [
        ("tenant_id", "other", "TOKEN_TENANT"),
        ("audience", "other", "TOKEN_AUDIENCE"),
        ("action", "claim.delete", "TOKEN_SCOPE"),
        ("sender_key_thumbprint", "wrong", "TOKEN_SENDER"),
        ("now", NOW + timedelta(hours=1), "TOKEN_EXPIRED"),
    ],
)
def test_token_verification_binds_request(
    field: str, value: object, reason: str
) -> None:
    arguments = {
        "tenant_id": "northstar",
        "audience": "mcp:claims",
        "action": "claim.read",
        "sender_key_thumbprint": "key:root",
        "now": NOW + timedelta(seconds=1),
    }
    arguments[field] = value
    with pytest.raises(PermissionError, match=reason):
        TokenBroker().verify(root_token(), **arguments)


def payment_flow() -> tuple[dict[str, object], AuthorizationEngine, object]:
    values = fixture(
        action="payment.create", parameters={"amount": 1200, "currency": "USD"}
    )
    values["intent"] = values["intent"].model_copy(update={"tool": "mcp:payments"})
    engine = AuthorizationEngine()
    decision = engine.decide(**values, now=NOW)
    return values, engine, decision


def test_high_risk_effect_requires_approval() -> None:
    values, _, decision = payment_flow()
    assert decision.outcome == DecisionOutcome.APPROVAL_REQUIRED
    with pytest.raises(PermissionError, match="DECISION_NOT_ALLOW"):
        EffectStore().execute(
            context=values["context"],
            intent=values["intent"],
            decision=decision,
            now=NOW,
        )


def test_signed_approval_enables_exact_payment() -> None:
    values, engine, decision = payment_flow()
    authority = ApprovalAuthority()
    receipt = authority.issue(
        context=values["context"],
        intent=values["intent"],
        policy_version=engine.policy_version,
        approver_id="user:supervisor",
        approver_role="claims-supervisor",
        now=NOW,
    )
    allowed = engine.approve(
        decision,
        authority=authority,
        receipt=receipt,
        context=values["context"],
        intent=values["intent"],
        now=NOW,
    )
    effect = EffectStore().execute(
        context=values["context"], intent=values["intent"], decision=allowed, now=NOW
    )
    assert effect.effect == "payment.create:claim:8842"


@pytest.mark.parametrize(
    ("mutation", "reason"),
    [
        ({"tenant_id": "other"}, "APPROVAL_TENANT"),
        ({"principal_id": "user:eve"}, "APPROVAL_PRINCIPAL"),
        ({"agent_id": "agent:other"}, "APPROVAL_AGENT"),
        ({"policy_version": "old"}, "APPROVAL_POLICY"),
        ({"approver_role": "viewer"}, "APPROVAL_ROLE"),
    ],
)
def test_approval_receipt_fails_closed(
    mutation: dict[str, object], reason: str
) -> None:
    values, engine, _ = payment_flow()
    authority = ApprovalAuthority()
    receipt = authority.issue(
        context=values["context"],
        intent=values["intent"],
        policy_version=engine.policy_version,
        approver_id="user:supervisor",
        approver_role="claims-supervisor",
        now=NOW,
    ).model_copy(update=mutation)
    with pytest.raises(PermissionError, match="APPROVAL_SIGNATURE"):
        authority.consume(
            receipt,
            context=values["context"],
            intent=values["intent"],
            policy_version=engine.policy_version,
            now=NOW,
        )


def test_approval_is_single_use_under_concurrency() -> None:
    values, engine, _ = payment_flow()
    authority = ApprovalAuthority()
    receipt = authority.issue(
        context=values["context"],
        intent=values["intent"],
        policy_version=engine.policy_version,
        approver_id="user:supervisor",
        approver_role="claims-supervisor",
        now=NOW,
    )

    def attempt() -> str:
        try:
            authority.consume(
                receipt,
                context=values["context"],
                intent=values["intent"],
                policy_version=engine.policy_version,
                now=NOW,
            )
            return "accepted"
        except PermissionError:
            return "rejected"

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: attempt(), range(8)))
    assert results.count("accepted") == 1
    assert results.count("rejected") == 7


def test_approval_wrong_intent_is_rejected() -> None:
    values, engine, _ = payment_flow()
    authority = ApprovalAuthority()
    receipt = authority.issue(
        context=values["context"],
        intent=values["intent"],
        policy_version=engine.policy_version,
        approver_id="user:supervisor",
        approver_role="claims-supervisor",
        now=NOW,
    )
    changed = values["intent"].model_copy(
        update={"parameters": {"amount": 4999, "currency": "USD"}}
    )
    with pytest.raises(PermissionError, match="APPROVAL_INTENT"):
        authority.consume(
            receipt,
            context=values["context"],
            intent=changed,
            policy_version=engine.policy_version,
            now=NOW,
        )


def test_effect_store_enforces_field_constraint() -> None:
    values = fixture(parameters={"bank_account": "attacker"})
    decision = AuthorizationEngine().decide(**values, now=NOW)
    with pytest.raises(PermissionError, match="FIELD_CONSTRAINT"):
        EffectStore().execute(
            context=values["context"],
            intent=values["intent"],
            decision=decision,
            now=NOW,
        )


def test_effect_store_is_idempotent() -> None:
    values = fixture()
    decision = AuthorizationEngine().decide(**values, now=NOW)
    store = EffectStore()
    first = store.execute(
        context=values["context"], intent=values["intent"], decision=decision, now=NOW
    )
    second = store.execute(
        context=values["context"], intent=values["intent"], decision=decision, now=NOW
    )
    assert first == second


def test_unknown_outcome_must_be_reconciled() -> None:
    values = fixture()
    decision = AuthorizationEngine().decide(**values, now=NOW)
    store = EffectStore()
    with pytest.raises(TimeoutError, match="OUTCOME_UNKNOWN"):
        store.execute(
            context=values["context"],
            intent=values["intent"],
            decision=decision,
            now=NOW,
            simulate_lost_response=True,
        )
    assert (
        store.reconcile(values["context"].operation_id, values["intent"].request_digest)
        is not None
    )


def test_recursive_redaction_and_pseudonymization() -> None:
    value = {
        "principal_id": "user:alice",
        "nested": {"authorization": "Bearer secret", "items": [{"api_key": "secret"}]},
    }
    result = redact(value)
    assert result["principal_id"].startswith("hmac:")
    assert result["nested"]["authorization"] == "[REDACTED]"
    assert result["nested"]["items"][0]["api_key"] == "[REDACTED]"
    assert "secret" not in str(result)


def test_telemetry_correlates_decision_without_raw_principal() -> None:
    values = fixture()
    decision = AuthorizationEngine().decide(**values, now=NOW)
    event = telemetry_event(
        "authorization.decision",
        trace_id="trace-1",
        context=values["context"],
        decision=decision,
    )
    assert event["decision_id"] == decision.decision_id
    assert event["principal_id"] != "user:alice"
    assert event["evidence_ids"]


def test_identity_event_matches_strict_schema() -> None:
    values = fixture()
    decision = AuthorizationEngine().decide(**values, now=NOW)
    event = telemetry_event(
        "authorization.decision",
        trace_id="trace-1",
        context=values["context"],
        decision=decision,
    )
    schema_path = Path(__file__).parents[1] / "schemas" / "identity_event.schema.json"
    schema = json.loads(schema_path.read_text())
    Draft202012Validator(
        schema, format_checker=Draft202012Validator.FORMAT_CHECKER
    ).validate(event)


def test_authzen_schema_rejects_prompt_supplied_admin_field() -> None:
    schema_path = Path(__file__).parents[1] / "schemas" / "authzen_request.schema.json"
    schema = json.loads(schema_path.read_text())
    request = {
        "subject": {"type": "agent", "id": "agent:claims", "is_admin": True},
        "action": {"name": "claim.update"},
        "resource": {"type": "claim", "id": "8842"},
        "context": {
            "principal_id": "user:alice",
            "task_id": "task:1",
            "operation_id": "op:1",
            "purpose": "claims_adjustment",
            "tool": "mcp:claims",
        },
    }
    errors = list(Draft202012Validator(schema).iter_errors(request))
    assert errors


def test_attack_fixture_matches_executable_matrix() -> None:
    path = Path(__file__).parents[1] / "data" / "attack_scenarios.json"
    rows = json.loads(path.read_text())
    assert {row["id"]: row["expected"] for row in rows} == CASES


def test_wrong_tool_binding_is_denied_before_fetch() -> None:
    values = fixture()
    values["intent"] = values["intent"].model_copy(update={"tool": "mcp:payments"})
    decision = AuthorizationEngine().decide(**values, now=NOW)
    assert decision.outcome == DecisionOutcome.DENY
    assert "TOOL_BINDING" in decision.reason_codes


def valid_federation() -> FederationEvidence:
    return FederationEvidence(
        issuer="https://partner.example",
        subject="agent:research",
        trust_anchor="https://federation.corp.example",
        metadata_digest="sha256:abc",
        fetched_at=NOW,
        allowed_actions=frozenset({"knowledge.search"}),
        requested_action="knowledge.search",
    )


def test_federation_intersects_local_policy() -> None:
    valid_federation().verify(NOW)
    with pytest.raises(PermissionError, match="LOCAL_POLICY"):
        valid_federation().model_copy(
            update={"requested_action": "payment.create"}
        ).verify(NOW)


def test_federation_metadata_must_be_fresh() -> None:
    with pytest.raises(PermissionError, match="STALE"):
        valid_federation().model_copy(
            update={"fetched_at": NOW - timedelta(hours=2)}
        ).verify(NOW)


def test_evidence_checkpoint_detects_edit() -> None:
    key = Ed25519PrivateKey.generate()
    chain = build_evidence_chain([{"event": "decision"}, {"event": "effect"}])
    checkpoint = sign_checkpoint(chain, key)
    tampered = copy.deepcopy(chain)
    tampered[0]["event"]["event"] = "allow-all"
    assert not verify_evidence(tampered, checkpoint, key.public_key())


def test_evidence_checkpoint_detects_valid_prefix_truncation() -> None:
    key = Ed25519PrivateKey.generate()
    chain = build_evidence_chain([{"event": "decision"}, {"event": "effect"}])
    checkpoint = sign_checkpoint(chain, key)
    assert not verify_evidence(chain[:-1], checkpoint, key.public_key())


def test_evidence_checkpoint_rejects_wrong_signer() -> None:
    key = Ed25519PrivateKey.generate()
    chain = build_evidence_chain([{"event": "decision"}])
    checkpoint = sign_checkpoint(chain, key)
    assert not verify_evidence(
        chain, checkpoint, Ed25519PrivateKey.generate().public_key()
    )


def test_incident_alert_requires_event_authority() -> None:
    responder = IncidentResponder()
    alert = SecurityAlert(
        finding_id="f1",
        producer="claims-api",
        event_type="stolen_token",
        token_id="t1",
        agent_id="a1",
    )
    with pytest.raises(PermissionError, match="PRODUCER_AUTHORITY"):
        responder.admit(alert)


def test_destructive_containment_requires_approval_and_is_idempotent() -> None:
    responder = IncidentResponder()
    action = containment_plan("f1", "t1", "a1")[1]
    with pytest.raises(PermissionError, match="APPROVAL"):
        responder.execute(action)
    assert responder.execute(action, destructive_approval=True) == responder.execute(
        action, destructive_approval=True
    )


def test_recovery_is_conjunctive() -> None:
    evidence = {
        "credential_rotated": True,
        "fresh_attestation": True,
        "persistence_removed": True,
        "incident_cleared": True,
        "approved": True,
    }
    assert recovery_ready(evidence)
    evidence["persistence_removed"] = False
    assert not recovery_ready(evidence)


def test_compliance_gate_requires_evidence_and_safe_evaluation() -> None:
    artifacts = {
        "agent_inventory": {},
        "authorization_decision": {},
        "effect_receipt": {},
        "telemetry_event": {},
        "signed_checkpoint": {},
        "evaluation_report": {"false_allow": 0, "approval_bypass": 0},
    }
    assert compliance_gate(artifacts) == (True, ())
    del artifacts["effect_receipt"]
    assert compliance_gate(artifacts)[0] is False


def test_hardened_evaluation_beats_weak_baseline() -> None:
    baseline = evaluate_baseline()
    hardened = evaluate()
    assert hardened["correct"] == hardened["total"]
    assert hardened["false_allow"] == 0
    assert hardened["approval_bypass"] == 0
    assert baseline["correct"] < hardened["correct"]
    assert baseline["false_allow"] > 0


def test_containment_action_schema_is_strict() -> None:
    with pytest.raises(ValidationError):
        ContainmentAction(
            action_id="a",
            finding_id="f",
            action="revoke",
            target="t",
            destructive=False,
            shell="rm",
        )


def test_agent_record_is_immutable() -> None:
    record: AgentRecord = fixture()["agent"]
    with pytest.raises(ValidationError):
        record.version = 99
