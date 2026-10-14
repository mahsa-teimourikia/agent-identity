from __future__ import annotations

import json
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path

import jwt
import pytest

COURSE = Path(__file__).parents[1]
sys.path.insert(0, str(COURSE))

from lab import (
    AGENT_ID,
    NOW,
    POLICY_VERSION,
    AgentProposal,
    ApprovalAuthority,
    GovernanceError,
    GovernanceStore,
    RequestContext,
    active_scenario,
    approvals,
    cases,
    evaluate,
    required_roles,
)


def test_release_gate_and_state_only_baseline_gap():
    secure, rows = evaluate()
    baseline, _ = evaluate(True)
    assert len(rows) == 27
    assert secure.correct == secure.total == 27
    assert secure.invalid_allows == secure.valid_blocks == 0
    assert baseline.invalid_allows == 20


def test_fixture_corpus_matches_executable_cases():
    fixture = json.loads((COURSE / "data/adversarial_cases.json").read_text())
    executable = cases()
    assert [item["case_id"] for item in fixture] == [
        case.case_id for case in executable
    ]
    assert [item["expected_allowed"] for item in fixture] == [
        case.expected for case in executable
    ]


@pytest.mark.parametrize("case", cases(), ids=lambda case: case.case_id)
def test_every_labelled_case(case):
    assert case.run(False) is case.expected


def test_signed_approval_receipt_is_bound_to_proposal_tenant_policy_and_role():
    proposal, authority = AgentProposal(), ApprovalAuthority()
    token = authority.issue("user:security-approver", proposal)
    header = jwt.get_unverified_header(token)
    claims = jwt.decode(token, options={"verify_signature": False})
    assert header == {
        "alg": "EdDSA",
        "kid": "user:security-approver",
        "typ": "governance-approval+jwt",
    }
    assert claims["role"] == "security"
    assert claims["proposal_digest"] == proposal.fingerprint
    assert claims["tenant"] == proposal.tenant_id
    assert claims["policy_version"] == POLICY_VERSION


@pytest.mark.parametrize(
    ("risk", "roles"),
    [
        ("low", {"owner"}),
        ("medium", {"owner", "platform"}),
        ("high", {"owner", "security"}),
        ("critical", {"owner", "security", "risk", "business_authority"}),
    ],
)
def test_risk_tier_routes_to_explicit_approval_roles(risk, roles):
    assert required_roles(risk) == roles


def test_unknown_risk_tier_fails_closed():
    with pytest.raises(GovernanceError, match="risk_tier_unknown"):
        required_roles("extreme")


def test_idempotent_register_and_activate_commands_do_not_duplicate_events():
    proposal, authority, store = AgentProposal(), ApprovalAuthority(), GovernanceStore()
    assert store.register(proposal, command_id="registration:stable") == store.register(
        proposal, command_id="registration:stable"
    )
    tokens = approvals(authority, proposal)
    first = store.activate(AGENT_ID, tokens, authority, command_id="activation:stable")
    second = store.activate(AGENT_ID, tokens, authority, command_id="activation:stable")
    assert first == second
    assert [event["event_type"] for event in store.events()] == [
        "registration_submitted",
        "approvals_verified",
        "identity_provisioned",
        "identity_activated",
    ]


def test_idempotency_key_is_bound_to_exact_request():
    store = GovernanceStore()
    store.register(AgentProposal(), command_id="registration:stable")
    with pytest.raises(GovernanceError, match="idempotency_conflict"):
        store.register(
            replace(
                AgentProposal(),
                purpose="Investigate a claim for a different approved purpose",
            ),
            command_id="registration:stable",
        )


def test_concurrent_activation_has_one_winner():
    proposal, authority, store = AgentProposal(), ApprovalAuthority(), GovernanceStore()
    store.register(proposal)

    def attempt(index: int) -> bool:
        tokens = [
            authority.issue("user:owner-approver", proposal, jti=f"owner:{index}"),
            authority.issue(
                "user:security-approver", proposal, jti=f"security:{index}"
            ),
        ]
        try:
            store.activate(AGENT_ID, tokens, authority, command_id=f"activate:{index}")
            return True
        except GovernanceError:
            return False

    with ThreadPoolExecutor(max_workers=8) as executor:
        assert sum(executor.map(attempt, range(16))) == 1
    assert store.get()["version"] == 2


def test_stale_transition_does_not_partially_mutate_state_or_audit():
    store, _, _ = active_scenario()
    before = store.events()
    with pytest.raises(GovernanceError, match="stale_version"):
        store.transition(
            "suspended",
            expected_version=1,
            actor="user:operator",
            reason="test",
            command_id="stale:transition",
        )
    assert store.get()["state"] == "active"
    assert store.events() == before


def test_emergency_signal_atomically_disables_credential_and_runtime_access():
    store, _, _ = active_scenario()
    result = store.handle_signal("credential_compromised")
    assert result["state"] == "quarantined"
    assert store.get()["credential_active"] is False
    assert store.authorize(RequestContext()).reason == "lifecycle_not_active"


def test_suspension_cannot_be_reactivated_without_a_new_reviewed_version():
    store, _, _ = active_scenario()
    store.handle_signal("owner_departed")
    with pytest.raises(GovernanceError, match="transition_invalid"):
        store.transition(
            "active",
            expected_version=3,
            actor="user:operator",
            reason="manual restore",
            command_id="unsafe:reactivation",
        )
    assert store.get()["state"] == "suspended"


def test_retirement_is_terminal_and_preserves_evidence():
    store, _, _ = active_scenario()
    store.transition(
        "retired",
        expected_version=2,
        actor="user:owner-approver",
        reason="service ended",
        command_id="retire:1",
    )
    before = store.events()
    with pytest.raises(GovernanceError, match="transition_invalid"):
        store.transition(
            "active",
            expected_version=3,
            actor="user:operator",
            reason="undelete",
            command_id="reactivate:retired",
        )
    assert store.get()["state"] == "retired"
    assert store.events() == before and store.verify_event_chain()


def test_hash_chain_detects_audit_tampering():
    store, _, _ = active_scenario()
    assert store.verify_event_chain()
    store.db.execute(
        "UPDATE events SET payload_json=? WHERE agent_id=? AND sequence=2",
        ('{"roles":["attacker"]}', AGENT_ID),
    )
    assert not store.verify_event_chain()


def test_recertification_extends_deadline_with_fresh_bound_approvals():
    store, authority, proposal = active_scenario()
    review_time = NOW + 20 * 86_400
    tokens = approvals(authority, proposal, now=review_time)
    result = store.recertify(tokens, authority, expected_version=2, now=review_time)
    assert result["version"] == 3
    assert result["review_due"] == review_time + 30 * 86_400
    assert store.authorize(replace(RequestContext(), now=NOW + 40 * 86_400)).allowed


def test_approval_receipts_are_single_use_across_lifecycle_commands():
    store, authority, proposal = active_scenario()
    review_time = NOW + 20 * 86_400
    tokens = approvals(authority, proposal, now=review_time)
    store.recertify(tokens, authority, expected_version=2, now=review_time)
    with pytest.raises(GovernanceError, match="approval_replayed"):
        store.recertify(
            tokens,
            authority,
            expected_version=3,
            now=review_time,
            command_id="recertify:replay",
        )


def test_metrics_surface_overdue_and_control_inconsistency():
    store, _, _ = active_scenario()
    assert store.metrics(now=NOW + 31 * 86_400) == {
        "total": 1,
        "active": 1,
        "non_active": 0,
        "overdue_reviews": 1,
        "active_without_credentials": 0,
    }


def test_json_schema_rejects_malformed_identity_before_persistence():
    store = GovernanceStore()
    with pytest.raises(GovernanceError, match="schema_invalid"):
        store.register(replace(AgentProposal(), agent_id="not-an-agent-id"))
    with pytest.raises(GovernanceError, match="identity_unknown"):
        store.get()


@pytest.mark.parametrize(
    "signal",
    [
        "owner_departed",
        "credential_compromised",
        "new_write_tool",
        "monitoring_disabled",
    ],
)
def test_supported_continuous_governance_signals_fail_closed(signal):
    store, _, _ = active_scenario()
    store.handle_signal(signal)
    assert not store.authorize(RequestContext()).allowed


def test_unknown_signal_cannot_silently_change_state():
    store, _, _ = active_scenario()
    with pytest.raises(GovernanceError, match="signal_unknown"):
        store.handle_signal("vibes_changed")
    assert store.get()["state"] == "active"


def test_policy_examples_cover_lifecycle_tenant_workload_review_and_denies():
    opa = (COURSE / "policies/opa/governance.rego").read_text().lower()
    cedar = (COURSE / "policies/cedar/governance.cedar").read_text().lower()
    for text in (opa, cedar):
        for required in ("active", "tenant", "workload", "review", "retired"):
            assert required in text


def test_course_lab_performs_no_network_io(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("network attempted")

    monkeypatch.setattr("socket.create_connection", forbidden)
    secure, _ = evaluate()
    assert secure.correct == secure.total
