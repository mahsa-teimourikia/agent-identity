"""Security regression suite for Intermediate 11."""

import importlib.util
import json
import sys
from dataclasses import replace
from pathlib import Path

import jwt
import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

COURSE = Path(__file__).parents[1]
SPEC = importlib.util.spec_from_file_location("intermediate11_lab", COURSE / "lab.py")
lab = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = lab
SPEC.loader.exec_module(lab)


def outcome(request_change=None, token=None, service_change=None, available=True):
    service, _pep, request, baseline_token = lab.course_fixture()
    if request_change:
        request = replace(request, **request_change)
    if service_change:
        service_change(service)
    return service.authorize(
        request,
        token if token is not None else baseline_token,
        dependencies_available=available,
    ).decision


def assert_deny(decision, reason):
    assert decision.outcome is lab.DecisionOutcome.DENY
    assert decision.reason_code == reason


def test_baseline_authorizes_and_executes_once():
    service, pep, request, token = lab.course_fixture()
    signed = service.authorize(request, token)
    assert signed.decision.outcome is lab.DecisionOutcome.ALLOW
    status, receipt = pep.execute(signed, request)
    assert status == "executed"
    assert receipt.effect == "claim_read"
    assert receipt.request_digest == lab.request_digest(request)


def test_canonical_digest_is_stable_and_security_complete():
    _service, _pep, request, _token = lab.course_fixture()
    assert lab.request_digest(request) == lab.request_digest(request)
    changes = (
        {"operation_id": "operation:other"},
        {"principal_id": "user:mallory"},
        {"agent_id": "agent:other"},
        {"workload_id": "spiffe://evil/workload"},
        {"tenant_id": "tenant:evil"},
        {"task_id": "task:evil"},
        {"action": "claim.update"},
        {"resource_id": "claim:999"},
        {"resource_version": 8},
        {"arguments": {"fields": ["diagnosis"]}},
        {"tool": replace(request.tool, server_id="mcp://evil")},
    )
    assert all(
        lab.request_digest(replace(request, **change)) != lab.request_digest(request)
        for change in changes
    )


@pytest.mark.parametrize(
    "token,reason",
    [
        (lambda: lab.issue_token(issuer="https://evil.example"), "TOKEN_INVALID"),
        (lambda: lab.issue_token(audience="https://evil.example"), "TOKEN_INVALID"),
        (
            lambda: lab.issue_token(key="attacker-key-that-is-at-least-32-bytes"),
            "TOKEN_INVALID",
        ),
        (
            lambda: lab.issue_token(
                issued_at=lab.NOW - 400,
                not_before=lab.NOW - 400,
                expires_at=lab.NOW - 1,
            ),
            "TOKEN_TIME_INVALID",
        ),
        (lambda: lab.issue_token(not_before=lab.NOW + 1), "TOKEN_TIME_INVALID"),
        (lambda: lab.issue_token(issued_at=lab.NOW + 31), "TOKEN_TIME_INVALID"),
        (
            lambda: lab.issue_token(
                issued_at=lab.NOW - 700,
                not_before=lab.NOW - 700,
                expires_at=lab.NOW + 1,
            ),
            "TOKEN_LIFETIME_EXCESSIVE",
        ),
        (lambda: "not-a-jwt", "TOKEN_INVALID"),
    ],
)
def test_token_validation_fails_closed(token, reason):
    assert_deny(outcome(token=token()), reason)


def test_token_missing_actor_is_denied():
    claims = {
        "iss": lab.ISSUER,
        "aud": lab.AUDIENCE,
        "sub": "user:alice",
        "workload_id": "spiffe://northstar.example/prod/claims",
        "tenant_id": lab.TENANT,
        "task_id": "task:483",
        "delegation_id": "delegation:leaf",
        "scope": "claim.read",
        "iat": lab.NOW - 1,
        "nbf": lab.NOW - 1,
        "exp": lab.NOW + 60,
        "jti": "token:no-actor",
    }
    token = jwt.encode(claims, lab.JWT_KEY, algorithm="HS256")
    assert_deny(outcome(token=token), "TOKEN_ACTOR_MISSING")


@pytest.mark.parametrize(
    "change,reason",
    [
        ({"principal_id": "user:mallory"}, "TOKEN_SUBJECT_MISMATCH"),
        ({"agent_id": "agent:mallory"}, "TOKEN_ACTOR_MISMATCH"),
        ({"workload_id": "spiffe://evil/workload"}, "TOKEN_WORKLOAD_MISMATCH"),
        ({"tenant_id": "tenant:evil"}, "TOKEN_TENANT_MISMATCH"),
        ({"resource_tenant": "tenant:evil"}, "CROSS_TENANT_RESOURCE"),
        ({"task_id": "task:evil"}, "TOKEN_TASK_MISMATCH"),
        ({"action": "claim.delete"}, "TOKEN_SCOPE_DENIED"),
        ({"resource_id": "claim:999"}, "DELEGATION_SCOPE_DENIED"),
    ],
)
def test_identity_scope_and_resource_substitution(change, reason):
    assert_deny(outcome(change), reason)


@pytest.mark.parametrize(
    "tool_change",
    [
        {"tool_id": "claims.delete"},
        {"server_id": "mcp://evil"},
        {"schema_hash": "0" * 64},
    ],
)
def test_tool_identity_and_definition_are_bound(tool_change):
    _service, _pep, request, _token = lab.course_fixture()
    decision = outcome({"tool": replace(request.tool, **tool_change)})
    assert_deny(decision, "TOOL_BINDING_MISMATCH")


def mutate_leaf(service, **changes):
    leaf = service.delegations["delegation:leaf"]
    service.delegations[leaf.delegation_id] = replace(leaf, **changes)


@pytest.mark.parametrize(
    "change,reason",
    [
        ({"delegatee": "agent:attacker"}, "DELEGATION_ACTOR_MISMATCH"),
        ({"tenant_id": "tenant:evil"}, "DELEGATION_CONTEXT_INVALID"),
        ({"task_id": "task:evil"}, "DELEGATION_CONTEXT_INVALID"),
        ({"not_before": lab.NOW + 1}, "DELEGATION_CONTEXT_INVALID"),
        ({"expires_at": lab.NOW}, "DELEGATION_CONTEXT_INVALID"),
        ({"depth": 3}, "DELEGATION_CONTEXT_INVALID"),
        ({"actions": ("claim.read", "claim.delete")}, "DELEGATION_ESCALATION"),
        ({"resources": ("claim:483", "claim:999")}, "DELEGATION_ESCALATION"),
        ({"expires_at": lab.NOW + 601}, "DELEGATION_ESCALATION"),
        ({"max_depth": 3}, "DELEGATION_ESCALATION"),
    ],
)
def test_delegation_mutations_are_denied(change, reason):
    assert_deny(
        outcome(service_change=lambda service: mutate_leaf(service, **change)), reason
    )


def test_non_redelegable_parent_denies_child():
    def mutate(service):
        root = service.delegations["delegation:root"]
        service.delegations[root.delegation_id] = replace(root, redelegable=False)

    assert_deny(outcome(service_change=mutate), "REDELEGATION_INVALID")


def test_wrong_delegator_denies_child():
    assert_deny(
        outcome(
            service_change=lambda service: mutate_leaf(service, delegator="agent:evil")
        ),
        "REDELEGATION_INVALID",
    )


def test_delegation_cycle_is_denied():
    def mutate(service):
        root = service.delegations["delegation:root"]
        service.delegations[root.delegation_id] = replace(
            root, parent_id="delegation:leaf"
        )

    assert_deny(outcome(service_change=mutate), "DELEGATION_CYCLE")


def test_unknown_delegation_is_denied():
    token = lab.issue_token(delegation_id="delegation:missing")
    assert_deny(outcome(token=token), "DELEGATION_UNKNOWN")


def test_revoked_delegation_is_denied_at_pdp():
    def revoke(service):
        service.revoked_delegations.add("delegation:leaf")

    assert_deny(outcome(service_change=revoke), "DELEGATION_REVOKED")


def test_policy_dependency_failure_denies():
    assert_deny(outcome(available=False), "POLICY_DEPENDENCY_UNAVAILABLE")


def test_untrusted_workload_denied_even_when_token_matches():
    token = lab.issue_token(workload_id="spiffe://northstar.example/dev/claims")
    assert_deny(
        outcome({"workload_id": "spiffe://northstar.example/dev/claims"}, token=token),
        "WORKLOAD_UNTRUSTED",
    )


def test_pep_requires_authenticated_allow_decision():
    service, pep, request, token = lab.course_fixture()
    with pytest.raises(lab.SecurityError, match="PEP_DECISION_REQUIRED"):
        pep.execute(None, request)
    denied = service.authorize(replace(request, action="claim.delete"), token)
    with pytest.raises(lab.SecurityError, match="PEP_DENIED_DECISION"):
        pep.execute(denied, replace(request, action="claim.delete"))


def test_pep_rejects_tampered_decision_signature():
    service, pep, request, token = lab.course_fixture()
    signed = service.authorize(request, token)
    tampered = replace(
        signed, decision=replace(signed.decision, expires_at=lab.NOW + 999)
    )
    with pytest.raises(lab.SecurityError, match="DECISION_SIGNATURE_INVALID"):
        pep.execute(tampered, request)


@pytest.mark.parametrize(
    "change,reason",
    [
        ({"arguments": {"fields": ["diagnosis"]}}, "PEP_REQUEST_MISMATCH"),
        (
            {"tool": lab.ToolBinding("claims.get", "mcp://evil", "0" * 64)},
            "PEP_REQUEST_MISMATCH",
        ),
        ({"resource_id": "claim:999"}, "PEP_REQUEST_MISMATCH"),
    ],
)
def test_pep_detects_parameter_resource_and_tool_swap(change, reason):
    service, pep, request, token = lab.course_fixture()
    signed = service.authorize(request, token)
    with pytest.raises(lab.SecurityError, match=reason):
        pep.execute(signed, replace(request, **change))


def test_pep_detects_operation_substitution():
    service, pep, request, token = lab.course_fixture()
    signed = service.authorize(request, token)
    changed = replace(request, operation_id="operation:evil")
    with pytest.raises(lab.SecurityError, match="PEP_OPERATION_MISMATCH"):
        pep.execute(signed, changed)


def test_pep_detects_expiry_revocation_and_toctou():
    service, pep, request, token = lab.course_fixture()
    signed = service.authorize(request, token)
    with pytest.raises(lab.SecurityError, match="PEP_DECISION_EXPIRED"):
        pep.execute(signed, request, now=lab.NOW + 31)
    service.revoked_delegations.add("delegation:leaf")
    with pytest.raises(lab.SecurityError, match="PEP_DELEGATION_REVOKED"):
        pep.execute(signed, request)
    service.revoked_delegations.clear()
    pep.resource_versions[request.resource_id] = 8
    with pytest.raises(lab.SecurityError, match="PEP_RESOURCE_VERSION_CHANGED"):
        pep.execute(signed, request)


def test_exact_execution_retry_reconciles_without_duplicate_effect():
    service, pep, request, token = lab.course_fixture()
    signed = service.authorize(request, token)
    first_status, first = pep.execute(signed, request)
    second_status, second = pep.execute(signed, request)
    assert first_status == "executed"
    assert second_status == "reconciled"
    assert first == second
    assert len(pep.receipts) == 1


def test_same_operation_with_changed_authorized_request_conflicts():
    service, pep, request, token = lab.course_fixture()
    first = service.authorize(request, token)
    pep.execute(first, request)
    changed = replace(request, arguments={"fields": ["status"]})
    second = service.authorize(changed, token)
    with pytest.raises(lab.SecurityError, match="PEP_IDEMPOTENCY_CONFLICT"):
        pep.execute(second, changed)


def test_attack_corpus_has_complete_expected_prevention():
    results, report = lab.run_attack_corpus()
    assert report.total == 10
    assert report.passed == 10
    assert report.failed == 0
    assert report.prevention_rate == 1.0
    assert len(report.categories_covered) >= 5
    assert all(result.passed for result in results)
    fixture = json.loads((COURSE / "data/attack_fixtures.json").read_text())
    assert [case["attack_id"] for case in fixture["cases"]] == [
        result.attack_id for result in results
    ]
    assert [case["expected_reason"] for case in fixture["cases"]] == [
        result.reason_code for result in results
    ]
    sample_report = json.loads((COURSE / "reports/sample_report.json").read_text())
    assert sample_report["summary"]["tests"] == report.total
    assert sample_report["summary"]["prevention_rate"] == report.prevention_rate


@settings(max_examples=30, deadline=None)
@given(
    st.dictionaries(
        st.text(min_size=1, max_size=12), st.integers(), min_size=1, max_size=4
    )
)
def test_property_any_consequential_argument_mutation_changes_digest(arguments):
    _service, _pep, request, _token = lab.course_fixture()
    if arguments == request.arguments:
        return
    assert lab.request_digest(
        replace(request, arguments=arguments)
    ) != lab.request_digest(request)
