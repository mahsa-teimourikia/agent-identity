from __future__ import annotations

import json
import sys
from datetime import timedelta
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError

COURSE = Path(__file__).parents[1]
sys.path.insert(0, str(COURSE))

import lab


def complete_assessment(agent: lab.AgentRecord | None = None):
    agent = agent or lab.agent_fixture()
    results, store = lab.assess_agent(agent)
    custody = lab.build_custody(
        [
            {
                "artifact_id": item.artifact_id,
                "actor": "collector:assurance",
                "action": "collected",
                "occurred_at": lab.NOW - timedelta(minutes=2),
            }
            for item in store.artifacts.values()
        ]
    )
    signer = lab.deterministic_private_key("audit-office")
    pack = lab.build_audit_pack(
        [agent], results, store.artifacts.values(), custody, [], signer=signer
    )
    return agent, results, store, custody, signer, pack


def test_release_gate_is_exact_and_has_no_false_passes():
    report = lab.evaluation()
    assert report["hardened"] == {
        "exact": 18,
        "total": 18,
        "accuracy": 1.0,
        "false_passes": 0,
        "false_blocks": 0,
    }
    assert report["release_gate"] is True


def test_weak_baseline_exposes_false_assurance():
    report = lab.evaluation()
    assert report["baseline"]["exact"] == 9
    assert report["baseline"]["false_passes"] == 8


@pytest.mark.parametrize("case", lab.assurance_cases(), ids=lambda case: case.case_id)
def test_each_labelled_assurance_case(case):
    assert lab.run_case(case) == case.expected


def test_agent_contract_is_strict():
    with pytest.raises(ValidationError):
        lab.agent_fixture(untrusted_extra="no")


def test_agent_contract_rejects_wrong_tenant():
    with pytest.raises(ValidationError, match="assessment tenant"):
        lab.agent_fixture(tenant="other")


def test_agent_contract_rejects_lifetime_without_credential():
    with pytest.raises(ValidationError, match="lifetime"):
        lab.agent_fixture(credential_type="none", credential_lifetime_minutes=5)


def test_evidence_store_accepts_valid_signed_artifact():
    artifact = lab.evidence_for_agent(lab.agent_fixture())[0]
    store = lab.EvidenceStore()
    assert store.admit(artifact)
    assert not store.rejections


def test_evidence_store_rejects_forged_signature():
    artifact = lab.evidence_for_agent(lab.agent_fixture())[0]
    artifact = artifact.model_copy(update={"signature": lab.b64(b"x" * 64)})
    store = lab.EvidenceStore()
    assert not store.admit(artifact)
    assert store.rejections[-1][1] == "invalid-signature"


def test_evidence_store_rejects_payload_tampering():
    artifact = lab.evidence_for_agent(lab.agent_fixture())[0]
    artifact = artifact.model_copy(
        update={
            "payload": artifact.payload.model_copy(
                update={"observed": {"passed": False}}
            )
        }
    )
    store = lab.EvidenceStore()
    assert not store.admit(artifact)
    assert store.rejections[-1][1] == "payload-digest-mismatch"


def test_evidence_store_rejects_source_producer_mismatch():
    artifact = lab.evidence_for_agent(lab.agent_fixture())[0]
    artifact = artifact.model_copy(update={"producer": "runtime-producer"})
    store = lab.EvidenceStore()
    assert not store.admit(artifact)
    assert store.rejections[-1][1] == "untrusted-source-binding"


def test_evidence_store_rejects_evidence_type_from_wrong_authoritative_source():
    artifact = lab.evidence_for_agent(lab.agent_fixture())[0]
    forged = lab.sign_artifact(
        artifact_id="ev-wrong-source-1",
        evidence_type="registry_record",
        source="runtime",
        collected_at=lab.NOW - timedelta(minutes=1),
        effective_at=lab.NOW - timedelta(minutes=2),
        payload=artifact.payload,
    )
    store = lab.EvidenceStore()
    assert not store.admit(forged)
    assert store.rejections[-1][1] == "untrusted-evidence-type-source"


def test_evidence_store_rejects_cross_tenant_artifact():
    artifact = lab.evidence_for_agent(lab.agent_fixture())[0]
    artifact = artifact.model_copy(update={"tenant": "other-tenant"})
    store = lab.EvidenceStore()
    assert not store.admit(artifact)
    assert store.rejections[-1][1] == "wrong-tenant"


def test_evidence_store_rejects_duplicate_artifact():
    artifact = lab.evidence_for_agent(lab.agent_fixture())[0]
    store = lab.EvidenceStore()
    assert store.admit(artifact)
    assert not store.admit(artifact)
    assert store.rejections[-1][1] == "duplicate-artifact"


def test_evidence_store_rejects_future_observation():
    artifact = lab.evidence_for_agent(lab.agent_fixture())[0]
    artifact = artifact.model_copy(
        update={"effective_at": lab.NOW + timedelta(hours=1)}
    )
    store = lab.EvidenceStore()
    assert not store.admit(artifact)
    assert store.rejections[-1][1] == "future-evidence"


def test_evidence_store_rejects_future_collection():
    artifact = lab.evidence_for_agent(lab.agent_fixture())[0]
    artifact = artifact.model_copy(
        update={"collected_at": lab.NOW + timedelta(hours=1)}
    )
    store = lab.EvidenceStore()
    assert not store.admit(artifact)
    assert store.rejections[-1][1] == "future-collection"


def test_signed_evidence_must_agree_with_assessed_inventory_state():
    good = lab.agent_fixture()
    changed = good.model_copy(update={"owner": ""})
    results, store = lab.assess_agent(changed, artifacts=lab.evidence_for_agent(good))
    assert not store.rejections
    ownership = next(result for result in results if result.control_id == "AG-02")
    assert ownership.status == "indeterminate"
    assert ownership.reason_code == "evidence-state-mismatch"


def test_missing_evidence_is_indeterminate_not_pass():
    agent = lab.agent_fixture()
    artifacts = lab.evidence_for_agent(agent)[:-1]
    results, _ = lab.assess_agent(agent, artifacts=artifacts)
    assert any(result.status == "indeterminate" for result in results)
    assert lab.release_decision(results) == "review"


def test_stale_evidence_is_incomplete():
    control = lab.CONTROL_BY_ID["AG-01"]
    artifact = lab.evidence_for_agent(lab.agent_fixture())[0]
    artifact = artifact.model_copy(update={"effective_at": lab.NOW - timedelta(days=4)})
    ids, complete, reason = lab.required_evidence(control, [artifact])
    assert ids == ()
    assert complete is False
    assert reason == "missing-evidence"


def test_valid_exception_never_becomes_pass():
    agent = lab.agent_fixture(
        "agent:legacy",
        credential_type="static_api_key",
        credential_lifetime_minutes=1440,
    )
    results, _ = lab.assess_agent(agent, exceptions=[lab.approved_exception()])
    credential = next(result for result in results if result.control_id == "CR-01")
    assert credential.status == "exception"
    assert credential.exception_id == "EX-12"
    assert lab.release_decision(results) == "review"


@pytest.mark.parametrize(
    "updates,reason",
    [
        (
            {"expires_at": lab.NOW - timedelta(seconds=1)},
            "exception-expired-or-not-yet-valid",
        ),
        ({"approver": "team:claims"}, "untrusted-exception-approver"),
        ({"subject": "agent:other"}, "exception-scope-mismatch"),
        ({"state": "revoked"}, "exception-not-approved"),
        (
            {"compensating_controls": frozenset({"vault"})},
            "compensating-controls-incomplete",
        ),
    ],
)
def test_invalid_exception_is_rejected(updates, reason):
    record = lab.approved_exception(**updates)
    accepted, observed = lab.valid_exception(
        record, control_id="CR-01", subject="agent:legacy"
    )
    assert accepted is False
    assert observed == reason


def test_development_control_is_not_applicable():
    agent = lab.agent_fixture(environment="dev")
    results, _ = lab.assess_agent(agent)
    assert {result.status for result in results} == {"not_applicable"}


def test_inactive_agent_only_requires_offboarding_control():
    agent = lab.agent_fixture(
        active=False,
        credential_type="none",
        credential_lifetime_minutes=0,
        offboarded_at=lab.NOW - timedelta(hours=1),
        credential_revoked=True,
        delegation_revoked=True,
    )
    results, _ = lab.assess_agent(agent)
    relevant = [result for result in results if result.status != "not_applicable"]
    assert [result.control_id for result in relevant] == ["LC-01"]
    assert relevant[0].status == "pass"


def test_noncritical_failure_does_not_block_release():
    agent = lab.agent_fixture(
        granted_permissions=frozenset(
            {"claims.read", "claims.write", "payments.write"}
        ),
        used_permissions=frozenset({"claims.read"}),
    )
    results, _ = lab.assess_agent(agent)
    least_privilege = next(result for result in results if result.control_id == "AC-01")
    assert least_privilege.status == "fail"
    assert least_privilege.critical is False
    assert lab.release_decision(results) == "release"


def test_completeness_names_numerator_and_denominator():
    results, _ = lab.assess_agent(lab.agent_fixture())
    assert lab.completeness(results) == {"complete": 5, "relevant": 5, "ratio": 1.0}


def test_custody_chain_verifies_and_detects_edit():
    chain = lab.build_custody(
        [
            {
                "artifact_id": "ev-a-1",
                "actor": "collector:a",
                "action": "collected",
                "occurred_at": lab.NOW,
            },
            {
                "artifact_id": "ev-a-1",
                "actor": "auditor:b",
                "action": "verified",
                "occurred_at": lab.NOW + timedelta(minutes=1),
            },
        ]
    )
    assert lab.verify_custody(chain)
    edited = list(chain)
    edited[0] = edited[0].model_copy(update={"actor": "attacker"})
    assert not lab.verify_custody(edited)


def test_custody_chain_detects_reordering_but_not_terminal_truncation_alone():
    chain = lab.build_custody(
        [
            {
                "artifact_id": f"ev-a-{i}",
                "actor": "collector:a",
                "action": "collected",
                "occurred_at": lab.NOW,
            }
            for i in range(1, 4)
        ]
    )
    assert not lab.verify_custody([chain[1], chain[0], chain[2]])
    assert lab.verify_custody(chain[:-1])


def test_active_legal_hold_overrides_retention_deletion():
    artifact = lab.evidence_for_agent(lab.agent_fixture())[0].model_copy(
        update={"effective_at": lab.NOW - timedelta(days=400)}
    )
    hold = lab.LegalHold(
        hold_id="LH-44",
        tenant=lab.TENANT,
        case_id="IR-2026-17",
        artifact_ids=frozenset({artifact.artifact_id}),
        issued_by="legal:counsel",
        issued_at=lab.NOW - timedelta(days=2),
    )
    assert lab.retention_action(artifact, retention_days=365, holds=[hold]) == "retain"
    released = hold.model_copy(update={"released_at": lab.NOW})
    assert (
        lab.retention_action(artifact, retention_days=365, holds=[released]) == "delete"
    )


def test_risk_sampling_is_deterministic_and_prioritizes_critical_agents():
    population = [
        lab.agent_fixture(f"agent:a-{i}", risk="critical" if i < 4 else "low")
        for i in range(20)
    ]
    first = lab.risk_sample(population, 8, seed=42)
    second = lab.risk_sample(population, 8, seed=42)
    assert [item.agent_id for item in first] == [item.agent_id for item in second]
    assert lab.sample_coverage(population, first)["critical_coverage"] >= 0.5


def test_segregation_of_duties_graph_exposes_conflict():
    report = lab.segregation_of_duties(
        {
            "team:builder": {"agent.create"},
            "team:reviewer": {"agent.approve"},
            "team:admin": {"agent.create", "agent.approve"},
        },
        [("agent.create", "agent.approve")],
    )
    assert report["conflicts"] == [
        {"principal": "team:admin", "permissions": ("agent.approve", "agent.create")}
    ]
    assert report["edges"] == 4


@pytest.mark.parametrize("size", [0, 3])
def test_risk_sampling_rejects_invalid_size(size):
    with pytest.raises(ValueError, match="sample size"):
        lab.risk_sample([lab.agent_fixture()], size)


def test_signed_audit_pack_verifies_independently():
    agent, results, store, custody, signer, pack = complete_assessment()
    assert lab.verify_audit_pack(
        pack,
        public_key=signer.public_key(),
        agents=[agent],
        results=results,
        artifacts=store.artifacts.values(),
        custody=custody,
    ) == (True, "verified")


def test_audit_pack_detects_artifact_truncation():
    agent, results, store, custody, signer, pack = complete_assessment()
    assert lab.verify_audit_pack(
        pack,
        public_key=signer.public_key(),
        agents=[agent],
        results=results,
        artifacts=list(store.artifacts.values())[:-1],
        custody=custody,
    ) == (False, "artifact-set-mismatch")


def test_audit_pack_detects_changed_result():
    agent, results, store, custody, signer, pack = complete_assessment()
    changed = list(results)
    changed[0] = changed[0].model_copy(update={"status": "fail"})
    assert lab.verify_audit_pack(
        pack,
        public_key=signer.public_key(),
        agents=[agent],
        results=changed,
        artifacts=store.artifacts.values(),
        custody=custody,
    ) == (False, "result-mismatch")


def test_audit_pack_rejects_wrong_signer():
    agent, results, store, custody, _, pack = complete_assessment()
    wrong = lab.deterministic_private_key("wrong-office")
    assert lab.verify_audit_pack(
        pack,
        public_key=wrong.public_key(),
        agents=[agent],
        results=results,
        artifacts=store.artifacts.values(),
        custody=custody,
    ) == (False, "invalid-pack-signature")


def test_audit_pack_detects_custody_truncation():
    agent, results, store, custody, signer, pack = complete_assessment()
    assert lab.verify_audit_pack(
        pack,
        public_key=signer.public_key(),
        agents=[agent],
        results=results,
        artifacts=store.artifacts.values(),
        custody=custody[:-1],
    ) == (False, "custody-mismatch")


def test_oscal_export_is_explicitly_versioned_and_traceable():
    _, results, _, _, _, pack = complete_assessment()
    root = lab.oscal_assessment_results(pack, results)["assessment-results"]
    assert root["metadata"]["oscal-version"] == "1.2.3"
    assert len(root["results"][0]["observations"]) == len(results)
    assert root["results"][0]["observations"][0]["relevant-evidence"]


def test_framework_mappings_have_versions_and_primary_sources():
    for mappings in lab.FRAMEWORK_MAPPINGS.values():
        for mapping in mappings:
            assert mapping.version
            assert mapping.source_url.startswith("https://")


def test_course_data_and_schema_are_valid_json():
    paths = [
        *sorted((COURSE / "data").glob("*.json")),
        COURSE / "schemas/control_result.schema.json",
    ]
    for path in paths:
        if " 2" not in path.name:
            json.loads(path.read_text())


def test_adversarial_fixture_matches_executable_cases():
    fixture = json.loads((COURSE / "data/adversarial_cases.json").read_text())
    expected = [
        {
            "case_id": case.case_id,
            "description": case.description,
            "expected": case.expected,
            "mutation": case.mutation,
        }
        for case in lab.assurance_cases()
    ]
    assert fixture == expected


def test_control_catalog_fixture_matches_executable_catalog():
    fixture = json.loads((COURSE / "data/control_catalog.json").read_text())
    expected = [
        control.model_dump(mode="json", exclude={"applicable_environments"})
        for control in lab.CONTROL_CATALOG
    ]
    assert fixture == expected


def test_control_result_matches_published_json_schema():
    result = lab.assess_agent(lab.agent_fixture())[0][0]
    schema = json.loads((COURSE / "schemas/control_result.schema.json").read_text())
    errors = list(
        Draft202012Validator(schema).iter_errors(result.model_dump(mode="json"))
    )
    assert errors == []


def test_lab_has_no_network_client_imports():
    source = (COURSE / "lab.py").read_text()
    assert "import requests" not in source
    assert "import httpx" not in source
    assert "urllib.request" not in source
