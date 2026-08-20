from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).parents[1]/"src"))
from assurance import build_profile, sensitive_write

def good():
    return dict(agent_registered=True,workload_attested=True,provenance_verified=True,
                evaluation_passed=True,governance_approved=True,quarantined=False)

def test_complete_evidence_allows():
    assert sensitive_write(build_profile(good()))=="allow"

def test_missing_evaluation_steps_up():
    x=good(); x["evaluation_passed"]=False
    assert sensitive_write(build_profile(x))=="step_up"

def test_quarantine_overrides_positive_evidence():
    x=good(); x["quarantined"]=True
    assert sensitive_write(build_profile(x))=="deny"
