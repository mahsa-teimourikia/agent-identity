from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).parents[1]/"src"))
from identity_graph import IdentityGraph
from detections import detect
from posture import score
def test_blast_radius():
    g=IdentityGraph(); g.add_node("a","agent"); g.add_node("b","tool"); g.add_edge("a","b","can_access")
    assert "b" in g.blast_radius("a")
def test_delegation_escalation():
    f=detect({"delegated_scope":{"read","write"},"parent_scope":{"read"}})
    assert "delegation_escalation" in f
def test_critical_posture_override():
    d={k:1 for k in ["inventory","least_privilege","credential_hygiene","delegation","detection","runtime_binding","external_trust","response"]}
    assert score(d,{"leaked_active_credential"})["score"]<=25
