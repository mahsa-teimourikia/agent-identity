from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).parents[1]/"src"))
from lifecycle import transition
from governance import required_approvers,sod_ok,posture
def test_illegal_activation():
    try: transition("draft","active"); assert False
    except ValueError: assert True
def test_high_approvals():
    assert required_approvers("high")=={"owner","security"}
def test_sod():
    assert not sod_ok("alice",["alice","security"])
def test_critical_override():
    p=posture({"owner":"x","short_lived":True,"review_current":True,"monitoring":True,
               "runtime_bound":True,"least_privilege":True,"forbidden_static_secret":True})
    assert p["score"]==0
