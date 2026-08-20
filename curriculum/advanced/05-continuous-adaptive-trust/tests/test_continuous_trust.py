from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).parents[1]/"src"))
from risk_engine import TrustState, apply_signal

def test_low_allows():
    s=TrustState("agent:claims")
    assert s.decision()=="ALLOW"

def test_high_steps_up():
    s=TrustState("agent:claims")
    assert apply_signal(s,"behavior","high")=="STEP_UP"

def test_critical_quarantines():
    s=TrustState("agent:claims")
    assert apply_signal(s,"threat","critical")=="QUARANTINE"

def test_revocation_precedence():
    s=TrustState("agent:claims");s.revoked=True
    assert s.decision()=="REVOKE"
