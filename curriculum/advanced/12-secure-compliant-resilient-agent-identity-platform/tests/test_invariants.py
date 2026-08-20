from datetime import datetime,timedelta,timezone
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).parents[1]))
from src.token_broker import issue,exchange,usable
from src.delegation import attenuated
from src.registry import transition

def test_token_exchange_cannot_escalate():
    p=issue("agent:a","api",{"read"})
    try:
        exchange(p,"api2",{"read","write"})
        assert False
    except PermissionError:
        assert True

def test_delegation_attenuation():
    now=datetime.now(timezone.utc)
    p={"actions":{"read","write"},"resources":{"r1","r2"},"expires_at":now+timedelta(hours=1),"max_depth":1}
    c={"actions":{"read"},"resources":{"r1"},"expires_at":now+timedelta(minutes=10),"depth":1}
    assert attenuated(p,c)

def test_lifecycle_bypass_blocked():
    try:
        transition("draft","active")
        assert False
    except ValueError:
        assert True

def test_audience_binding():
    t=issue("agent:a","claims-api",{"read"})
    assert usable(t,"claims-api","read")
    assert not usable(t,"payments-api","read")
