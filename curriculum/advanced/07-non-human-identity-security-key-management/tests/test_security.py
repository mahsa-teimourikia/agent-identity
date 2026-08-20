from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).parents[1]/"src"))
from credentials import issue,usable
from security import redact
def test_audience():
    t=issue("agent:claims","claims-api",{"read"})
    assert usable(t,"claims-api","read")
    assert not usable(t,"payments-api","read")
def test_scope():
    t=issue("agent:claims","claims-api",{"read"})
    assert not usable(t,"claims-api","delete")
def test_redact():
    assert "Bearer" not in redact("Authorization: Bearer abc.def.ghi")
