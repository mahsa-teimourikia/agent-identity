from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).parents[1]/"src"))
from did_utils import parse_did,validate_document
from trust import attenuated

def test_parse():
    assert parse_did("did:web:agents.example")["method"]=="web"

def test_substitution():
    try:
        validate_document("did:web:a.example",{"id":"did:web:b.example","verificationMethod":[]})
        assert False
    except ValueError:
        assert True

def test_attenuation():
    p={"actions":["read","update"],"resource":"claims"}
    c={"actions":["read"],"resource":"claims"}
    assert attenuated(p,c)

def test_escalation_rejected():
    p={"actions":["read"],"resource":"claims"}
    c={"actions":["read","update"],"resource":"claims"}
    assert not attenuated(p,c)
