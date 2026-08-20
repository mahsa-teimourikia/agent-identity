from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).parents[1]))
from src.evidence import build_chain,verify_chain
def test_tamper_evident_chain():
    c=build_chain([{"event":"issue"},{"event":"authorize"}])
    assert verify_chain(c)
    c[0]["event"]["event"]="tampered"
    assert not verify_chain(c)
