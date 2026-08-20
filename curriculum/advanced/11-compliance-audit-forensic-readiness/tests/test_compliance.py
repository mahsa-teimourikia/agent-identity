from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).parents[1]/"src"))
from evaluator import evaluate_agent,gate
from evidence import artifact,manifest
def test_bad_prod_agent_blocks_gate():
    a={"id":"a","registered":True,"owner":"","environment":"prod","credential_type":"static_api_key","credential_lifetime_minutes":999}
    assert not gate(evaluate_agent(a))
def test_good_prod_agent():
    a={"id":"a","registered":True,"owner":"team","environment":"prod","credential_type":"workload","credential_lifetime_minutes":10}
    assert gate(evaluate_agent(a))
def test_manifest_has_hash():
    a=artifact("x","registry",{"x":1})
    assert manifest("C","Q",[a])["artifacts"][0]["sha256"]
