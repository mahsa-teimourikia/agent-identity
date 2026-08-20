from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).parents[1]/"src"))
from redaction import redact,fingerprint
from evidence import build_chain,verify_chain
def test_secret_redaction():
    assert redact({"access_token":"secret","x":1})["access_token"]=="[REDACTED]"
def test_fingerprint_stable():
    assert fingerprint("credential-1")==fingerprint("credential-1")
def test_chain_integrity():
    c=build_chain([{"x":1},{"x":2}]); assert verify_chain(c)
    c[0]["event"]["x"]=9; assert not verify_chain(c)
