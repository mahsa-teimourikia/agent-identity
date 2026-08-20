import re, json
DID_RE=re.compile(r"^did:([a-z0-9]+):(.+)$")

def parse_did(did):
    m=DID_RE.match(did)
    if not m: raise ValueError("invalid DID")
    return {"did":did,"method":m.group(1),"method_specific_id":m.group(2)}

def method_allowed(did,allowed=("web","key")):
    return parse_did(did)["method"] in allowed

def validate_document(requested_did,doc):
    if doc.get("id") != requested_did:
        raise ValueError("DID document substitution")
    if "verificationMethod" not in doc:
        raise ValueError("no verification methods")
    return True
