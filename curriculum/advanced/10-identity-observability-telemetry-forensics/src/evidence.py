import json, hashlib
def canonical(x): return json.dumps(x,sort_keys=True,separators=(",",":"),default=str)
def hash_event(event,previous=""):
    return hashlib.sha256((previous+canonical(event)).encode()).hexdigest()
def build_chain(events):
    out=[]; prev=""
    for e in events:
        h=hash_event(e,prev); out.append({"event":e,"previous_hash":prev,"hash":h}); prev=h
    return out
def verify_chain(chain):
    prev=""
    for item in chain:
        if item["previous_hash"]!=prev or item["hash"]!=hash_event(item["event"],prev): return False
        prev=item["hash"]
    return True
