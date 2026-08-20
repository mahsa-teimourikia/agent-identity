import json,hashlib
def canonical(x): return json.dumps(x,sort_keys=True,separators=(",",":"),default=str)
def build_chain(events):
    out=[];prev=""
    for e in events:
        h=hashlib.sha256((prev+canonical(e)).encode()).hexdigest()
        out.append({"event":e,"previous_hash":prev,"hash":h})
        prev=h
    return out
def verify_chain(chain):
    prev=""
    for row in chain:
        if row["previous_hash"]!=prev:return False
        if row["hash"]!=hashlib.sha256((prev+canonical(row["event"])).encode()).hexdigest():return False
        prev=row["hash"]
    return True
