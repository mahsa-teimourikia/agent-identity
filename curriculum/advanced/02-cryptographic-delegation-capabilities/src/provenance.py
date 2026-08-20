import hashlib, json
def event_hash(event, previous_hash=""):
    body={"event":event,"previous_hash":previous_hash}
    return hashlib.sha256(json.dumps(body,sort_keys=True,separators=(",",":")).encode()).hexdigest()

def verify_chain(events):
    prev=""
    for row in events:
        expected=event_hash(row["event"],prev)
        if expected != row["hash"]: return False
        prev=row["hash"]
    return True
