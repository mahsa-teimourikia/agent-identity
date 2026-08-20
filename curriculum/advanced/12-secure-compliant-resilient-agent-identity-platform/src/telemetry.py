from datetime import datetime,timezone
import hashlib,hmac,json
def fingerprint(value,key=b"course-demo-key"):
    return hmac.new(key,value.encode(),hashlib.sha256).hexdigest()
def event(event_type,trace_id,actor,**kwargs):
    return {"schema":"agent.identity.event/1.0","event_type":event_type,
            "timestamp":datetime.now(timezone.utc).isoformat(),
            "trace_id":trace_id,"actor":actor,**kwargs}
def redact(d):
    sensitive={"access_token","refresh_token","authorization","api_key","client_secret","private_key"}
    return {k:("[REDACTED]" if k.lower() in sensitive else v) for k,v in d.items()}
