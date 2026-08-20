import re, hashlib, hmac
SENSITIVE_KEYS={"access_token","refresh_token","api_key","client_secret","private_key","authorization","cookie"}
def redact(obj):
    if isinstance(obj,dict):
        return {k:("[REDACTED]" if k.lower() in SENSITIVE_KEYS else redact(v)) for k,v in obj.items()}
    if isinstance(obj,list): return [redact(x) for x in obj]
    return obj
def fingerprint(identifier,key=b"training-only-key"):
    return hmac.new(key,identifier.encode(),hashlib.sha256).hexdigest()
