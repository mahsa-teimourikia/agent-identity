import base64, json
from datetime import datetime, timezone
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()

def b64(x): return base64.urlsafe_b64encode(x).decode().rstrip("=")
def unb64(x): return base64.urlsafe_b64decode(x + "=" * (-len(x) % 4))

def issue(private_key: Ed25519PrivateKey, credential: dict):
    return {"credential": credential, "proof": {"type":"Ed25519Signature","value":b64(private_key.sign(canonical(credential)))}}

def verify(public_key: Ed25519PublicKey, envelope: dict):
    public_key.verify(unb64(envelope["proof"]["value"]), canonical(envelope["credential"]))
    return envelope["credential"]

def temporal_valid(c, now=None):
    now = now or datetime.now(timezone.utc)
    start=datetime.fromisoformat(c["validFrom"])
    end=datetime.fromisoformat(c["validUntil"])
    return start <= now < end
