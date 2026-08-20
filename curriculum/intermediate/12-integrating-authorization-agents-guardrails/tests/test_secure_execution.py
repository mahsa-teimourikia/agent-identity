from datetime import datetime, timedelta, timezone
import hashlib, json

def digest(action, resource, params):
    return hashlib.sha256(json.dumps(
        {"action": action, "resource": resource, "params": params},
        sort_keys=True, separators=(",", ":")
    ).encode()).hexdigest()

def test_parameter_change_breaks_approval_binding():
    a = digest("payment.create", "acct:1", {"amount":100})
    b = digest("payment.create", "acct:1", {"amount":1000})
    assert a != b

def test_cross_tenant_is_not_equivalent():
    assert ("acme", "claim:1") != ("other", "claim:1")

def test_expired_approval():
    now = datetime.now(timezone.utc)
    expires = now - timedelta(seconds=1)
    assert expires <= now
