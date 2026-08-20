def decide(trust, risk, tenant_match, active=True):
    if not trust or not tenant_match or not active:
        return "deny"
    if risk == "critical":
        return "deny"
    if risk == "high":
        return "step_up"
    return "allow"

def test_cross_tenant_never_allows():
    for risk in ["low","high","critical"]:
        assert decide(True,risk,False) == "deny"

def test_untrusted_agent_never_allows():
    assert decide(False,"low",True) == "deny"

def test_expired_task_denies():
    assert decide(True,"low",True,False) == "deny"

def test_risk_monotonicity():
    assert decide(True,"low",True) == "allow"
    assert decide(True,"high",True) == "step_up"
    assert decide(True,"critical",True) == "deny"
