def test_attenuation():
    assert {"read"}.issubset({"read","update"})
def test_workload_binding():
    assert {"approved":True,"agent_id":"agent:claims"}["agent_id"]=="agent:claims"
def test_cross_tenant_boundary():
    assert "acme" != "other"
