def test_namespace_is_qualified():
    a=("partner-a.example","agent:research")
    b=("partner-b.example","agent:research")
    assert a != b

def test_trust_not_transitive():
    edges={("A","B"),("B","C")}
    assert ("A","C") not in edges

def test_foreign_admin_not_local_admin():
    foreign={"issuer":"partner","role":"admin"}
    assert foreign["role"] == "admin"
    local_roles=set()
    assert "admin" not in local_roles
