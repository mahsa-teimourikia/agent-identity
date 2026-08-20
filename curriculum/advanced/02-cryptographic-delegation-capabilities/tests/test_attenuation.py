def attenuated(parent, child):
    return (
        set(child["actions"]).issubset(parent["actions"])
        and set(child["resources"]).issubset(parent["resources"])
        and child["expires"] <= parent["expires"]
        and child["depth"] > parent["depth"]
    )

def test_valid_attenuation():
    p={"actions":{"read","update"},"resources":{"c1","c2"},"expires":100,"depth":0}
    c={"actions":{"read"},"resources":{"c1"},"expires":90,"depth":1}
    assert attenuated(p,c)

def test_action_escalation_rejected():
    p={"actions":{"read"},"resources":{"c1"},"expires":100,"depth":0}
    c={"actions":{"read","delete"},"resources":{"c1"},"expires":90,"depth":1}
    assert not attenuated(p,c)
