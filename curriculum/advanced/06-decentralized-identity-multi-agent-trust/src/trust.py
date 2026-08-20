def trusted_credential(credential, trusted_issuers, expected_subject):
    if credential["issuer"] not in trusted_issuers: return False
    if credential["subject"] != expected_subject: return False
    if credential.get("revoked"): return False
    return True

def delegation_valid(d, caller, action, resource):
    return (
        d["delegate"] == caller
        and action in d["actions"]
        and resource == d["resource"]
        and not d.get("revoked",False)
    )

def attenuated(parent, child):
    return (
        set(child["actions"]).issubset(parent["actions"])
        and child["resource"] == parent["resource"]
    )
