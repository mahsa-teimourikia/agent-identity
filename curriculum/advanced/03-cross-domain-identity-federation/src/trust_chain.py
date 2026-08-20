def validate_chain(chain, accepted_anchor):
    if not chain: return False
    if chain[-1]["subject"] != accepted_anchor: return False
    for statement in chain:
        if not statement.get("signature_valid"): return False
        if not statement.get("time_valid"): return False
    for child, parent in zip(chain, chain[1:]):
        if child["issuer"] != parent["subject"]: return False
    return True
