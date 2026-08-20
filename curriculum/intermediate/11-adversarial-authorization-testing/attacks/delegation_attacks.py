"""Delegation attack fixtures."""
def scope_escalation(parent, child):
    return not set(child["actions"]).issubset(set(parent["actions"]))

def resource_expansion(parent, child):
    return parent["resource"] != "*" and child["resource"] == "*"

def actor_substitution(delegation, caller):
    return delegation["delegatee"] != caller

def depth_violation(chain, max_depth):
    return len(chain) - 1 > max_depth

def illegal_redelegation(parent):
    return not parent.get("redelegable", False)
