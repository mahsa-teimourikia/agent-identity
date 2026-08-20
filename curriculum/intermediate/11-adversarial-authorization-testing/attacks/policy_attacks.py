"""Policy mutation helpers for defensive testing."""
import copy

def remove_tenant_check(policy):
    x=copy.deepcopy(policy)
    x["require_same_tenant"]=False
    return x

def make_fail_open(policy):
    x=copy.deepcopy(policy)
    x["fail_closed"]=False
    return x

def add_wildcard(policy):
    x=copy.deepcopy(policy)
    x["allowed_resources"]=["*"]
    return x
