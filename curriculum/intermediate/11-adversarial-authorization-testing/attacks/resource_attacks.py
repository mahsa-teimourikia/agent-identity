"""Resource authorization attack fixtures."""
def cross_tenant(principal, resource):
    return principal["tenant"] != resource["tenant"]

def parameter_swap(approved_digest, executed_digest):
    return approved_digest != executed_digest
