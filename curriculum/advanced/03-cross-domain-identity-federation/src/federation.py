from dataclasses import dataclass
from typing import FrozenSet

@dataclass(frozen=True)
class FederatedPrincipal:
    issuer: str
    subject: str
    trust_domain: str
    principal_type: str

@dataclass(frozen=True)
class FederationPolicy:
    domain: str
    active: bool
    audiences: FrozenSet[str]
    agent_types: FrozenSet[str]
    max_ttl_seconds: int

def validate_foreign_principal(p, policy, audience, agent_type):
    if not policy.active: return False, "FEDERATION_DISABLED"
    if p.trust_domain != policy.domain: return False, "DOMAIN"
    if audience not in policy.audiences: return False, "AUDIENCE"
    if agent_type not in policy.agent_types: return False, "AGENT_TYPE"
    return True, "VALID"
