from dataclasses import dataclass, field
from datetime import datetime, timezone
SEVERITY={"low":10,"medium":35,"high":70,"critical":100}

@dataclass
class TrustState:
    principal: str
    dimensions: dict = field(default_factory=lambda:{
        "identity":0,"workload":0,"behavior":0,"threat":0,"transaction":0})
    quarantined: bool=False
    revoked: bool=False

    @property
    def score(self): return max(self.dimensions.values())

    def decision(self):
        if self.revoked: return "REVOKE"
        if self.quarantined or self.score>=90: return "QUARANTINE"
        if self.score>=70: return "STEP_UP"
        if self.score>=45: return "REDUCE"
        return "ALLOW"

def apply_signal(state, dimension, severity):
    state.dimensions[dimension]=SEVERITY[severity]
    return state.decision()
