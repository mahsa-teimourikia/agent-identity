from dataclasses import dataclass, field
from typing import Any
@dataclass(frozen=True)
class SecurityContext:
    principal_id:str
    tenant_id:str
    agent_id:str
    workload_id:str
    task_id:str
    delegation_id:str|None=None

@dataclass
class Intent:
    action:str
    resource:str
    tool:str
    purpose:str
    parameters:dict[str,Any]=field(default_factory=dict)

@dataclass
class Decision:
    outcome:str
    decision_id:str
    reason:str
    constraints:dict[str,Any]=field(default_factory=dict)
    obligations:list[str]=field(default_factory=list)
