from datetime import datetime, timezone
from pydantic import BaseModel, Field
from typing import Any
class IdentityEvent(BaseModel):
    schema_name:str="agent.identity.event"
    schema_version:str="1.0"
    event_type:str
    timestamp:datetime=Field(default_factory=lambda:datetime.now(timezone.utc))
    trace_id:str
    actor:dict[str,Any]
    subject:dict[str,Any]|None=None
    action:str|None=None
    resource:str|None=None
    decision:str|None=None
    policy:dict[str,Any]|None=None
    delegation_id:str|None=None
    attributes:dict[str,Any]={}
