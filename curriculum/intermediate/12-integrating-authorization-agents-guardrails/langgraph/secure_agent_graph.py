"""Conceptual LangGraph authorization-gate pattern.

This file is intentionally provider-neutral. Plug in your own model and PDP.
"""
from typing import TypedDict, Literal

class State(TypedDict):
    intent: dict
    authz: dict | None
    result: dict | None

def authorize_node(state: State) -> State:
    intent = state["intent"]
    # Replace with OPA/Cedar/OpenFGA/application PDP call.
    allowed = intent.get("action") in {"claim.read", "claim.update"}
    state["authz"] = {
        "decision": "allow" if allowed else "deny",
        "decision_id": "demo-decision"
    }
    return state

def route_after_authz(state: State) -> Literal["execute", "deny"]:
    return "execute" if state["authz"]["decision"] == "allow" else "deny"
