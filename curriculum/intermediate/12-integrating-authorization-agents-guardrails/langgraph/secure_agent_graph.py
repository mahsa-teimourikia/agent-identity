"""Credential-free LangGraph adapter for the application-owned runtime.

LangGraph supplies durable orchestration. ``SecureAgentRuntime`` remains the
policy enforcement point, including commit-time reauthorization.
"""

from __future__ import annotations

from typing import Any, Literal, TypedDict

from lab import RunResult, SecureAgentRuntime, SecurityContext, valid_context
from langgraph.graph import END, START, StateGraph

RUNTIME = SecureAgentRuntime()


class AgentState(TypedDict, total=False):
    context: SecurityContext
    intent: dict[str, Any]
    result: RunResult
    route: Literal["executed", "approval", "blocked"]


def execute_node(state: AgentState) -> AgentState:
    """Run the complete security boundary as an idempotent graph node."""
    result = RUNTIME.run(state.get("context", valid_context()), state["intent"])
    if result.terminal_state.value in {"executed", "reconciled"}:
        route: Literal["executed", "approval", "blocked"] = "executed"
    elif result.terminal_state.value == "approval_required":
        route = "approval"
    else:
        route = "blocked"
    return {**state, "result": result, "route": route}


def route_result(state: AgentState) -> Literal["executed", "approval", "blocked"]:
    return state["route"]


def terminal_node(state: AgentState) -> AgentState:
    return state


def build_graph():
    """Compile the graph; production callers should add a durable checkpointer."""
    builder = StateGraph(AgentState)
    builder.add_node("execute", execute_node)
    builder.add_node("executed", terminal_node)
    builder.add_node("approval", terminal_node)
    builder.add_node("blocked", terminal_node)
    builder.add_edge(START, "execute")
    builder.add_conditional_edges(
        "execute",
        route_result,
        {"executed": "executed", "approval": "approval", "blocked": "blocked"},
    )
    builder.add_edge("executed", END)
    builder.add_edge("approval", END)
    builder.add_edge("blocked", END)
    return builder.compile()


GRAPH = build_graph()
