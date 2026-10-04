"""Compiled LangGraph that routes all effects through the capstone platform."""

from __future__ import annotations

from typing import Any, Literal, TypedDict

from capstone_runtime import (
    RunResult,
    SecureAgentPlatform,
    SecurityContext,
    valid_context,
)
from langgraph.graph import END, START, StateGraph

PLATFORM = SecureAgentPlatform()


class CapstoneState(TypedDict, total=False):
    context: SecurityContext
    intent: dict[str, Any]
    result: RunResult
    route: Literal["executed", "approval", "blocked"]


def enforce_node(state: CapstoneState) -> CapstoneState:
    """One idempotent node owns authorization, effect, receipt, and evidence."""
    result = PLATFORM.run(state.get("context", valid_context()), state["intent"])
    if result.terminal_state.value in {"executed", "reconciled"}:
        route: Literal["executed", "approval", "blocked"] = "executed"
    elif result.terminal_state.value == "approval_required":
        route = "approval"
    else:
        route = "blocked"
    return {**state, "result": result, "route": route}


def route_result(state: CapstoneState) -> Literal["executed", "approval", "blocked"]:
    return state["route"]


def terminal_node(state: CapstoneState) -> CapstoneState:
    return state


def build_graph():
    builder = StateGraph(CapstoneState)
    builder.add_node("enforce", enforce_node)
    for node in ("executed", "approval", "blocked"):
        builder.add_node(node, terminal_node)
        builder.add_edge(node, END)
    builder.add_edge(START, "enforce")
    builder.add_conditional_edges(
        "enforce",
        route_result,
        {"executed": "executed", "approval": "approval", "blocked": "blocked"},
    )
    return builder.compile()


GRAPH = build_graph()
