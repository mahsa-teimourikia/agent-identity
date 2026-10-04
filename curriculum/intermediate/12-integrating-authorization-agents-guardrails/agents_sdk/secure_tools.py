"""OpenAI Agents SDK adapter; defining tools requires no API credentials."""

from __future__ import annotations

from dataclasses import dataclass

from agents import RunContextWrapper, function_tool
from lab import SecureAgentRuntime, SecurityContext, canonical


@dataclass
class AgentRuntimeContext:
    security_context: SecurityContext
    runtime: SecureAgentRuntime


@function_tool(
    name_override="claims_get",
    description_override="Read an assigned synthetic claim through policy enforcement.",
)
def claims_get(
    ctx: RunContextWrapper[AgentRuntimeContext],
    operation_id: str,
    resource_id: str,
    purpose: str,
) -> str:
    """Read a claim; trusted identity comes only from the run context."""
    result = ctx.context.runtime.run(
        ctx.context.security_context,
        {
            "operation_id": operation_id,
            "tool_name": "claims.get",
            "resource_id": resource_id,
            "arguments": {},
            "purpose": purpose,
        },
    )
    return canonical(result)


@function_tool(
    name_override="payments_create",
    description_override="Propose a synthetic payment through policy enforcement.",
    needs_approval=True,
)
def payments_create(
    ctx: RunContextWrapper[AgentRuntimeContext],
    operation_id: str,
    resource_id: str,
    amount_cents: int,
    currency: str,
    payee: str,
    purpose: str,
) -> str:
    """Request a payment; SDK pause and signed application approval are separate."""
    result = ctx.context.runtime.run(
        ctx.context.security_context,
        {
            "operation_id": operation_id,
            "tool_name": "payments.create",
            "resource_id": resource_id,
            "arguments": {
                "amount_cents": amount_cents,
                "currency": currency,
                "payee": payee,
            },
            "purpose": purpose,
        },
    )
    return canonical(result)


TOOLS = (claims_get, payments_create)
