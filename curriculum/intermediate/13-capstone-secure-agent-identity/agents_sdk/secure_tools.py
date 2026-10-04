"""Credential-free OpenAI Agents SDK tools backed by the capstone PEP."""

from __future__ import annotations

from dataclasses import dataclass

from agents import RunContextWrapper, function_tool
from capstone_runtime import SecureAgentPlatform, SecurityContext, canonical


@dataclass
class PlatformContext:
    security_context: SecurityContext
    platform: SecureAgentPlatform


@function_tool(
    name_override="claims_get",
    description_override="Read an assigned synthetic claim through the capstone PEP.",
)
def claims_get(
    ctx: RunContextWrapper[PlatformContext],
    operation_id: str,
    resource_id: str,
    purpose: str,
) -> str:
    """Read a claim; identity comes only from trusted run context."""
    result = ctx.context.platform.run(
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
    description_override="Propose a synthetic payment through the capstone PEP.",
    needs_approval=True,
)
def payments_create(
    ctx: RunContextWrapper[PlatformContext],
    operation_id: str,
    resource_id: str,
    amount_cents: int,
    currency: str,
    payee: str,
    purpose: str,
) -> str:
    """Request payment; SDK interruption and signed policy approval are distinct."""
    result = ctx.context.platform.run(
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
