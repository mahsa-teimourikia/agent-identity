"""MCP SDK v2 server surface backed by the same application PEP.

Authentication middleware must construct the trusted context in production.
The local course uses a deterministic synthetic context and starts no server.
"""

from __future__ import annotations

from capstone_runtime import SecureAgentPlatform, canonical, valid_context
from mcp.types import ToolAnnotations

try:
    from mcp.server.mcpserver import MCPServer

    SDK_V2 = True
except ModuleNotFoundError:  # pragma: no cover - notebook kernels with MCP SDK v1
    from mcp.server.fastmcp import FastMCP as MCPServer

    SDK_V2 = False

_instructions = "Synthetic training server; every tool crosses the capstone PEP."
SERVER = (
    MCPServer("northstar-capstone", version="2026-10-04", instructions=_instructions)
    if SDK_V2
    else MCPServer("northstar-capstone", instructions=_instructions)
)
PLATFORM = SecureAgentPlatform()
TOOL_NAMES = ("claims_get", "payments_create")


def mcp_tool(**kwargs):
    """Use the v2 API while allowing older notebook kernels to render the lab."""
    if not SDK_V2:  # pragma: no cover - compatibility only
        kwargs.pop("structured_output", None)
    return SERVER.tool(**kwargs)


@mcp_tool(
    description="Read an assigned synthetic claim.",
    annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False),
    structured_output=False,
)
async def claims_get(operation_id: str, resource_id: str, purpose: str) -> str:
    """Read an assigned claim through the shared enforcement point."""
    result = PLATFORM.run(
        valid_context(),
        {
            "operation_id": operation_id,
            "tool_name": "claims.get",
            "resource_id": resource_id,
            "arguments": {},
            "purpose": purpose,
        },
    )
    return canonical(result)


@mcp_tool(
    description="Propose a synthetic payment; application approval is still required.",
    annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True),
    structured_output=False,
)
async def payments_create(
    operation_id: str,
    resource_id: str,
    amount_cents: int,
    currency: str,
    payee: str,
    purpose: str,
) -> str:
    """Request a payment through the shared enforcement point."""
    result = PLATFORM.run(
        valid_context(),
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
