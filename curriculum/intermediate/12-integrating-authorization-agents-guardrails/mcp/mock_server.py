"""Local MCP-style boundary with server, audience, and invocation checks."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from lab import RunResult, SecureAgentRuntime, SecurityContext, TerminalState


@dataclass(frozen=True)
class MCPRequest:
    server_id: str
    audience: str
    tool_name: str
    operation_id: str
    resource_id: str
    arguments: Mapping[str, Any]
    purpose: str
    # This demo accepts derived claims, never a downstream bearer token.
    bearer_token: str | None = None


class SecureMCPBoundary:
    def __init__(self, runtime: SecureAgentRuntime) -> None:
        self.runtime = runtime

    def invoke(self, context: SecurityContext, request: MCPRequest) -> RunResult:
        if request.bearer_token is not None:
            return RunResult(
                TerminalState.DENIED,
                "TOKEN_PASSTHROUGH_FORBIDDEN",
                request.operation_id,
            )
        spec = self.runtime.tools.get(request.tool_name)
        if spec is None:
            return RunResult(TerminalState.DENIED, "TOOL_UNKNOWN", request.operation_id)
        if request.server_id != spec.server_id:
            return RunResult(
                TerminalState.DENIED, "UNTRUSTED_MCP_SERVER", request.operation_id
            )
        if request.audience != spec.audience:
            return RunResult(
                TerminalState.DENIED, "TOKEN_AUDIENCE_INVALID", request.operation_id
            )
        if request.tool_name not in self.runtime.discover_tools(context):
            return RunResult(
                TerminalState.DENIED, "TOOL_NOT_DISCOVERABLE", request.operation_id
            )
        return self.runtime.run(
            context,
            {
                "operation_id": request.operation_id,
                "tool_name": request.tool_name,
                "resource_id": request.resource_id,
                "arguments": dict(request.arguments),
                "purpose": request.purpose,
            },
        )
