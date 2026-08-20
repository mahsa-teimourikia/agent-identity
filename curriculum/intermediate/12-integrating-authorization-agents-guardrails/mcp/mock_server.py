"""A local mock MCP authorization boundary used by the notebook."""
from dataclasses import dataclass

@dataclass
class MCPRequest:
    server_id: str
    tool: str
    tenant: str
    token_audience: str
    args: dict

def authorize_mcp(req: MCPRequest, expected_server: str, allowed_tools: set[str]):
    if req.server_id != expected_server:
        return False, "UNTRUSTED_MCP_SERVER"
    if req.token_audience != expected_server:
        return False, "INVALID_TOKEN_AUDIENCE"
    if req.tool not in allowed_tools:
        return False, "TOOL_NOT_AUTHORIZED"
    return True, "ALLOW"
