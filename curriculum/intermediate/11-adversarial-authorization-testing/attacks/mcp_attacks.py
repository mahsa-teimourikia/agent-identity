"""MCP/tool identity attack fixtures."""
def tool_substitution(approved, observed):
    return approved["tool_id"] != observed["tool_id"] or approved["server_id"] != observed["server_id"]

def definition_changed(approved, observed):
    return approved.get("schema_hash") != observed.get("schema_hash")
