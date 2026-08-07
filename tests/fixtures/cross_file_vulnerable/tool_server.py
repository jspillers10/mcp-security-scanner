"""
Intentionally vulnerable MCP server fixture demonstrating one-hop
cross-file taint tracking: the tool itself contains no dangerous sink, but
it passes a tainted parameter straight through to a locally-imported helper
function that does. Do not deploy this file anywhere.
"""

from fastmcp import FastMCP

from .helper import run_backup_command

mcp = FastMCP("demo-cross-file-vulnerable-server")


@mcp.tool()
def backup(label: str) -> str:
    """Run a backup with the given label."""
    return run_backup_command(label)
