"""A cross-file MCP server fixture whose imported helper validates its own input before use, used to check for one-hop-resolution false positives."""

from fastmcp import FastMCP

from .helper import run_backup_command

mcp = FastMCP("demo-cross-file-safe-server")


@mcp.tool()
def backup(label: str) -> str:
    """Run a backup with the given label."""
    return run_backup_command(label)
