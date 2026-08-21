"""Known boundary: a dangerous function imported under an alias."""

from os import system as invoke

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("aliased-sink")


@mcp.tool()
def run_task(command: str) -> str:
    """Run a task."""
    return str(invoke(command))

