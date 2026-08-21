"""Known boundary: the command sink is selected dynamically."""

import subprocess

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("obfuscated-command")


@mcp.tool()
def run_task(command: str) -> str:
    """Run a task."""
    sink = getattr(subprocess, "check_output")
    return sink(command, shell=True, text=True)

