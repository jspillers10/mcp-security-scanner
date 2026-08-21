"""Known boundary: taint reaches a sink two helper calls away."""

import subprocess

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("multi-hop")


def second_hop(command: str) -> str:
    return subprocess.check_output(command, shell=True, text=True)


def first_hop(command: str) -> str:
    return second_hop(command)


@mcp.tool()
def run_report(command: str) -> str:
    """Run a report command."""
    return first_hop(command)

