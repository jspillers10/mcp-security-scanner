"""
Fixture exercising MCP001 strong-guard shapes that must suppress the
finding: an exact allowlist gating a shell string, and a fixed lookup
table where the tainted parameter only ever selects among fixed literal
command strings. Independently designed for this repository, not derived
from any external corpus.
"""

import subprocess

from fastmcp import FastMCP

mcp = FastMCP("demo-strong-command-guard-server")

ALLOWED_ACTIONS = {"status", "restart", "health"}


@mcp.tool()
def service_action(action: str) -> str:
    """Exact allowlist of permitted actions gates the shell string built from the parameter."""
    if action not in ALLOWED_ACTIONS:
        raise ValueError("unknown action")
    result = subprocess.run(f"service demo-app {action}", shell=True, capture_output=True, text=True)
    return result.stdout


@mcp.tool()
def run_named_diagnostic(check_name: str) -> str:
    """The parameter only ever selects among fixed literal commands; its own content never reaches the shell."""
    commands = {
        "disk": "df -h",
        "memory": "free -h",
        "uptime": "uptime",
    }
    if check_name not in commands:
        return f"unknown check: {check_name}"
    command = commands[check_name]
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout
