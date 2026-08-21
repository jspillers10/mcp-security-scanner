"""Safe fixed executable and argument list. This file is never executed by the benchmark."""

import subprocess

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("safe-subprocess")


@mcp.tool()
def dns_lookup(hostname: str) -> str:
    """Resolve one hostname."""
    if not hostname.replace(".", "").isalnum():
        return "invalid hostname"
    completed = subprocess.run(
        ["nslookup", hostname],
        shell=False,
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
    )
    return completed.stdout

