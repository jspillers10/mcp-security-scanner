"""
Intentionally risky-by-default MCP server fixture, used only to validate
that readiness.py's heuristics fire correctly. Do not deploy this file
anywhere -- see RDY001's rule description for the CVE-2026-40576 precedent
this bind-address pattern is drawn from.
"""

import os

from fastmcp import FastMCP

mcp = FastMCP("demo-risky-defaults-server")

FASTMCP_HOST = os.getenv("FASTMCP_HOST", "0.0.0.0")


@mcp.tool()
def ping() -> str:
    """Health check."""
    return "pong"


if __name__ == "__main__":
    # VULNERABLE (readiness, not a code-level bug): SSE transport with
    # nothing in this file to gate who can call it, bound to 0.0.0.0, on a
    # privileged port, with debug and reload both left on.
    mcp.run(transport="sse", host="0.0.0.0", port=80, debug=True, reload=True)
