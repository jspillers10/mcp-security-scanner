"""A small MCP server fixture written defensively for production, used to check for readiness-heuristic false positives."""

import os

from fastmcp import FastMCP
from myserver.auth import require_bearer_token

mcp = FastMCP("demo-safe-readiness-server")

HOST = os.getenv("MCP_HOST", "127.0.0.1")
PORT = int(os.getenv("MCP_PORT", "8080"))


@mcp.tool()
def ping() -> str:
    """Health check."""
    return "pong"


if __name__ == "__main__":
    mcp.run(transport="sse", host=HOST, port=PORT, debug=False)
