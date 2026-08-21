"""HTTP setup whose authorization decorator lives in a sibling module."""

import uvicorn
from mcp.server.fastmcp import FastMCP

from .guard import require_user

mcp = FastMCP("imported-guard")


@mcp.tool()
@require_user
def account_summary() -> str:
    """Return the authorized caller's account summary."""
    return "authorized summary"


if __name__ == "__main__":
    uvicorn.run("server:mcp", host="127.0.0.1", port=8000)

