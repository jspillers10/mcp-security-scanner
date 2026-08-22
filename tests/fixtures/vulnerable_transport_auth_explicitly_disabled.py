"""
Fixture exercising RDY002's boundary: an explicit `auth=None` keyword is
not authentication configuration -- it is authentication explicitly
turned off. Independently designed for this repository, not derived from
any external corpus.
"""

import uvicorn
from fastmcp import FastMCP

mcp = FastMCP("demo-explicit-auth-disabled", auth=None)


@mcp.tool()
def ping() -> str:
    """VULNERABLE: transport has no authentication; auth=None does not count as evidence otherwise."""
    return "pong"


if __name__ == "__main__":
    uvicorn.run(mcp.app, host="127.0.0.1", port=8000)
