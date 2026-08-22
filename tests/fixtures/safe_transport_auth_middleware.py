"""
Fixture exercising RDY002's safe boundary: middleware registered at
module scope (outside any tool/resource body) that actually protects the
transport. Independently designed for this repository, not derived from
any external corpus.
"""

import uvicorn
from fastmcp import FastMCP
from starlette.middleware.authentication import AuthenticationMiddleware

mcp = FastMCP("demo-protected-transport")
mcp.app.add_middleware(AuthenticationMiddleware, backend=object())


@mcp.tool()
def ping() -> str:
    """Health check."""
    return "pong"


if __name__ == "__main__":
    uvicorn.run(mcp.app, host="127.0.0.1", port=8000)
