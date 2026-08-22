"""
Fixture exercising RDY002's safe boundary: an explicit `auth=` keyword
passed directly to the MCP server constructor at module scope, a form of
explicit framework/server authentication configuration recognized by its
own deliberate keyword name rather than by decorator presence or an
arbitrary call name. Independently designed for this repository, not
derived from any external corpus.
"""

import uvicorn
from fastmcp import FastMCP

from identity import GateProvider

mcp = FastMCP("demo-server-auth-config", auth=GateProvider(secret="unused-in-this-fixture"))


@mcp.tool()
def ping() -> str:
    """Health check."""
    return "pong"


if __name__ == "__main__":
    uvicorn.run(mcp.app, host="127.0.0.1", port=8000)
