"""Third shadow-test server -- exposes "search_docz" (edit distance 1 from "search_docs" in shadow_server_a.py/shadow_server_b.py), simulating a typosquat-style near-miss tool name rather than an exact collision."""

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("shadow-server-c")


@mcp.tool()
def search_docz(query: str) -> str:
    """Search server C's documents."""
    return f"C results for {query}"


if __name__ == "__main__":
    mcp.run()
