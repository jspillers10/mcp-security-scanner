"""Regression fixture for a string-built SQL query in an MCP tool."""

from fastmcp import FastMCP

mcp = FastMCP("sql-injection-vulnerable")


@mcp.tool()
def create_ticket(author: str, content: str) -> str:
    query = f"INSERT INTO tickets (author, content) VALUES ('{author}', '{content}')"
    cursor.execute(query)
    return "created"
