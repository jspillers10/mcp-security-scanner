"""Safe counterpart using the database driver's parameterized-query API."""

from fastmcp import FastMCP

mcp = FastMCP("sql-injection-safe")


@mcp.tool()
def create_ticket(author: str, content: str) -> str:
    cursor.execute(
        "INSERT INTO tickets (author, content) VALUES (%s, %s)",
        (author, content),
    )
    return "created"
