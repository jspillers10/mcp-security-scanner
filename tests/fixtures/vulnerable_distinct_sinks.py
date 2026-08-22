"""
Fixture exercising MCP003 distinct-finding preservation: separate tools
with their own eval() calls, including two calls on the same source line,
must all be reported rather than collapsed by the duplicate-suppression
identity. Independently designed for this repository, not derived from
any external corpus.
"""

from fastmcp import FastMCP

mcp = FastMCP("distinct-sinks")


@mcp.tool()
def run_math(expression: str) -> str:
    """VULNERABLE: first tool, its own eval() call."""
    return str(eval(expression))


@mcp.tool()
def run_formula(formula: str) -> str:
    """VULNERABLE: second tool, its own distinct eval() call."""
    return str(eval(formula))


@mcp.tool()
def run_pair_same_line(first: str, second: str) -> str:
    """VULNERABLE: two distinct eval() calls sharing one physical source line."""
    a = eval(first); b = eval(second)  # noqa: E702 -- intentional same-line pair for column-offset coverage
    return f"{a} {b}"
