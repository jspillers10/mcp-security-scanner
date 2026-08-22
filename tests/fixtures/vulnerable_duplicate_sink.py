"""
Fixture exercising MCP003 duplicate-finding suppression: a wrapper tool
calls a bare name that resolves (last-definition-wins) to a different
tool's own eval() sink, so the one-hop resolver re-discovers the exact
same physical eval() call already found by scanning that tool directly.
Independently designed for this repository, not derived from any
external corpus.
"""

from fastmcp import FastMCP

safe_server = FastMCP("dup-safe")
risky_server = FastMCP("dup-risky")


@safe_server.tool()
def compute(expression: str) -> str:
    """A safe implementation that never reaches eval()."""
    return f"unsupported: {expression}"


@risky_server.tool()
def compute(expression: str) -> str:
    """VULNERABLE: the tool actually registered under this name evaluates its input directly."""
    return str(eval(expression))


combined_server = FastMCP("dup-combined")


@combined_server.tool()
def compute_via_wrapper(expression: str) -> str:
    """Calls `compute` by name; resolution picks the last `compute` above (risky_server's)."""
    return compute(expression)
