"""
Fixture exercising RDY002's corrected boundary: no decorator stacked on a
tool/resource function proves the transport itself is authenticated,
regardless of the decorator's name or what it claims to do. A per-tool
wrapper -- even one named for authentication -- only ever intercepts
calls to that one tool; it says nothing about whether the SSE/HTTP
transport gates access before any tool is reachable (an unauthenticated
caller can still list tools, or call a different tool with no such
decorator). Independently designed for this repository, not derived from
any external corpus.
"""

import uvicorn
from fastmcp import FastMCP

mcp = FastMCP("demo-decorator-boundary-unprotected-transport")


def trace(function):
    """An unrelated tracing decorator. No authentication behavior."""
    return function


def retry(function):
    """An unrelated retry decorator. No authentication behavior."""
    return function


def require_session(function):
    """An authentication-shaped decorator name. Still a no-op wrapping only this one tool."""
    return function


def noop(function):
    """A neutral no-op decorator: no auth-shaped name, no behavior."""
    return function


@mcp.tool()
@trace
def traced_tool() -> str:
    """VULNERABLE: wrapped only by an unrelated tracing decorator."""
    return "traced"


@mcp.tool()
@retry
def retried_tool() -> str:
    """VULNERABLE: wrapped only by an unrelated retry decorator."""
    return "retried"


@mcp.tool()
@require_session
def gated_looking_tool() -> str:
    """VULNERABLE: an authentication-shaped decorator name on one tool does not gate the transport."""
    return "session-checked, allegedly"


@mcp.tool()
@noop
def noop_wrapped_tool() -> str:
    """VULNERABLE: a neutral no-op decorator proves nothing."""
    return "wrapped"


@mcp.tool()
def unwrapped_tool() -> str:
    """VULNERABLE: reachable directly, with no decorator at all -- the same transport as every tool above."""
    return "unwrapped"


if __name__ == "__main__":
    uvicorn.run(mcp.app, host="127.0.0.1", port=8000)
