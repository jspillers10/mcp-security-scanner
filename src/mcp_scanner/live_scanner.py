"""
Live-connection scan mode: connects to a *running* MCP server over stdio or
SSE transport using the official MCP Python SDK, calls list_tools() and
list_resources() to retrieve the descriptions and schemas the server
actually reports at runtime, and runs the same description heuristics from
description_scanner.py against them.

This is explicitly not a traffic-interception proxy and does not monitor
requests/responses during ongoing operation. It connects once, enumerates
what the server currently advertises, scans that, and disconnects. A server
that changes its tool descriptions after this scan runs -- the "rug pull"
pattern DVMCP's own Rug Pull challenge models -- would need a fresh scan to
catch the change; this mode has no persistent visibility into a live
session. See the README's Limitations section.

Requires the optional `mcp` dependency (the official MCP Python SDK, a
free/open-source protocol client -- not a paid API, and importing it
performs no network calls of its own). It is intentionally NOT a default
dependency, since the rest of this project runs with zero third-party
packages; install it with `pip install -e ".[live]"`. Every function here
that touches the SDK imports it lazily, so importing this module (or the
rest of the package) never requires it to be installed -- only actually
calling scan_live_stdio()/scan_live_sse()/connect_stdio()/connect_sse() does.
"""

import asyncio

from .description_scanner import scan_description_text

# A broken command (typo'd path, a script that hangs before speaking MCP on
# stdin/stdout) or an unreachable URL must not hang the scanner forever --
# there's no other backstop against that once we've handed control to the
# SDK's own read loop.
DEFAULT_CONNECT_TIMEOUT_SECONDS = 20


class LiveConnectionError(RuntimeError):
    """Raised when connecting to or enumerating a live MCP server fails,
    wrapping whatever the SDK/transport raised with a message that names
    what was being attempted. Callers (cli.py, config_scanner.py) catch
    this specifically to report a clean error instead of a raw traceback.
    """


def _require_mcp_sdk():
    try:
        import mcp  # noqa: F401
    except ImportError as e:
        raise LiveConnectionError(
            "Live scanning requires the optional 'mcp' dependency (the official MCP Python SDK). "
            'Install it with: pip install -e ".[live]"'
        ) from e


async def _enumerate(session):
    await session.initialize()
    tools_result = await session.list_tools()
    try:
        resources_result = await session.list_resources()
        resources = resources_result.resources
    except Exception:
        # Not every server implements resources/list -- that's a capability
        # gap on the server's part, not a reason to fail the whole scan.
        resources = []
    return tools_result.tools, resources


async def _connect_stdio(command, args, env):
    from mcp import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client

    params = StdioServerParameters(command=command, args=list(args or []), env=env)
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            return await _enumerate(session)


async def _connect_sse(url):
    from mcp import ClientSession
    from mcp.client.sse import sse_client

    async with sse_client(url) as (read, write):
        async with ClientSession(read, write) as session:
            return await _enumerate(session)


def connect_stdio(command, args=None, env=None, timeout=DEFAULT_CONNECT_TIMEOUT_SECONDS):
    """Launch `command` as a subprocess speaking MCP over stdin/stdout,
    initialize a session, and return (tools, resources) -- the raw SDK
    result objects (mcp.types.Tool / mcp.types.Resource). Reused by
    config_scanner.py, which only needs tool names, not the description
    scan.
    """
    _require_mcp_sdk()
    try:
        return asyncio.run(asyncio.wait_for(_connect_stdio(command, args, env), timeout=timeout))
    except LiveConnectionError:
        raise
    except asyncio.TimeoutError as e:
        raise LiveConnectionError(f"timed out after {timeout}s connecting via stdio to '{command}' -- is it a valid MCP server?") from e
    except Exception as e:
        raise LiveConnectionError(f"failed to connect via stdio to '{command}': {e}") from e


def connect_sse(url, timeout=DEFAULT_CONNECT_TIMEOUT_SECONDS):
    """Connect to a running server over SSE/HTTP at `url` and return
    (tools, resources) -- see connect_stdio().
    """
    _require_mcp_sdk()
    try:
        return asyncio.run(asyncio.wait_for(_connect_sse(url), timeout=timeout))
    except LiveConnectionError:
        raise
    except asyncio.TimeoutError as e:
        raise LiveConnectionError(f"timed out after {timeout}s connecting via SSE to '{url}'") from e
    except Exception as e:
        raise LiveConnectionError(f"failed to connect via SSE to '{url}': {e}") from e


def _scan_items(items):
    findings = []
    for item in items:
        name = getattr(item, "name", "?")
        description = getattr(item, "description", None)
        if not description:
            continue
        findings.extend(scan_description_text(name, description))
    return findings


def scan_live_stdio(command, args=None, env=None, timeout=DEFAULT_CONNECT_TIMEOUT_SECONDS):
    """Connect over stdio, enumerate tools/resources, and run the
    description heuristics against what the server reports. Returns
    (findings, tools, resources).
    """
    tools, resources = connect_stdio(command, args, env, timeout=timeout)
    findings = _scan_items(tools) + _scan_items(resources)
    return findings, tools, resources


def scan_live_sse(url, timeout=DEFAULT_CONNECT_TIMEOUT_SECONDS):
    """Same as scan_live_stdio(), but over SSE/HTTP."""
    tools, resources = connect_sse(url, timeout=timeout)
    findings = _scan_items(tools) + _scan_items(resources)
    return findings, tools, resources
