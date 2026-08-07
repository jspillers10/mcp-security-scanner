"""
Multi-server config scanner: reads a client MCP config file, connects to
every server it lists (reusing live_scanner.py's connection code), and
flags tool names that collide -- exactly or by simple similarity -- across
two or more of the configured servers.

Config format: both Claude Desktop's `claude_desktop_config.json` and
Claude Code's MCP config (`.mcp.json`, or entries added via `claude mcp
add`) share the same top-level shape:

    {"mcpServers": {"<name>": {...server spec...}, ...}}

They differ in what a server spec can contain: Claude Desktop's is
stdio-only (`command`, `args`, `env`); Claude Code's additionally supports
remote servers via a `url` field (with an optional `type` of `"sse"` or
`"http"`). This module doesn't need to distinguish which config flavor it's
reading -- it just checks each spec for `url` first, then `command`, and
connects accordingly. A spec with neither is reported as an error for that
server, not silently skipped.

This is a lightweight "tool shadowing" check, not a proxy: it connects once
per server, enumerates tools, and compares names across servers. A server
that registers a shadow tool *after* this scan runs -- the live
tool-redefinition attack DVMCP's own "Tool Shadowing" and "Rug Pull"
challenges model -- would need a re-scan to catch it. See the README's
Limitations section.
"""

import json
from dataclasses import dataclass, field

from .live_scanner import LiveConnectionError, connect_sse, connect_stdio

MIN_NAME_LENGTH_FOR_SIMILARITY = 4
MAX_SIMILARITY_DISTANCE = 2


@dataclass(frozen=True)
class ShadowCheck:
    check_id: str
    title: str
    severity: str  # "high" | "medium"


SHADOW_CHECKS = {
    "SHADOW001": ShadowCheck(
        check_id="SHADOW001",
        title="Identical tool name registered by multiple configured servers",
        severity="high",
    ),
    "SHADOW002": ShadowCheck(
        check_id="SHADOW002",
        title="Suspiciously similar tool names registered by different configured servers",
        severity="medium",
    ),
}


@dataclass
class ShadowFinding:
    check_id: str
    detail: str
    severity: str = field(init=False)
    title: str = field(init=False)

    def __post_init__(self):
        check = SHADOW_CHECKS[self.check_id]
        self.severity = check.severity
        self.title = check.title


def load_server_specs(config_path: str):
    """Parse a client MCP config file and return a list of (name, spec)
    pairs from its `mcpServers` object. Raises ValueError if the file isn't
    valid JSON or has no `mcpServers` object -- that's a config-format
    problem the caller should surface directly, not something to guess
    past.
    """
    with open(config_path, "r", encoding="utf-8") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError as e:
            raise ValueError(f"{config_path} is not valid JSON: {e}") from e

    servers = data.get("mcpServers")
    if not isinstance(servers, dict):
        raise ValueError(f"{config_path} has no top-level \"mcpServers\" object (checked for the shape both Claude Desktop and Claude Code use)")

    return list(servers.items())


def _connect_for_spec(name, spec):
    """Connect to one configured server per its spec, returning the raw
    tools list. Raises LiveConnectionError (from live_scanner.py) or
    ValueError (unrecognized spec shape) -- the caller is expected to catch
    both and record them as a per-server error rather than aborting the
    whole scan over one bad/unreachable entry.
    """
    if "url" in spec:
        tools, _resources = connect_sse(spec["url"])
        return tools
    if "command" in spec:
        tools, _resources = connect_stdio(spec["command"], spec.get("args"), spec.get("env"))
        return tools
    raise ValueError(f"server '{name}' has neither \"command\" nor \"url\" -- can't determine how to connect to it")


def _levenshtein(a: str, b: str) -> int:
    """Standard edit-distance DP. Tool names are short, so O(len(a)*len(b))
    is negligible here -- no need for a third-party dependency for this.
    """
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        curr = [i] + [0] * len(b)
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            curr[j] = min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost)
        prev = curr
    return prev[-1]


def _find_shadowed_tools(per_server):
    """Compare tool names across every server that connected successfully
    and flag exact collisions (SHADOW001) and near-miss/typosquat-shaped
    collisions (SHADOW002, edit distance <= 2, case-insensitive, only
    across *different* servers -- a server author reusing similar names
    within their own tool set is their own business, not a cross-server
    shadowing risk).
    """
    findings = []
    exact_map = {}
    all_tools = []  # (server_name, tool_name)

    for server_name, result in per_server.items():
        for tool_name in result["tools"]:
            exact_map.setdefault(tool_name, []).append(server_name)
            all_tools.append((server_name, tool_name))

    for tool_name, servers in exact_map.items():
        distinct_servers = sorted(set(servers))
        if len(distinct_servers) > 1:
            findings.append(
                ShadowFinding(
                    "SHADOW001",
                    f"tool '{tool_name}' is registered identically by multiple servers: {', '.join(distinct_servers)}",
                )
            )

    seen_pairs = set()
    for i in range(len(all_tools)):
        server_a, name_a = all_tools[i]
        for j in range(i + 1, len(all_tools)):
            server_b, name_b = all_tools[j]
            if server_a == server_b or name_a == name_b:
                continue
            if min(len(name_a), len(name_b)) < MIN_NAME_LENGTH_FOR_SIMILARITY:
                continue
            distance = _levenshtein(name_a.lower(), name_b.lower())
            if distance == 0 or distance > MAX_SIMILARITY_DISTANCE:
                continue
            pair_key = tuple(sorted([f"{server_a}:{name_a}", f"{server_b}:{name_b}"]))
            if pair_key in seen_pairs:
                continue
            seen_pairs.add(pair_key)
            findings.append(
                ShadowFinding(
                    "SHADOW002",
                    f"tool '{name_a}' (server '{server_a}') is suspiciously similar to '{name_b}' (server '{server_b}') -- edit distance {distance}",
                )
            )

    return findings


def scan_config(config_path: str):
    """Connect to every server listed in `config_path`, enumerate their
    tools, and check for cross-server tool-name collisions. Returns
    (shadow_findings, per_server, errors) where per_server is
    {server_name: {"tools": [names...], "error": str | None}} and errors is
    a flat list of "<server>: <message>" strings, mirroring the
    (findings, errors) shape the rest of this project returns.
    """
    specs = load_server_specs(config_path)
    per_server = {}
    errors = []

    for name, spec in specs:
        try:
            tools = _connect_for_spec(name, spec)
            per_server[name] = {"tools": [t.name for t in tools], "error": None}
        except (LiveConnectionError, ValueError) as e:
            per_server[name] = {"tools": [], "error": str(e)}
            errors.append(f"{name}: {e}")

    shadow_findings = _find_shadowed_tools(per_server)
    return shadow_findings, per_server, errors
