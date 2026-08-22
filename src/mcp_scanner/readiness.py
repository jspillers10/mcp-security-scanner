"""
Production-readiness heuristics for MCP server source code.

Different in kind from analyzer.py's checks (MCP00x) and
description_scanner.py's checks (MCP1xx): those are vulnerability
findings -- something in the code, or in a tool's description, is actively
dangerous. These are risky *defaults* -- ways a server can be technically
not-vulnerable-by-itself and still be shipped in a posture no one would
choose after a moment's review. A single readiness finding rarely IS the
bug; it's the kind of thing that turns an unrelated bug into an incident (a
0.0.0.0 bind doesn't grant an attacker anything on its own, but it does mean
whatever else goes wrong is reachable from every interface on the host, not
just localhost). Findings here use a separate namespace (RDY0xx, no SAIF
mapping) and a separate report section so a reader never confuses "this is
a risky default" with "this is an exploitable bug" -- see report.py.

Real-world precedent, not a hypothetical: the default-bind-to-0.0.0.0
pattern RDY001 looks for is exactly the aggravating factor documented in
CVE-2026-40576 / GHSA-j98m-w3xp-9f56 (excel-mcp-server) -- a server whose
SSE transport bound to 0.0.0.0 by default, turning what would have been a
localhost-only exposure into one reachable from the network.

All checks are best-effort text/AST heuristics over a single file (or, for
the SECURITY.md check, a single directory) -- the same lightweight,
explainable-over-exhaustive philosophy as the rest of this project. Notably,
the missing-auth check (RDY002) looks only within the one file it's scanning
-- a server that sets up SSE transport in one module and enforces auth in
another will produce a false positive here. See the README's Limitations
section.
"""

import ast
import os
from dataclasses import dataclass, field

from .analyzer import RESOURCE_DECORATOR_NAMES, TOOL_DECORATOR_NAMES


@dataclass(frozen=True)
class ReadinessCheck:
    check_id: str
    title: str
    severity: str  # "high" | "medium" | "low"
    description: str
    remediation: str


READINESS_CHECKS = {
    "RDY001": ReadinessCheck(
        check_id="RDY001",
        title="Server binds to 0.0.0.0 by default",
        severity="medium",
        description=(
            "The server -- or an env-var default feeding into it -- binds "
            "its host to 0.0.0.0, making it reachable from every network "
            "interface rather than just localhost. This is the exact "
            "aggravating factor documented in CVE-2026-40576 "
            "(GHSA-j98m-w3xp-9f56, excel-mcp-server): a default bind "
            "address turned an otherwise-local exposure into one reachable "
            "from the network."
        ),
        remediation=(
            "Default to binding 127.0.0.1 and require an explicit opt-in "
            "(env var or CLI flag) to bind more broadly. If 0.0.0.0 is "
            "genuinely required (e.g. a containerized deployment behind a "
            "reverse proxy), pair it with authentication (see RDY002) and "
            "network-level access control."
        ),
    ),
    "RDY002": ReadinessCheck(
        check_id="RDY002",
        title="No apparent authentication for SSE/HTTP transport",
        severity="high",
        description=(
            "The server sets up an SSE or streamable-HTTP transport "
            "(network-reachable by design) with no reference anywhere in "
            "this file to an authentication or authorization mechanism. "
            "Unlike stdio transport, which inherits the process's own "
            "trust boundary, SSE/HTTP transport is reachable by anything "
            "that can route to the port -- with no auth check, that's "
            "anyone."
        ),
        remediation=(
            "Add an explicit authentication check (API key, bearer token, "
            "OAuth) in front of the transport's request handling, and "
            "confirm it actually executes on every request path."
        ),
    ),
    "RDY003": ReadinessCheck(
        check_id="RDY003",
        title="No SECURITY.md in repository root",
        severity="low",
        description=(
            "The scanned directory has no SECURITY.md, so there's no "
            "documented way for someone who finds a vulnerability to "
            "report it responsibly, and no stated supported-version or "
            "disclosure policy."
        ),
        remediation=("Add a SECURITY.md describing supported versions and how to report a vulnerability privately."),
    ),
    "RDY004": ReadinessCheck(
        check_id="RDY004",
        title="Hardcoded privileged port (<1024)",
        severity="low",
        description=(
            "The server hardcodes a port below 1024. Binding these "
            "requires elevated privileges on most platforms, so a server "
            "hardcoded to one either can't start without running as "
            "root/administrator (an unnecessarily large privilege grant "
            "for a network service), or was written assuming a deployment "
            "context that may not match how it's actually run."
        ),
        remediation=(
            "Use an unprivileged port (>= 1024) by default, and make the port configurable rather than hardcoded."
        ),
    ),
    "RDY005": ReadinessCheck(
        check_id="RDY005",
        title="Debug mode left enabled",
        severity="high",
        description=(
            "The server is started with debug=True. Debug modes in common "
            "Python web frameworks (Flask/Werkzeug in particular) can "
            "expose an interactive in-browser debugger and stack traces "
            "containing source code and local variables to anyone who can "
            "trigger an unhandled exception -- the Werkzeug debugger is a "
            "well-known remote-code-execution vector when reachable over "
            "the network."
        ),
        remediation=(
            "Ensure debug=False (or unset) in whatever config actually "
            "reaches production. Gate any debug=True behind a check that "
            "can't evaluate true in a deployed environment."
        ),
    ),
    "RDY006": ReadinessCheck(
        check_id="RDY006",
        title="Auto-reload left enabled",
        severity="medium",
        description=(
            "The server is started with reload=True. Auto-reload is a "
            "development convenience (the process restarts when source "
            "files change) with no place in a production deployment -- it "
            "usually means a dev-oriented run configuration reached "
            "production unmodified."
        ),
        remediation="Ensure reload=False (or unset) in production configuration.",
    ),
}


@dataclass
class ReadinessFinding:
    check_id: str
    line: int
    detail: str
    severity: str = field(init=False)
    title: str = field(init=False)

    def __post_init__(self):
        check = READINESS_CHECKS[self.check_id]
        self.severity = check.severity
        self.title = check.title


# This is a detection signature, not a network bind.
ZERO_BIND = "0.0.0.0"  # nosec B104

# Deliberately broad substring net -- this check's whole job is "is there
# any hint of auth anywhere in the file's actual code," not to identify a
# specific mechanism. Matched only against identifiers (import names,
# decorator names, call names) -- see _has_auth_reference() -- never
# against string/docstring contents. An earlier version of this matched
# against raw source text (including docstrings), which produced a real
# false negative: DVMCP's Tool Poisoning challenge (challenges/easy/
# challenge2/server.py) embeds the phrase "requires special authorization"
# inside a *poisoned tool docstring* -- text designed to manipulate a model,
# not an auth check -- and that alone was enough to make the file look
# authenticated to a text-substring search. Restricting the search to
# identifiers closes that specific hole; it doesn't guarantee there isn't a
# different one.
AUTH_SUBSTRINGS = ("auth", "bearer", "oauth", "jwt", "apikey", "api_key", "token")

TRANSPORT_STRINGS = {"sse", "streamable-http", "http"}
TRANSPORT_CALL_NAMES = {"sse_app", "streamable_http_app", "SseServerTransport"}


def _call_keyword(call_node, name):
    for kw in call_node.keywords:
        if kw.arg == name:
            return kw.value
    return None


def _const_str(node):
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _const_int(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, int) and not isinstance(node.value, bool):
        return node.value
    return None


def _const_bool(node):
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, bool) else None


def _is_getenv_call(func):
    if (
        isinstance(func, ast.Attribute)
        and func.attr == "getenv"
        and isinstance(func.value, ast.Name)
        and func.value.id == "os"
    ):
        return True
    if (
        isinstance(func, ast.Attribute)
        and func.attr == "get"
        and isinstance(func.value, ast.Attribute)
        and func.value.attr == "environ"
    ):
        return True
    if isinstance(func, ast.Name) and func.id == "getenv":
        return True
    return False


def _check_zero_bind(tree):
    findings = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            host_val = _call_keyword(node, "host")
            if host_val is not None and _const_str(host_val) == ZERO_BIND:
                findings.append(ReadinessFinding("RDY001", node.lineno, 'call sets host="0.0.0.0"'))
                continue
            if _is_getenv_call(node.func) and len(node.args) >= 2:
                key = _const_str(node.args[0])
                default = _const_str(node.args[1])
                if default == ZERO_BIND and key and "host" in key.lower():
                    call_name = (
                        node.func.attr if isinstance(node.func, ast.Attribute) else getattr(node.func, "id", "getenv")
                    )
                    findings.append(
                        ReadinessFinding(
                            "RDY001",
                            node.lineno,
                            f'{call_name}({key!r}, "0.0.0.0") -- 0.0.0.0 default for a host-like env var',
                        )
                    )
        elif isinstance(node, ast.Assign):
            value = _const_str(node.value)
            if value == ZERO_BIND:
                for target in node.targets:
                    if isinstance(target, ast.Name) and "host" in target.id.lower():
                        findings.append(ReadinessFinding("RDY001", node.lineno, f'{target.id} = "0.0.0.0"'))
    return findings


def _check_ports_and_debug(tree):
    findings = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        port_val = _call_keyword(node, "port")
        if port_val is not None:
            port = _const_int(port_val)
            if port is not None and 0 < port < 1024:
                findings.append(
                    ReadinessFinding(
                        "RDY004", node.lineno, f"hardcoded port={port} (requires elevated privileges to bind)"
                    )
                )
        debug_val = _call_keyword(node, "debug")
        if debug_val is not None and _const_bool(debug_val) is True:
            findings.append(ReadinessFinding("RDY005", node.lineno, "debug=True"))
        reload_val = _call_keyword(node, "reload")
        if reload_val is not None and _const_bool(reload_val) is True:
            findings.append(ReadinessFinding("RDY006", node.lineno, "reload=True"))
    return findings


def _call_name(func):
    if isinstance(func, ast.Attribute):
        return func.attr
    if isinstance(func, ast.Name):
        return func.id
    return None


def _has_auth_hint(name):
    if not name:
        return False
    lowered = name.lower()
    return any(s in lowered for s in AUTH_SUBSTRINGS)


def _decorator_name(dec):
    target = dec.func if isinstance(dec, ast.Call) else dec
    if isinstance(target, ast.Attribute):
        return target.attr
    if isinstance(target, ast.Name):
        return target.id
    return None


def _is_tool_or_resource_function(node) -> bool:
    return any(_decorator_name(dec) in TOOL_DECORATOR_NAMES | RESOURCE_DECORATOR_NAMES for dec in node.decorator_list)


# Keyword argument names treated as explicit authentication configuration,
# but only on a small allowlist of recognized MCP server constructors. An
# `auth=` keyword on requests.get(), httpx.Client(), or an arbitrary
# application constructor is request/application configuration, not evidence
# that the MCP transport itself is protected.
_EXPLICIT_AUTH_KEYWORDS = ("auth", "authentication")
_FASTMCP_MODULES = {"fastmcp", "mcp.server.fastmcp"}
_DISABLED_AUTH_NAME_PARTS = ("disabled", "noauth", "no_auth", "anonymous")


def _qualified_call_name(func):
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def _auth_value_is_enabled(value) -> bool:
    if isinstance(value, ast.Constant):
        return value.value not in (None, False, "", 0)
    if isinstance(value, (ast.List, ast.Tuple, ast.Set, ast.Dict)):
        return bool(getattr(value, "elts", None) or getattr(value, "keys", None))

    name = None
    if isinstance(value, ast.Name):
        name = value.id
    elif isinstance(value, ast.Call):
        name = _qualified_call_name(value.func)
    if name and any(part in name.lower() for part in _DISABLED_AUTH_NAME_PARTS):
        return False
    return True


def _is_explicitly_disabled_auth_call(call_node) -> bool:
    name = _qualified_call_name(call_node.func)
    return bool(name and any(part in name.lower() for part in _DISABLED_AUTH_NAME_PARTS))


def _collect_fastmcp_imports(tree):
    constructor_names = set()
    module_names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module in _FASTMCP_MODULES:
            for alias in node.names:
                if alias.name == "FastMCP":
                    constructor_names.add(alias.asname or alias.name)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in _FASTMCP_MODULES:
                    module_names.add(alias.asname or alias.name.split(".")[0])
    return constructor_names, module_names


def _is_recognized_fastmcp_call(call_node, constructor_names, module_names) -> bool:
    func = call_node.func
    if isinstance(func, ast.Name):
        return func.id in constructor_names
    return (
        isinstance(func, ast.Attribute)
        and func.attr == "FastMCP"
        and isinstance(func.value, ast.Name)
        and func.value.id in module_names
    )


def _has_explicit_auth_keyword(call_node, constructor_names, module_names) -> bool:
    if not _is_recognized_fastmcp_call(call_node, constructor_names, module_names):
        return False
    for kw in call_node.keywords:
        if kw.arg in _EXPLICIT_AUTH_KEYWORDS:
            return _auth_value_is_enabled(kw.value)
    return False


def _collect_calls_in_tool_or_resource_bodies(tree) -> set:
    """id()s of every Call node inside a tool/resource-decorated
    function's subtree (including its own decorator_list). Used to
    exclude those calls from _has_auth_reference's general auth-shaped-
    call-name scan: a call made as part of one tool's own business logic
    (e.g. a "check_email" tool calling get_tokens() to look up a stored
    token) says nothing about whether the transport itself requires
    authentication -- it's the same category of evidence the module
    docstring already excludes for docstring text, generalized to
    business-logic code that happens to run inside a tool/resource body.
    """
    excluded: set = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and _is_tool_or_resource_function(node):
            excluded.update(id(child) for child in ast.walk(node) if isinstance(child, ast.Call))
    return excluded


def _find_transport_setup(tree):
    """Return the line number of the first SSE/HTTP transport setup call
    found, or None. Covers `transport="sse"`/`"streamable-http"`/`"http"`
    kwargs, `uvicorn.run(...)`, and the FastMCP/low-level-SDK
    sse_app()/streamable_http_app()/SseServerTransport() call shapes.
    """
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = _call_name(func)
        if (
            name == "run"
            and isinstance(func, ast.Attribute)
            and isinstance(func.value, ast.Name)
            and func.value.id == "uvicorn"
        ):
            return node.lineno
        if name in TRANSPORT_CALL_NAMES:
            return node.lineno
        transport_kw = _call_keyword(node, "transport")
        if transport_kw is not None and _const_str(transport_kw) in TRANSPORT_STRINGS:
            return node.lineno
    return None


def _has_auth_reference(tree):
    """True if the file's actual code references something that plausibly
    gates the transport: an auth-shaped import (anywhere), an auth-shaped
    decorator on a *non*-tool/resource function (e.g. ASGI middleware
    setup or a route handler), an auth-shaped call made outside a
    tool/resource body, or an explicit `auth=`/`authentication=` keyword
    passed to a call outside a tool/resource body (see
    _has_explicit_auth_keyword). Deliberately does not look at
    string/docstring contents; see the AUTH_SUBSTRINGS comment for why.

    A tool/resource function's own decorators and the calls inside its
    body are excluded entirely from this scan -- see
    _collect_calls_in_tool_or_resource_bodies. Neither is evidence the
    *transport* is gated: a decorator wrapping one tool proves at most
    that one tool has some per-call behavior, not that the SSE/HTTP
    endpoint itself requires authentication before any tool is reachable
    (an unauthenticated caller can still list tools, or call a different
    tool that carries no such decorator). This applies regardless of the
    decorator's name -- an authentication-shaped name like `require_auth`
    stacked on one tool is exactly as inconclusive as a neutral one like
    `require_session`, `trace`, or `retry`; none of them can be told apart
    from a no-op decorator by inspecting only its call site, and treating
    the decorator's mere presence (or its name) as proof of transport-wide
    protection is exactly the class of unsound guess this check must not
    make. A tool literally named "authenticate" (application-level login
    logic) is likewise excluded via the same tool/resource handling: it is
    reachable through the same unauthenticated transport as every other
    tool, not a gate in front of it.

    This means RDY002 currently has **no** static path to recognizing
    per-tool authorization as protecting the transport -- only module-level
    evidence (an import, non-tool decorator, non-tool-body call, or an
    explicit `auth=` constructor keyword) suppresses it. Where a real
    server genuinely gates every tool through a per-tool mechanism with no
    module-level trace of it, this check cannot currently tell that apart
    from an unprotected transport, and reports RDY002 rather than guessing.
    """
    excluded_calls = _collect_calls_in_tool_or_resource_bodies(tree)
    fastmcp_constructors, fastmcp_modules = _collect_fastmcp_imports(tree)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if _has_auth_hint(alias.name) or _has_auth_hint(alias.asname):
                    return True
        elif isinstance(node, ast.ImportFrom):
            if _has_auth_hint(node.module):
                return True
            for alias in node.names:
                if _has_auth_hint(alias.name) or _has_auth_hint(alias.asname):
                    return True
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if _is_tool_or_resource_function(node):
                continue
            for dec in node.decorator_list:
                if _has_auth_hint(_decorator_name(dec)):
                    return True
        elif isinstance(node, ast.Call):
            if id(node) in excluded_calls:
                continue
            if _is_explicitly_disabled_auth_call(node):
                continue
            if _has_auth_hint(_call_name(node.func)):
                return True
            if _has_explicit_auth_keyword(node, fastmcp_constructors, fastmcp_modules):
                return True
    return False


def _check_missing_auth(tree):
    line = _find_transport_setup(tree)
    if line is None:
        return []
    if _has_auth_reference(tree):
        return []
    return [
        ReadinessFinding(
            "RDY002",
            line,
            "SSE/HTTP transport set up here, but no auth-related import, decorator, or call found anywhere in this file",
        )
    ]


def scan_file(path: str):
    """Per-file readiness checks: 0.0.0.0 binds, missing auth for SSE/HTTP
    transport, hardcoded privileged ports, debug/reload flags. Mirrors
    analyzer.scan_file()'s (findings, errors) signature.
    """
    with open(path, "r", encoding="utf-8") as f:
        source = f.read()

    try:
        tree = ast.parse(source, filename=path)
    except SyntaxError as e:
        return [], [f"Could not parse {path}: {e}"]

    findings = []
    findings.extend(_check_zero_bind(tree))
    findings.extend(_check_ports_and_debug(tree))
    findings.extend(_check_missing_auth(tree))
    findings.sort(key=lambda f: f.line)
    return findings, []


def check_security_md(root_path: str):
    """Repository-level check: is there a SECURITY.md directly in
    `root_path`? Returns a single ReadinessFinding, or None if one exists
    (or `root_path` isn't a directory). The caller is responsible for
    invoking this once per directory scan, not once per file -- unlike
    every other check in this module, it isn't tied to a specific source
    file or line.
    """
    if not os.path.isdir(root_path):
        return None
    for name in os.listdir(root_path):
        if name.lower() == "security.md":
            return None
    return ReadinessFinding("RDY003", 0, f"no SECURITY.md found in {root_path}")
