"""
RDY002 transport-auth reasoning: a token-shaped identifier, an
application-level "authenticate" tool, auth-related prose with no
enforcement code, or ANY decorator stacked on a tool/resource function
(regardless of name, including an authentication-shaped one) must not
suppress the finding. A decorator around one tool proves at most that one
tool has some per-call behavior -- it does not prove the SSE/HTTP
transport itself is gated, since an unauthenticated caller can still
reach a different tool with no such decorator, or list tools at all.

Module-level middleware, and an explicit `auth=`/`authentication=`
keyword passed to a call outside a tool/resource body, are the only
recognized safe boundaries -- both are evidence that exists independently
of any single tool's own wrapper.

Fixtures are independently designed for this repository, not copied from
DVMCP -- see vulnerable_transport_auth_boundaries.py,
vulnerable_transport_auth_decorators.py,
vulnerable_transport_auth_explicitly_disabled.py,
safe_transport_auth_middleware.py, and safe_transport_auth_server_config.py.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from mcp_scanner.readiness import scan_file

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def _rdy002(findings):
    return [f for f in findings if f.check_id == "RDY002"]


def _scan_source(tmp_path, source):
    path = tmp_path / "server.py"
    path.write_text(source, encoding="utf-8")
    findings, errors = scan_file(str(path))
    assert errors == []
    return _rdy002(findings)


def test_token_shaped_identifier_does_not_suppress_finding():
    findings, errors = scan_file(os.path.join(FIXTURES, "vulnerable_transport_auth_boundaries.py"))
    assert errors == []
    assert _rdy002(findings), "a token-shaped variable/path must not suppress RDY002"


def test_authenticate_tool_does_not_suppress_finding():
    # Same fixture as above: the file's only auth-shaped code is the
    # authenticate() tool itself (an application-level login tool) plus a
    # business-logic helper it calls -- neither gates the transport.
    findings, _ = scan_file(os.path.join(FIXTURES, "vulnerable_transport_auth_boundaries.py"))
    assert _rdy002(findings), "an application-level authenticate() tool must not suppress RDY002"


def test_prose_mentioning_authentication_does_not_suppress_finding():
    # The fixture's authenticate() docstring says "Authentication is
    # enforced by this project's security policy" -- text, not code.
    findings, _ = scan_file(os.path.join(FIXTURES, "vulnerable_transport_auth_boundaries.py"))
    assert _rdy002(findings), "auth-related docstring text with no enforcement code must not suppress RDY002"


def test_business_logic_call_inside_unrelated_tool_does_not_suppress_finding():
    # A business-logic call with an auth-shaped name (get_tokens-style)
    # made *inside* a tool body must not count, even when that tool isn't
    # the one named "authenticate".
    findings, _ = scan_file(os.path.join(FIXTURES, "vulnerable_transport_auth_boundaries.py"))
    assert _rdy002(findings), "a load_session_tokens() call inside a tool body must not suppress RDY002"


def test_tracing_decorator_does_not_suppress_finding():
    findings, errors = scan_file(os.path.join(FIXTURES, "vulnerable_transport_auth_decorators.py"))
    assert errors == []
    assert _rdy002(findings), "@trace on a tool must not suppress RDY002"


def test_retry_decorator_does_not_suppress_finding():
    findings, _ = scan_file(os.path.join(FIXTURES, "vulnerable_transport_auth_decorators.py"))
    assert _rdy002(findings), "@retry on a tool must not suppress RDY002"


def test_neutral_noop_decorator_does_not_suppress_finding():
    findings, _ = scan_file(os.path.join(FIXTURES, "vulnerable_transport_auth_decorators.py"))
    assert _rdy002(findings), "a neutral no-op decorator on a tool must not suppress RDY002"


def test_authentication_shaped_per_tool_decorator_does_not_suppress_finding():
    # The core correction: even a decorator NAMED for authentication
    # (require_session), stacked on exactly one tool, must not suppress
    # RDY002 -- it does not prove the transport itself is gated, and its
    # mere name is not proof of enforcement (the corrected reviewer-packet
    # Case 15 fixture behind this reasoning is a documented no-op).
    findings, _ = scan_file(os.path.join(FIXTURES, "vulnerable_transport_auth_decorators.py"))
    assert _rdy002(findings), "an authentication-shaped per-tool decorator must not suppress RDY002"


def test_explicitly_disabled_auth_does_not_suppress_finding():
    findings, errors = scan_file(os.path.join(FIXTURES, "vulnerable_transport_auth_explicitly_disabled.py"))
    assert errors == []
    assert _rdy002(findings), "auth=None must not be read as authentication configuration"


def test_module_level_middleware_suppresses_finding():
    findings, errors = scan_file(os.path.join(FIXTURES, "safe_transport_auth_middleware.py"))
    assert errors == []
    assert _rdy002(findings) == [], f"expected middleware setup to suppress RDY002, got: {_rdy002(findings)}"


def test_explicit_server_auth_config_suppresses_finding():
    findings, errors = scan_file(os.path.join(FIXTURES, "safe_transport_auth_server_config.py"))
    assert errors == []
    assert _rdy002(findings) == [], f"expected auth= server configuration to suppress RDY002, got: {_rdy002(findings)}"


def test_requests_auth_keyword_does_not_suppress_finding(tmp_path):
    findings = _scan_source(
        tmp_path,
        'import requests\nimport uvicorn\nrequests.get("https://example.test", auth=credentials)\n'
        'uvicorn.run("server:mcp", host="127.0.0.1", port=8000)\n',
    )
    assert findings, "requests.get(auth=...) is not MCP transport authentication"


def test_httpx_client_auth_keyword_does_not_suppress_finding(tmp_path):
    findings = _scan_source(
        tmp_path,
        "import httpx\nimport uvicorn\nclient = httpx.Client(auth=credentials)\n"
        'uvicorn.run("server:mcp", host="127.0.0.1", port=8000)\n',
    )
    assert findings, "httpx.Client(auth=...) is not MCP transport authentication"


def test_unrelated_constructor_auth_keyword_does_not_suppress_finding(tmp_path):
    findings = _scan_source(
        tmp_path,
        "import uvicorn\napplication = ReportApplication(auth=credentials)\n"
        'uvicorn.run("server:mcp", host="127.0.0.1", port=8000)\n',
    )
    assert findings, "an unrelated constructor's auth= keyword must not count"


def test_unrelated_class_named_fastmcp_does_not_suppress_finding(tmp_path):
    findings = _scan_source(
        tmp_path,
        "import uvicorn\nclass FastMCP:\n    def __init__(self, name, auth=None): pass\n"
        'application = FastMCP("reports", auth=credentials)\n'
        'uvicorn.run("server:mcp", host="127.0.0.1", port=8000)\n',
    )
    assert findings, "a local class merely named FastMCP must not count"


def test_empty_or_false_fastmcp_auth_does_not_suppress_finding(tmp_path):
    for value in ("None", "False", "''", "0", "[]", "{}"):
        findings = _scan_source(
            tmp_path,
            f'from fastmcp import FastMCP\nimport uvicorn\nmcp = FastMCP("demo", auth={value})\n'
            'uvicorn.run(mcp.app, host="127.0.0.1", port=8000)\n',
        )
        assert findings, f"FastMCP(auth={value}) must not count as enabled authentication"


def test_explicitly_disabled_provider_does_not_suppress_finding(tmp_path):
    findings = _scan_source(
        tmp_path,
        "from fastmcp import FastMCP\nimport uvicorn\n"
        'mcp = FastMCP("demo", auth=DisabledAuthProvider())\n'
        'uvicorn.run(mcp.app, host="127.0.0.1", port=8000)\n',
    )
    assert findings, "an explicitly disabled provider must not count"


def test_fastmcp_auth_inside_tool_does_not_suppress_finding(tmp_path):
    findings = _scan_source(
        tmp_path,
        'from fastmcp import FastMCP\nimport uvicorn\nmcp = FastMCP("demo")\n'
        '@mcp.tool()\ndef build_child():\n    return FastMCP("child", auth=provider)\n'
        'uvicorn.run(mcp.app, host="127.0.0.1", port=8000)\n',
    )
    assert findings, "FastMCP(auth=...) inside a tool body must not count"
