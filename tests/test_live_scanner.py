import os
import socket
import subprocess
import sys
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

pytest.importorskip("mcp", reason="live-scan tests require the optional 'mcp' SDK: pip install -e '.[live]'")

from mcp_scanner.live_scanner import LiveConnectionError, scan_live_sse, scan_live_stdio

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures", "live")
SSE_HOST = "127.0.0.1"
SSE_PORT = 8933
SSE_URL = f"http://{SSE_HOST}:{SSE_PORT}/sse"


def test_scan_live_stdio_detects_poisoned_description():
    # Real end-to-end round trip: spawns the fixture as a subprocess,
    # speaks the actual MCP protocol over its stdin/stdout, and scans what
    # it reports -- not a mocked SDK.
    findings, tools, resources = scan_live_stdio(sys.executable, [os.path.join(FIXTURES, "vulnerable_server.py")])
    assert {t.name for t in tools} == {"setup", "clean_tool"}
    assert resources == []
    rule_ids = {f.rule_id for f in findings}
    assert "MCP101" in rule_ids


def test_scan_live_stdio_finding_has_no_line_number_but_has_tool_name():
    findings, _, _ = scan_live_stdio(sys.executable, [os.path.join(FIXTURES, "vulnerable_server.py")])
    hit = next(f for f in findings if f.rule_id == "MCP101")
    assert hit.line == 0
    assert hit.function_name == "setup"


def test_scan_live_stdio_clean_tool_in_same_server_not_flagged():
    findings, _, _ = scan_live_stdio(sys.executable, [os.path.join(FIXTURES, "vulnerable_server.py")])
    assert not any(f.function_name == "clean_tool" for f in findings)


def test_scan_live_stdio_safe_server_has_no_findings():
    findings, tools, _ = scan_live_stdio(sys.executable, [os.path.join(FIXTURES, "safe_server.py")])
    assert {t.name for t in tools} == {"get_order_status", "list_reports"}
    assert findings == []


def test_scan_live_stdio_bad_command_raises_live_connection_error():
    with pytest.raises(LiveConnectionError):
        scan_live_stdio(sys.executable, ["/nonexistent/path/to/nothing.py"], timeout=5)


def _wait_for_port(host, port, timeout_seconds):
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1):
                return True
        except OSError:
            time.sleep(0.3)
    return False


@pytest.fixture(scope="module")
def running_sse_server():
    # Real subprocess bound to a real (loopback-only) port -- proves the
    # SSE code path against actual network I/O, not a mock. Polls the port
    # rather than sleeping a fixed duration, since ASGI startup time isn't
    # constant across machines.
    proc = subprocess.Popen(
        [sys.executable, os.path.join(FIXTURES, "vulnerable_sse_server.py")],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    try:
        if not _wait_for_port(SSE_HOST, SSE_PORT, timeout_seconds=15):
            proc.terminate()
            pytest.fail("SSE fixture server never opened its port")
        yield
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


def test_scan_live_sse_detects_poisoned_description(running_sse_server):
    findings, tools, resources = scan_live_sse(SSE_URL)
    assert {t.name for t in tools} == {"setup"}
    assert any(f.rule_id == "MCP101" for f in findings)
