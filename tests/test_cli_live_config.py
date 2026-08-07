import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

pytest.importorskip("mcp", reason="live/config CLI tests require the optional 'mcp' SDK: pip install -e '.[live]'")

from mcp_scanner import cli

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures", "live")


def test_cli_live_stdio_reports_poisoned_description(capsys):
    with pytest.raises(SystemExit) as exc_info:
        cli.main(["live", "stdio", sys.executable, os.path.join(FIXTURES, "vulnerable_server.py")])
    output = capsys.readouterr().out
    assert "MCP101" in output
    assert "2 tool(s)" in output
    # MCP101 is medium severity, not critical/high -- exit code reflects that.
    assert exc_info.value.code == 0


def test_cli_live_stdio_safe_server_exits_zero_with_no_findings(capsys):
    with pytest.raises(SystemExit) as exc_info:
        cli.main(["live", "stdio", sys.executable, os.path.join(FIXTURES, "safe_server.py")])
    output = capsys.readouterr().out
    assert "No description findings" in output
    assert exc_info.value.code == 0


def test_cli_live_json_format(capsys):
    with pytest.raises(SystemExit):
        cli.main(["live", "--format", "json", "stdio", sys.executable, os.path.join(FIXTURES, "vulnerable_server.py")])
    output = capsys.readouterr().out
    data = json.loads(output)
    assert data["tool_count"] == 2
    assert any(f["rule_id"] == "MCP101" for f in data["findings"])


def test_cli_config_detects_shadowed_tools(tmp_path, capsys):
    config = tmp_path / "config.json"
    config.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "server-a": {"command": sys.executable, "args": [os.path.join(FIXTURES, "shadow_server_a.py")]},
                    "server-b": {"command": sys.executable, "args": [os.path.join(FIXTURES, "shadow_server_b.py")]},
                }
            }
        )
    )
    with pytest.raises(SystemExit) as exc_info:
        cli.main(["config", str(config)])
    output = capsys.readouterr().out
    assert "SHADOW001" in output
    assert exc_info.value.code == 1


def test_cli_config_no_shadow_exits_zero(tmp_path, capsys):
    config = tmp_path / "config.json"
    config.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "server-a": {"command": sys.executable, "args": [os.path.join(FIXTURES, "shadow_server_a.py")]},
                    "clean": {"command": sys.executable, "args": [os.path.join(FIXTURES, "clean_server.py")]},
                }
            }
        )
    )
    with pytest.raises(SystemExit) as exc_info:
        cli.main(["config", str(config)])
    output = capsys.readouterr().out
    assert "No tool-name collisions" in output
    assert exc_info.value.code == 0


def test_cli_legacy_positional_path_invocation_still_works(tmp_path, capsys):
    # Backward compatibility: the pre-subcommand invocation style
    # (`mcp-scanner path/to/server.py`, no "scan" keyword) must keep
    # working exactly as before "live"/"config" were added.
    server = tmp_path / "server.py"
    server.write_text("x = 1\n")
    with pytest.raises(SystemExit) as exc_info:
        cli.main([str(tmp_path)])
    output = capsys.readouterr().out
    assert "MCP Security Scan" in output
    assert exc_info.value.code == 0
