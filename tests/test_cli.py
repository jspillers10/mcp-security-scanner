import builtins
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from mcp_scanner import cli
from mcp_scanner.live_scanner import LiveConnectionError, _require_mcp_sdk
from mcp_scanner.report import format_text


def _run_cli(args):
    with pytest.raises(SystemExit) as exc_info:
        cli.main(args)
    return exc_info.value.code


def test_cli_help(capsys):
    assert _run_cli(["--help"]) == 0
    output = capsys.readouterr().out
    assert "mcp-scanner" in output
    assert "sarif" in output


def test_text_output_regression(tmp_path, capsys):
    server = tmp_path / "safe.py"
    server.write_text("value = 1\n", encoding="utf-8")

    assert _run_cli([str(server)]) == 0
    assert capsys.readouterr().out == format_text(str(server), [], [], []) + "\n\n"


def test_json_output_regression(tmp_path, capsys):
    server = tmp_path / "safe.py"
    server.write_text("value = 1\n", encoding="utf-8")

    assert _run_cli([str(server), "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out) == [
        {
            "path": str(server),
            "errors": [],
            "findings": [],
            "readiness": [],
        }
    ]


def test_sarif_output_file_and_stdout_behavior(tmp_path, capsys):
    server = tmp_path / "safe.py"
    output = tmp_path / "results.sarif"
    server.write_text("value = 1\n", encoding="utf-8")

    assert _run_cli([str(server), "--format", "sarif", "-o", str(output)]) == 0
    assert capsys.readouterr().out == ""
    data = json.loads(output.read_text(encoding="utf-8"))
    assert data["version"] == "2.1.0"
    assert data["runs"][0]["results"] == []


def test_json_output_file_and_stdout_behavior(tmp_path, capsys):
    server = tmp_path / "safe.py"
    output = tmp_path / "results.json"
    server.write_text("value = 1\n", encoding="utf-8")

    assert _run_cli([str(server), "--format", "json", "-o", str(output)]) == 0
    assert capsys.readouterr().out == ""
    assert json.loads(output.read_text(encoding="utf-8"))[0]["path"] == str(server)


def test_output_file_requires_machine_readable_format(tmp_path, capsys):
    server = tmp_path / "safe.py"
    server.write_text("value = 1\n", encoding="utf-8")

    assert _run_cli([str(server), "-o", str(tmp_path / "output.txt")]) == 2
    assert "requires --format json or --format sarif" in capsys.readouterr().err


def test_nonexistent_path_exits_two(capsys):
    assert _run_cli(["definitely-not-a-real-path"]) == 2
    assert "path does not exist" in capsys.readouterr().err


def test_nonexistent_config_path_exits_two(tmp_path, capsys):
    assert _run_cli(["config", str(tmp_path / "missing.json")]) == 2
    assert "could not read" in capsys.readouterr().err


def test_invalid_python_is_reported_and_exits_two(tmp_path, capsys):
    server = tmp_path / "invalid.py"
    server.write_text("def broken(:\n", encoding="utf-8")

    assert _run_cli([str(server), "--format", "json"]) == 2
    output = json.loads(capsys.readouterr().out)
    assert output[0]["findings"] == []
    assert output[0]["errors"]


def test_empty_directory_has_explicit_text_result(tmp_path, capsys):
    (tmp_path / "SECURITY.md").write_text("# Security\n", encoding="utf-8")

    assert _run_cli([str(tmp_path)]) == 0
    assert "No Python files found" in capsys.readouterr().out


def test_fail_on_thresholds_apply_to_vulnerability_findings(tmp_path, capsys):
    server = tmp_path / "secret.py"
    server.write_text('API_KEY = "abcdefghijklmnop"\n', encoding="utf-8")

    assert _run_cli([str(server), "--fail-on", "critical"]) == 0
    capsys.readouterr()
    assert _run_cli([str(server), "--fail-on", "high"]) == 1


def test_optional_live_dependency_absence_has_actionable_error(monkeypatch):
    real_import = builtins.__import__

    def reject_mcp(name, *args, **kwargs):
        if name == "mcp":
            raise ImportError("simulated missing optional dependency")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", reject_mcp)
    with pytest.raises(LiveConnectionError, match="live"):
        _require_mcp_sdk()
