import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from mcp_scanner.config_scanner import (
    _find_shadowed_tools,
    _levenshtein,
    load_server_specs,
)

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures", "live")


def _check_ids(findings):
    return {f.check_id for f in findings}


# -- pure-Python pieces: no live connection needed --------------------------


def test_levenshtein_basic_cases():
    assert _levenshtein("search_docs", "search_docs") == 0
    assert _levenshtein("search_docs", "search_docz") == 1
    assert _levenshtein("", "abc") == 3
    assert _levenshtein("abc", "") == 3


def test_load_server_specs_reads_mcp_servers_object(tmp_path):
    config = tmp_path / "config.json"
    config.write_text(
        json.dumps(
            {"mcpServers": {"a": {"command": "python", "args": ["a.py"]}, "b": {"url": "http://localhost:1/sse"}}}
        )
    )
    specs = load_server_specs(str(config))
    assert dict(specs)["a"] == {"command": "python", "args": ["a.py"]}
    assert dict(specs)["b"] == {"url": "http://localhost:1/sse"}


def test_load_server_specs_rejects_invalid_json(tmp_path):
    config = tmp_path / "config.json"
    config.write_text("{not valid json")
    with pytest.raises(ValueError):
        load_server_specs(str(config))


def test_load_server_specs_rejects_missing_file(tmp_path):
    with pytest.raises(ValueError, match="could not read"):
        load_server_specs(str(tmp_path / "missing.json"))


def test_load_server_specs_rejects_missing_mcp_servers_key(tmp_path):
    config = tmp_path / "config.json"
    config.write_text(json.dumps({"somethingElse": {}}))
    with pytest.raises(ValueError):
        load_server_specs(str(config))


def test_load_server_specs_rejects_non_object_server_entry(tmp_path):
    config = tmp_path / "config.json"
    config.write_text(json.dumps({"mcpServers": {"broken": None}}))
    with pytest.raises(ValueError, match="every.*value must be an object"):
        load_server_specs(str(config))


def test_find_shadowed_tools_exact_collision():
    per_server = {
        "server-a": {"tools": ["search_docs"], "error": None},
        "server-b": {"tools": ["search_docs"], "error": None},
    }
    findings = _find_shadowed_tools(per_server)
    assert "SHADOW001" in _check_ids(findings)


def test_find_shadowed_tools_near_miss():
    per_server = {
        "server-a": {"tools": ["search_docs"], "error": None},
        "server-c": {"tools": ["search_docz"], "error": None},
    }
    findings = _find_shadowed_tools(per_server)
    assert "SHADOW002" in _check_ids(findings)


def test_find_shadowed_tools_no_collision_across_distinct_servers():
    per_server = {
        "server-a": {"tools": ["search_docs"], "error": None},
        "clean": {"tools": ["get_weather"], "error": None},
    }
    assert _find_shadowed_tools(per_server) == []


def test_find_shadowed_tools_ignores_duplicates_within_the_same_server():
    # A server listing the same tool name twice (shouldn't happen, but if
    # it did) isn't a cross-server shadowing signal.
    per_server = {"server-a": {"tools": ["search_docs", "search_docs"], "error": None}}
    assert _find_shadowed_tools(per_server) == []


def test_find_shadowed_tools_short_names_excluded_from_similarity_check():
    # "a" vs "b" would be edit distance 1 -- meaningless at this length, and
    # would otherwise flood short/common tool names as false positives.
    per_server = {
        "server-a": {"tools": ["run"], "error": None},
        "server-b": {"tools": ["ran"], "error": None},
    }
    assert _find_shadowed_tools(per_server) == []


# -- real end-to-end: connects to actual stdio MCP server subprocesses ------

pytest.importorskip(
    "mcp", reason="config-scan integration tests require the optional 'mcp' SDK: pip install -e '.[live]'"
)

from mcp_scanner.config_scanner import scan_config  # noqa: E402


def _write_config(tmp_path, servers):
    config = tmp_path / "mcp_config.json"
    config.write_text(json.dumps({"mcpServers": servers}))
    return str(config)


def _stdio_spec(fixture_name):
    return {"command": sys.executable, "args": [os.path.join(FIXTURES, fixture_name)]}


def test_scan_config_detects_exact_shadow_across_real_servers(tmp_path):
    config_path = _write_config(
        tmp_path,
        {
            "server-a": _stdio_spec("shadow_server_a.py"),
            "server-b": _stdio_spec("shadow_server_b.py"),
        },
    )
    shadow_findings, per_server, errors = scan_config(config_path)
    assert errors == []
    assert per_server["server-a"]["tools"] == ["search_docs"]
    assert per_server["server-b"]["tools"] == ["search_docs"]
    assert "SHADOW001" in _check_ids(shadow_findings)


def test_scan_config_detects_near_miss_across_real_servers(tmp_path):
    config_path = _write_config(
        tmp_path,
        {
            "server-a": _stdio_spec("shadow_server_a.py"),
            "server-c": _stdio_spec("shadow_server_c.py"),
        },
    )
    shadow_findings, per_server, errors = scan_config(config_path)
    assert errors == []
    assert "SHADOW002" in _check_ids(shadow_findings)


def test_scan_config_no_findings_for_genuinely_distinct_servers(tmp_path):
    config_path = _write_config(
        tmp_path,
        {
            "server-a": _stdio_spec("shadow_server_a.py"),
            "clean": _stdio_spec("clean_server.py"),
        },
    )
    shadow_findings, per_server, errors = scan_config(config_path)
    assert errors == []
    assert shadow_findings == []


def test_scan_config_records_per_server_error_without_aborting_whole_scan(tmp_path):
    config_path = _write_config(
        tmp_path,
        {
            "broken": {"command": sys.executable, "args": ["/nonexistent/nothing.py"]},
            "server-a": _stdio_spec("shadow_server_a.py"),
        },
    )
    shadow_findings, per_server, errors = scan_config(config_path)
    assert per_server["broken"]["error"] is not None
    assert per_server["broken"]["tools"] == []
    assert per_server["server-a"]["tools"] == ["search_docs"]
    assert any("broken" in e for e in errors)


def test_scan_config_reports_missing_transport_spec(tmp_path):
    config_path = _write_config(tmp_path, {"weird": {"notes": "no command or url here"}})
    shadow_findings, per_server, errors = scan_config(config_path)
    assert per_server["weird"]["error"] is not None
    assert "weird" in errors[0]
