import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from mcp_scanner.analyzer import scan_file

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def _rule_ids(findings):
    return {f.rule_id for f in findings}


def test_safe_fixture_has_no_findings():
    findings, errors = scan_file(os.path.join(FIXTURES, "safe_example.py"))
    assert errors == []
    assert findings == [], f"expected no findings, got: {[f.rule_id for f in findings]}"


def test_vulnerable_fixture_detects_command_injection():
    findings, _ = scan_file(os.path.join(FIXTURES, "vulnerable_example.py"))
    ids = _rule_ids(findings)
    assert "MCP001" in ids


def test_vulnerable_fixture_detects_command_injection_via_intermediate_variable():
    findings, _ = scan_file(os.path.join(FIXTURES, "vulnerable_example.py"))
    hits = [f for f in findings if f.rule_id == "MCP001" and f.function_name == "export_report"]
    assert hits, "expected command injection finding in export_report (tainted var assigned before sink call)"


def test_vulnerable_fixture_detects_path_traversal():
    findings, _ = scan_file(os.path.join(FIXTURES, "vulnerable_example.py"))
    assert "MCP002" in _rule_ids(findings)


def test_vulnerable_fixture_detects_eval():
    findings, _ = scan_file(os.path.join(FIXTURES, "vulnerable_example.py"))
    assert "MCP003" in _rule_ids(findings)


def test_vulnerable_fixture_detects_hardcoded_secret():
    findings, _ = scan_file(os.path.join(FIXTURES, "vulnerable_example.py"))
    assert "MCP004" in _rule_ids(findings)


def test_vulnerable_fixture_detects_debug_resource():
    findings, _ = scan_file(os.path.join(FIXTURES, "vulnerable_example.py"))
    assert "MCP005" in _rule_ids(findings)


def test_vulnerable_fixture_detects_excessive_agency():
    findings, _ = scan_file(os.path.join(FIXTURES, "vulnerable_example.py"))
    assert "MCP006" in _rule_ids(findings)


def test_vulnerable_fixture_detects_unsafe_deserialization():
    findings, _ = scan_file(os.path.join(FIXTURES, "vulnerable_example.py"))
    assert "MCP007" in _rule_ids(findings)


def test_safe_subprocess_with_argv_list_not_flagged_as_injection():
    # Regression test: subprocess.run([...]) without shell=True should not be
    # treated as command injection, even if an argument is tainted.
    findings, _ = scan_file(os.path.join(FIXTURES, "safe_example.py"))
    assert not any(f.rule_id == "MCP001" for f in findings)


def test_validated_path_not_flagged_as_traversal():
    # Regression test: a guard clause that raises on an invalid path should
    # suppress the path-traversal finding for that variable.
    findings, _ = scan_file(os.path.join(FIXTURES, "safe_example.py"))
    assert not any(f.rule_id == "MCP002" for f in findings)
