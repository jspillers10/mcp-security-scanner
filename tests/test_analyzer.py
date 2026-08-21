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


def test_same_file_helper_detects_command_injection():
    findings, errors = scan_file(os.path.join(FIXTURES, "vulnerable_same_file_helper.py"))
    assert errors == []
    hits = [f for f in findings if f.rule_id == "MCP001"]
    assert hits, f"expected MCP001 through same-file helper, got: {_rule_ids(findings)}"
    assert hits[0].function_name == "_run_shell"
    assert "via same-file helper" in hits[0].detail


def test_safe_same_file_helper_has_no_command_injection_finding():
    findings, errors = scan_file(os.path.join(FIXTURES, "safe_same_file_helper.py"))
    assert errors == []
    assert not any(f.rule_id == "MCP001" for f in findings)


def test_string_built_sql_query_detects_sql_injection():
    findings, errors = scan_file(os.path.join(FIXTURES, "vulnerable_sql_injection.py"))
    assert errors == []
    assert "MCP008" in _rule_ids(findings)


def test_parameterized_sql_query_is_not_flagged():
    findings, errors = scan_file(os.path.join(FIXTURES, "safe_sql_injection.py"))
    assert errors == []
    assert not any(f.rule_id == "MCP008" for f in findings)


def test_programmatic_add_tool_registration_detects_command_injection():
    # Regression test for the documented gap: a server that wraps FastMCP in
    # a custom class and registers handlers via self.mcp.add_tool(self.fn)
    # instead of @mcp.tool() previously produced zero findings, not because
    # the code was safe, but because the analyzer never looked at it.
    findings, errors = scan_file(os.path.join(FIXTURES, "vulnerable_programmatic_example.py"))
    assert errors == []
    ids = _rule_ids(findings)
    assert "MCP001" in ids, f"expected command injection finding via add_tool(), got: {ids}"


def test_programmatic_add_resource_registration_detects_exposed_debug_resource():
    findings, _ = scan_file(os.path.join(FIXTURES, "vulnerable_programmatic_example.py"))
    assert "MCP005" in _rule_ids(findings)


def test_programmatic_registration_findings_are_labeled_as_such():
    # The finding detail should make it obvious this was found via
    # add_tool()/add_resource(), not a decorator, so a report reader isn't
    # confused about why there's no @mcp.tool() line next to it.
    findings, _ = scan_file(os.path.join(FIXTURES, "vulnerable_programmatic_example.py"))
    assert any("add_tool()" in f.detail for f in findings)


def test_if_else_both_branches_returning_is_not_treated_as_validation():
    # Regression test for a real false negative: an if/else where BOTH
    # branches return their own computed result (ordinary branching logic,
    # not a rejecting guard clause) must not suppress a path-traversal
    # finding just because each branch happens to contain a `return`.
    # Caught by running the scanner against the actual DVMCP Challenge 10
    # server_sse.py, where `if config_name.endswith(".json"): ... return
    # ... else: ... return ...` was silently marking config_name
    # "validated" even though neither branch checks it at all.
    src = """
from fastmcp import FastMCP
mcp = FastMCP("x")

@mcp.tool()
def get_config(config_name: str) -> str:
    if config_name.endswith(".json"):
        with open(config_name) as f:
            data = f.read()
        return data
    else:
        with open(config_name) as f:
            data = f.read()
        return data
"""
    import ast

    from mcp_scanner.analyzer import MCPAnalyzer

    tree = ast.parse(src)
    analyzer = MCPAnalyzer(src)
    analyzer.visit(tree)
    ids = _rule_ids(analyzer.findings)
    assert "MCP002" in ids, f"expected path-traversal finding, got: {ids}"


def test_true_guard_clause_still_suppresses_finding():
    # Make sure tightening the if/else check didn't break the real case it
    # exists for: a genuine single-sided guard clause with no else.
    src = """
from fastmcp import FastMCP
mcp = FastMCP("x")

@mcp.tool()
def read_report(report_name: str) -> str:
    if report_name not in {"a", "b"}:
        raise ValueError("invalid")
    with open(report_name) as f:
        return f.read()
"""
    import ast

    from mcp_scanner.analyzer import MCPAnalyzer

    tree = ast.parse(src)
    analyzer = MCPAnalyzer(src)
    analyzer.visit(tree)
    ids = _rule_ids(analyzer.findings)
    assert "MCP002" not in ids, f"expected no path-traversal finding on validated input, got: {ids}"


def test_decorator_and_programmatic_pattern_in_same_file_no_double_counting():
    # A file with both patterns should not have decorator-registered tools
    # re-processed by the programmatic pass (which would duplicate findings).
    findings, _ = scan_file(os.path.join(FIXTURES, "vulnerable_example.py"))
    export_report_hits = [f for f in findings if f.function_name == "export_report" and f.rule_id == "MCP001"]
    assert len(export_report_hits) == 1
