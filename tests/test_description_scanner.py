import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from mcp_scanner.analyzer import scan_file

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def _rule_ids(findings):
    return {f.rule_id for f in findings}


def test_safe_description_fixture_has_no_description_findings():
    findings, errors = scan_file(os.path.join(FIXTURES, "safe_description_example.py"))
    assert errors == []
    description_findings = [f for f in findings if f.rule_id.startswith("MCP1")]
    assert description_findings == [], f"expected no description findings, got: {description_findings}"


def test_vulnerable_fixture_detects_imperative_language():
    findings, _ = scan_file(os.path.join(FIXTURES, "vulnerable_description_example.py"))
    hits = [f for f in findings if f.rule_id == "MCP101" and f.function_name == "setup"]
    assert hits, "expected model-directed imperative language finding on setup()"


def test_vulnerable_fixture_detects_invisible_unicode():
    findings, _ = scan_file(os.path.join(FIXTURES, "vulnerable_description_example.py"))
    hits = [f for f in findings if f.rule_id == "MCP102" and f.function_name == "fetch_notes"]
    assert hits, "expected invisible-Unicode finding on fetch_notes()"
    assert "200B" in hits[0].detail


def test_vulnerable_fixture_detects_base64_blob():
    findings, _ = scan_file(os.path.join(FIXTURES, "vulnerable_description_example.py"))
    hits = [f for f in findings if f.rule_id == "MCP103" and f.function_name == "sync_data"]
    assert hits, "expected base64-blob finding on sync_data()"


def test_vulnerable_fixture_detects_hijack_language():
    findings, _ = scan_file(os.path.join(FIXTURES, "vulnerable_description_example.py"))
    hits = [f for f in findings if f.rule_id == "MCP104" and f.function_name == "get_weather_v2"]
    assert hits, "expected tool-hijacking finding on get_weather_v2()"


def test_description_findings_use_prompt_injection_saif_category():
    findings, _ = scan_file(os.path.join(FIXTURES, "vulnerable_description_example.py"))
    description_findings = [f for f in findings if f.rule_id.startswith("MCP1")]
    assert description_findings
    assert all(f.saif_category == "Prompt Injection" for f in description_findings)


def test_inline_suppression_silences_matching_rule():
    # Regression-style guard: store_webhook_secret's description says "You
    # must provide a valid, non-empty token" -- which would normally trip
    # MCP101 -- but carries a `# mcp-scanner: ignore=MCP101` comment on the
    # same line, so it must not appear in findings.
    findings, _ = scan_file(os.path.join(FIXTURES, "safe_description_example.py"))
    hits = [f for f in findings if f.function_name == "store_webhook_secret"]
    assert hits == [], f"expected suppression to silence this finding, got: {hits}"


def test_suppression_is_specific_to_named_rules():
    # A bare "# mcp-scanner: ignore=MCP101" suppresses MCP101 specifically,
    # not every description finding on that line, by design.
    from mcp_scanner.description_scanner import _suppressed_rules

    assert _suppressed_rules(["x  # mcp-scanner: ignore=MCP101"], 1) == {"MCP101"}
    assert _suppressed_rules(["x  # mcp-scanner: ignore=MCP101,MCP103"], 1) == {"MCP101", "MCP103"}
    assert _suppressed_rules(["x  # mcp-scanner: ignore"], 1) == "ALL"
    assert _suppressed_rules(["x  # nothing here"], 1) is None
