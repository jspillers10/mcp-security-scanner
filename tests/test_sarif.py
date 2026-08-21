import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from mcp_scanner import __version__
from mcp_scanner.analyzer import scan_file as scan_vulnerabilities
from mcp_scanner.readiness import READINESS_CHECKS, ReadinessFinding
from mcp_scanner.readiness import scan_file as scan_readiness
from mcp_scanner.rules import RULES
from mcp_scanner.sarif import SARIF_SCHEMA, SARIF_VERSION, _normalize_uri, to_sarif

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def _scan_result(path):
    findings, errors = scan_vulnerabilities(path)
    readiness, readiness_errors = scan_readiness(path)
    return path, findings, errors + readiness_errors, readiness


def test_sarif_has_required_structure_and_tool_metadata():
    path = os.path.join(FIXTURES, "vulnerable_example.py")
    sarif = to_sarif(path, [_scan_result(path)])

    assert sarif["$schema"] == SARIF_SCHEMA
    assert sarif["version"] == SARIF_VERSION
    assert len(sarif["runs"]) == 1
    driver = sarif["runs"][0]["tool"]["driver"]
    assert driver["name"] == "mcp-security-scanner"
    assert driver["semanticVersion"] == __version__


def test_sarif_driver_defines_every_static_and_readiness_rule():
    sarif = to_sarif(".", [])
    rules = sarif["runs"][0]["tool"]["driver"]["rules"]
    assert {rule["id"] for rule in rules} == set(RULES) | set(READINESS_CHECKS)
    assert all(rule["shortDescription"]["text"] for rule in rules)
    assert all(rule["fullDescription"]["text"] for rule in rules)
    assert all(rule["help"]["text"] for rule in rules)


def test_sarif_results_include_rule_message_location_and_severity():
    path = os.path.join(FIXTURES, "vulnerable_example.py")
    sarif = to_sarif(path, [_scan_result(path)])
    results = sarif["runs"][0]["results"]
    command_injection = next(result for result in results if result["ruleId"] == "MCP001")

    assert command_injection["kind"] == "fail"
    assert command_injection["level"] == "error"
    assert command_injection["message"]["text"]
    assert command_injection["properties"]["severity"] == "critical"
    assert command_injection["properties"]["saifCategory"]
    location = command_injection["locations"][0]["physicalLocation"]
    assert location["artifactLocation"]["uri"] == "vulnerable_example.py"
    assert location["region"]["startLine"] > 0


def test_sarif_severity_mapping_covers_error_warning_and_note(tmp_path):
    server = tmp_path / "server.py"
    server.write_text(
        """
from fastmcp import FastMCP
mcp = FastMCP("x")

@mcp.tool(description="You must provide a value")
def run(value: str):
    return eval(value)
""",
        encoding="utf-8",
    )
    result = _scan_result(str(server))
    repo_readiness = [ReadinessFinding("RDY003", 0, "missing")]
    sarif = to_sarif(str(tmp_path), [result], repo_readiness)
    levels = {item["ruleId"]: item["level"] for item in sarif["runs"][0]["results"]}

    assert levels["MCP003"] == "error"
    assert levels["MCP101"] == "warning"
    assert levels["RDY003"] == "note"


def test_readiness_findings_are_separate_review_results():
    path = os.path.join(FIXTURES, "vulnerable_readiness_example.py")
    sarif = to_sarif(path, [_scan_result(path)])
    readiness = [result for result in sarif["runs"][0]["results"] if result["properties"]["findingType"] == "readiness"]

    assert readiness
    assert all(result["ruleId"].startswith("RDY") for result in readiness)
    assert all(result["kind"] == "review" for result in readiness)
    assert all("saifCategory" not in result["properties"] for result in readiness)


def test_empty_sarif_has_no_results_and_is_json_serializable():
    sarif = to_sarif(".", [])
    assert sarif["runs"][0]["results"] == []
    assert json.loads(json.dumps(sarif))["version"] == "2.1.0"


def test_multiple_findings_are_deterministic():
    path = os.path.join(FIXTURES, "vulnerable_example.py")
    scan_result = _scan_result(path)
    first = to_sarif(path, [scan_result])
    second = to_sarif(path, [scan_result])

    assert first == second
    results = first["runs"][0]["results"]
    locations = [
        (
            result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            result["locations"][0]["physicalLocation"].get("region", {}).get("startLine", 0),
            result["ruleId"],
        )
        for result in results
    ]
    assert locations == sorted(locations)


def test_scan_errors_are_notifications_not_findings(tmp_path):
    path = tmp_path / "invalid.py"
    path.write_text("def broken(:\n", encoding="utf-8")
    scan_result = _scan_result(str(path))
    sarif = to_sarif(str(path), [scan_result])
    run = sarif["runs"][0]

    assert run["results"] == []
    assert run["invocations"][0]["executionSuccessful"] is False
    assert run["invocations"][0]["toolExecutionNotifications"]


def test_path_normalization_handles_windows_and_posix_separators():
    assert _normalize_uri(r"src\server.py") == "src/server.py"
    assert _normalize_uri("src/server.py") == "src/server.py"
    assert _normalize_uri("project files/server.py") == "project%20files/server.py"
