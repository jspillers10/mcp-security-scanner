"""SARIF 2.1.0 serialization for static and readiness scan results."""

import os
from pathlib import Path
from typing import Any, Iterable, Sequence
from urllib.parse import quote

from . import __version__
from .readiness import READINESS_CHECKS, ReadinessFinding
from .rules import RULES

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"
TOOL_NAME = "mcp-security-scanner"
TOOL_INFORMATION_URI = "https://github.com/jspillers10/mcp-security-scanner"

SARIF_LEVELS = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
}


def _normalize_uri(path: str) -> str:
    """Return a slash-normalized, URI-safe path without host-specific separators."""
    normalized = Path(path.replace("\\", "/")).as_posix()
    return quote(normalized, safe="/:")


def _relative_uri(path: str, scan_root: str) -> str:
    absolute_path = os.path.abspath(path)
    absolute_root = os.path.abspath(scan_root)
    base = absolute_root if os.path.isdir(absolute_root) else os.path.dirname(absolute_root)
    try:
        relative = os.path.relpath(absolute_path, base)
    except ValueError:
        relative = absolute_path
    return _normalize_uri(relative)


def _rule_descriptor(rule_id: str, rule, finding_type: str) -> dict:
    descriptor: dict[str, Any] = {
        "id": rule_id,
        "name": rule_id,
        "shortDescription": {"text": rule.title},
        "fullDescription": {"text": rule.description},
        "help": {"text": rule.remediation},
        "defaultConfiguration": {"level": SARIF_LEVELS[rule.severity]},
        "properties": {
            "severity": rule.severity,
            "findingType": finding_type,
        },
    }
    if finding_type == "vulnerability":
        descriptor["properties"].update(
            {
                "saifCategory": rule.saif_category,
                "saifCode": rule.saif_code,
            }
        )
    return descriptor


def _driver_rules() -> list[dict]:
    descriptors = [_rule_descriptor(rule_id, rule, "vulnerability") for rule_id, rule in RULES.items()]
    descriptors.extend(_rule_descriptor(check_id, check, "readiness") for check_id, check in READINESS_CHECKS.items())
    return sorted(descriptors, key=lambda descriptor: descriptor["id"])


def _location(path: str, line: int, scan_root: str) -> dict:
    physical_location: dict[str, Any] = {
        "artifactLocation": {"uri": _relative_uri(path, scan_root)},
    }
    if line > 0:
        physical_location["region"] = {"startLine": line}
    return {"physicalLocation": physical_location}


def _vulnerability_result(path: str, finding, scan_root: str, rule_indexes: dict[str, int]) -> dict:
    location_path = finding.file or path
    result = {
        "ruleId": finding.rule_id,
        "ruleIndex": rule_indexes[finding.rule_id],
        "kind": "fail",
        "level": SARIF_LEVELS[finding.severity],
        "message": {"text": finding.detail},
        "locations": [_location(location_path, finding.line, scan_root)],
        "properties": {
            "severity": finding.severity,
            "findingType": "vulnerability",
            "function": finding.function_name,
            "saifCategory": finding.saif_category,
            "saifCode": finding.saif_code,
        },
    }
    return result


def _readiness_result(
    path: str,
    finding: ReadinessFinding,
    scan_root: str,
    rule_indexes: dict[str, int],
) -> dict:
    return {
        "ruleId": finding.check_id,
        "ruleIndex": rule_indexes[finding.check_id],
        "kind": "review",
        "level": SARIF_LEVELS[finding.severity],
        "message": {"text": finding.detail},
        "locations": [_location(path, finding.line, scan_root)],
        "properties": {
            "severity": finding.severity,
            "findingType": "readiness",
        },
    }


def _result_sort_key(result: dict) -> tuple:
    physical = result["locations"][0]["physicalLocation"]
    return (
        physical["artifactLocation"]["uri"],
        physical.get("region", {}).get("startLine", 0),
        result["ruleId"],
        result["message"]["text"],
    )


def to_sarif(
    scan_root: str,
    scan_results: Sequence[tuple[str, Iterable, Iterable[str], Iterable[ReadinessFinding]]],
    repo_readiness: Iterable[ReadinessFinding] = (),
) -> dict:
    """Build a deterministic SARIF log from the findings the scanner produced.

    ``scan_results`` entries are ``(path, findings, errors, readiness)``. Errors
    become tool execution notifications, never security results.
    """
    rules = _driver_rules()
    rule_indexes = {rule["id"]: index for index, rule in enumerate(rules)}
    results: list[dict[str, Any]] = []
    notifications: list[dict[str, Any]] = []

    for path, findings, errors, readiness in scan_results:
        results.extend(_vulnerability_result(path, finding, scan_root, rule_indexes) for finding in findings)
        results.extend(_readiness_result(path, finding, scan_root, rule_indexes) for finding in readiness)
        notifications.extend(
            {
                "descriptor": {"id": "SCAN_ERROR"},
                "level": "error",
                "message": {"text": error},
                "locations": [_location(path, 0, scan_root)],
            }
            for error in errors
        )

    results.extend(_readiness_result(scan_root, finding, scan_root, rule_indexes) for finding in repo_readiness)
    results.sort(key=_result_sort_key)
    notifications.sort(key=lambda item: item["message"]["text"])

    invocation: dict[str, Any] = {"executionSuccessful": not notifications}
    if notifications:
        invocation["toolExecutionNotifications"] = notifications

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "semanticVersion": __version__,
                        "informationUri": TOOL_INFORMATION_URI,
                        "rules": rules,
                    }
                },
                "invocations": [invocation],
                "results": results,
            }
        ],
    }
