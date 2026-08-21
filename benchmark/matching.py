"""Deterministic one-to-one matching of scanner findings to ground truth."""

from __future__ import annotations

from typing import Any


def normalize_path(path: str) -> str:
    """Normalize a relative benchmark path to slash-separated form."""

    normalized = path.replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized


def _line_distance(case: dict[str, Any], finding: dict[str, Any]) -> int | None:
    location = case["location"]
    line = finding["line"]
    start = location["start_line"]
    end = location.get("end_line", start)
    mode = case["matching"]["mode"]
    tolerance = case["matching"].get("line_tolerance", 0)

    if mode == "exact":
        return 0 if start == line else None
    if start - tolerance <= line <= end + tolerance:
        if start <= line <= end:
            return 0
        return min(abs(line - start), abs(line - end))
    return None


def _candidate_score(case: dict[str, Any], finding: dict[str, Any]) -> tuple[int, int, str, str] | None:
    expected = case["expected_result"]
    if expected["classification"] != "finding":
        return None
    if expected["rule_id"] != finding["rule_id"] or normalize_path(case["file"]) != normalize_path(finding["path"]):
        return None
    if expected.get("severity") and finding.get("severity") != expected["severity"]:
        return None

    expected_function = case["location"].get("function")
    function_penalty = 0
    if expected_function:
        if expected_function != finding.get("function"):
            return None
    else:
        function_penalty = 1

    distance = _line_distance(case, finding)
    if distance is None:
        return None
    return (distance, function_penalty, case["id"], finding["id"])


def match_findings(cases: list[dict[str, Any]], findings: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Return stable matches, false negatives, and false positives.

    Every expected case and finding can be used at most once. Candidate pairs
    are ranked by line distance, function specificity, case ID, and finding ID.
    This makes duplicate scanner results visible as false positives instead of
    allowing them to inflate the true-positive count.
    """

    expected_cases = sorted(
        (case for case in cases if case["expected_result"]["classification"] == "finding"),
        key=lambda case: case["id"],
    )
    ordered_findings = sorted(
        findings,
        key=lambda finding: (
            finding["path"],
            finding["rule_id"],
            finding["line"],
            finding.get("function", ""),
            finding["id"],
        ),
    )

    candidates: list[tuple[tuple[int, int, str, str], dict[str, Any], dict[str, Any]]] = []
    for case in expected_cases:
        for finding in ordered_findings:
            score = _candidate_score(case, finding)
            if score is not None:
                candidates.append((score, case, finding))
    candidates.sort(key=lambda item: item[0])

    used_cases: set[str] = set()
    used_findings: set[str] = set()
    matches: list[dict[str, Any]] = []
    for score, case, finding in candidates:
        if case["id"] in used_cases or finding["id"] in used_findings:
            continue
        used_cases.add(case["id"])
        used_findings.add(finding["id"])
        matches.append(
            {
                "case_id": case["id"],
                "finding_id": finding["id"],
                "rule_id": finding["rule_id"],
                "vulnerability_class": case["vulnerability_class"],
                "severity": finding.get("severity"),
                "path": finding["path"],
                "expected_line": case["location"]["start_line"],
                "actual_line": finding["line"],
                "line_distance": score[0],
            }
        )

    false_negatives = [
        {
            "case_id": case["id"],
            "rule_id": case["expected_result"]["rule_id"],
            "path": case["file"],
            "line": case["location"]["start_line"],
            "title": case["title"],
            "vulnerability_class": case["vulnerability_class"],
        }
        for case in expected_cases
        if case["id"] not in used_cases
    ]
    false_positives = [finding for finding in ordered_findings if finding["id"] not in used_findings]

    return {
        "matches": sorted(matches, key=lambda item: item["case_id"]),
        "false_negatives": sorted(false_negatives, key=lambda item: item["case_id"]),
        "false_positives": false_positives,
    }


def attribute_safe_cases(false_positives: list[dict[str, Any]], cases: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Annotate an FP when it lands in a reviewed no-finding case."""

    safe_cases = [case for case in cases if case["expected_result"]["classification"] == "no_finding"]
    attributed: list[dict[str, Any]] = []
    for finding in false_positives:
        result = dict(finding)
        for case in sorted(safe_cases, key=lambda item: item["id"]):
            if normalize_path(case["file"]) != normalize_path(finding["path"]):
                continue
            unexpected = case["expected_result"].get("unexpected_rules", [])
            if unexpected and finding["rule_id"] not in unexpected:
                continue
            if _line_distance(case, finding) is not None:
                result["safe_case_id"] = case["id"]
                break
        attributed.append(result)
    return attributed
