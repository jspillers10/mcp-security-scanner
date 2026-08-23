"""Deterministic, non-retrieving infrastructure for the field-validation pilot.

This module prepares and validates study artifacts. It intentionally contains no
repository retrieval, package installation, subject-code import, or scanner execution.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import math
import os
import re
import tokenize
from collections import defaultdict
from pathlib import Path
from typing import Any

from .matching import normalize_path
from .retrieve import file_sha256, tree_sha256
from .validation import BenchmarkInputError, load_json, validate_with_schema

SCHEMA_ROOT = Path(__file__).parent / "field_validation" / "schemas"


def canonical_sha256(value: Any) -> str:
    """Hash a JSON-compatible value using a stable canonical representation."""

    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def validate_artifact(path: Path, artifact_type: str) -> dict[str, Any]:
    """Load and schema-validate one public field-validation artifact."""

    allowed = {
        "candidate-register",
        "pilot-manifest",
        "case-inventory",
        "normalized-findings",
        "adjudication",
        "review-history",
        "review-selection",
        "reviewer-packet",
        "tool-run",
        "evidence-record",
        "pilot-metrics",
    }
    if artifact_type not in allowed:
        raise BenchmarkInputError(f"Unknown field-validation artifact type: {artifact_type}")
    document = load_json(path)
    validate_with_schema(document, SCHEMA_ROOT / f"{artifact_type}.schema.json", path)
    _validate_artifact_semantics(document, artifact_type)
    screen_public_artifact(document)
    return document


def _validate_artifact_semantics(document: dict[str, Any], artifact_type: str) -> None:
    if artifact_type == "candidate-register":
        query_ids = [item["query_id"] for item in document["queries"]]
        candidate_ids = [item["candidate_id"] for item in document["candidates"]]
        _require_unique(query_ids, "candidate discovery query")
        _require_unique(candidate_ids, "candidate")
        known_queries = set(query_ids)
        by_id = {item["candidate_id"]: item for item in document["candidates"]}
        canonical_by_lineage: dict[str, list[str]] = defaultdict(list)
        for candidate in document["candidates"]:
            unknown = set(candidate["discovery_query_ids"]) - known_queries
            if unknown:
                raise BenchmarkInputError(
                    f"Candidate {candidate['candidate_id']} references unknown discovery queries: {sorted(unknown)}"
                )
            if candidate["lineage_role"] == "canonical":
                canonical_by_lineage[candidate["lineage_id"]].append(candidate["candidate_id"])
                if candidate["duplicate_of"] is not None:
                    raise BenchmarkInputError(f"Canonical candidate {candidate['candidate_id']} cannot be a duplicate")
            else:
                target = by_id.get(candidate["duplicate_of"])
                if target is None or target["lineage_id"] != candidate["lineage_id"]:
                    raise BenchmarkInputError(f"Duplicate relationship is invalid for {candidate['candidate_id']}")
        ambiguous = sorted(lineage for lineage, ids in canonical_by_lineage.items() if len(ids) != 1)
        if ambiguous:
            raise BenchmarkInputError(f"Each lineage must have one canonical candidate: {ambiguous}")
    elif artifact_type == "pilot-manifest":
        repositories = document["repositories"]
        repository_ids = [item["repository_id"] for item in repositories]
        _require_unique(repository_ids, "repository")
        if document["authorization_state"] == "phase-5b-authorized":
            if len(repositories) != 3 or len(document["selection"]["selected_candidate_ids"]) != 3:
                raise BenchmarkInputError("An authorized pilot manifest must contain exactly three repositories")
        for tool in document["tools"]:
            expected = (
                "phase-5b-authorized" if document["authorization_state"] == "phase-5b-authorized" else "not-authorized"
            )
            if tool["execution_authorization_state"] != expected:
                raise BenchmarkInputError(f"Tool authorization conflicts with manifest state: {tool['tool']}")
        for mapping in document["claim_mappings"]:
            baseline_rules = mapping["bandit_rule_ids"] + mapping["semgrep_rule_ids"]
            if mapping["comparison_status"] == "comparison-eligible" and not baseline_rules:
                raise BenchmarkInputError(f"Comparison-eligible claim {mapping['claim_class']} has no baseline rule")
            if mapping["comparison_status"] == "unique-scope" and baseline_rules:
                raise BenchmarkInputError(f"Unique-scope claim {mapping['claim_class']} has baseline rules")
        _require_unique([item["claim_class"] for item in document["claim_mappings"]], "claim mapping")
    elif artifact_type == "case-inventory":
        _require_unique([item["case_id"] for item in document["cases"]], "case")
        for case in document["cases"]:
            if case["study_id"] != document["study_id"] or case["corpus_id"] != document["corpus_id"]:
                raise BenchmarkInputError(f"Case {case['case_id']} conflicts with inventory identity")
            if case["location"]["end_line"] < case["location"]["start_line"]:
                raise BenchmarkInputError(f"Case {case['case_id']} has an inverted location")
            if case["matching"]["mode"] == "exact" and case["matching"]["line_tolerance"] != 0:
                raise BenchmarkInputError(f"Exact case {case['case_id']} cannot declare line tolerance")
    elif artifact_type == "normalized-findings":
        _require_unique([item["finding_id"] for item in document["findings"]], "finding")
        for finding in document["findings"]:
            if finding["tool"] != document["tool"] or finding["repository_id"] != document["repository_id"]:
                raise BenchmarkInputError(f"Finding {finding['finding_id']} conflicts with its document identity")
    elif artifact_type == "adjudication":
        _require_unique([item["record_id"] for item in document["records"]], "adjudication record")
        if document["supersedes"] == document["round_id"]:
            raise BenchmarkInputError("An adjudication round cannot supersede itself")
        _validate_round_supersession(document, "adjudication")
        for record in document["records"]:
            if record["case_id"] is None and record["finding_id"] is None:
                raise BenchmarkInputError(f"Adjudication {record['record_id']} has no case or finding identity")
            if record["outcome"] == "disputed" and record["disagreement_state"] != "unresolved":
                raise BenchmarkInputError(f"Disputed adjudication {record['record_id']} must remain unresolved")
            _validate_disagreement(record, record["record_id"])
    elif artifact_type == "review-history":
        _require_unique([item["review_record_id"] for item in document["reviews"]], "review record")
        if document["supersedes"] == document["round_id"]:
            raise BenchmarkInputError("A review round cannot supersede itself")
        _validate_round_supersession(document, "review")
        for review in document["reviews"]:
            output_decision = review["output_aware_decision"]
            changed = output_decision is not None and output_decision != review["initial_blind_decision"]
            if review["decision_changed"] != changed:
                raise BenchmarkInputError(f"Review {review['review_record_id']} has contradictory decision_changed")
            if output_decision is None and review["output_aware_rationale"]:
                raise BenchmarkInputError(f"Review {review['review_record_id']} has rationale without a decision")
            if review["resolution_method"] == "third-reviewer" and review["third_reviewer_decision"] is None:
                raise BenchmarkInputError(f"Review {review['review_record_id']} lacks a third-reviewer decision")
            if review["resolution_method"] == "third-reviewer" and review["third_reviewer_role_id"] is None:
                raise BenchmarkInputError(f"Review {review['review_record_id']} lacks a third-reviewer role")
            if review["resolution_method"] != "third-reviewer" and any(
                (
                    review["third_reviewer_role_id"],
                    review["third_reviewer_decision"],
                    review["third_reviewer_rationale"],
                )
            ):
                raise BenchmarkInputError(f"Review {review['review_record_id']} has undeclared third-review data")
            _validate_disagreement(review, review["review_record_id"])
    elif artifact_type == "review-selection":
        _require_unique([item["review_item_id"] for item in document["members"]], "review selection member")
        if document["selection_state"] == "frozen" and document["zero_finding_repository_count"] < 3:
            raise BenchmarkInputError("A frozen reviewer selection needs three zero-finding repositories")
        for member in document["members"]:
            if member["member_kind"] == "case" and (
                member["case_id"] is None or member["source_sample_id"] is not None
            ):
                raise BenchmarkInputError(f"Review member {member['review_item_id']} has contradictory case identity")
            if member["member_kind"] == "zero-finding-source" and (
                member["source_sample_id"] is None or member["case_id"] is not None
            ):
                raise BenchmarkInputError(f"Review member {member['review_item_id']} has contradictory source identity")
    elif artifact_type == "reviewer-packet":
        _require_unique([item["review_item_id"] for item in document["items"]], "reviewer packet item")
        if document["item_count"] != len(document["items"]):
            raise BenchmarkInputError("Reviewer packet item_count does not match items")
        forbidden_keys = {
            "selection_reason",
            "selection_reasons",
            "detection_status",
            "finding_id",
            "tool",
            "tool_rule_id",
            "severity",
            "outcome",
            "classification",
            "disagreement_state",
        }
        leaked = sorted(_collect_keys(document) & forbidden_keys)
        if leaked:
            raise BenchmarkInputError(f"Blind reviewer packet leaks forbidden fields: {leaked}")
    elif artifact_type == "tool-run":
        _require_unique([item["path"] for item in document["file_statuses"]], "tool-run file")
        if document["authorization_state"] != "phase-5b-authorized" and document["execution_state"] != "not-started":
            raise BenchmarkInputError("Tool execution requires explicit Phase 5B authorization")
        if not document["subject_code_execution_prohibited"] or not document["deployed_system_interaction_prohibited"]:
            raise BenchmarkInputError("Tool runs must preserve subject-code and deployed-system prohibitions")
    elif artifact_type == "evidence-record":
        _require_unique([item["redaction_id"] for item in document["redactions"]], "redaction")
        if document["raw_output"]["tracked"]:
            raise BenchmarkInputError("Raw output must never be tracked")
    elif artifact_type == "pilot-metrics":
        if any(key in document for key in ("recall", "f1")):
            raise BenchmarkInputError("Pilot metrics must not report recall or F1")


def _require_unique(values: list[str], label: str) -> None:
    if len(values) != len(set(values)):
        raise BenchmarkInputError(f"Duplicate {label} ID")


def _collect_keys(value: Any) -> set[str]:
    if isinstance(value, dict):
        return set(value) | {key for child in value.values() for key in _collect_keys(child)}
    if isinstance(value, list):
        return {key for child in value for key in _collect_keys(child)}
    return set()


def _validate_round_supersession(document: dict[str, Any], label: str) -> None:
    sequence = document["round_sequence"]
    supersedes = document["supersedes"]
    if sequence == 1 and supersedes is not None:
        raise BenchmarkInputError(f"Initial {label} round cannot supersede another round")
    if sequence > 1 and supersedes is None:
        raise BenchmarkInputError(f"Later {label} round must identify the superseded round")


def _validate_disagreement(record: dict[str, Any], identity: str) -> None:
    expected = {
        "none": {"not-needed"},
        "resolved": {"discussion", "third-reviewer"},
        "unresolved": {"unresolved"},
    }
    if record["resolution_method"] not in expected[record["disagreement_state"]]:
        raise BenchmarkInputError(f"Record {identity} has contradictory disagreement resolution")


def screen_public_artifact(value: Any) -> None:
    """Fail closed on common credential forms before a public artifact is staged."""

    text = json.dumps(value, sort_keys=True, ensure_ascii=False)
    patterns = {
        "private key": r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
        "GitHub token": r"gh[pousr]_[A-Za-z0-9]{20,}",
        "AWS access key": r"AKIA[0-9A-Z]{16}",
        "credential assignment": (
            r"(?i)(?:password|passwd|secret|api[_-]?key|access[_-]?token)"
            r"\s*[:=]\s*[\\\"]?[A-Za-z0-9._~+/=-]{12,}"
        ),
    }
    for label, pattern in patterns.items():
        if re.search(pattern, text):
            raise BenchmarkInputError(f"Public artifact contains a possible {label}; quarantine and redact it")


def deterministic_select(register: dict[str, Any], count: int, seed: str) -> dict[str, Any]:
    """Select candidates without using scanner or baseline output.

    Each lineage must declare exactly one eligible canonical representative. Representatives
    are ordered by a SHA-256 rank derived from the frozen seed, all declared strata, and
    candidate ID, then selected round-robin across sorted strata.
    """

    if count < 1:
        raise BenchmarkInputError("Selection count must be positive")
    if not register["discovery_frozen"]:
        raise BenchmarkInputError("Candidate discovery must be frozen before selection")
    all_candidates = register["candidates"]
    by_id = {item["candidate_id"]: item for item in all_candidates}
    for item in all_candidates:
        duplicate_of = item.get("duplicate_of")
        if duplicate_of is not None:
            target = by_id.get(duplicate_of)
            if target is None:
                raise BenchmarkInputError(
                    f"Candidate {item['candidate_id']} references unknown duplicate {duplicate_of}"
                )
            if target["lineage_id"] != item["lineage_id"]:
                raise BenchmarkInputError(f"Candidate {item['candidate_id']} crosses lineage in duplicate_of")
    eligible = [
        item
        for item in all_candidates
        if item["screening_status"] == "included"
        and item["license"]["status"] == "compatible"
        and item["lineage_role"] == "canonical"
        and not item["intentionally_vulnerable_training"]
        and not item["used_for_scanner_development"]
    ]
    by_lineage: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in eligible:
        by_lineage[item["lineage_id"]].append(item)
    ambiguous = sorted(lineage for lineage, items in by_lineage.items() if len(items) != 1)
    if ambiguous:
        raise BenchmarkInputError(f"Lineages must have one eligible canonical representative: {ambiguous}")
    representatives = [items[0] for items in by_lineage.values()]
    if len(representatives) < count:
        raise BenchmarkInputError(
            f"Requested {count} repositories but only {len(representatives)} lineages are eligible"
        )

    by_stratum: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in representatives:
        stratum = "|".join(
            [
                item["strata"]["framework"],
                item["strata"]["maintenance"],
                item["strata"]["size_band"],
                item["strata"]["popularity_band"],
                item["strata"]["application_type"],
            ]
        )
        by_stratum[stratum].append(item)
    for stratum, items in by_stratum.items():
        items.sort(key=lambda item: (canonical_sha256([seed, stratum, item["candidate_id"]]), item["candidate_id"]))

    selected: list[dict[str, Any]] = []
    strata = sorted(by_stratum)
    while len(selected) < count:
        progressed = False
        for stratum in strata:
            if by_stratum[stratum] and len(selected) < count:
                selected.append(by_stratum[stratum].pop(0))
                progressed = True
        if not progressed:
            break
    selected_ids = [item["candidate_id"] for item in selected]
    return {
        "schema_version": "1.0",
        "selection_kind": "pilot",
        "seed": seed,
        "algorithm": "sha256-ranked-stratified-round-robin-v1",
        "requested_count": count,
        "candidate_register_sha256": canonical_sha256(register),
        "selected_candidate_ids": selected_ids,
        "selection_sha256": canonical_sha256(selected_ids),
    }


def build_file_inventory(root: Path, repository_id: str, commit: str, paths: list[str]) -> dict[str, Any]:
    """Hash an explicitly scoped list of Python source files without importing them."""

    resolved_root = root.resolve()
    if not resolved_root.is_dir():
        raise BenchmarkInputError(f"Repository root does not exist: {resolved_root}")
    normalized_paths = sorted({normalize_path(path) for path in paths})
    files: list[dict[str, Any]] = []
    for relative in normalized_paths:
        if not relative.endswith(".py"):
            raise BenchmarkInputError(f"Scoped file is not Python source: {relative}")
        lexical_target = resolved_root / relative
        target = lexical_target.resolve()
        try:
            target.relative_to(resolved_root)
        except ValueError as error:
            raise BenchmarkInputError(f"Scoped path escapes repository root: {relative}") from error
        if not target.is_file():
            raise BenchmarkInputError(f"Scoped file is missing: {relative}")
        current = lexical_target
        while current != resolved_root:
            if current.is_symlink():
                raise BenchmarkInputError(f"Scoped path contains a symlink: {relative}")
            current = current.parent
        data = target.read_bytes()
        source_status = "ready"
        encoding: str | None = None
        python_lines: int | None = None
        failure_reason: str | None = None
        try:
            encoding, _ = tokenize.detect_encoding(io.BytesIO(data).readline)
            python_lines = len(data.decode(encoding).splitlines())
        except (LookupError, SyntaxError, UnicodeDecodeError) as error:
            source_status = "encoding-error"
            failure_reason = f"Python source encoding could not be decoded: {type(error).__name__}"
        files.append(
            {
                "path": relative,
                "sha256": file_sha256(target),
                "bytes": len(data),
                "encoding": encoding,
                "python_lines": python_lines,
                "source_status": source_status,
                "scanner_status": "pending" if source_status == "ready" else "not-presented",
                "failure_reason": failure_reason,
            }
        )
    hashes = [{"path": item["path"], "sha256": item["sha256"]} for item in files]
    return {
        "repository_id": repository_id,
        "commit": commit,
        "files": files,
        "scoped_tree_sha256": tree_sha256(hashes),
        "scoped_python_lines": sum(item["python_lines"] or 0 for item in files),
    }


def normalize_findings(tool: str, repository_id: str, findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Normalize already redacted tool findings into a common semantic shape."""

    if tool not in {"mcp-security-scanner", "bandit", "semgrep"}:
        raise BenchmarkInputError(f"Unsupported comparison tool: {tool}")
    normalized: list[dict[str, Any]] = []
    occurrences: dict[str, int] = defaultdict(int)
    for finding in findings:
        physical_identity = [
            tool,
            repository_id,
            finding["claim_class"],
            normalize_path(finding["path"]),
            finding["line"],
            finding.get("context", ""),
            finding["tool_rule_id"],
        ]
        physical_key = canonical_sha256(physical_identity)
        occurrence = finding.get("occurrence")
        if occurrence is None:
            occurrences[physical_key] += 1
            occurrence = occurrences[physical_key]
        if not isinstance(occurrence, int) or occurrence < 1:
            raise BenchmarkInputError("Finding occurrence must be a positive integer")
        identity = [*physical_identity, occurrence]
        normalized.append(
            {
                "finding_id": f"finding-{canonical_sha256(identity)[:16]}",
                "physical_identity": f"physical-{physical_key[:16]}",
                "occurrence": occurrence,
                "tool": tool,
                "repository_id": repository_id,
                "tool_rule_id": finding["tool_rule_id"],
                "claim_class": finding["claim_class"],
                "path": normalize_path(finding["path"]),
                "line": finding["line"],
                "context": finding.get("context"),
                "severity": finding.get("severity"),
                "redacted_message": finding.get("redacted_message", ""),
            }
        )
    normalized.sort(key=lambda item: item["finding_id"])
    ids = [item["finding_id"] for item in normalized]
    if len(ids) != len(set(ids)):
        raise BenchmarkInputError("Duplicate finding occurrence identity")
    return {"schema_version": "1.0", "tool": tool, "repository_id": repository_id, "findings": normalized}


def match_cases(cases: list[dict[str, Any]], findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Return deterministic maximum-cardinality, minimum-priority-cost matches."""

    ordered_cases = sorted(cases, key=lambda item: item["case_id"])
    ordered_findings = sorted(findings, key=lambda item: item["finding_id"])
    candidate_edges: list[tuple[dict[str, Any], dict[str, Any], tuple[int, int, int, int, int]]] = []
    max_distance = 0
    for case_index, case in enumerate(ordered_cases):
        for finding_index, finding in enumerate(ordered_findings):
            priority = _matching_priority(case, finding, case_index, finding_index)
            if priority is not None:
                max_distance = max(max_distance, priority[2])
                candidate_edges.append((case, finding, priority))

    base = max(len(ordered_cases), len(ordered_findings), max_distance) + 2
    source = 0
    case_offset = 1
    finding_offset = case_offset + len(ordered_cases)
    sink = finding_offset + len(ordered_findings)
    graph: list[list[dict[str, Any]]] = [[] for _ in range(sink + 1)]

    def add_edge(start: int, end: int, capacity: int, cost: int, identity: tuple[str, str] | None = None) -> None:
        forward = {"to": end, "rev": len(graph[end]), "capacity": capacity, "cost": cost, "identity": identity}
        reverse = {"to": start, "rev": len(graph[start]), "capacity": 0, "cost": -cost, "identity": None}
        graph[start].append(forward)
        graph[end].append(reverse)

    case_nodes = {case["case_id"]: case_offset + index for index, case in enumerate(ordered_cases)}
    finding_nodes = {finding["finding_id"]: finding_offset + index for index, finding in enumerate(ordered_findings)}
    for case in ordered_cases:
        add_edge(source, case_nodes[case["case_id"]], 1, 0)
    for finding in ordered_findings:
        add_edge(finding_nodes[finding["finding_id"]], sink, 1, 0)
    for case, finding, priority in sorted(candidate_edges, key=lambda item: item[2]):
        cost = 0
        for component in priority:
            cost = cost * base + component
        add_edge(
            case_nodes[case["case_id"]],
            finding_nodes[finding["finding_id"]],
            1,
            cost,
            (case["case_id"], finding["finding_id"]),
        )

    while _augment_shortest_path(graph, source, sink):
        pass

    matches: list[dict[str, Any]] = []
    used_cases: set[str] = set()
    used_findings: set[str] = set()
    for case in ordered_cases:
        for edge in graph[case_nodes[case["case_id"]]]:
            identity = edge["identity"]
            if identity is None or edge["capacity"] != 0:
                continue
            finding = next(item for item in ordered_findings if item["finding_id"] == identity[1])
            distance = _line_distance(case, finding)
            matches.append({"case_id": identity[0], "finding_id": identity[1], "line_distance": distance})
            used_cases.add(identity[0])
            used_findings.add(identity[1])
    return {
        "matches": sorted(matches, key=lambda item: (item["case_id"], item["finding_id"])),
        "unmatched_case_ids": sorted(case["case_id"] for case in cases if case["case_id"] not in used_cases),
        "unmatched_finding_ids": sorted(
            finding["finding_id"] for finding in findings if finding["finding_id"] not in used_findings
        ),
    }


def _matching_priority(
    case: dict[str, Any], finding: dict[str, Any], case_index: int, finding_index: int
) -> tuple[int, int, int, int, int] | None:
    if case["repository_id"] != finding["repository_id"] or case["claim_class"] != finding["claim_class"]:
        return None
    if normalize_path(case["file"]) != normalize_path(finding["path"]):
        return None
    expected_context = case["context"].get("name")
    if expected_context and expected_context != finding.get("context"):
        return None
    distance = _line_distance(case, finding)
    if distance is None:
        return None
    exact_penalty = 0 if distance == 0 else 1
    context_penalty = 0 if expected_context else 1
    return (exact_penalty, context_penalty, distance, case_index, finding_index)


def _line_distance(case: dict[str, Any], finding: dict[str, Any]) -> int | None:
    location = case["location"]
    start = location["start_line"]
    end = location["end_line"]
    line = finding["line"]
    matching = case["matching"]
    if matching["mode"] == "exact":
        return 0 if start <= line <= end else None
    tolerance = matching["line_tolerance"]
    if start - tolerance <= line <= end + tolerance:
        return 0 if start <= line <= end else min(abs(line - start), abs(line - end))
    return None


def _augment_shortest_path(graph: list[list[dict[str, Any]]], source: int, sink: int) -> bool:
    node_count = len(graph)
    infinity = 10**30
    distance = [infinity] * node_count
    previous: list[tuple[int, int] | None] = [None] * node_count
    distance[source] = 0
    for _ in range(node_count - 1):
        changed = False
        for node, edges in enumerate(graph):
            if distance[node] == infinity:
                continue
            for edge_index, edge in enumerate(edges):
                if edge["capacity"] <= 0:
                    continue
                target = edge["to"]
                candidate = distance[node] + edge["cost"]
                predecessor = (node, edge_index)
                if candidate < distance[target] or (
                    candidate == distance[target] and (previous[target] is None or predecessor < previous[target])
                ):
                    distance[target] = candidate
                    previous[target] = predecessor
                    changed = True
        if not changed:
            break
    if previous[sink] is None:
        return False
    node = sink
    while node != source:
        prior_node, edge_index = previous[node]  # type: ignore[misc]
        edge = graph[prior_node][edge_index]
        edge["capacity"] -= 1
        graph[node][edge["rev"]]["capacity"] += 1
        node = prior_node
    return True


def build_blind_packet(
    cases: list[dict[str, Any]], source_samples: list[dict[str, Any]], selection: dict[str, Any]
) -> dict[str, Any]:
    """Build the reviewer-visible packet from a separate administrative selection."""

    by_id = {case["case_id"]: case for case in cases}
    samples_by_id = {sample["source_sample_id"]: sample for sample in source_samples}
    packet_items = []
    for member in sorted(selection["members"], key=lambda item: item["review_item_id"]):
        if member["member_kind"] == "case":
            case = by_id.get(member["case_id"])
            if case is None:
                raise BenchmarkInputError(f"Reviewer selection references unknown case: {member['case_id']}")
            source = case
        else:
            sample = samples_by_id.get(member["source_sample_id"])
            if sample is None:
                raise BenchmarkInputError(
                    f"Reviewer selection references unknown source sample: {member['source_sample_id']}"
                )
            source = sample
        packet_items.append(
            {
                "review_item_id": member["review_item_id"],
                "repository_id": source["repository_id"],
                "commit": source["commit"],
                "file": normalize_path(source["file"]),
                "source_region": source["source_region"],
                "security_claim": source["security_claim"],
                "threat_model_assumptions": source["threat_model_assumptions"],
                "blind_decision": None,
                "blind_rationale": "",
            }
        )
    return {
        "schema_version": "1.0",
        "blind": True,
        "item_count": len(packet_items),
        "items": packet_items,
    }


def select_external_review_cases(
    cases: list[dict[str, Any]],
    mandatory_by_reason: dict[str, list[str]],
    zero_finding_samples: list[dict[str, Any]],
    seed: str,
) -> dict[str, Any]:
    """Apply the protocol's deduplicated mandatory and random reviewer sampling rule."""

    known_ids = {case["case_id"] for case in cases}
    mandatory = {case_id for ids in mandatory_by_reason.values() for case_id in ids}
    unknown = sorted(mandatory - known_ids)
    if unknown:
        raise BenchmarkInputError(f"Mandatory reviewer selection references unknown cases: {', '.join(unknown)}")
    remaining = [case for case in cases if case["case_id"] not in mandatory]
    if len(cases) < 30:
        random_ids = sorted(case["case_id"] for case in remaining)
    else:
        target = min(len(remaining), 75, max(30, math.ceil(len(remaining) * 0.25)))
        by_stratum: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for case in remaining:
            stratum = "|".join(
                [
                    case["rule_family"],
                    case["framework"],
                    case["repository_id"],
                    case["detection_status"],
                    case["case_kind"],
                ]
            )
            by_stratum[stratum].append(case)
        for stratum, items in by_stratum.items():
            items.sort(key=lambda item: (canonical_sha256([seed, stratum, item["case_id"]]), item["case_id"]))
        random_ids = []
        strata = sorted(by_stratum)
        while len(random_ids) < target:
            progressed = False
            for stratum in strata:
                if by_stratum[stratum] and len(random_ids) < target:
                    random_ids.append(by_stratum[stratum].pop(0)["case_id"])
                    progressed = True
            if not progressed:
                break
    reasons: dict[str, set[str]] = defaultdict(set)
    for reason, ids in mandatory_by_reason.items():
        for case_id in ids:
            reasons[case_id].add(reason)
    for case_id in random_ids:
        reasons[case_id].add("seeded-random")
    members = [
        {
            "review_item_id": f"review-case-{case_id}",
            "member_kind": "case",
            "case_id": case_id,
            "source_sample_id": None,
            "repository_id": next(case["repository_id"] for case in cases if case["case_id"] == case_id),
            "selection_reasons": sorted(case_reasons),
        }
        for case_id, case_reasons in sorted(reasons.items())
    ]
    for sample in sorted(zero_finding_samples, key=lambda item: item["source_sample_id"]):
        members.append(
            {
                "review_item_id": f"review-source-{sample['source_sample_id']}",
                "member_kind": "zero-finding-source",
                "case_id": None,
                "source_sample_id": sample["source_sample_id"],
                "repository_id": sample["repository_id"],
                "selection_reasons": ["zero-finding-repository-source-sample"],
            }
        )
    return {
        "schema_version": "1.0",
        "selection_state": "draft",
        "seed": seed,
        "algorithm": "mandatory-set-plus-sha256-stratified-random-v1",
        "eligible_case_count": len(cases),
        "mandatory_unique_case_count": len(mandatory),
        "random_case_count": len(random_ids),
        "zero_finding_repository_count": len({item["repository_id"] for item in zero_finding_samples}),
        "members": members,
    }


def calculate_pilot_metrics(
    repositories: list[dict[str, Any]],
    scanner_findings: list[dict[str, Any]],
    adjudications: list[dict[str, Any]],
    claim_mappings: list[dict[str, Any]],
    baseline_matches: dict[str, list[str]],
) -> dict[str, Any]:
    """Calculate only protocol-approved pilot outcomes, never recall or F1."""

    decision_ids = [item["finding_id"] for item in adjudications]
    if len(decision_ids) != len(set(decision_ids)):
        raise BenchmarkInputError("Duplicate adjudication finding identity")
    decisions = {item["finding_id"]: item["outcome"] for item in adjudications}
    validated = [finding for finding in scanner_findings if decisions.get(finding["finding_id"]) == "TP"]
    false_positives = [finding for finding in scanner_findings if decisions.get(finding["finding_id"]) == "FP"]
    decided = len(validated) + len(false_positives)

    mappings_by_class: dict[str, dict[str, Any]] = {}
    duplicates: set[str] = set()
    for mapping in claim_mappings:
        claim_class = mapping["claim_class"]
        if claim_class in mappings_by_class:
            duplicates.add(claim_class)
        mappings_by_class[claim_class] = mapping
    if duplicates:
        raise BenchmarkInputError(f"Duplicate claim mappings: {sorted(duplicates)}")

    eligible: list[dict[str, Any]] = []
    unique_scope: list[dict[str, Any]] = []
    unsupported: list[dict[str, Any]] = []
    unresolved: list[dict[str, Any]] = []
    for finding in validated:
        selected_mapping = mappings_by_class.get(finding["claim_class"])
        if selected_mapping is None or selected_mapping["comparison_status"] == "pending":
            unresolved.append(finding)
            continue
        baseline_rules = selected_mapping["bandit_rule_ids"] + selected_mapping["semgrep_rule_ids"]
        if selected_mapping["comparison_status"] == "comparison-eligible":
            if not baseline_rules:
                raise BenchmarkInputError(
                    f"Comparison-eligible claim {finding['claim_class']} has no applicable baseline rule"
                )
            eligible.append(finding)
        elif selected_mapping["comparison_status"] == "unique-scope":
            if baseline_rules:
                raise BenchmarkInputError(f"Unique-scope claim {finding['claim_class']} has baseline rules")
            unique_scope.append(finding)
        elif selected_mapping["comparison_status"] == "unsupported":
            unsupported.append(finding)
    incremental = [finding for finding in eligible if not baseline_matches.get(finding["finding_id"], [])]

    successful = [repository for repository in repositories if _repository_analyzable(repository)]
    scoped_lines = sum(repository["scoped_python_lines"] for repository in repositories)
    outcome_counts: dict[str, int] = defaultdict(int)
    for item in adjudications:
        outcome_counts[item["outcome"]] += 1
    return {
        "schema_version": "1.0",
        "precision": {
            "tp": len(validated),
            "fp": len(false_positives),
            "value": _ratio(len(validated), decided),
        },
        "repository_analyzability": {
            "successful": len(successful),
            "included": len(repositories),
            "value": _ratio(len(successful), len(repositories)),
        },
        "comparison_eligible_incremental_signal": {
            "count": len(incremental),
            "denominator": len(eligible),
            "proportion": _ratio(len(incremental), len(eligible)),
        },
        "unique_scope_validated_signal": {"count": len(unique_scope)},
        "mapping_outcomes": {
            "unsupported_count": len(unsupported),
            "unsupported_finding_ids": sorted(item["finding_id"] for item in unsupported),
            "unresolved_count": len(unresolved),
            "unresolved_finding_ids": sorted(item["finding_id"] for item in unresolved),
        },
        "review_burden": {
            "false_positives": len(false_positives),
            "per_repository": _ratio(len(false_positives), len(repositories)),
            "per_scoped_thousand_python_lines": _ratio(len(false_positives) * 1000, scoped_lines),
        },
        "outcome_counts": dict(sorted(outcome_counts.items())),
        "outcomes_not_reported": ["recall", "f1"],
    }


def _repository_analyzable(repository: dict[str, Any]) -> bool:
    files = repository["files"]
    return (
        bool(files)
        and repository.get("unhandled_error") is None
        and all(
            item.get("source_status", "ready") == "ready"
            and item["scanner_status"] in {"result", "supported-no-finding"}
            for item in files
        )
    )


def _ratio(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 6) if denominator else None


def initialize_quarantine(path: Path) -> None:
    """Create an untracked local raw-output directory with restrictive permissions."""

    path.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path, 0o700)
    except OSError as error:
        raise BenchmarkInputError(f"Could not restrict quarantine permissions: {error}") from error


def recall_subset_size(primary_corpus_size: int) -> int:
    if primary_corpus_size < 1:
        raise BenchmarkInputError("Primary corpus size must be positive")
    return max(5, math.ceil(primary_corpus_size * 0.2))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate_parser = subparsers.add_parser("validate", help="Validate a public study artifact")
    validate_parser.add_argument("artifact_type")
    validate_parser.add_argument("path", type=Path)

    select_parser = subparsers.add_parser("select", help="Select from an approved frozen candidate register")
    select_parser.add_argument("register", type=Path)
    select_parser.add_argument("--count", type=int, default=3)
    select_parser.add_argument("--seed", required=True)
    select_parser.add_argument("--output", type=Path, required=True)

    quarantine_parser = subparsers.add_parser("init-quarantine", help="Create a restricted raw-output directory")
    quarantine_parser.add_argument("path", type=Path, default=Path("benchmark/field_validation/quarantine"), nargs="?")

    hash_parser = subparsers.add_parser("hash-files", help="Hash an explicit scoped Python file list")
    hash_parser.add_argument("root", type=Path)
    hash_parser.add_argument("--repository-id", required=True)
    hash_parser.add_argument("--commit", required=True)
    hash_parser.add_argument("--paths", type=Path, required=True, help="JSON array of repository-relative paths")
    hash_parser.add_argument("--output", type=Path, required=True)

    args = parser.parse_args(argv)
    try:
        if args.command == "validate":
            validate_artifact(args.path, args.artifact_type)
            print(f"Validated {args.artifact_type}: {args.path}")
        elif args.command == "select":
            register = validate_artifact(args.register, "candidate-register")
            write_json(args.output, deterministic_select(register, args.count, args.seed))
            print(f"Selection written to {args.output}")
        elif args.command == "init-quarantine":
            initialize_quarantine(args.path)
            print(f"Restricted quarantine ready at {args.path}")
        elif args.command == "hash-files":
            paths_value = json.loads(args.paths.read_text(encoding="utf-8"))
            if not isinstance(paths_value, list) or not all(isinstance(item, str) for item in paths_value):
                raise BenchmarkInputError("Scoped paths document must be a JSON array of strings")
            inventory = build_file_inventory(args.root, args.repository_id, args.commit, paths_value)
            write_json(args.output, inventory)
            print(f"Scoped inventory written to {args.output}")
    except (BenchmarkInputError, OSError, UnicodeError, json.JSONDecodeError, KeyError) as error:
        parser.exit(2, f"pilot infrastructure error: {error}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
