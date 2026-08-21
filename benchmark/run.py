"""Run a pinned, non-executing benchmark and write reproducible evidence."""

from __future__ import annotations

import argparse
import json
import os
import platform
import subprocess  # nosec B404
import sys
import time
from datetime import datetime, timezone
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any

from mcp_scanner import __version__ as scanner_version
from mcp_scanner.analyzer import scan_file
from mcp_scanner.readiness import scan_file as scan_readiness

from .matching import attribute_safe_cases, match_findings
from .metrics import summarize
from .retrieve import file_sha256, retrieve_corpus, tree_sha256, verify_corpus
from .validation import (
    BenchmarkInputError,
    load_json,
    select_corpus,
    validate_semantics,
    validate_with_schema,
)

# Git metadata is queried with an argument list, shell disabled, and an explicit timeout.
SECURITY_GROUPS = {"code_vulnerability", "description_vulnerability"}


def _git(project_root: Path, args: list[str]) -> tuple[int, str]:
    try:
        # The executable and metadata subcommands are fixed by this harness.
        completed = subprocess.run(  # nosec B603 B607
            ["git", "-C", str(project_root), *args],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return (1, "")
    return (completed.returncode, completed.stdout.strip())


def scanner_identity(project_root: Path) -> dict[str, Any]:
    return_code, commit = _git(project_root, ["rev-parse", "HEAD"])
    status_code, status = _git(project_root, ["status", "--porcelain", "--untracked-files=all"])
    source_files = sorted((project_root / "src/mcp_scanner").glob("*.py"))
    hashes = [{"path": path.relative_to(project_root).as_posix(), "sha256": file_sha256(path)} for path in source_files]
    return {
        "package_version": scanner_version,
        "git_commit": commit if return_code == 0 else None,
        "git_dirty": bool(status) if status_code == 0 else None,
        "source_tree_sha256": tree_sha256(hashes),
        "source_files": hashes,
    }


def benchmark_identity(
    project_root: Path, manifest_path: Path, truth_path: Path, truth: dict[str, Any]
) -> dict[str, Any]:
    benchmark_root = project_root / "benchmark"
    harness_files = sorted(benchmark_root.glob("*.py")) + sorted((benchmark_root / "schemas").glob("*.json"))
    hashes = [
        {"path": path.relative_to(project_root).as_posix(), "sha256": file_sha256(path)} for path in harness_files
    ]
    return {
        "methodology_version": truth["methodology_version"],
        "manifest_sha256": file_sha256(manifest_path),
        "ground_truth_sha256": file_sha256(truth_path),
        "harness_tree_sha256": tree_sha256(hashes),
        "harness_files": hashes,
    }


def _relative_finding_path(corpus_root: Path, scanned_path: Path, finding_file: str | None) -> str:
    effective = Path(finding_file).resolve() if finding_file else scanned_path.resolve()
    try:
        return effective.relative_to(corpus_root.resolve()).as_posix()
    except ValueError as error:
        raise BenchmarkInputError(f"Scanner reported a finding outside the corpus root: {effective}") from error


def scan_corpus(corpus: dict[str, Any], corpus_root: Path) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    readiness: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    finding_counter = 0
    readiness_counter = 0

    for file_spec in sorted(corpus["files"], key=lambda item: item["path"]):
        relative_path = file_spec["path"]
        path = corpus_root / relative_path
        try:
            file_findings, file_errors = scan_file(str(path))
            file_readiness, readiness_errors = scan_readiness(str(path))
        except (OSError, UnicodeError) as error:
            file_findings, file_readiness = [], []
            file_errors, readiness_errors = [f"Could not read {path}: {error}"], []

        for message in sorted(set(file_errors + readiness_errors)):
            errors.append({"path": relative_path, "message": message})
        for finding in file_findings:
            finding_counter += 1
            findings.append(
                {
                    "id": f"security-{finding_counter:04d}",
                    "rule_id": finding.rule_id,
                    "path": _relative_finding_path(corpus_root, path, finding.file),
                    "line": finding.line,
                    "function": finding.function_name,
                    "severity": finding.severity,
                    "title": finding.title,
                    "detail": finding.detail,
                }
            )
        for item in file_readiness:
            readiness_counter += 1
            readiness.append(
                {
                    "id": f"readiness-{readiness_counter:04d}",
                    "rule_id": item.check_id,
                    "path": relative_path,
                    "line": item.line,
                    "function": None,
                    "severity": item.severity,
                    "title": item.title,
                    "detail": item.detail,
                }
            )

    def finding_key(item: dict[str, Any]) -> tuple[str, str, int, str, str]:
        return (item["path"], item["rule_id"], item["line"], item.get("function") or "", item["detail"])

    findings.sort(key=finding_key)
    readiness.sort(key=finding_key)
    for index, item in enumerate(findings, start=1):
        item["id"] = f"security-{index:04d}"
    for index, item in enumerate(readiness, start=1):
        item["id"] = f"readiness-{index:04d}"
    return {"security_findings": findings, "readiness_findings": readiness, "scanner_errors": errors}


def _cases_for_group(cases: list[dict[str, Any]], groups: set[str]) -> list[dict[str, Any]]:
    return [case for case in cases if case["metric_group"] in groups]


def classify(raw: dict[str, Any], truth: dict[str, Any]) -> dict[str, Any]:
    cases = truth["cases"]
    security_cases = _cases_for_group(cases, SECURITY_GROUPS)
    readiness_cases = _cases_for_group(cases, {"readiness"})
    security = match_findings(security_cases, raw["security_findings"])
    readiness = match_findings(readiness_cases, raw["readiness_findings"])
    security["false_positives"] = attribute_safe_cases(security["false_positives"], security_cases)
    readiness["false_positives"] = attribute_safe_cases(readiness["false_positives"], readiness_cases)
    excluded = [
        {
            "case_id": case["id"],
            "category": case["category"],
            "vulnerability_class": case["vulnerability_class"],
            "path": case["file"],
            "line": case["location"]["start_line"],
            "title": case["title"],
            "reason": case["rationale"],
        }
        for case in cases
        if case["metric_group"] == "excluded"
    ]
    return {"security": security, "readiness": readiness, "excluded_cases": excluded}


def calculate_metrics(raw: dict[str, Any], classifications: dict[str, Any], truth: dict[str, Any]) -> dict[str, Any]:
    by_group: dict[str, Any] = {}
    for group in sorted(SECURITY_GROUPS):
        group_cases = _cases_for_group(truth["cases"], {group})
        group_findings = [
            item
            for item in raw["security_findings"]
            if (item["rule_id"].startswith("MCP1")) == (group == "description_vulnerability")
        ]
        by_group[group] = summarize(match_findings(group_cases, group_findings))

    return {
        "schema_version": "1.0",
        "corpus_id": truth["corpus_id"],
        "security": summarize(classifications["security"]),
        "security_by_group": by_group,
        "readiness": summarize(classifications["readiness"]),
        "scanner_errors": len(raw["scanner_errors"]),
        "excluded_cases": len(classifications["excluded_cases"]),
        "accuracy": None,
        "accuracy_note": "Not calculated because the benchmark does not define an exhaustive true-negative universe.",
    }


def _metric(value: float | None) -> str:
    return "N/A" if value is None else f"{value:.3f}"


def markdown_report(
    corpus: dict[str, Any], raw: dict[str, Any], classifications: dict[str, Any], metrics: dict[str, Any]
) -> str:
    security = metrics["security"]["overall"]
    readiness = metrics["readiness"]["overall"]
    lines = [
        f"# Benchmark report: {corpus['name']}",
        "",
        f"- Corpus ID: `{corpus['id']}`",
        f"- Corpus commit: `{raw['corpus']['commit']}`",
        f"- Corpus tree SHA-256: `{raw['corpus']['tree_sha256']}`",
        f"- Scanner version: `{raw['scanner']['package_version']}`",
        f"- Scanner commit: `{raw['scanner']['git_commit']}`",
        f"- Scanner source SHA-256: `{raw['scanner']['source_tree_sha256']}`",
        f"- Scanner worktree dirty: `{str(raw['scanner']['git_dirty']).lower()}`",
        f"- Benchmark harness SHA-256: `{raw['benchmark']['harness_tree_sha256']}`",
        f"- Ground-truth SHA-256: `{raw['benchmark']['ground_truth_sha256']}`",
        f"- Scanner errors: `{metrics['scanner_errors']}`",
        "",
        "## Security findings",
        "",
        "| TP | FP | FN | Precision | Recall | F1 |",
        "|---:|---:|---:|---:|---:|---:|",
        f"| {security['tp']} | {security['fp']} | {security['fn']} | {_metric(security['precision'])} | {_metric(security['recall'])} | {_metric(security['f1'])} |",
        "",
        "| Rule | TP | FP | FN | Precision | Recall | F1 |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for rule_id, values in metrics["security"]["by_rule"].items():
        lines.append(
            f"| {rule_id} | {values['tp']} | {values['fp']} | {values['fn']} | "
            f"{_metric(values['precision'])} | {_metric(values['recall'])} | {_metric(values['f1'])} |"
        )
    lines.extend(
        [
            "",
            "## Infrastructure readiness",
            "",
            "Readiness findings are risky deployment defaults, not confirmed vulnerabilities.",
            "",
            "| TP | FP | FN | Precision | Recall | F1 |",
            "|---:|---:|---:|---:|---:|---:|",
            f"| {readiness['tp']} | {readiness['fp']} | {readiness['fn']} | {_metric(readiness['precision'])} | {_metric(readiness['recall'])} | {_metric(readiness['f1'])} |",
            "",
            "## False positives",
            "",
        ]
    )
    if classifications["security"]["false_positives"]:
        for item in classifications["security"]["false_positives"]:
            safe = f"; safe case `{item['safe_case_id']}`" if item.get("safe_case_id") else ""
            lines.append(f"- `{item['rule_id']}` at `{item['path']}:{item['line']}`{safe}: {item['detail']}")
    else:
        lines.append("- None.")
    lines.extend(["", "## False negatives", ""])
    if classifications["security"]["false_negatives"]:
        for item in classifications["security"]["false_negatives"]:
            lines.append(
                f"- `{item['rule_id']}` case `{item['case_id']}` at `{item['path']}:{item['line']}`: {item['title']}"
            )
    else:
        lines.append("- None.")
    lines.extend(
        [
            "",
            "## Interpretation limits",
            "",
            f"- {len(classifications['excluded_cases'])} declared cases are outside the scored static-analysis scope.",
            "- Wilson 95% intervals are included in metrics.json; this curated corpus is not a random sample, so the intervals describe denominator uncertainty only and do not establish population validity.",
            "- Accuracy is intentionally not reported because true negatives are not exhaustively enumerable.",
            "- Corpus source files were read and parsed as text. They were never imported, launched, installed, or connected to an external service.",
            "",
        ]
    )
    return "\n".join(lines)


def _write_json(path: Path, value: dict[str, Any]) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def _dependency_versions() -> dict[str, str | None]:
    result: dict[str, str | None] = {}
    for package in ("jsonschema", "mcp-security-scanner"):
        try:
            result[package] = version(package)
        except PackageNotFoundError:
            result[package] = None
    return result


def _regressions(current: dict[str, Any], baseline: dict[str, Any]) -> list[str]:
    messages: list[str] = []
    for section in ("security", "readiness"):
        now = current[section]["overall"]
        before = baseline[section]["overall"]
        for count, direction in (("tp", "lower"), ("fp", "higher"), ("fn", "higher")):
            changed = now[count] < before[count] if direction == "lower" else now[count] > before[count]
            if changed:
                messages.append(f"{section}.{count} is {now[count]} versus baseline {before[count]}")
        for metric in ("precision", "recall", "f1"):
            if now[metric] is not None and before[metric] is not None and now[metric] < before[metric]:
                messages.append(f"{section}.{metric} is {now[metric]} versus baseline {before[metric]}")
    if current["scanner_errors"] > baseline.get("scanner_errors", 0):
        messages.append("scanner error count increased")
    return messages


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", default="dvmcp-79734c19", help="Corpus ID from the manifest")
    parser.add_argument("--manifest", type=Path, default=Path("benchmark/manifest.json"))
    parser.add_argument("--corpus-path", type=Path, help="Existing corpus checkout or local fixture root")
    parser.add_argument("--retrieve", action="store_true", help="Retrieve the pinned corpus when absent")
    parser.add_argument("--output-dir", type=Path, help="Output directory (default: benchmark/results/CORPUS)")
    parser.add_argument("--baseline", type=Path, help="Prior metrics.json used for regression comparison")
    args = parser.parse_args(argv)
    if args.retrieve and args.corpus_path:
        parser.error("--retrieve and --corpus-path are mutually exclusive")

    started_at = datetime.now(timezone.utc)
    started = time.perf_counter()
    try:
        manifest_path = args.manifest.resolve()
        project_root = manifest_path.parent.parent
        manifest = load_json(manifest_path)
        validate_with_schema(manifest, manifest_path.parent / "schemas/manifest.schema.json", manifest_path)
        corpus = select_corpus(manifest, args.corpus)
        truth_path = project_root / corpus["ground_truth"]
        truth = load_json(truth_path)
        validate_with_schema(truth, manifest_path.parent / "schemas/ground-truth.schema.json", truth_path)
        validate_semantics(corpus, truth)

        corpus_root = (args.corpus_path or project_root / corpus["default_path"]).resolve()
        if args.retrieve:
            verification = retrieve_corpus(corpus, corpus_root)
        else:
            verification = verify_corpus(corpus, corpus_root)

        scan_result = scan_corpus(corpus, corpus_root)
        raw_corpus = {key: value for key, value in verification.items() if key != "root"}
        raw = {
            "schema_version": "1.0",
            "corpus": raw_corpus,
            "scanner": scanner_identity(project_root),
            "benchmark": benchmark_identity(project_root, manifest_path, truth_path, truth),
            **scan_result,
        }
        classifications = classify(raw, truth)
        metrics = calculate_metrics(raw, classifications, truth)
        results = {
            "schema_version": "1.0",
            "corpus_id": corpus["id"],
            **classifications,
        }
        regressions: list[str] = []
        if args.baseline:
            regressions = _regressions(metrics, load_json(args.baseline))

        output_dir = (args.output_dir or project_root / "benchmark/results" / corpus["id"]).resolve()
        output_dir.mkdir(parents=True, exist_ok=True)
        _write_json(output_dir / "raw-results.json", raw)
        _write_json(output_dir / "classifications.json", results)
        _write_json(output_dir / "metrics.json", metrics)
        (output_dir / "report.md").write_text(
            markdown_report(corpus, raw, classifications, metrics), encoding="utf-8", newline="\n"
        )
        metadata = {
            "schema_version": "1.0",
            "started_at_utc": started_at.isoformat(),
            "elapsed_seconds": round(time.perf_counter() - started, 6),
            "command": [sys.executable, "-m", "benchmark.run", *(argv if argv is not None else sys.argv[1:])],
            "working_directory": os.getcwd(),
            "corpus_directory": str(corpus_root),
            "platform": platform.platform(),
            "python_version": platform.python_version(),
            "python_implementation": platform.python_implementation(),
            "dependencies": _dependency_versions(),
            "output_directory": str(output_dir),
            "regressions": regressions,
        }
        _write_json(output_dir / "run-metadata.json", metadata)
    except BenchmarkInputError as error:
        parser.exit(2, f"benchmark input error: {error}\n")

    overall = metrics["security"]["overall"]
    print(
        f"{corpus['id']}: TP={overall['tp']} FP={overall['fp']} FN={overall['fn']} "
        f"precision={_metric(overall['precision'])} recall={_metric(overall['recall'])} "
        f"F1={_metric(overall['f1'])}"
    )
    print(f"Evidence written to {output_dir}")
    if raw["scanner_errors"]:
        return 2
    if regressions:
        for message in regressions:
            print(f"regression: {message}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
