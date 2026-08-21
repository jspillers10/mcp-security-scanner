import copy
import json
import subprocess
from pathlib import Path

import pytest

from benchmark.matching import attribute_safe_cases, match_findings, normalize_path
from benchmark.metrics import score, summarize
from benchmark.retrieve import _git, verify_corpus
from benchmark.run import _regressions, classify, main, scan_corpus
from benchmark.validation import (
    BenchmarkInputError,
    load_json,
    select_corpus,
    validate_semantics,
    validate_with_schema,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = PROJECT_ROOT / "benchmark/manifest.json"
SCHEMA_ROOT = PROJECT_ROOT / "benchmark/schemas"


def _manifest():
    return load_json(MANIFEST_PATH)


def _case(case_id="case-1", rule_id="MCP001", mode="exact", tolerance=0, metric_group="code_vulnerability"):
    return {
        "id": case_id,
        "corpus": "sample",
        "title": "expected case",
        "file": "server.py",
        "location": {"start_line": 10, "end_line": 10, "function": "tool"},
        "vulnerability_class": "command-injection",
        "category": "in_scope_vulnerability",
        "metric_group": metric_group,
        "in_scope": True,
        "expected_result": {
            "classification": "finding",
            "rule_id": rule_id,
            "severity": "critical",
            "unexpected_rules": [],
        },
        "rationale": "test rationale",
        "review_status": {"state": "single-reviewed"},
        "matching": {"mode": mode, "line_tolerance": tolerance},
    }


def _finding(finding_id="finding-1", rule_id="MCP001", line=10, path="server.py", function="tool"):
    return {
        "id": finding_id,
        "rule_id": rule_id,
        "path": path,
        "line": line,
        "function": function,
        "severity": "critical",
        "detail": "detail",
    }


def test_manifest_and_ground_truth_documents_validate():
    manifest = _manifest()
    validate_with_schema(manifest, SCHEMA_ROOT / "manifest.schema.json", MANIFEST_PATH)
    for corpus in manifest["corpora"]:
        truth_path = PROJECT_ROOT / corpus["ground_truth"]
        truth = load_json(truth_path)
        validate_with_schema(truth, SCHEMA_ROOT / "ground-truth.schema.json", truth_path)
        validate_semantics(corpus, truth)


def test_malformed_manifest_metadata_is_rejected(tmp_path):
    malformed = copy.deepcopy(_manifest())
    malformed["corpora"][0]["execution_prohibited"] = "yes"
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(malformed), encoding="utf-8")
    with pytest.raises(BenchmarkInputError, match="Schema validation failed"):
        validate_with_schema(malformed, SCHEMA_ROOT / "manifest.schema.json", path)


def test_local_fixture_hashes_and_tree_hash_are_pinned():
    corpus = select_corpus(_manifest(), "local-boundaries-v1")
    verified = verify_corpus(corpus, PROJECT_ROOT / corpus["default_path"])
    assert verified["tree_sha256"] == corpus["tree_sha256"]
    assert len(verified["files"]) == len(corpus["files"])


def test_changed_fixture_hash_is_rejected(tmp_path):
    corpus = copy.deepcopy(select_corpus(_manifest(), "local-boundaries-v1"))
    first = corpus["files"][0]
    target = tmp_path / first["path"]
    target.parent.mkdir(parents=True)
    target.write_text("changed", encoding="utf-8")
    with pytest.raises(BenchmarkInputError, match="Hash mismatch"):
        verify_corpus({**corpus, "files": [first]}, tmp_path)


def test_duplicate_ground_truth_ids_are_rejected():
    corpus = {"id": "sample", "files": [{"path": "server.py"}]}
    case = _case()
    truth = {"corpus_id": "sample", "cases": [case, copy.deepcopy(case)]}
    with pytest.raises(BenchmarkInputError, match="Duplicate"):
        validate_semantics(corpus, truth)


def test_exact_matching_requires_rule_path_line_and_function():
    case = _case()
    assert len(match_findings([case], [_finding()])["matches"]) == 1
    assert len(match_findings([case], [_finding(rule_id="MCP002")])["false_negatives"]) == 1
    assert len(match_findings([case], [_finding(path="other.py")])["false_negatives"]) == 1
    assert len(match_findings([case], [_finding(line=11)])["false_negatives"]) == 1
    assert len(match_findings([case], [_finding(function="other")])["false_negatives"]) == 1


def test_windows_and_posix_relative_paths_normalize_for_matching():
    assert normalize_path(r"nested\server.py") == "nested/server.py"
    case = _case()
    case["file"] = "nested/server.py"
    assert len(match_findings([case], [_finding(path=r"nested\server.py")])["matches"]) == 1


def test_line_tolerant_matching_respects_tolerance():
    case = _case(mode="line_tolerant", tolerance=2)
    assert len(match_findings([case], [_finding(line=12)])["matches"]) == 1
    result = match_findings([case], [_finding(line=13)])
    assert len(result["false_negatives"]) == 1
    assert len(result["false_positives"]) == 1


def test_duplicate_findings_do_not_inflate_true_positives():
    result = match_findings([_case()], [_finding(), _finding(finding_id="finding-2")])
    assert len(result["matches"]) == 1
    assert len(result["false_positives"]) == 1


def test_safe_case_attribution_is_deterministic():
    safe = _case()
    safe["id"] = "safe-case"
    safe["expected_result"] = {
        "classification": "no_finding",
        "rule_id": None,
        "severity": None,
        "unexpected_rules": ["MCP001"],
    }
    attributed = attribute_safe_cases([_finding()], [safe])
    assert attributed[0]["safe_case_id"] == "safe-case"


def test_metrics_handle_known_and_empty_denominators():
    assert score(8, 2, 2)["precision"] == 0.8
    assert score(8, 2, 2)["recall"] == 0.8
    assert score(0, 0, 0)["precision"] is None
    assert score(0, 0, 0)["recall"] is None
    summary = summarize(
        {
            "matches": [{"rule_id": "MCP001"}],
            "false_positives": [{"rule_id": "MCP001"}],
            "false_negatives": [{"rule_id": "MCP002"}],
        }
    )
    assert summary["overall"]["tp"] == 1
    assert summary["by_rule"]["MCP002"]["recall"] == 0.0


def test_excluded_cases_do_not_become_false_negatives():
    included = _case()
    excluded = copy.deepcopy(included)
    excluded["id"] = "excluded-case"
    excluded["metric_group"] = "excluded"
    excluded["in_scope"] = False
    excluded["category"] = "runtime_only"
    excluded["expected_result"] = {
        "classification": "excluded",
        "rule_id": None,
        "severity": None,
        "unexpected_rules": [],
    }
    raw = {"security_findings": [], "readiness_findings": [], "scanner_errors": []}
    result = classify(raw, {"cases": [included, excluded]})
    assert [item["case_id"] for item in result["security"]["false_negatives"]] == ["case-1"]
    assert [item["case_id"] for item in result["excluded_cases"]] == ["excluded-case"]


def test_local_runner_outputs_are_deterministic(tmp_path):
    first = tmp_path / "first"
    second = tmp_path / "second"
    common = [
        "--corpus",
        "local-boundaries-v1",
        "--manifest",
        str(MANIFEST_PATH),
        "--corpus-path",
        str(PROJECT_ROOT / "benchmark/fixtures"),
    ]
    assert main([*common, "--output-dir", str(first)]) == 0
    assert main([*common, "--output-dir", str(second)]) == 0
    for name in ("raw-results.json", "classifications.json", "metrics.json", "report.md"):
        assert (first / name).read_bytes() == (second / name).read_bytes()
    first_metadata = json.loads((first / "run-metadata.json").read_text(encoding="utf-8"))
    second_metadata = json.loads((second / "run-metadata.json").read_text(encoding="utf-8"))
    assert first_metadata["elapsed_seconds"] >= 0
    assert second_metadata["elapsed_seconds"] >= 0

    metrics = json.loads((first / "metrics.json").read_text(encoding="utf-8"))
    classifications = json.loads((first / "classifications.json").read_text(encoding="utf-8"))
    assert metrics["security"]["overall"] == {
        "f1": None,
        "fn": 0,
        "fp": 3,
        "precision": 0.0,
        "precision_ci95_wilson": [0.0, 0.561497],
        "recall": None,
        "recall_ci95_wilson": None,
        "tp": 0,
    }
    assert {item["safe_case_id"] for item in classifications["security"]["false_positives"]} == {
        "local-safe-benign-imperative",
        "local-safe-legitimate-base64",
        "local-safe-registration-resemblance",
    }
    assert len(classifications["excluded_cases"]) == 7


def test_scanner_errors_are_recorded_once(monkeypatch, tmp_path):
    target = tmp_path / "server.py"
    target.write_text("pass\n", encoding="utf-8")

    monkeypatch.setattr("benchmark.run.scan_file", lambda path: ([], ["parse failure"]))
    monkeypatch.setattr("benchmark.run.scan_readiness", lambda path: ([], ["parse failure"]))
    result = scan_corpus({"files": [{"path": "server.py"}]}, tmp_path)

    assert result["security_findings"] == []
    assert result["readiness_findings"] == []
    assert result["scanner_errors"] == [{"path": "server.py", "message": "parse failure"}]


def test_runner_returns_nonzero_for_hash_mismatch(tmp_path):
    bad_root = tmp_path / "corpus"
    bad_root.mkdir()
    with pytest.raises(SystemExit) as raised:
        main(
            [
                "--corpus",
                "local-boundaries-v1",
                "--manifest",
                str(MANIFEST_PATH),
                "--corpus-path",
                str(bad_root),
                "--output-dir",
                str(tmp_path / "out"),
            ]
        )
    assert raised.value.code == 2


def test_git_timeout_is_wrapped_as_input_error(monkeypatch):
    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="git", timeout=1)

    monkeypatch.setattr(subprocess, "run", timeout)
    with pytest.raises(BenchmarkInputError, match="failed safely"):
        _git(["status"], timeout=1)


def test_regression_policy_flags_worse_counts_and_rates():
    baseline = {
        "security": {"overall": {"tp": 10, "fp": 1, "fn": 1, "precision": 0.9, "recall": 0.9, "f1": 0.9}},
        "readiness": {"overall": {"tp": 2, "fp": 0, "fn": 0, "precision": 1.0, "recall": 1.0, "f1": 1.0}},
        "scanner_errors": 0,
    }
    current = copy.deepcopy(baseline)
    current["security"]["overall"].update({"tp": 9, "fp": 2, "fn": 2, "precision": 0.8, "recall": 0.8, "f1": 0.8})
    assert _regressions(current, baseline)
    assert _regressions(baseline, baseline) == []
