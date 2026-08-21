"""Schema and semantic validation for benchmark inputs."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator


class BenchmarkInputError(ValueError):
    """Raised when a benchmark input is invalid or inconsistent."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise BenchmarkInputError(f"Could not load JSON from {path}: {error}") from error
    if not isinstance(value, dict):
        raise BenchmarkInputError(f"Expected a JSON object in {path}")
    return value


def validate_with_schema(document: dict[str, Any], schema_path: Path, document_path: Path) -> None:
    schema = load_json(schema_path)
    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(document), key=lambda error: list(error.absolute_path))
    if errors:
        first = errors[0]
        location = "/".join(str(part) for part in first.absolute_path) or "<root>"
        raise BenchmarkInputError(f"Schema validation failed for {document_path} at {location}: {first.message}")


def select_corpus(manifest: dict[str, Any], corpus_id: str) -> dict[str, Any]:
    for corpus in manifest["corpora"]:
        if corpus["id"] == corpus_id:
            return corpus
    available = ", ".join(corpus["id"] for corpus in manifest["corpora"])
    raise BenchmarkInputError(f"Unknown corpus {corpus_id!r}; available corpora: {available}")


def validate_semantics(corpus: dict[str, Any], truth: dict[str, Any]) -> None:
    if truth["corpus_id"] != corpus["id"]:
        raise BenchmarkInputError(
            f"Ground-truth corpus_id {truth['corpus_id']!r} does not match manifest corpus {corpus['id']!r}"
        )
    scoped_files = {item["path"] for item in corpus["files"]}
    ids: set[str] = set()
    for case in truth["cases"]:
        if case["id"] in ids:
            raise BenchmarkInputError(f"Duplicate ground-truth case ID: {case['id']}")
        ids.add(case["id"])
        if case["corpus"] != corpus["id"]:
            raise BenchmarkInputError(f"Ground-truth case {case['id']} has the wrong corpus: {case['corpus']}")
        if case["file"] not in scoped_files:
            raise BenchmarkInputError(f"Ground-truth case {case['id']} names an unscoped file: {case['file']}")
        classification = case["expected_result"]["classification"]
        metric_group = case["metric_group"]
        if classification == "finding" and metric_group == "excluded":
            raise BenchmarkInputError(f"Included finding case {case['id']} cannot use metric_group=excluded")
        if classification == "excluded" and metric_group != "excluded":
            raise BenchmarkInputError(f"Excluded case {case['id']} must use metric_group=excluded")
        if case["in_scope"] != (metric_group != "excluded"):
            raise BenchmarkInputError(f"Ground-truth case {case['id']} has inconsistent in_scope metadata")
        if classification == "finding" and case["review_status"]["state"] == "pending":
            raise BenchmarkInputError(f"Pending case {case['id']} cannot enter the metric denominator")
