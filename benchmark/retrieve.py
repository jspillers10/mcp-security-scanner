"""Retrieve and verify a pinned corpus without executing corpus code."""

from __future__ import annotations

import argparse
import hashlib
import subprocess  # nosec B404
from pathlib import Path
from typing import Any

from .validation import BenchmarkInputError, load_json, select_corpus, validate_with_schema

# Git is invoked with an argument list, shell disabled, and an explicit timeout.


def _git(args: list[str], timeout: int) -> str:
    try:
        # The executable and subcommands are fixed or drawn from the validated manifest.
        completed = subprocess.run(  # nosec B603 B607
            ["git", *args],
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise BenchmarkInputError(f"Git command failed safely: {error}") from error
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or f"exit {completed.returncode}"
        raise BenchmarkInputError(f"Git command failed: {detail}")
    return completed.stdout.strip()


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def tree_sha256(file_hashes: list[dict[str, str]]) -> str:
    digest = hashlib.sha256()
    for item in sorted(file_hashes, key=lambda value: value["path"]):
        digest.update(item["path"].encode("utf-8"))
        digest.update(b"\0")
        digest.update(item["sha256"].encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest()


def verify_corpus(corpus: dict[str, Any], root: Path) -> dict[str, Any]:
    root = root.resolve()
    if not root.is_dir():
        raise BenchmarkInputError(f"Corpus directory does not exist: {root}")

    actual_files: list[dict[str, str]] = []
    for expected in corpus["files"]:
        target = (root / expected["path"]).resolve()
        try:
            target.relative_to(root)
        except ValueError as error:
            raise BenchmarkInputError(f"Corpus path escapes root: {expected['path']}") from error
        if not target.is_file():
            raise BenchmarkInputError(f"Required corpus file is missing: {expected['path']}")
        actual_hash = file_sha256(target)
        if actual_hash != expected["sha256"]:
            raise BenchmarkInputError(
                f"Hash mismatch for {expected['path']}: expected {expected['sha256']}, got {actual_hash}"
            )
        actual_files.append({"path": expected["path"], "sha256": actual_hash})

    actual_tree = tree_sha256(actual_files)
    if actual_tree != corpus["tree_sha256"]:
        raise BenchmarkInputError(f"Corpus tree hash mismatch: expected {corpus['tree_sha256']}, got {actual_tree}")

    git_commit = None
    git_dir = root / ".git"
    if git_dir.exists():
        git_commit = _git(["-C", str(root), "rev-parse", "HEAD"], timeout=10)
        expected_commit = corpus.get("commit")
        if expected_commit and git_commit != expected_commit:
            raise BenchmarkInputError(f"Corpus commit mismatch: expected {expected_commit}, got {git_commit}")
    elif corpus.get("require_git_commit"):
        raise BenchmarkInputError(f"Corpus {corpus['id']} must be a Git checkout so its commit can be verified")

    return {
        "corpus_id": corpus["id"],
        "root": str(root),
        "commit": git_commit or corpus.get("commit"),
        "tree_sha256": actual_tree,
        "files": actual_files,
    }


def retrieve_corpus(corpus: dict[str, Any], destination: Path, timeout: int = 180) -> dict[str, Any]:
    repository = corpus.get("repository")
    commit = corpus.get("commit")
    if not repository or not commit:
        raise BenchmarkInputError(f"Corpus {corpus['id']} is local and cannot be retrieved")
    if destination.exists():
        return verify_corpus(corpus, destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    _git(["clone", "--no-checkout", repository, str(destination)], timeout=timeout)
    _git(["-C", str(destination), "checkout", "--detach", commit], timeout=timeout)
    return verify_corpus(corpus, destination)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpus", help="Corpus ID from benchmark/manifest.json")
    parser.add_argument("--manifest", type=Path, default=Path("benchmark/manifest.json"))
    parser.add_argument("--destination", type=Path)
    args = parser.parse_args(argv)

    try:
        manifest = load_json(args.manifest)
        validate_with_schema(manifest, args.manifest.parent / "schemas/manifest.schema.json", args.manifest)
        corpus = select_corpus(manifest, args.corpus)
        destination = args.destination or Path(corpus["default_path"])
        verification = retrieve_corpus(corpus, destination)
    except BenchmarkInputError as error:
        parser.exit(2, f"benchmark retrieval error: {error}\n")
    print(f"Verified {verification['corpus_id']} at {verification['commit']} ({verification['tree_sha256']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
