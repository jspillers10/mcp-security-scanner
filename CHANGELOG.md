# Changelog

All notable changes are recorded here. This project follows the structure of
Keep a Changelog, but does not claim semantic-versioning stability during the research
preview.

## Unreleased

### Added

- SARIF 2.1.0 output with deterministic rule metadata and source locations.
- Output-file support for machine-readable CLI formats.
- GitHub Actions checks for tests, coverage, linting, formatting, typing, security, and packaging.
- Project-specific security and contribution policies.
- SQL-injection rule MCP008 and same-file one-hop helper analysis.
- A pinned, hash-verified, non-executing DVMCP benchmark with schema-validated ground truth.
- Deterministic one-to-one matching, per-rule metrics, Wilson intervals, raw evidence, and regression baselines.
- Project-owned false-positive and declared false-negative-boundary fixtures.

### Changed

- Packaging metadata and optional dependency groups are now defined in `pyproject.toml`.
- Invalid scan paths and unreadable or invalid Python inputs now return exit code 2.
- Benchmark claims now distinguish reproducible measurements, historical observations, and excluded scope.

## 0.1.0

- Initial research-preview scanner with static MCP rules, description heuristics,
  readiness checks, live enumeration, and config-level tool-name collision checks.
