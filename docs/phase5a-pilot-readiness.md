# Phase 5A field-validation pilot readiness

Phase 5A translates the approved
[field-validation protocol](field-validation-protocol.md) into local, non-retrieving pilot
infrastructure. It does not select a corpus or report a field measurement.

## Infrastructure boundary

The implementation provides:

- Empty candidate, manifest, case-inventory, findings, adjudication, review, tool-run,
  evidence, and metrics templates.
- JSON Schemas and semantic identity checks for public artifacts.
- Deterministic seeded, stratified selection with upstream-lineage deduplication.
- Explicit Python file inventories with per-file and canonical tree SHA-256 hashes.
- Redacted normalization for MCP Security Scanner, Bandit, and Semgrep findings.
- Semantic claim-class and physical-location matching without cross-tool severity equality.
- Maximum-cardinality one-to-one matching with deterministic priority costs.
- Administrative reviewer selection separated from the blind reviewer-visible packet.
- Zero-finding repository source samples represented as administrative source samples,
  not detected cases.
- Immutable individual blind and output-aware review history.
- Stable duplicate-finding occurrences preserved for review-burden measurement.
- Python source-encoding detection and explicit encoding-error status.
- Static-tool authorization recorded separately from permanent subject-code prohibitions.
- Stable tool-run evidence separated from volatile environment and timing metadata.
- Precision, analyzability, comparison-eligible incremental signal, unique-scope validated
  signal, and review-burden calculations.
- Ignored raw-output quarantine and subject-source workspace paths.

The operator workflow and Phase 5B authorization gate are documented in the
[field-validation artifact guide](../benchmark/field_validation/README.md).

## Frozen deterministic controls

The empty pilot manifest records:

- Selection seed: `phase5-pilot-selection-v1-20260823`
- Selection algorithm: `sha256-ranked-stratified-round-robin-v1`
- Manual checklist version: `phase5-pilot-checklist-v1`

These identifiers establish infrastructure defaults only. Phase 5B must freeze the actual
candidate register hash, selected candidate IDs, exact commits, source scope, file hashes,
tool versions, configurations, and claim mappings before tool output is revealed.

## Research limitations

- Phase 5A tests use project-owned synthetic records only.
- No conclusion about external repository analyzability or finding quality is available.
- A schema-valid artifact may still require human licensing, threat-model, and security
  review.
- Public credential screening is heuristic and requires human review before staging.
- Restrictive POSIX mode requests do not guarantee equivalent Windows access control.
- Static matching does not prove runtime exploitability.
- One external reviewer remains one external review, not independent consensus.
- License-based exclusions may alter corpus composition and prevent representativeness.

## Authorization required for Phase 5B

Separate approval is required before any candidate discovery, selection, repository
retrieval, external source inventory, tool execution, result handling, adjudication,
reviewer outreach, disclosure, or publication. Subject code must remain uninstalled,
unimported, and unexecuted. Deployed systems, credentials, APIs, live services, network
probing, and live scanning remain outside scope.

Static-analysis tool execution may begin only after Phase 5B explicitly authorizes the
frozen pilot. That authorization does not permit installing, importing, building,
executing, or launching subject code.
