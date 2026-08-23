# Field-validation pilot artifacts

This directory contains Phase 5A infrastructure for the separately authorized
three-repository pilot described in the
[field-validation protocol](../../docs/field-validation-protocol.md). It contains no
repository candidates, retrieved source, raw tool output, findings, adjudications, or
study results.

## Layout

- `schemas/` defines public, schema-validated study artifacts and restricted
  administrative records.
- `templates/` contains empty infrastructure-only starting documents.
- `quarantine/` is ignored and reserved for access-restricted raw tool output.
- `workspace/` is ignored and reserved for separately authorized subject-source work.
- [`benchmark/pilot.py`](../pilot.py) provides deterministic preparation helpers.

The tracked templates are safe to inspect and validate. They must not be populated with
repository identities or tool results until Phase 5B is explicitly authorized.

## Artifact sequence

The pilot must preserve the protocol order:

1. Record and freeze discovery queries and the candidate pool.
2. Apply inclusion, exclusion, license, provenance, and duplicate-lineage screening.
3. Freeze the candidate register and record its canonical SHA-256 hash.
4. Run deterministic seeded selection for exactly three distinct lineages.
5. Pin exact commits and freeze the explicit Python source scope.
6. Hash every scoped file and the canonical scoped tree.
7. Freeze tool identities, versions, configurations, commands, and semantic claim mappings.
8. Complete and hash any required pre-output case inventory without detection fields.
9. Only then run tools under separate authorization.
10. Record each authorized static-tool run without changing the subject-code prohibition.
11. Quarantine raw output, screen it, redact it, and normalize publishable findings.
12. Match cases and findings at maximum cardinality, adjudicate, and preserve versioned rounds.
13. Freeze reviewer selection in a restricted administrative record.
14. Generate a separate blind packet without selection or tool-state fields.
15. Preserve individual blind and output-aware decisions in immutable review rounds.
16. Calculate and schema-validate protocol-approved pilot outcomes.

Tool output must not alter repository selection, source scope, claim mappings, review
checklists, or a frozen initial case inventory.

## Phase 5A commands

Validate every empty template:

```bash
python -m benchmark.pilot validate candidate-register benchmark/field_validation/templates/candidate-register.json
python -m benchmark.pilot validate pilot-manifest benchmark/field_validation/templates/pilot-manifest.json
python -m benchmark.pilot validate case-inventory benchmark/field_validation/templates/case-inventory.json
python -m benchmark.pilot validate normalized-findings benchmark/field_validation/templates/normalized-mcp-security-scanner.json
python -m benchmark.pilot validate normalized-findings benchmark/field_validation/templates/normalized-bandit.json
python -m benchmark.pilot validate normalized-findings benchmark/field_validation/templates/normalized-semgrep.json
python -m benchmark.pilot validate adjudication benchmark/field_validation/templates/adjudication.json
python -m benchmark.pilot validate review-history benchmark/field_validation/templates/review-history.json
python -m benchmark.pilot validate review-selection benchmark/field_validation/templates/review-selection.json
python -m benchmark.pilot validate reviewer-packet benchmark/field_validation/templates/reviewer-packet.json
python -m benchmark.pilot validate tool-run benchmark/field_validation/templates/tool-run.json
python -m benchmark.pilot validate evidence-record benchmark/field_validation/templates/evidence-record.json
python -m benchmark.pilot validate pilot-metrics benchmark/field_validation/templates/pilot-metrics.json
```

Create the ignored local quarantine without putting content in it:

```bash
python -m benchmark.pilot init-quarantine benchmark/field_validation/quarantine
```

The helper requests owner-only permissions. Windows permission semantics may not fully
enforce POSIX mode bits, so the operator must verify effective local access controls before
placing sensitive output there.

## Phase 5B authorization gate

The following actions are prohibited during Phase 5A and require separate, explicit Phase
5B authorization:

- Running public discovery queries or selecting repository candidates.
- Recording real repository URLs, metadata, licenses, or maintainer information.
- Retrieving, cloning, downloading, or updating any external repository.
- Populating the ignored subject-source workspace.
- Enumerating or hashing files from an external repository checkout.
- Freezing the real three-repository selection, commits, file scope, or case inventory.
- Installing, importing, building, executing, or launching subject code.
- Running MCP Security Scanner, Bandit, Semgrep, or CodeQL against external source.
- Reading, normalizing, matching, adjudicating, or publishing real tool output.
- Contacting maintainers or beginning a responsible-disclosure process.

Phase 5B authorization must still prohibit subject-code execution and deployed-system
interaction unless a later protocol revision explicitly changes those boundaries.

## Raw-output handling

Raw results never become tracked artifacts automatically. They first enter the ignored
`quarantine/` directory, which must be access-restricted locally. The operator must screen
for credentials, tokens, private information, personal data, and unnecessary operational
detail without using any discovered credential. Public normalized results must be
redacted, record every redaction and reason, and pass secret scanning before staging.

When original output cannot be published, retain only its SHA-256 hash and a restricted
handling record in the public evidence package. Discovery of sensitive material stops the
study and starts the responsible-disclosure process.

## Blind-review boundary

`review-selection.json` is an administrative artifact and is not shown during blind
review. It records the seed, algorithm, eligibility counts, mandatory categories,
selection reasons, zero-finding source samples, and final membership. The reviewer-visible
`reviewer-packet.json` contains only neutral provenance, pinned source regions, the claim
under review, threat-model assumptions, and blank decision fields. Review decisions are
stored later in immutable `review-history.json` rounds so the initial blind decision is
never overwritten.

## Tool authorization boundary

The manifest and tool-run artifacts distinguish static-tool authorization from subject
execution. Before Phase 5B, tool execution state is `not-authorized` and run state is
`not-started`. After explicit Phase 5B authorization, approved static-analysis tools may
read pinned source text. Subject-code installation, import, build, execution, and launch
remain prohibited. Deployed-system interaction also remains prohibited.

## Reported measurements

The pilot helpers support:

- Adjudicated finding precision.
- Repository analyzability using the all-scoped-files rule.
- Comparison-eligible incremental signal against pre-mapped applicable rules.
- Unique-scope validated signal reported outside the comparison proportion.
- False-positive review burden per repository and per scoped thousand Python lines.

The pilot infrastructure does not calculate or report recall or F1. Those measurements
remain restricted to the frozen, exhaustively reviewed recall-subset design for the future
primary study.
