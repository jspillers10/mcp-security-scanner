# MCP scanner field-validation protocol

## 1. Purpose and research question

This protocol defines a future, non-executing field-validation study. It does not select
repositories, create a corpus, or report a measurement.

The primary research question is:

> How much useful security signal does MCP-aware analysis add over applicable general
> Python security tools on a versioned corpus of public MCP repositories?

The study is intended to measure review-relevant static signal within a declared corpus.
It does not estimate vulnerability prevalence, runtime exploitability, or production
readiness. The existing [benchmark methodology](benchmark.md),
[Phase 3 results](phase3-results.md), and [runtime-lab boundaries](../runtime_lab/README.md)
remain separate evidence with separate claims.

For this study, "useful security signal" has five measurable primary components:

1. Adjudicated precision of MCP Security Scanner findings, overall and per supported rule
   where the denominator is valid.
2. Repository analyzability rate: included repositories successfully analyzed under the
   complete-file requirements in Section 10 divided by all included repositories.
3. Comparison-eligible incremental signal: the count and proportion of validated
   scanner-detected cases in semantic claim classes with at least one pre-mapped
   applicable Bandit or Semgrep rule that are not reported by any applicable mapped
   baseline rule. This is observed additional review signal within the applicable
   comparison scope, not evidence of superior general accuracy.
4. Unique-scope validated signal: the separate count of validated scanner-detected cases
   in MCP-specific claim classes with no applicable Bandit or Semgrep rule. These cases do
   not enter the comparison-eligible incremental-signal proportion.
5. Review burden: false-positive findings per repository and per scoped thousand lines of
   Python. These rates are descriptive and are not ecosystem estimates.

Secondary outcomes may include tool overlap, finding density, framework coverage,
unsupported cases, and scanner-error categories. Recall and F1 are separate
recall-subset outcomes governed by Section 8 and must not be inferred for the complete
field corpus.

## 2. Scope and authorization boundary

The primary field corpus will target 20 to 30 public repositories containing Python MCP
servers. Every repository and every analyzed file will be pinned to an exact commit.
Analysis is limited to source text and public repository metadata required for provenance,
licensing, framework identification, and responsible disclosure.

Repository code must never be imported, executed, installed, or launched. The study will
not perform live scanning, network probing, credential testing, exploit attempts, package
installation from a subject repository, or interaction with deployed systems. It will not
use private repositories, leaked code, private data, or repositories requiring
authentication. Public availability of source does not authorize testing a deployed
system.

For each candidate, the study will record the declared license, the source of that license
claim, whether a license file exists, and any relevant analysis or redistribution terms.
Repositories whose terms do not clearly permit the planned source analysis will be
excluded before retrieval into the study corpus.

## 3. Inclusion criteria

A primary-corpus repository must satisfy all of these criteria before any scanner result
is considered:

1. Its source repository is publicly accessible without authentication.
2. It contains a Python MCP server or Python MCP tool or resource implementation.
3. An MCP framework, server construction, decorator, or registration pattern can be
   identified from source text or public repository documentation.
4. It contains sufficient source code for meaningful static analysis.
5. Repository provenance, an exact commit, and licensing information can be recorded.
6. The relevant Python files can be enumerated without importing or executing code.
7. It is not deliberately vulnerable training material for the primary field corpus.
8. It was not used to tune, benchmark, or design the current scanner.

## 4. Exclusion criteria

Candidates will be excluded when any of the following applies:

- The repository is an educational vulnerable lab or challenge corpus.
- It is a fork, mirror, template copy, or vendored duplicate of another included candidate.
- The relevant content is generated code without meaningful security-review value.
- The MCP implementation is not Python.
- An exact commit or stable file set cannot be pinned reproducibly.
- Licensing or provenance is absent, contradictory, or ambiguous for the planned use.
- The repository was used to tune the current scanner or its rule fixtures.
- Determining whether it is an MCP server would require importing or executing code.
- Access requires credentials, private membership, or acceptance of terms incompatible
  with the protocol.
- The candidate contains exposed private data that cannot be handled safely within the
  study.

Exclusion is not a negative quality judgment. Every screened candidate and its reason will
remain in the inclusion and exclusion log.

Excluding repositories with ambiguous or incompatible licenses may change the corpus's
framework, maintainer, application, popularity, or size composition. The resulting corpus
must not be described as representative of all public MCP repositories.

## 5. Sampling method

### Candidate discovery

After protocol approval, candidate discovery may use reproducible public repository and
code-search queries based on MCP framework imports, server construction, decorators,
registration calls, language, and repository topics. Search services, query strings,
query dates, result-page limits, and ordering will be recorded. Candidate discovery must
occur before running any security scanner on a candidate.

The candidate register will preserve every screened result, including duplicate, included,
excluded, pilot, and not-yet-resolved entries. Selection must never depend on whether the
MCP Security Scanner, Bandit, Semgrep, or another tool finds an issue.

### Sampling controls

The final corpus will use predefined strata where the candidate pool permits them:

- MCP framework or registration family.
- Archived versus actively maintained status.
- Repository-size band measured by scoped Python source lines and file count.
- Popularity band using a recorded, descriptive public metadata field.
- Standalone server versus server embedded in a larger application.

Popularity will not be treated as a security or quality signal. Very large repositories
may be capped by a predefined source-scope rule, not by scanner output. Archived projects
may be included as their own stratum but will not substitute for maintained projects.
Forks and mirrors will be mapped to an upstream lineage, and only one representative from
that lineage may enter the primary corpus.

When more eligible candidates exist than the target permits, selection within strata will
use a recorded deterministic ordering followed by a seeded random sample. The seed and
algorithm will be fixed before tools run. Zero-finding repositories remain in the corpus.

### Pilot separation

Exactly three repositories will form the initial pilot after this protocol is approved.
Pilot results will not be pooled into the final primary measurement. Pilot repositories
will be labeled separately and excluded from the 20 to 30 repository primary corpus. Any
protocol, data-model, tool-configuration, or detector change prompted by the pilot will be
documented before the final corpus and scanner version are frozen.

## 6. Units of analysis and deterministic matching

The primary classification unit is a case tied to one physical source location and one
security claim. A case records the normalized repository-relative file, source region,
rule or comparison class, source, sink, preconditions, and expected result.

For sink-based rules, a distinct physical sink is a distinct case. Direct and propagated
paths to the same sink are not separate cases. Separate sink calls are separate cases.
Distinct MCP tool or resource registrations are separate cases when the registration is
the security-relevant unit. One logical credential bundle at one source region is one
case, even when it contains multiple related values. Repository-level deployment signals
are separate cases tied to the most specific configuration or transport location
available.

Each tool finding receives a stable finding ID. Eligible findings and positive cases will
use deterministic one-to-one matching compatible with the existing
[benchmark method](benchmark.md#6-matching-method): normalized file, mapped rule or claim
class, function or registration context when declared, and exact or explicitly bounded
physical source location. Cross-tool matching uses predeclared semantic claim classes and
physical source locations. Equal severity labels are not required because tools may use
different severity systems. Approximate location matching is never implicit. One finding
and one case can each be matched at most once.

Repository is the aggregation unit for corpus coverage, error reporting, and descriptive
finding density. It is not a substitute for location-level correctness classification.

## 7. Tool comparison

The planned comparison includes:

- MCP Security Scanner, frozen at a recorded package version, commit, and source hash.
- Bandit, limited to rules applicable to the scoped Python source.
- Semgrep, using a named and commit-pinned ruleset with a preserved configuration.
- CodeQL only if a non-executing, language-appropriate analysis can be configured and
  reproduced fairly across the full primary corpus.

Tool versions, rule selections, exclusions, commands, exit codes, parse errors, and raw
outputs will be handled under Section 12. General-tool rules will be mapped in advance to
the semantic security claims they can reasonably address. Comparison records distinguish
`rule-not-applicable`, `rule-unsupported`, `tool-error`, and
`applicable-rule-missed-case`. Absence of an applicable rule is not a false negative.
Rules with no MCP-aware analogue may be reported as descriptive general-tool findings but
will not enter a forced head-to-head denominator. MCP-specific rules with no general-tool
analogue will be labeled as unique scope, not as automatic evidence of superior accuracy.
Unique-scope cases are reported separately from comparison-eligible cases. The absence of
a baseline rule is neither a baseline false negative nor evidence of inferior baseline
accuracy.

The tools have different goals, rule taxonomies, severity labels, data-flow models, and
output units. Raw or unmatched finding totals must not be presented as direct accuracy
comparisons or evidence that one tool is more accurate. CodeQL will be
omitted, with a recorded reason, if database creation requires subject build or execution,
if language coverage differs materially, or if configuration cannot be made consistent.

## 8. Ground truth and adjudication

### Case records

Ground truth will be machine-readable and schema-validated. Each case will record at
least:

- Stable case ID, corpus ID, repository ID, and pinned commit.
- Normalized repository-relative file and exact or bounded line location.
- Function, tool, resource, registration, or repository context.
- Vulnerability or readiness class and applicable tool rule identifiers.
- Source, sink, attack preconditions, and relevant control or validation.
- Proposed expected result and metric group.
- Classification and rationale.
- Reviewer identity by non-sensitive role identifier, review state, date, and confidence.
- Matching mode and any explicit line tolerance.
- Disclosure status when applicable.

The classification vocabulary is `TP`, `FP`, `FN`, `disputed`, `unsupported`, `excluded`,
and `scanner-error`. A case may also record an applicable general-tool outcome without
forcing it into the MCP scanner's classification. Safe reviewed regions may be represented
as expected no-finding cases to improve false-positive attribution.

### Adjudication sequence

The primary study must follow this locked order:

1. Freeze the candidate pool.
2. Apply the inclusion and exclusion criteria.
3. Freeze the final corpus and exact commits.
4. Freeze the sampling seed and algorithm.
5. Select and freeze the recall subset described below.
6. Freeze file scope, tool versions, rule mappings, primary outcomes, and the manual-review
   checklist.
7. Complete, schema-validate, and hash the manual candidate-case inventory for the recall
   subset.
8. Preserve that inventory without scanner-result or baseline-result fields.
9. Run the tools.
10. Match outputs to the frozen inventory and semantic claim mappings.
11. Adjudicate unmatched findings and unmatched cases.
12. Preserve corrections as immutable, versioned rounds.

Tool results must not influence candidate-pool composition, corpus selection,
recall-subset selection, source scope, the review checklist, or the initial candidate-case
inventory.

### Recall subset

Recall and F1 must not be reported for the complete 20 to 30 repository corpus unless
every relevant scoped file receives a documented exhaustive case inventory. Instead, the
recall-subset size is the maximum of five repositories or the mathematical ceiling of 20
percent of the primary corpus. Thus, 20 repositories produce a five-repository subset, 26
produce a six-repository subset, and 30 produce a six-repository subset. Selection uses
the frozen seeded and stratified process before any scanner or baseline output is
revealed.

Reviewers will examine every scoped MCP-relevant Python file in the subset using the
predefined source, sink, registration, description, credential, and readiness checklist.
The resulting candidate-case inventory will be completed, schema-validated, frozen, and
hashed before tool output is revealed. FN, recall, and F1 will be calculated only against
this adjudicated inventory and labeled `recall-subset recall` and `recall-subset F1`.

For the remaining field corpus, the study reports finding precision, validated cases,
coverage, errors, and descriptive signal without claiming recall. Exhaustive checklist
review may still miss latent vulnerabilities, and recall-subset measurements apply only
to the adjudicated claim inventory.

A scanner error is not a clean result and is counted separately. Unsupported cases remain
visible and outside denominators whose tools do not claim to cover them. Excluded cases
retain their exclusion reason. Disputed cases are reported separately unless a predefined
consensus rule resolves them.

### Disagreement and frozen rounds

Review disagreements will preserve each reviewer's decision and rationale. Resolution may
use documented discussion or a third reviewer. If no resolution is reached, the case
remains disputed and is not represented as independent consensus. Sensitivity analysis
may show how plausible disputed labels affect metrics.

The initial scanner measurement is immutable after review begins. Detector changes,
ground-truth corrections, or scope changes become later, clearly versioned rounds. The
frozen initial results, restricted raw-output records, classifications, metrics, and
disputed decisions remain recoverable under the sensitive-output controls. A genuine
ground-truth defect is documented before a label changes.

## 9. Independent review

At least one reviewer outside the project will review a fixed sample containing:

- Every critical and high-severity MCP Security Scanner finding.
- Every disputed case.
- Every potential false negative in the recall subset.
- Every proposed ground-truth correction.
- A seeded, stratified random sample of 25 percent of all remaining cases, with a minimum
  of 30 and a maximum of 75 when enough cases exist.
- Source samples from at least three zero-finding repositories.

The mandatory categories will first be combined into a set of unique case IDs. Each case
is counted once even when it belongs to multiple mandatory categories. The seeded 25
percent random sample is drawn only from eligible cases not already selected through a
mandatory category. If the total eligible case count is below the minimum, the reviewer
will review every eligible case. The random portion will be stratified, where populated
strata permit, by rule family, framework, repository, detected versus undetected status,
and positive versus safe case. The selection seed, algorithm, strata, eligible-case
count, rounding rule, selected IDs, final reviewer-packet case count, and every case's
selection reason will be frozen and recorded.

Reviewer records will describe role and relevant security, Python, or MCP background
without publishing private identifying information. Participation by one external reviewer
will be described as one external review, not independent consensus.

For the blind portion, the reviewer packet will show only the pinned source region,
security claim under review, threat-model assumptions, and blank decision fields. It will
not reveal whether any scanner or baseline tool produced a finding, and it will not reveal
TP, FP, or FN labels. The reviewer records and freezes the initial blind decision and
rationale before any output-aware discussion. If the reviewer changes a decision after
seeing tool output, both the initial blind decision and the post-discussion decision are
retained and reported separately. Cases that cannot be blinded will state why.

## 10. Metrics and analysis

The primary field-corpus outcomes are adjudicated precision, repository analyzability
rate, comparison-eligible incremental signal, unique-scope validated signal, and review
burden as defined in Section 1. Precision will be reported overall and per supported rule
or predeclared claim class where its denominator is valid. A zero denominator is reported
as not applicable, not coerced to zero or one.

A repository counts as successfully analyzable only when every scoped file is presented
to the scanner, the scanner completes without an unhandled error, and every scoped file
receives a recorded result or an explicit supported status. No parse or scan error may be
silently treated as a clean result. Unsupported rule coverage is not automatically a
scanner error, but it must be reported separately. A partially analyzed repository does
not count as successfully analyzable for the primary repository-level rate. Its number of
successfully analyzed files and each failure reason are reported separately.

For comparison-eligible incremental signal, the numerator is validated scanner-detected
cases not reported by any applicable mapped Bandit or Semgrep rule. The denominator is
all validated scanner-detected cases in semantic claim classes with at least one
pre-mapped applicable Bandit or Semgrep rule. The count and proportion are reported as
observed additional review signal within the applicable comparison scope, not superior
general accuracy.

Unique-scope validated signal is the separate count of validated scanner-detected cases
in MCP-specific semantic claim classes with no applicable Bandit or Semgrep rule. These
cases are excluded from the comparison-eligible incremental-signal denominator and
proportion. Absence of a baseline rule is not classified as a baseline false negative and
is not evidence of inferior baseline accuracy.

FN, recall, and F1 are reported only for the frozen, exhaustively reviewed recall subset,
unless the same inventory standard is later satisfied for the entire corpus. Those
results must use the labels `recall-subset recall` and `recall-subset F1`.

The study will also report:

- Repositories and scoped files successfully analyzed.
- Repository coverage and scanner-error counts.
- Unsupported frameworks and unsupported-framework coverage.
- Findings and cases by repository, framework, and review state.
- Confidence intervals where denominators and sampling assumptions support a useful
  interpretation.
- Finding density as descriptive findings per scoped source size, not as vulnerability
  prevalence.
- Comparison-eligible incremental cases and unique-scope validated cases, reported as
  separate measurements.
- Overlap between MCP-aware and applicable general-tool findings after case-level mapping.
- Disputed, unsupported, excluded, and unresolved-disclosure counts.

Comparative claims will be restricted to pre-mapped applicable rule scopes. No metric will
be presented as an estimate of production vulnerability prevalence, ecosystem-wide tool
accuracy, runtime exploitability, or production readiness.

Binomial proportions will use Wilson score intervals at a predeclared confidence level
when the case definition, denominator, and sampling assumptions support that
interpretation. An interval will not be reported when those conditions are not met.
Confidence intervals describe uncertainty conditional on the selected and adjudicated
cases. They do not make the selected corpus representative of the public MCP ecosystem.

Because findings within a repository are not independent, repository-level bootstrap
resampling may be reported as a sensitivity analysis. Any bootstrap procedure must record
its seed, repository as the unit of resampling, number of replicates, interval construction
method, and treatment of repositories with zero eligible cases.

## 11. Research integrity protections

- Freeze the initial scanner version, commit, source hash, and configuration before the
  pilot measurement and again before the separate primary measurement.
- Pin every repository commit and hash every scoped file plus the canonical scoped tree.
- Predefine primary metrics, matching, exclusions, and tool-scope mappings.
- Never change ground truth silently or to improve a score.
- Retain historical result hashes, restricted handling records, redacted normalized
  results, classifications, metrics, and review decisions.
- Document detector or protocol changes as later rounds, never as replacements for the
  frozen initial round.
- Retain negative results, scanner errors, and zero-finding repositories.
- Report limitations, missing denominators, framework gaps, and possible benchmark leakage.
- Record every repository previously used for scanner tuning and exclude it from the
  primary corpus.
- Separate pilot evidence from the primary measurement.
- Do not claim that public source availability authorizes testing a deployed system.

## 12. Responsible disclosure

### Sensitive-output handling

Raw tool output initially enters a local, access-restricted, untracked quarantine and does
not automatically become a tracked artifact. Before normalization or publication, it
must be screened for credentials, tokens, private information, personal data, and
unnecessary operational detail.

A discovered credential must never be validated by using it. An active or suspected
secret must never be committed or published. When original output cannot be published,
the study retains a cryptographic hash and restricted handling record, then produces a
redacted normalized result for the reproducibility package. Every redaction and its reason
will be recorded. Generated public artifacts must pass secret scanning before staging.

Discovery of sensitive material stops the study and begins the responsible-disclosure
process below. Access, copying, and retention will be limited to what is necessary for
safe adjudication and disclosure.

### Disclosure process

Every potential repository vulnerability requires manual confirmation before any report.
Reviewers will check the repository's `SECURITY.md`, security advisory instructions, or
other reporting policy at the pinned or current public repository state. Disclosure will
use the private channel requested by the maintainer before public discussion.

Reports will avoid working harmful instructions, real credentials, private data, and
unnecessary operational detail. Severity will not be claimed without source evidence,
preconditions, affected scope, and a documented rationale. Maintainers will receive a
reasonable response window appropriate to the apparent impact and project activity.

A repository or case may remain anonymized in the public study report while disclosure is
unresolved. Public reporting will record only the minimum evidence necessary for research
interpretation. Findings that cannot be responsibly disclosed must not be used for
self-promotion. Discovery of a credential or private information triggers the stop rules
below and secure handling, not validation or use of the secret.

## 13. Reproducibility artifacts planned for later phases

Protocol approval authorizes none of these artifacts by itself. A later approved pilot and
primary study will create versioned forms of:

- Candidate register with discovery source, query, date, and screening state.
- Inclusion and exclusion log with objective reasons.
- Pinned corpus manifest with repository URLs, commits, licenses, scope, and exclusions.
- Per-file SHA-256 hashes and canonical scoped-tree hashes.
- Tool versions, source identities, rulesets, configurations, and commands.
- Redacted normalized tool results and scanner-error records suitable for release.
- Restricted raw-output hashes, handling records, and redaction logs when originals cannot
  be published.
- Machine-readable, schema-validated ground truth.
- Reviewer packets, decisions, rationale, blind-review state, and disagreement records.
- Deterministic classifications and metrics.
- Environment and timing metadata separated from deterministic evidence.
- Final limitations, benchmark-leakage assessment, and disclosure status.

Stable evidence will be separated from volatile environment metadata. Generated results
will not overwrite reviewed baselines. Hash and schema failures will stop analysis before
classification.

## 14. Three-repository pilot plan

After protocol approval, a separately authorized pilot will use exactly three public
repositories that meet the screening criteria. It will test the process, not estimate the
primary result. The pilot will evaluate:

1. Reproducible repository retrieval, commit pinning, and file hashing.
2. License-source and provenance recording.
3. Framework identification and static source-scope enumeration.
4. Static scanning without importing, installing, executing, or launching repository code.
5. Fair Bandit and pinned Semgrep configuration, and CodeQL feasibility only if safe.
6. Manual case inventory and adjudication effort.
7. External-review packet, blind-review feasibility, and disagreement recording.
8. Whether schemas, matching units, classifications, or metadata require correction.

Pilot repositories, quarantined result records, redacted normalized results, and metrics
will remain labeled pilot evidence. They will not be presented as the final measurement or
included in the 20 to 30 repository primary corpus. Protocol revisions prompted by the
pilot will be versioned and approved before the primary corpus is sampled.

## 15. Stop and revision rules

The study pauses immediately if any of these conditions occurs:

- Any subject code is unexpectedly imported, installed, executed, or launched.
- Authorization, repository provenance, or licensing becomes ambiguous.
- Real credentials, private information, or non-public source is exposed.
- Raw or generated output containing suspected sensitive material has not completed
  quarantine review, redaction, and secret scanning.
- A repository commit or scoped file set cannot be reproduced and hash-verified.
- Ground-truth disagreement changes the meaning or denominator of a primary metric.
- A comparison tool proves materially unfair because its scope, setup, or required build
  behavior differs from the predefined comparison.
- Candidate selection is influenced by scanner findings or observed tool output.
- A tool attempts network access, dependency installation, build execution, or contact
  with a deployed system outside the approved retrieval boundary.
- The case unit or matching process permits duplicate credit or cannot distinguish
  materially different claims.
- Responsible disclosure cannot proceed safely for evidence needed in a public report.

After a stop, the event, affected artifacts, containment action, and proposed protocol
revision will be recorded. Work resumes only after review and explicit approval. A revision
that changes sampling, scope, units, adjudication, or a primary metric creates a new
protocol version and does not rewrite earlier evidence.

## 16. Approval boundary

Approval of this document permits review of the protocol only. It does not authorize
candidate selection, external repository retrieval, scanning, installation, execution,
disclosure, detector modification, or publication. The next possible activity is the
separately approved three-repository pilot, and it must follow the stop rules above.
