# Contributing

Thanks for helping improve mcp-security-scanner. This project favors small,
explainable security rules, focused tests, and explicit limitations over broad claims.

## Development setup

Python 3.10 through 3.13 is supported. Create and activate a virtual environment,
then install the project in editable mode:

```bash
python -m venv .venv
# POSIX: source .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[test,dev]"
```

To run the live and config integration tests, also install the optional MCP SDK:

```bash
python -m pip install -e ".[live,test,dev]"
```

The core static scanner intentionally has no third-party runtime dependencies.

## Tests and code quality

Run the same checks used by continuous integration:

```bash
python -m pytest -q
python -m pytest --cov=mcp_scanner --cov-report=term-missing --cov-report=xml
python -m ruff check src benchmark tests
python -m ruff format --check src benchmark tests
python -m mypy src benchmark
python -m bandit -q -r src benchmark -x benchmark/fixtures,benchmark/.corpora,benchmark/results
python -m build
```

Live tests launch local subprocesses and bind an SSE fixture to loopback. They are
skipped when the `live` extra is absent.

## Benchmark changes

Install `.[benchmark,test,dev]` before changing the research harness. Do not update a
ground-truth label merely to make a current scanner result pass. Record source, sink,
preconditions, rationale, review state, and an exact or explicitly tolerant location.
Preserve unsupported cases as exclusions instead of counting them as misses for rules
that do not claim to cover them.

Run both corpora after changing matching, metrics, rules, or fixtures:

```bash
python -m benchmark.run --corpus local-boundaries-v1 --output-dir benchmark/results/local-boundaries-v1
python -m benchmark.run --corpus dvmcp-79734c19 --retrieve --output-dir benchmark/results/dvmcp-79734c19 --baseline benchmark/baselines/dvmcp-79734c19/metrics.json
```

The DVMCP checkout and generated results are ignored. A baseline change requires a clear
adjudication or scanner-behavior explanation and review of the raw FP/FN classifications.
Never import, install, or launch benchmark corpus files.

## Adding or changing a rule

- Add rule metadata to the appropriate authoritative registry.
- Generate findings only from behavior the scanner actually observed.
- Include vulnerable and safe counterexamples where practical.
- Test the rule identifier, severity, location, message, and output serialization.
- Document important false-positive and false-negative boundaries.
- Never use a third-party system for testing without explicit authorization.

## Pull requests

Keep pull requests focused and explain the security reasoning. Include tests for
behavior changes and update the README, rule documentation, or changelog when needed.
Do not include virtual environments, coverage files, builds, credentials, or generated
scan reports. By contributing, you agree that your contribution is licensed under the
project's MIT License.
