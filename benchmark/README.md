# Research benchmark

This directory contains the Phase 2 static-analysis benchmark. Start with
[`docs/benchmark.md`](../docs/benchmark.md) for the full methodology and interpretation.

## Layout

- `manifest.json`: pinned corpus provenance, scope, commits, file hashes, and exclusions
- `schemas/`: JSON Schemas for the manifest and ground truth
- `ground_truth/`: reviewed expected, safe, readiness, and excluded cases
- `fixtures/`: project-owned false-positive and known-boundary examples
- `matching.py` and `metrics.py`: deterministic classification and measurement
- `retrieve.py`: timeout-bounded Git retrieval and verification
- `run.py`: the one-command non-executing benchmark runner
- `baselines/`: reviewed metric baselines used for regression checks
- `.corpora/` and `results/`: ignored retrieval and generated evidence directories
- `field_validation/` and `pilot.py`: Phase 5A non-retrieving pilot infrastructure and
  operator workflow

## Quick start

```bash
python -m pip install -e ".[benchmark]"
python -m benchmark.run --corpus dvmcp-79734c19 --retrieve --output-dir benchmark/results/dvmcp-79734c19 --baseline benchmark/baselines/dvmcp-79734c19/metrics.json
```

The runner never imports or executes corpus files. Exit 0 means the run completed and no
requested baseline regression was found. Exit 1 means measured regression. Exit 2 means
invalid inputs, hash or commit failure, scanner error, timeout, or another harness failure.
