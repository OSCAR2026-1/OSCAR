# OSCAR Artifact

This repository contains the OSCAR implementation, the 50-case evaluation
benchmark, and the independent evaluation package used to reproduce the
reported concrete-impact and propagation-boundary results.

## Layout

```text
tool/          OSCAR implementation and tests
benchmark/     benchmark cases and runtime contracts
evaluation/    reference labels and evaluator
scripts/       artifact verification and experiment entry points
```

## Requirements

- Python 3.11 or later
- Docker
- The immutable container images listed in
  `benchmark/release/container_images.json`

Verify the repository and the local container environment:

```bash
python3 scripts/verify_artifact.py
python3 benchmark/scripts/verify_environment.py
```

## Run OSCAR

```bash
./scripts/run_benchmark.sh results/oscar-50 4
```

The first argument is the output directory and the second is the worker count.
The blind predictions are written to `results/oscar-50/predictions.jsonl`.

## Evaluate the Predictions

```bash
./scripts/evaluate.sh \
  results/oscar-50/predictions.jsonl \
  results/evaluation.json
```

The output reports whether OSCAR correctly identifies realized vulnerability
effects across all 50 cases. For cases where an effect is realized, it also
evaluates whether OSCAR correctly identifies the maximum propagation boundary,
including per-boundary metrics, macro averages, coverage, and accuracy.

## Tool Tests

```bash
cd tool
PYTHONPATH=. python3 -m unittest discover -s tests -v
```

## Licenses

OSCAR is licensed under Apache License 2.0. Benchmark components retain their
upstream licenses. See `tool/LICENSE`, `benchmark/LICENSE`, and
`benchmark/THIRD_PARTY_NOTICES.md`.
