# Contributing

OSCAR accepts changes to the blind analysis runtime, contracts, documentation,
and label-free tests. Contributions must not include hidden labels, evaluator-only
annotations, credentials, private execution traces, or case-specific answer logic.

Before submitting a change, run:

```bash
python3 -m unittest discover -s tests -p 'test_*.py'
python3 scripts/build_public_release.py --verify-only --allow-missing-license
git diff --check
```

Real vulnerability fixtures must be independently redistributable and must not
contain secrets or third-party source that the project cannot publish.
