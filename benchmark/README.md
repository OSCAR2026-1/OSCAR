# OSCAR-Benchmark

OSCAR-Benchmark is a 50-case execution benchmark for evaluating
cross-layer runtime effects of known OSS vulnerabilities in agent systems.
It is versioned separately from the OSCAR tool.

## Contents

This repository contains the benchmark manifest, container contract, release
builder, release verifier, and repository tests. The complete case payload is
published as the `oscar-benchmark-v1.tar.gz` release asset rather than committed
to Git.

The release payload contains vulnerable/fixed case contracts, scoped source and
patch material, Host runners, profiles, and runtime support.

```text
OSCAR-Benchmark/
  README.md
  LICENSE
  NOTICE
  SECURITY.md
  THIRD_PARTY_NOTICES.md
  test_set.json
  release/
    benchmark_manifest.json
    container_images.json
    public_manifest.json
  scripts/
    build_release.py
    verify_release.py
  tests/
  dist/                         generated, not tracked
```

The release archive expands to:

```text
oscar-benchmark/
  test_set.json
  release/
  benchmark/
    cases/
    profiles/
    runners/
    runtime/
    readiness.json
```

## Verify a release

```bash
python3 scripts/verify_release.py \
  --archive dist/oscar-benchmark-v1.tar.gz \
  --checksum dist/oscar-benchmark-v1.tar.gz.sha256

python3 scripts/verify_environment.py
```

The verifier checks archive paths, the 50-case manifest, case contracts,
container identities, and the archive checksum without extracting files.

## Run with OSCAR

Docker and the immutable images listed in `release/container_images.json` must
be available locally. After extracting the release asset, run from the OSCAR
tool repository:

```bash
PYTHONPATH=. python3 oscar.py run-test-set \
  --manifest ../oscar-benchmark/test_set.json \
  --output /tmp/oscar-benchmark-run \
  --workers 4
```

## Build the release

Maintainers build from a verified case bundle:

```bash
python3 scripts/build_release.py \
  --source path/to/verified-public-case-bundle \
  --refresh-metadata

python3 scripts/build_release.py \
  --source path/to/verified-public-case-bundle \
  --output dist/oscar-benchmark-v1.tar.gz
```

## Licensing

Repository-authored packaging code and metadata are licensed under Apache-2.0.
Bundled upstream source, dependencies, patches, fixtures, and documentation
retain their original licenses. See `THIRD_PARTY_NOTICES.md` and the license
files preserved alongside the corresponding assets.
