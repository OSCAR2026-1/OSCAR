#!/usr/bin/env sh
set -eu

artifact_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
output_dir=${1:-"$artifact_root/results/oscar-50"}
workers=${2:-4}

cd "$artifact_root"
PYTHONPATH="$artifact_root/tool" python3 "$artifact_root/tool/oscar.py" run-test-set \
  --manifest "$artifact_root/benchmark/test_set.json" \
  --output "$output_dir" \
  --workers "$workers"
