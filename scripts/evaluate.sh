#!/usr/bin/env sh
set -eu

artifact_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
predictions=${1:-"$artifact_root/results/oscar-50/predictions.jsonl"}
output=${2:-"$artifact_root/results/evaluation.json"}

python3 "$artifact_root/evaluation/evaluate.py" \
  --predictions "$predictions" \
  --reference "$artifact_root/evaluation/reference_labels.json" \
  --output "$output"
