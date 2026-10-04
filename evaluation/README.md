# Evaluation

`reference_labels.json` contains the reference impact and maximum propagation
boundary labels for the 50 benchmark cases.

Run both evaluations with:

```bash
python3 evaluation/evaluate.py \
  --predictions results/oscar-50/predictions.jsonl \
  --reference evaluation/reference_labels.json \
  --output results/evaluation.json
```

The first evaluation determines whether OSCAR correctly identifies realized
vulnerability effects across all 50 cases. The second evaluates the predicted
`B_ENV`, `B_TOOL`, or `B_AGENT` boundary over the 28 reference cases whose
concrete-impact label is `IMPACT_YES`.
