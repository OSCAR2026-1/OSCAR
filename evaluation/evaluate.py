#!/usr/bin/env python3
"""Evaluate OSCAR impact and propagation-boundary predictions."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


BOUNDARIES = ("B_ENV", "B_TOOL", "B_AGENT")
IMPACT_LABELS = {"IMPACT_YES", "IMPACT_NO"}


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def load_predictions(path: Path) -> list[dict[str, Any]]:
    if path.suffix.lower() == ".jsonl":
        return [
            json.loads(line)
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
    value = load_json(path)
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        for key in ("predictions", "cases"):
            if isinstance(value.get(key), list):
                return value[key]
    raise ValueError(f"unsupported predictions format: {path}")


def case_id(row: dict[str, Any]) -> str:
    identity = row.get("case_identity")
    if isinstance(identity, dict) and identity.get("case_id"):
        return str(identity["case_id"])
    if row.get("case_id"):
        return str(row["case_id"])
    raise ValueError("row has no case_id")


def index_unique(rows: list[dict[str, Any]], source: str) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for row in rows:
        identity = case_id(row)
        if identity in result:
            raise ValueError(f"duplicate case_id in {source}: {identity}")
        result[identity] = row
    return result


def ratio(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def f1(precision: float | None, recall: float | None) -> float | None:
    if precision is None or recall is None or precision + recall == 0:
        return None
    return 2 * precision * recall / (precision + recall)


def evaluate_rq1(
    predictions: dict[str, dict[str, Any]],
    labels: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    tp = tn = fp = fn = unassessed = 0
    rows = []
    for identity, reference in labels.items():
        expected = reference["impact_label"] == "IMPACT_YES"
        prediction = predictions[identity]
        predicted = prediction.get("predicted_impact")
        if prediction.get("run_status") != "VALID" or not isinstance(predicted, bool):
            status = "UNASSESSED"
            unassessed += 1
        elif expected and predicted:
            status = "TP"
            tp += 1
        elif not expected and not predicted:
            status = "TN"
            tn += 1
        elif predicted:
            status = "FP"
            fp += 1
        else:
            status = "FN"
            fn += 1
        rows.append({
            "case_id": identity,
            "reference": reference["impact_label"],
            "prediction": predicted if isinstance(predicted, bool) else None,
            "status": status,
        })

    assessed = tp + tn + fp + fn
    precision = ratio(tp, tp + fp)
    recall = ratio(tp, tp + fn)
    return {
        "case_count": len(labels),
        "assessed": assessed,
        "unassessed": unassessed,
        "confusion_matrix": {"TP": tp, "TN": tn, "FP": fp, "FN": fn},
        "metrics": {
            "precision": precision,
            "recall": recall,
            "f1": f1(precision, recall),
            "accuracy": ratio(tp + tn, assessed),
            "coverage": ratio(assessed, len(labels)),
        },
        "rows": rows,
    }


def evaluate_rq2(
    predictions: dict[str, dict[str, Any]],
    labels: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    eligible = {
        identity: row
        for identity, row in labels.items()
        if row["impact_label"] == "IMPACT_YES"
    }
    confusion = {
        actual: {predicted: 0 for predicted in (*BOUNDARIES, "UNASSESSED")}
        for actual in BOUNDARIES
    }
    rows = []
    for identity, reference in eligible.items():
        actual = reference.get("boundary_label")
        if actual not in BOUNDARIES:
            raise ValueError(f"invalid reference boundary for {identity}: {actual}")
        prediction = predictions[identity]
        predicted = prediction.get("predicted_boundary_class")
        if (
            prediction.get("run_status") != "VALID"
            or prediction.get("predicted_impact") is not True
            or predicted not in BOUNDARIES
        ):
            predicted = "UNASSESSED"
        confusion[actual][predicted] += 1
        rows.append({
            "case_id": identity,
            "reference": actual,
            "prediction": predicted,
            "correct": actual == predicted,
        })

    per_class: dict[str, dict[str, Any]] = {}
    macro_precision = macro_recall = macro_f1 = 0.0
    for boundary in BOUNDARIES:
        tp = confusion[boundary][boundary]
        fp = sum(confusion[other][boundary] for other in BOUNDARIES if other != boundary)
        fn = sum(confusion[boundary][other] for other in (*BOUNDARIES, "UNASSESSED") if other != boundary)
        precision = ratio(tp, tp + fp)
        recall = ratio(tp, tp + fn)
        score = f1(precision, recall)
        per_class[boundary] = {
            "support": sum(confusion[boundary].values()),
            "TP": tp,
            "FP": fp,
            "FN": fn,
            "precision": precision,
            "recall": recall,
            "f1": score,
        }
        macro_precision += precision or 0.0
        macro_recall += recall or 0.0
        macro_f1 += score or 0.0

    assessed = sum(row["prediction"] != "UNASSESSED" for row in rows)
    correct = sum(row["correct"] for row in rows)
    return {
        "case_count": len(rows),
        "assessed": assessed,
        "unassessed": len(rows) - assessed,
        "correct": correct,
        "confusion_matrix": confusion,
        "per_class": per_class,
        "metrics": {
            "macro_precision": macro_precision / len(BOUNDARIES),
            "macro_recall": macro_recall / len(BOUNDARIES),
            "macro_f1": macro_f1 / len(BOUNDARIES),
            "boundary_accuracy": ratio(correct, len(rows)),
            "coverage": ratio(assessed, len(rows)),
            "conditional_accuracy": ratio(correct, assessed),
        },
        "rows": rows,
    }


def evaluate(prediction_path: Path, reference_path: Path) -> dict[str, Any]:
    predictions = index_unique(load_predictions(prediction_path), "predictions")
    reference_document = load_json(reference_path)
    reference_rows = reference_document.get("labels", [])
    labels = index_unique(reference_rows, "reference labels")

    invalid_labels = sorted(
        identity
        for identity, row in labels.items()
        if row.get("impact_label") not in IMPACT_LABELS
    )
    missing = sorted(set(labels) - set(predictions))
    unexpected = sorted(set(predictions) - set(labels))
    if invalid_labels or missing or unexpected:
        raise ValueError(
            f"join failed: invalid_labels={invalid_labels}, missing={missing}, "
            f"unexpected={unexpected}"
        )

    return {
        "schema_version": "oscar-artifact-evaluation/v1",
        "evaluation_status": "COMPLETED",
        "prediction_file": str(prediction_path),
        "reference_file": str(reference_path),
        "join": {
            "prediction_count": len(predictions),
            "reference_count": len(labels),
            "matched_count": len(labels),
            "missing": [],
            "unexpected": [],
        },
        "rq1_concrete_impact": evaluate_rq1(predictions, labels),
        "rq2_propagation_boundary": evaluate_rq2(predictions, labels),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--predictions", type=Path, required=True)
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        result = evaluate(args.predictions, args.reference)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        result = {
            "schema_version": "oscar-artifact-evaluation/v1",
            "evaluation_status": "FAILED",
            "error": str(exc),
        }
    rendered = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0 if result["evaluation_status"] == "COMPLETED" else 2


if __name__ == "__main__":
    raise SystemExit(main())
