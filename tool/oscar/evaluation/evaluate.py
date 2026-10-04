"""Independent evaluator for blind OSCAR predictions.

This is the only effectiveness component that reads hidden GT labels.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Iterable

try:
    from oscar.runtime.environment import compare_environment_manifests
    from oscar.contracts.prediction_contract import validate_prediction_contract
except ImportError:  # pragma: no cover - direct script execution
    from oscar.runtime.environment import compare_environment_manifests
    from oscar.contracts.prediction_contract import validate_prediction_contract


TARGETS = {"concrete-impact", "agent-observation"}
GT_LABELS = {
    "agent-observation": {"POSITIVE", "NEGATIVE"},
    "concrete-impact": {"IMPACT_YES", "IMPACT_NO"},
}
NON_STATISTICAL_STATUSES = {"INVALID", "BLOCKED", "UNASSESSED"}


def _component_origin(row: dict[str, Any]) -> str:
    component = row.get("vulnerability_component")
    if isinstance(component, dict) and component.get("origin"):
        return str(component["origin"])
    return "DIRECT_RUNTIME_DEPENDENCY" if isinstance(row.get("direct_runtime_dependency"), dict) else "UNKNOWN"


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _rows(path: Path) -> list[dict[str, Any]]:
    if path.suffix.lower() == ".jsonl":
        result = []
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.strip():
                value = json.loads(line)
                if isinstance(value, dict):
                    result.append(value)
        return result
    value = load_json(path)
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    if isinstance(value, dict):
        for key in ("predictions", "cases", "active_cases", "ground_truth"):
            if isinstance(value.get(key), list):
                return [item for item in value[key] if isinstance(item, dict)]
        return [value]
    raise ValueError(f"unsupported JSON root in {path}")


def _identity(row: dict[str, Any]) -> dict[str, Any]:
    identity = row.get("case_identity", row.get("identity", row.get("case", {})))
    if not isinstance(identity, dict):
        identity = {}
    return identity


def identity_key(row: dict[str, Any]) -> tuple[str, ...]:
    identity = _identity(row)
    case_id = identity.get("case_id", row.get("case_id", ""))
    if case_id:
        return ("case_id", str(case_id))
    return ("metadata",) + metadata_key(row)


def metadata_key(row: dict[str, Any]) -> tuple[str, ...]:
    identity = _identity(row)
    versions = identity.get("versions", {}) if isinstance(identity.get("versions"), dict) else {}
    tool = identity.get("tool", {})
    if isinstance(tool, dict):
        tool = tool.get("name", "")
    advisory = identity.get("advisory", identity.get("vulnerability", ""))
    server = identity.get("server", identity.get("repository", ""))
    values = (
        str(advisory),
        str(identity.get("package", "")),
        str(server),
        str(identity.get("vulnerable_version", versions.get("vulnerable", ""))),
        str(identity.get("fixed_version", versions.get("fixed", ""))),
        str(tool),
    )
    return values


def _label(row: dict[str, Any], target: str) -> str | None:
    if target == "concrete-impact":
        value = row.get("impact_label")
    else:
        value = row.get("ground_truth_label", row.get("label"))
    return str(value).upper() if value is not None else None


def _prediction_status(row: dict[str, Any]) -> str:
    value = row.get("run_status", row.get("prediction", {}).get("run_status"))
    return str(value).upper() if value is not None else "INVALID"


def _prediction_reachable(row: dict[str, Any]) -> bool | None:
    value = row.get("predicted_reachability")
    if value is None and isinstance(row.get("prediction"), dict):
        value = row["prediction"].get("agent_observation_reachable", row["prediction"].get("reachable"))
    return value if isinstance(value, bool) else None


def _prediction_value(row: dict[str, Any], target: str) -> bool | None:
    if target == "concrete-impact":
        value = row.get("predicted_impact")
        return value if isinstance(value, bool) else None
    return _prediction_reachable(row)


def _target_status(row: dict[str, Any], target: str) -> str:
    status = _prediction_status(row)
    if target == "concrete-impact" and status == "VALID" and row.get("impact_status") == "UNASSESSED":
        return "UNASSESSED"
    return status


def _manifest(row: dict[str, Any], base: Path) -> dict[str, Any] | None:
    embedded = row.get("environment_manifest")
    if isinstance(embedded, dict):
        return embedded
    if isinstance(embedded, str):
        path = (base / embedded).resolve()
        if path.exists():
            return load_json(path)
    reference = row.get("environment_manifest_path")
    if reference:
        path = (base / str(reference)).resolve()
        if path.exists():
            return load_json(path)
    reference = row.get("environment_manifest_file")
    if reference:
        path = (base / str(reference)).resolve()
        if path.exists():
            return load_json(path)
    return None


def evaluate(
    prediction_path: Path,
    gt_path: Path,
    output_path: Path,
    *,
    target: str,
) -> dict[str, Any]:
    if target not in TARGETS:
        raise ValueError(f"target must be one of {sorted(TARGETS)}")
    predictions = _rows(prediction_path)
    gt_rows = _rows(gt_path)
    contract_errors_by_prediction_id: dict[int, list[str]] = {}
    preflight_contract_errors: list[dict[str, Any]] = []
    for index, row in enumerate(predictions):
        errors = validate_prediction_contract(
            row,
            target=target,
            allow_v1_agent_observation=target == "agent-observation",
        )
        if errors:
            contract_errors_by_prediction_id[id(row)] = errors
            preflight_contract_errors.append({
                "prediction_index": index,
                "identity_key": identity_key(row),
                "errors": errors,
            })
    gt_by_key: dict[tuple[str, ...], dict[str, Any]] = {}
    duplicate_gt: list[dict[str, Any]] = []
    for row in gt_rows:
        key = identity_key(row)
        if key in gt_by_key:
            duplicate_gt.append({"identity_key": key, "reason": "duplicate hidden GT"})
        else:
            gt_by_key[key] = row

    prediction_by_key: dict[tuple[str, ...], dict[str, Any]] = {}
    prediction_by_metadata: dict[tuple[str, ...], list[dict[str, Any]]] = {}
    duplicate_predictions: list[dict[str, Any]] = []
    for row in predictions:
        key = identity_key(row)
        if key in prediction_by_key:
            duplicate_predictions.append({"identity_key": key, "reason": "duplicate prediction"})
        else:
            prediction_by_key[key] = row
        prediction_by_metadata.setdefault(metadata_key(row), []).append(row)

    if duplicate_gt or duplicate_predictions:
        result = {
            "schema_version": "vulveil-evaluation/v2",
            "evaluation_status": "FAILED",
            "failure_reason": "DUPLICATE_IDENTITY",
            "evaluator": "OSCAR independent evaluator",
            "evaluation_target": target,
            "prediction_file": str(prediction_path.resolve()),
            "hidden_gt_file": str(gt_path.resolve()),
            "counts": {
                "predictions": len(predictions), "hidden_gt": len(gt_rows), "evaluated": 0,
                "eligible_hidden_gt": sum(_label(row, target) in GT_LABELS[target] for row in gt_rows),
                "missing_prediction": 0, "prediction_without_gt": 0,
                "duplicate_prediction": len(duplicate_predictions), "duplicate_gt": len(duplicate_gt),
                "invalid": len(preflight_contract_errors),
                "contract_invalid": len(preflight_contract_errors),
                "blocked": 0, "unassessed": 0,
                "environment_mismatch": 0, "ambiguous_metadata_join": 0,
            },
            "confusion_matrix": {"TP": 0, "TN": 0, "FP": 0, "FN": 0},
            "metrics": {"precision": None, "recall": None, "f1": None, "accuracy": None},
            "coverage": {"assessed_coverage": 0.0, "abstention_unassessed_rate": None},
            "join_audit": {
                "rows": [], "missing_prediction": [], "prediction_without_gt": [],
                "duplicate_prediction": duplicate_predictions, "duplicate_gt": duplicate_gt,
                "environment_mismatch": [],
                "invalid_prediction_contract": preflight_contract_errors,
                "ambiguous_metadata_join": [],
            },
            "statistics_policy": {
                "metrics_usable_for_formal_conclusions": False,
                "duplicate_identity_fails_closed": True,
                "invalid_blocked_unassessed_excluded_from_confusion_matrix": True,
                "evaluation_target_is_explicit": True,
            },
            "component_origin_breakdown": {},
        }
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        return result

    joins: list[dict[str, Any]] = []
    tp = tn = fp = fn = 0
    invalid = blocked = unassessed = 0
    environment_mismatches: list[dict[str, Any]] = []
    ambiguous_metadata_joins: list[dict[str, Any]] = []
    origin_counts: dict[str, dict[str, Any]] = {}
    matched_prediction_ids: set[int] = set()
    for key, gt in gt_by_key.items():
        label = _label(gt, target)
        origin = _component_origin(gt)
        origin_counts.setdefault(origin, {"hidden_gt": 0, "eligible_hidden_gt": 0, "evaluated": 0, "TP": 0, "TN": 0, "FP": 0, "FN": 0, "excluded": 0})
        origin_counts[origin]["hidden_gt"] += 1
        if label in GT_LABELS[target]:
            origin_counts[origin]["eligible_hidden_gt"] += 1
        prediction = prediction_by_key.get(key)
        if prediction is None:
            metadata_candidates = prediction_by_metadata.get(metadata_key(gt), [])
            if len(metadata_candidates) > 1:
                ambiguous = {
                    "identity_key": key,
                    "metadata_key": metadata_key(gt),
                    "candidate_count": len(metadata_candidates),
                }
                ambiguous_metadata_joins.append(ambiguous)
                joins.append({**ambiguous, "status": "AMBIGUOUS_METADATA_JOIN", "gt_label": label,
                              "component_origin": origin})
                invalid += 1
                origin_counts[origin]["excluded"] += 1
                continue
            prediction = metadata_candidates[0] if len(metadata_candidates) == 1 else None
        if prediction is None:
            joins.append({"identity_key": key, "status": "MISSING_PREDICTION", "gt_label": label, "component_origin": origin})
            continue
        matched_prediction_ids.add(id(prediction))
        contract_errors = contract_errors_by_prediction_id.get(id(prediction), [])
        if contract_errors:
            joins.append({
                "identity_key": key,
                "status": "INVALID_PREDICTION_CONTRACT",
                "gt_label": label,
                "component_origin": origin,
                "contract_errors": contract_errors,
            })
            invalid += 1
            origin_counts[origin]["excluded"] += 1
            continue
        status = _target_status(prediction, target)
        parity = None
        gt_manifest = _manifest(gt, gt_path.parent)
        prediction_manifest = _manifest(prediction, prediction_path.parent)
        gt_digest = gt.get("environment_manifest_digest")
        prediction_digest = prediction.get("environment_manifest_digest")
        if gt_digest and prediction_digest and gt_digest != prediction_digest:
            parity = {"status": "INVALID_ENVIRONMENT_PARITY", "differences": ["manifest_sha256"]}
        elif gt_manifest and prediction_manifest:
            parity = compare_environment_manifests(gt_manifest, prediction_manifest)
        if parity and parity["status"] != "MATCHED":
            environment_mismatches.append({"identity_key": key, **parity})
            joins.append({"identity_key": key, "status": "INVALID_ENVIRONMENT_PARITY", "gt_label": label})
            invalid += 1
            origin_counts[origin]["excluded"] += 1
            continue
        predicted = _prediction_value(prediction, target)
        if status == "BLOCKED":
            blocked += 1
            join_status = "BLOCKED"
            origin_counts[origin]["excluded"] += 1
        elif status == "UNASSESSED":
            unassessed += 1
            join_status = "UNASSESSED"
            origin_counts[origin]["excluded"] += 1
        elif status != "VALID" or predicted is None:
            invalid += 1
            join_status = "INVALID"
            origin_counts[origin]["excluded"] += 1
        elif label not in GT_LABELS[target]:
            unassessed += 1
            join_status = "UNASSESSED"
            origin_counts[origin]["excluded"] += 1
        else:
            expected = label in {"POSITIVE", "IMPACT_YES"}
            join_status = "TP" if expected and predicted else "TN" if not expected and not predicted else "FP" if predicted else "FN"
            if join_status == "TP":
                tp += 1
            elif join_status == "TN":
                tn += 1
            elif join_status == "FP":
                fp += 1
            else:
                fn += 1
            origin_counts[origin]["evaluated"] += 1
            origin_counts[origin][join_status] += 1
        joins.append({
            "identity_key": key,
            "status": join_status,
            "prediction_status": status,
            "prediction": predicted,
            "gt_label": label,
            "component_origin": origin,
        })

    missing_gt_predictions = [
        {"identity_key": key, "status": "PREDICTION_WITHOUT_GT"}
        for key, prediction in prediction_by_key.items()
        if id(prediction) not in matched_prediction_ids
    ]
    evaluated = tp + tn + fp + fn
    eligible_hidden_gt = sum(_label(row, target) in GT_LABELS[target] for row in gt_rows)
    matched_eligible = evaluated + invalid + blocked + unassessed
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    f1 = 2 * precision * recall / (precision + recall) if precision is not None and recall is not None and precision + recall else None
    accuracy = (tp + tn) / evaluated if evaluated else None
    for values in origin_counts.values():
        origin_evaluated = values["evaluated"]
        origin_tp, origin_tn = values["TP"], values["TN"]
        origin_fp, origin_fn = values["FP"], values["FN"]
        origin_precision = origin_tp / (origin_tp + origin_fp) if origin_tp + origin_fp else None
        origin_recall = origin_tp / (origin_tp + origin_fn) if origin_tp + origin_fn else None
        values["metrics"] = {
            "precision": origin_precision,
            "recall": origin_recall,
            "f1": 2 * origin_precision * origin_recall / (origin_precision + origin_recall)
            if origin_precision is not None and origin_recall is not None and origin_precision + origin_recall else None,
            "accuracy": (origin_tp + origin_tn) / origin_evaluated if origin_evaluated else None,
        }
        values["assessed_coverage"] = origin_evaluated / values["eligible_hidden_gt"] if values["eligible_hidden_gt"] else None
    contract_failed = bool(preflight_contract_errors)
    result = {
        "schema_version": "vulveil-evaluation/v2",
        "evaluation_status": "FAILED" if contract_failed else "COMPLETED",
        **({"failure_reason": "INVALID_PREDICTION_CONTRACT"} if contract_failed else {}),
        "evaluator": "OSCAR independent evaluator",
        "evaluation_target": target,
        "prediction_file": str(prediction_path.resolve()),
        "hidden_gt_file": str(gt_path.resolve()),
        "counts": {
            "predictions": len(predictions),
            "hidden_gt": len(gt_rows),
            "evaluated": evaluated,
            "eligible_hidden_gt": eligible_hidden_gt,
            "missing_prediction": len([item for item in joins if item["status"] == "MISSING_PREDICTION"]),
            "prediction_without_gt": len(missing_gt_predictions),
            "duplicate_prediction": len(duplicate_predictions),
            "duplicate_gt": len(duplicate_gt),
            "invalid": invalid,
            "contract_invalid": len(preflight_contract_errors),
            "blocked": blocked,
            "unassessed": unassessed,
            "environment_mismatch": len(environment_mismatches),
            "ambiguous_metadata_join": len(ambiguous_metadata_joins),
        },
        "confusion_matrix": {"TP": tp, "TN": tn, "FP": fp, "FN": fn},
        "metrics": {"precision": precision, "recall": recall, "f1": f1, "accuracy": accuracy},
        "coverage": {
            "assessed_coverage": evaluated / eligible_hidden_gt if eligible_hidden_gt else None,
            "abstention_unassessed_rate": (invalid + blocked + unassessed) / matched_eligible if matched_eligible else None,
        },
        "join_audit": {
            "rows": joins,
            "missing_prediction": [item for item in joins if item["status"] == "MISSING_PREDICTION"],
            "prediction_without_gt": missing_gt_predictions,
            "duplicate_prediction": duplicate_predictions,
            "duplicate_gt": duplicate_gt,
            "environment_mismatch": environment_mismatches,
            "invalid_prediction_contract": preflight_contract_errors,
            "ambiguous_metadata_join": ambiguous_metadata_joins,
        },
        "statistics_policy": {
            "invalid_blocked_unassessed_excluded_from_confusion_matrix": True,
            "evaluator_only_component_reading_hidden_gt": True,
            "component_origin_breakdown_uses_hidden_gt_only": True,
            "evaluation_target_is_explicit": True,
            "agent_observation_labels_are_never_impact_labels": target == "concrete-impact",
            "metrics_usable_for_formal_conclusions": not contract_failed and evaluated > 0,
            "duplicate_identity_fails_closed": True,
        },
        "component_origin_breakdown": origin_counts,
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate blind OSCAR predictions against hidden GT.")
    parser.add_argument("--predictions", required=True)
    parser.add_argument("--hidden-gt", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--target", required=True, choices=sorted(TARGETS))
    args = parser.parse_args()
    result = evaluate(Path(args.predictions), Path(args.hidden_gt), Path(args.output), target=args.target)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 2 if result.get("evaluation_status") == "FAILED" else 0


if __name__ == "__main__":
    raise SystemExit(main())
