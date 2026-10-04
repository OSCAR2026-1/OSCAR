"""End-to-end blind test-set orchestration.

The test-set manifest contains only label-free blind cases. Hidden labels are
opened only after every blind case has finished, by the independent evaluator.
"""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import re
from pathlib import Path
from typing import Any

try:
    from oscar.runtime.blind_runtime import BlindCaseError, _scan_blind_value, load_json, run_blind_case, validate_blind_case
    from oscar.runtime.environment import build_frozen_environment_manifest
    from oscar.evaluation.evaluate import evaluate
    from oscar.runtime.failure_diagnostics import aggregate_diagnostics, diagnose_prediction
    from oscar.contracts.prediction_contract import assert_prediction_contract, validate_prediction_contract
except ImportError:  # pragma: no cover - direct script execution
    from oscar.runtime.blind_runtime import BlindCaseError, _scan_blind_value, load_json, run_blind_case, validate_blind_case
    from oscar.runtime.environment import build_frozen_environment_manifest
    from oscar.evaluation.evaluate import evaluate
    from oscar.runtime.failure_diagnostics import aggregate_diagnostics, diagnose_prediction
    from oscar.contracts.prediction_contract import assert_prediction_contract, validate_prediction_contract


def _safe_name(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_.-]+", "-", value).strip("-") or "case"


def _case_id(spec: dict[str, Any]) -> str:
    value = spec.get("case_id")
    if not isinstance(value, str) or not value:
        value = spec.get("identity", {}).get("advisory")
    if not isinstance(value, str) or not value:
        raise ValueError("blind case must define case_id or legacy identity.advisory")
    return value


def load_test_set(path: Path) -> list[Path]:
    manifest = load_json(path.resolve())
    if manifest.get("schema_version") != "vulveil-test-set/v1":
        raise ValueError("test set schema_version must be vulveil-test-set/v1")
    manifest_errors = _scan_blind_value(manifest)
    if manifest_errors:
        raise ValueError("test set is not label-free: " + "; ".join(manifest_errors))
    rows = manifest.get("cases")
    if not isinstance(rows, list) or not rows:
        raise ValueError("test set must contain a non-empty cases list")
    result: list[Path] = []
    seen: set[str] = set()
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("case"), str):
            raise ValueError("each test set case must contain a relative case path")
        case_path = (path.parent / row["case"]).resolve()
        try:
            case_path.relative_to(path.parent.resolve())
        except ValueError as exc:
            raise ValueError(f"case path escapes test set directory: {row['case']}") from exc
        if case_path in result:
            raise ValueError(f"duplicate test case path: {case_path}")
        spec = load_json(case_path)
        errors = validate_blind_case(spec)
        if errors:
            raise ValueError(f"invalid blind case {case_path}: {'; '.join(errors)}")
        case_id = _case_id(spec)
        if case_id in seen:
            raise ValueError(f"duplicate case_id: {case_id}")
        seen.add(case_id)
        result.append(case_path)
    return result


def _invalid_prediction(spec: dict[str, Any], error: Exception) -> dict[str, Any]:
    identity = dict(spec.get("identity", {}))
    identity["case_id"] = spec.get("case_id", identity.get("advisory", ""))
    raw_reason = f"{type(error).__name__}: {error}"
    reason_probe = {"invalid_reason": raw_reason}
    invalid_reason = raw_reason if not _scan_blind_value(reason_probe) else (
        f"{type(error).__name__}: error message redacted by blind contract"
    )
    return {
        "schema_version": "vulveil-prediction/v2",
        "case_identity": identity,
        "run_status": "INVALID",
        "invalid_reason": invalid_reason,
        "predicted_reachability": None,
        "predicted_impact": None,
        "impact_status": "UNASSESSED",
        "impact_effect_ids": [],
        "effect_realized": None,
        "maximum_effect_boundary": "UNASSESSED",
        "agent_visible": None,
        "impact_reason": "blind execution failed before impact assessment",
        "repetition_policy": {
            "schema_version": "vulveil-impact-repetitions/v1",
            "minimum_paired_repetitions": 3,
            "vulnerable_repetitions": 0,
            "fixed_repetitions": 0,
            "all_runs_valid_and_paired": False,
        },
        "per_effect": {},
    }


def _evaluation_audit(evaluation: dict[str, Any], expected_cases: int) -> dict[str, Any]:
    counts = evaluation["counts"]
    failures: list[str] = []
    if counts.get("predictions") != expected_cases:
        failures.append("prediction_count_mismatch")
    if counts.get("hidden_gt") != expected_cases:
        failures.append("hidden_gt_count_mismatch")
    if counts.get("evaluated") != expected_cases:
        failures.append("evaluated_count_mismatch")
    for field in (
        "missing_prediction",
        "prediction_without_gt",
        "duplicate_prediction",
        "duplicate_gt",
        "invalid",
        "blocked",
        "unassessed",
        "environment_mismatch",
    ):
        if counts.get(field, 0):
            failures.append(f"{field}_present")
    return {"status": "PASSED" if not failures else "FAILED", "failures": failures}


def _resumable_prediction(spec: dict[str, Any], case_output: Path) -> dict[str, Any] | None:
    """Reuse only a prediction whose label-free case manifest still matches."""
    prediction_path = case_output / "prediction.json"
    manifest_path = case_output / "environment_manifest.json"
    if not prediction_path.is_file() or not manifest_path.is_file():
        return None
    try:
        prediction = load_json(prediction_path)
        manifest = load_json(manifest_path)
    except (OSError, ValueError, json.JSONDecodeError):
        return None
    if not isinstance(prediction, dict) or not isinstance(manifest, dict):
        return None
    if prediction.get("schema_version") != "vulveil-prediction/v2":
        return None
    if validate_prediction_contract(prediction):
        return None
    if _scan_blind_value(prediction, allow_runtime_status=True):
        return None
    expected_case_id = str(spec.get("case_id", spec.get("identity", {}).get("advisory", "")))
    if prediction.get("case_identity", {}).get("case_id") != expected_case_id:
        return None
    if prediction.get("run_status") not in {"VALID", "UNASSESSED", "BLOCKED", "INVALID"}:
        return None
    expected_manifest = build_frozen_environment_manifest(spec, case_output)
    if manifest.get("manifest_sha256") != expected_manifest.get("manifest_sha256"):
        return None
    if prediction.get("environment_manifest_digest") != manifest.get("manifest_sha256"):
        return None
    return prediction


def _run_case_attempt(case_path: Path, case_output: Path) -> tuple[dict[str, Any], str | None]:
    spec = load_json(case_path)
    try:
        prediction = run_blind_case(spec, case_output, base_dir=case_path.parent)
        error = None
    except Exception as exc:  # noqa: BLE001 - one bad case must not abort a batch
        prediction = _invalid_prediction(spec, exc)
        assert_prediction_contract(prediction)
        (case_output / "prediction.json").parent.mkdir(parents=True, exist_ok=True)
        (case_output / "prediction.json").write_text(
            json.dumps(prediction, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        error = str(exc)
    return prediction, error


def _run_one_case(
    case_path: Path,
    case_output: Path,
    *,
    resume: bool,
    environment_retries: int = 0,
) -> dict[str, Any]:
    spec = load_json(case_path)
    case_id = _case_id(spec)
    reused = _resumable_prediction(spec, case_output) if resume else None
    if reused is not None:
        prediction, error, resumed = reused, None, True
    else:
        prediction, error = _run_case_attempt(case_path, case_output)
        resumed = False
    visible_error = prediction.get("invalid_reason") if error else None
    attempts: list[dict[str, Any]] = [{
        "attempt": 0,
        "output": str(case_output),
        "run_status": prediction.get("run_status", "INVALID"),
        "error": visible_error,
        "diagnostic": diagnose_prediction(prediction),
    }]
    for retry_index in range(1, environment_retries + 1):
        if not attempts[-1]["diagnostic"].get("retryable_environment_failure"):
            break
        retry_output = case_output / f"retry-{retry_index}"
        retry_prediction, retry_error = _run_case_attempt(case_path, retry_output)
        retry_visible_error = retry_prediction.get("invalid_reason") if retry_error else None
        attempts.append({
            "attempt": retry_index,
            "output": str(retry_output),
            "run_status": retry_prediction.get("run_status", "INVALID"),
            "error": retry_visible_error,
            "diagnostic": diagnose_prediction(retry_prediction),
        })
    return {"case_id": case_id, "case": str(case_path), "output": str(case_output),
            "run_status": prediction.get("run_status", "INVALID"), "error": visible_error,
            "resumed": resumed, "retry_count": len(attempts) - 1,
            "retry_resolved": any(
                item["attempt"] > 0 and item["run_status"] == "VALID" for item in attempts
            ),
            "attempts": attempts, "prediction": prediction}


def run_test_set(
    manifest_path: Path,
    output_root: Path,
    hidden_gt_path: Path | None = None,
    *,
    evaluation_target: str | None = None,
    workers: int = 1,
    resume: bool = False,
    environment_retries: int = 0,
) -> dict[str, Any]:
    if not isinstance(workers, int) or workers < 1:
        raise ValueError("workers must be a positive integer")
    if not isinstance(environment_retries, int) or environment_retries < 0:
        raise ValueError("environment_retries must be a non-negative integer")
    if hidden_gt_path is not None and evaluation_target not in {"agent-observation", "concrete-impact"}:
        raise ValueError("evaluation_target must be explicit when hidden GT is supplied")
    case_paths = load_test_set(manifest_path)
    output_root = output_root.resolve()
    output_root.mkdir(parents=True, exist_ok=True)
    predictions: list[dict[str, Any]] = []
    runs: list[dict[str, Any]] = []
    used_output_names: set[str] = set()

    entries: list[tuple[Path, Path]] = []
    for case_path in case_paths:
        spec = load_json(case_path)
        case_id = _case_id(spec)
        output_name = _safe_name(case_id)
        if output_name in used_output_names:
            raise ValueError(f"case output name collision: {case_id}")
        used_output_names.add(output_name)
        entries.append((case_path, output_root / "cases" / output_name))

    completed: dict[int, dict[str, Any]] = {}
    if workers == 1:
        for index, (case_path, case_output) in enumerate(entries):
            completed[index] = _run_one_case(
                case_path, case_output, resume=resume, environment_retries=environment_retries
            )
    else:
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="vulveil-case") as pool:
            futures = {
                pool.submit(
                    _run_one_case, case_path, case_output, resume=resume,
                    environment_retries=environment_retries,
                ): index
                for index, (case_path, case_output) in enumerate(entries)
            }
            for future in as_completed(futures):
                completed[futures[future]] = future.result()

    for index in range(len(entries)):
        run = completed[index]
        prediction = run.pop("prediction")
        predictions.append(prediction)
        runs.append(run)

    predictions_path = output_root / "predictions.jsonl"
    predictions_path.write_text(
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in predictions),
        encoding="utf-8",
    )
    diagnostic_summary = aggregate_diagnostics([diagnose_prediction(row) for row in predictions])
    diagnostics_path = output_root / "diagnostic_summary.json"
    diagnostics_path.write_text(json.dumps(diagnostic_summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    retry_diagnostics = [
        attempt["diagnostic"]
        for run in runs
        for attempt in run.get("attempts", [])[1:]
    ]
    retry_diagnostic_summary = aggregate_diagnostics(retry_diagnostics)
    retry_diagnostics_path = output_root / "retry_diagnostic_summary.json"
    retry_diagnostics_path.write_text(
        json.dumps(retry_diagnostic_summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    result: dict[str, Any] = {
        "schema_version": "vulveil-e2e-test-run/v1",
        "status": "COMPLETED" if all(row.get("run_status") in {"VALID", "UNASSESSED", "BLOCKED", "INVALID"} for row in predictions) else "ERROR",
        "test_set": str(manifest_path.resolve()),
        "output_root": str(output_root),
        "prediction_file": str(predictions_path),
        "diagnostic_summary_file": str(diagnostics_path),
        "diagnostic_category_counts": diagnostic_summary["category_counts"],
        "retry_diagnostic_summary_file": str(retry_diagnostics_path),
        "case_count": len(predictions),
        "valid_count": sum(row.get("run_status") == "VALID" for row in predictions),
        "unassessed_count": sum(row.get("run_status") == "UNASSESSED" for row in predictions),
        "blocked_count": sum(row.get("run_status") == "BLOCKED" for row in predictions),
        "invalid_count": sum(row.get("run_status") == "INVALID" for row in predictions),
        "workers": workers,
        "resume": resume,
        "environment_retries": environment_retries,
        "resumed_count": sum(item.get("resumed") is True for item in runs),
        "retry_count": sum(item.get("retry_count", 0) for item in runs),
        "retry_resolved_count": sum(item.get("retry_resolved") is True for item in runs),
        "runs": runs,
    }
    if hidden_gt_path is not None:
        evaluation_path = output_root / "evaluation.json"
        evaluation = evaluate(predictions_path, hidden_gt_path.resolve(), evaluation_path, target=str(evaluation_target))
        audit = _evaluation_audit(evaluation, len(predictions))
        result["evaluation_file"] = str(evaluation_path)
        result["evaluation_status"] = audit["status"]
        result["evaluation_audit"] = audit
        result["evaluation"] = {
            "confusion_matrix": evaluation["confusion_matrix"],
            "metrics": evaluation["metrics"],
            "counts": evaluation["counts"],
        }
    (output_root / "test_set_run.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Run a label-free OSCAR blind test set end to end")
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--hidden-gt")
    parser.add_argument("--evaluation-target", choices=("agent-observation", "concrete-impact"))
    parser.add_argument("--workers", type=int, default=1, help="parallel blind case workers (default: 1)")
    parser.add_argument("--resume", action="store_true", help="reuse matching label-free predictions in the output directory")
    parser.add_argument("--retry-environment", type=int, default=0, help="retry only environment-classified failures without replacing the original prediction")
    args = parser.parse_args()
    result = run_test_set(
        Path(args.manifest),
        Path(args.output),
        Path(args.hidden_gt) if args.hidden_gt else None,
        evaluation_target=args.evaluation_target,
        workers=args.workers,
        resume=args.resume,
        environment_retries=args.retry_environment,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    if result["status"] != "COMPLETED":
        return 1
    if result.get("invalid_count", 0) or result.get("blocked_count", 0):
        return 2
    if result.get("evaluation_status") == "FAILED":
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
