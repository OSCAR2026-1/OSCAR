"""Structural and semantic validation for OSCAR prediction artifacts."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from oscar.paths import SCHEMA_ROOT


PREDICTION_V2 = "vulveil-prediction/v2"
PREDICTION_V1 = "vulveil-prediction/v1"
IMPACT_REPETITION_PROTOCOL = "vulveil-impact-repetitions/v1"
MINIMUM_PAIRED_REPETITIONS = 3
BOUNDARY_RANK = {
    "PRESENT_ONLY": 0,
    "VULNERABILITY_ANCHOR": 1,
    "SERVER_OR_EXTERNAL_EFFECT": 2,
    "L0_RAW_MCP_RESULT": 3,
    "L1_NORMALIZED_TOOL_RESULT": 4,
    "L2_HOST_PROCESSED_TOOL_RESULT": 5,
    "L3_SESSION_TOOL_RESULT": 6,
    "L4_MODEL_VISIBLE_OBSERVATION": 7,
    "UNASSESSED": -1,
}


def _schema() -> dict[str, Any]:
    path = SCHEMA_ROOT / "prediction.schema.json"
    return json.loads(path.read_text(encoding="utf-8"))


def _format_schema_error(error: Any) -> str:
    location = "$" + "".join(
        f"[{item}]" if isinstance(item, int) else f".{item}" for item in error.absolute_path
    )
    return f"{location}: {error.message}"


def _binding_errors(
    effect_id: str,
    item: dict[str, Any],
    minimum: int,
    *,
    require_minimum: bool,
) -> list[str]:
    errors: list[str] = []
    vulnerable = item.get("vulnerable_repetition_bindings", [])
    fixed = item.get("fixed_repetition_bindings", [])
    if not isinstance(vulnerable, list) or not isinstance(fixed, list):
        return [f"per_effect.{effect_id}: repetition bindings must be arrays"]
    if len(vulnerable) != len(fixed) or (require_minimum and len(vulnerable) < minimum):
        errors.append(f"per_effect.{effect_id}: requires at least {minimum} paired repetitions")
        return errors
    vulnerable_by_pair: dict[str, dict[str, Any]] = {}
    fixed_by_pair: dict[str, dict[str, Any]] = {}
    for side, bindings, target in (
        ("vulnerable", vulnerable, vulnerable_by_pair),
        ("fixed", fixed, fixed_by_pair),
    ):
        repetitions: set[int] = set()
        for binding in bindings:
            if not isinstance(binding, dict):
                errors.append(f"per_effect.{effect_id}: {side} binding must be an object")
                continue
            pair_identity = binding.get("pair_identity")
            repetition = binding.get("repetition")
            if binding.get("effect_id") != effect_id:
                errors.append(f"per_effect.{effect_id}: {side} binding effect_id mismatch")
            if not isinstance(pair_identity, str) or not pair_identity:
                errors.append(f"per_effect.{effect_id}: {side} binding lacks pair_identity")
            elif pair_identity in target:
                errors.append(f"per_effect.{effect_id}: duplicate {side} pair_identity")
            else:
                target[pair_identity] = binding
            if not isinstance(repetition, int) or repetition < 1 or repetition in repetitions:
                errors.append(f"per_effect.{effect_id}: invalid or duplicate {side} repetition")
            else:
                repetitions.add(repetition)
            if binding.get("valid") is not True:
                errors.append(f"per_effect.{effect_id}: {side} repetition is not valid")
            refs = binding.get("evidence_refs")
            if not isinstance(refs, list) or any(not isinstance(ref, str) or not ref for ref in refs):
                errors.append(f"per_effect.{effect_id}: {side} repetition has invalid effect-specific evidence refs")
            else:
                synthetic_prefix = f"effect:{effect_id}:trace:"
                if any(ref.startswith(synthetic_prefix) for ref in refs):
                    errors.append(
                        f"per_effect.{effect_id}: {side} repetition uses synthesized trace-level evidence refs"
                    )
                if (require_minimum or item.get("stable_across_repetitions") is True) and not refs:
                    errors.append(f"per_effect.{effect_id}: {side} repetition lacks effect-specific evidence refs")
    if set(vulnerable_by_pair) != set(fixed_by_pair):
        errors.append(f"per_effect.{effect_id}: vulnerable/fixed pair identities differ")
    else:
        for pair_identity in vulnerable_by_pair:
            if vulnerable_by_pair[pair_identity].get("repetition") != fixed_by_pair[pair_identity].get("repetition"):
                errors.append(f"per_effect.{effect_id}: repetition mismatch for pair {pair_identity}")
    statuses = [binding.get("realization_status") for binding in vulnerable if isinstance(binding, dict)]
    fixed_statuses = [binding.get("effect_status") for binding in fixed if isinstance(binding, dict)]
    if item.get("stable_across_repetitions") is True and (
        len(statuses) < minimum or len(set(statuses)) != 1 or "UNASSESSED" in statuses
        or len(set(fixed_statuses)) != 1 or "UNASSESSED" in fixed_statuses
        or (statuses and statuses[0] == "NOT_REALIZED" and fixed_statuses[0] != "NOT_REALIZED")
    ):
        errors.append(f"per_effect.{effect_id}: stable flag contradicts vulnerable repetitions")
    if item.get("patch_attribution") == "SUPPORTED":
        for binding in fixed:
            if not isinstance(binding, dict):
                continue
            if binding.get("effect_status") != "BLOCKED":
                errors.append(f"per_effect.{effect_id}: supported attribution requires fixed BLOCKED status")
            if not binding.get("blocking_reason"):
                errors.append(f"per_effect.{effect_id}: supported attribution requires a blocking reason")
    return errors


def semantic_prediction_errors(prediction: dict[str, Any]) -> list[str]:
    """Validate cross-field constraints that JSON Schema cannot express safely."""
    errors: list[str] = []
    run_status = prediction.get("run_status")
    impact_status = prediction.get("impact_status")
    predicted_impact = prediction.get("predicted_impact")
    predicted_reachability = prediction.get("predicted_reachability")
    agent_visible = prediction.get("agent_visible")
    maximum_boundary = prediction.get("maximum_effect_boundary")
    impact_ids = prediction.get("impact_effect_ids", [])
    per_effect = prediction.get("per_effect", {})
    policy = prediction.get("repetition_policy", {})

    if run_status != "VALID" and (predicted_impact is not None or predicted_reachability is not None):
        errors.append("non-VALID runs require null binary predictions")
    expected_impact = {"IMPACT_YES": True, "IMPACT_NO": False, "UNASSESSED": None}.get(impact_status)
    if predicted_impact is not expected_impact:
        errors.append("impact_status and predicted_impact are inconsistent")
    if agent_visible is True:
        if predicted_reachability is not True:
            errors.append("agent_visible=true requires predicted_reachability=true")
        if BOUNDARY_RANK.get(str(maximum_boundary), -1) < BOUNDARY_RANK["L4_MODEL_VISIBLE_OBSERVATION"]:
            errors.append("agent_visible=true requires exact L4 maximum boundary")
    if predicted_reachability is True and agent_visible is not True:
        errors.append("predicted_reachability=true requires agent_visible=true")
    if run_status == "VALID" and predicted_reachability is False and agent_visible is not False:
        errors.append("VALID predicted_reachability=false requires agent_visible=false")

    if not isinstance(impact_ids, list) or len(impact_ids) != len(set(impact_ids)) or any(
        not isinstance(effect_id, str) or not effect_id for effect_id in impact_ids
    ):
        errors.append("impact_effect_ids must be unique non-empty strings")
        impact_ids = []
    if not isinstance(per_effect, dict) or any(not isinstance(effect_id, str) or not effect_id for effect_id in per_effect):
        errors.append("per_effect keys must be non-empty effect IDs")
        per_effect = {}

    minimum = policy.get("minimum_paired_repetitions") if isinstance(policy, dict) else None
    if minimum != MINIMUM_PAIRED_REPETITIONS:
        errors.append(f"minimum_paired_repetitions must be {MINIMUM_PAIRED_REPETITIONS}")
        minimum = MINIMUM_PAIRED_REPETITIONS
    if isinstance(policy, dict):
        vulnerable_count = policy.get("vulnerable_repetitions")
        fixed_count = policy.get("fixed_repetitions")
        if impact_status in {"IMPACT_YES", "IMPACT_NO"} and (
            policy.get("all_runs_valid_and_paired") is not True
            or not isinstance(vulnerable_count, int) or vulnerable_count < minimum
            or not isinstance(fixed_count, int) or fixed_count < minimum
            or vulnerable_count != fixed_count
        ):
            errors.append("formal impact requires the complete minimum paired repetition policy")

    for effect_id, item in per_effect.items():
        if not isinstance(item, dict):
            errors.append(f"per_effect.{effect_id} must be an object")
            continue
        errors.extend(_binding_errors(
            effect_id, item, minimum,
            require_minimum=(
                impact_status in {"IMPACT_YES", "IMPACT_NO"}
                and item.get("consequence_role") == "CONCRETE"
            ),
        ))
        if isinstance(policy, dict):
            if len(item.get("vulnerable_repetition_bindings", [])) != policy.get("vulnerable_repetitions"):
                errors.append(f"per_effect.{effect_id}: vulnerable binding count contradicts repetition policy")
            if len(item.get("fixed_repetition_bindings", [])) != policy.get("fixed_repetitions"):
                errors.append(f"per_effect.{effect_id}: fixed binding count contradicts repetition policy")

    if impact_status == "IMPACT_YES":
        if not impact_ids:
            errors.append("IMPACT_YES requires at least one impact effect")
        if prediction.get("effect_realized") is not True:
            errors.append("IMPACT_YES requires effect_realized=true")
        for effect_id in impact_ids:
            item = per_effect.get(effect_id)
            if not isinstance(item, dict):
                errors.append(f"impact effect {effect_id} is absent from per_effect")
                continue
            required = {
                "realization_status": "REALIZED",
                "consequence_role": "CONCRETE",
                "patch_attribution": "SUPPORTED",
                "stable_across_repetitions": True,
            }
            for field, expected in required.items():
                if item.get(field) != expected:
                    errors.append(f"impact effect {effect_id} requires {field}={expected}")
    elif impact_status == "IMPACT_NO":
        if impact_ids:
            errors.append("IMPACT_NO requires empty impact_effect_ids")
        concrete_effect_ids = [
            effect_id for effect_id, item in per_effect.items()
            if isinstance(item, dict) and item.get("consequence_role") == "CONCRETE"
        ]
        if not concrete_effect_ids:
            errors.append("IMPACT_NO requires at least one concrete effect candidate")
        for effect_id, item in per_effect.items():
            if not isinstance(item, dict):
                continue
            if item.get("consequence_role") == "CONCRETE" and item.get("realization_status") == "REALIZED":
                errors.append(f"IMPACT_NO contradicts realized concrete effect {effect_id}")
            if item.get("consequence_role") == "UNRESOLVED" or item.get("realization_status") == "UNASSESSED":
                errors.append(f"IMPACT_NO contradicts potentially material unresolved effect {effect_id}")
            if item.get("consequence_role") == "CONCRETE" and (
                item.get("realization_status") != "NOT_REALIZED"
                or item.get("stable_across_repetitions") is not True
            ):
                errors.append(f"IMPACT_NO requires stable NOT_REALIZED concrete effect {effect_id}")
    return sorted(set(errors))


def validate_prediction_contract(
    prediction: Any,
    *,
    target: str | None = None,
    allow_v1_agent_observation: bool = False,
) -> list[str]:
    if not isinstance(prediction, dict):
        return ["prediction must be an object"]
    version = prediction.get("schema_version")
    if version == PREDICTION_V1:
        if target != "agent-observation" or not allow_v1_agent_observation:
            return ["v1 prediction is only allowed by the explicit agent-observation compatibility path"]
        status = str(prediction.get("run_status", "INVALID")).upper()
        value = prediction.get("predicted_reachability")
        if status == "VALID" and not isinstance(value, bool):
            return ["VALID v1 prediction requires boolean predicted_reachability"]
        if status != "VALID" and value is not None:
            return ["non-VALID v1 prediction requires null predicted_reachability"]
        return []
    if version != PREDICTION_V2:
        return ["prediction schema_version is not supported"]
    validator = Draft202012Validator(_schema())
    errors = [_format_schema_error(error) for error in validator.iter_errors(prediction)]
    errors.extend(semantic_prediction_errors(prediction))
    return sorted(set(errors))


def assert_prediction_contract(prediction: dict[str, Any]) -> None:
    errors = validate_prediction_contract(prediction)
    if errors:
        raise ValueError("INVALID_PREDICTION_CONTRACT: " + "; ".join(errors))


__all__ = [
    "IMPACT_REPETITION_PROTOCOL",
    "MINIMUM_PAIRED_REPETITIONS",
    "assert_prediction_contract",
    "semantic_prediction_errors",
    "validate_prediction_contract",
]
