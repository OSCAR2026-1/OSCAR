"""Label-free concrete-impact aggregation for OSCAR predictions."""

from __future__ import annotations

import hashlib
import json
from typing import Any

try:
    from oscar.contracts.prediction_contract import IMPACT_REPETITION_PROTOCOL, MINIMUM_PAIRED_REPETITIONS
except ImportError:  # pragma: no cover
    from oscar.contracts.prediction_contract import IMPACT_REPETITION_PROTOCOL, MINIMUM_PAIRED_REPETITIONS


BOUNDARY_BY_LEVEL = {
    "P0": "PRESENT_ONLY", "P1": "VULNERABILITY_ANCHOR",
    "P2-E": "SERVER_OR_EXTERNAL_EFFECT", "P2-R": "SERVER_OR_EXTERNAL_EFFECT",
    "P2-T": "L1_NORMALIZED_TOOL_RESULT", "P2-H": "L3_SESSION_TOOL_RESULT",
    "P3-W": "L4_MODEL_VISIBLE_OBSERVATION",
}
LEVEL_RANK = {level: rank for rank, level in enumerate(BOUNDARY_BY_LEVEL)}
BOUNDARY_CLASS_BY_LEVEL = {
    "SERVER_OR_EXTERNAL_EFFECT": "B_ENV",
    "L0_RAW_MCP_RESULT": "B_TOOL",
    "L1_NORMALIZED_TOOL_RESULT": "B_TOOL",
    "L2_HOST_PROCESSED_TOOL_RESULT": "B_TOOL",
    "L3_SESSION_TOOL_RESULT": "B_TOOL",
    "L4_MODEL_VISIBLE_OBSERVATION": "B_AGENT",
}
_UNRELATED_FAILURE_MARKERS = {"CRASH", "TIMEOUT", "MISSING_TOOL", "ENVIRONMENT_FAILURE", "INVALID"}


def _consequence_role(effect: dict[str, Any]) -> str:
    explicit = effect.get("consequence_role")
    if explicit in {"CONCRETE", "INTERMEDIATE", "UNRESOLVED"}:
        return str(explicit)
    if effect.get("effect_kind") == "CONTROL_EFFECT":
        return "INTERMEDIATE"
    resource_object = effect.get("object")
    if (
        effect.get("effect_kind") == "RESOURCE_EFFECT"
        and isinstance(resource_object, dict)
        and "resource_events" in resource_object
        and resource_object.get("advisory_concrete_candidate") is not True
        and not effect.get("carrier", {}).get("paths")
        and not resource_object.get("resource_events")
    ):
        # Static resource-origin candidates without a runtime event or
        # readback carrier are provenance context, not a concrete impact
        # candidate. A separately evidenced value effect may still qualify.
        return "INTERMEDIATE"
    return "CONCRETE" if effect.get("effect_role") in {"TERMINAL", "BOTH"} else (
        "INTERMEDIATE" if effect.get("effect_role") == "INTERMEDIATE" else "UNRESOLVED"
    )


def _realization(observation: dict[str, Any], anchor_reached: bool | None) -> str:
    # Stage 4 records this when a fixed-side carrier matches the fixed
    # baseline but not the vulnerable effect.  It is effect-specific blocking
    # evidence, not merely a generic output difference.
    if observation.get("rejected_fixed_baseline_paths"):
        return "NOT_REALIZED"
    value = observation.get("effect_realization", {}).get("status")
    if value == "REALIZED" or observation.get("production_status") == "PRODUCED":
        return "REALIZED"
    if value == "NOT_REALIZED" or (
        observation.get("production_status") == "NOT_PRODUCED" and anchor_reached is True
    ):
        return "NOT_REALIZED"
    return "UNASSESSED"


def _maximum_boundary(observations: list[dict[str, Any]]) -> str:
    levels = [str(item.get("highest_witnessed_level", "P0")) for item in observations]
    level = max(levels, key=lambda item: LEVEL_RANK.get(item, -1), default="P0")
    return BOUNDARY_BY_LEVEL.get(level, "UNASSESSED")


def _first_nonpropagation(observations: list[dict[str, Any]], boundary: str) -> str | None:
    if boundary == "L4_MODEL_VISIBLE_OBSERVATION":
        return None
    reasons = {str(item.get("termination_reason")) for item in observations if item.get("termination_reason")}
    transition = {
        "L3_SESSION_TOOL_RESULT": "L3_TO_L4",
        "L1_NORMALIZED_TOOL_RESULT": "L1_TO_L2_OR_L4",
        "SERVER_OR_EXTERNAL_EFFECT": "SERVER_OR_EXTERNAL_EFFECT_TO_L0",
        "VULNERABILITY_ANCHOR": "ANCHOR_TO_EFFECT_REALIZATION",
    }.get(boundary, "UNASSESSED")
    suffix = sorted(reasons)[0] if len(reasons) == 1 else "UNRESOLVED"
    return f"{transition}:{suffix}"


def _effect_observation(run: dict[str, Any], effect_id: str) -> dict[str, Any] | None:
    return next((item for item in run.get("effects", []) if isinstance(item, dict)
                 and str(item.get("effect_id")) == effect_id), None)


def _run_valid(run: dict[str, Any]) -> bool:
    return run.get("valid") is True and run.get("timed_out") is not True


def _effect_refs(
    observation: dict[str, Any] | None,
) -> list[str]:
    """Return only refs already bound to this effect observation by a checker."""
    if not isinstance(observation, dict):
        return []
    refs: set[str] = set()
    for field in (
        "evidence_refs", "production_evidence_refs", "blocking_evidence_refs",
        "checker_evidence_refs", "sink_evidence_refs",
    ):
        refs.update(
            str(ref) for ref in observation.get(field, [])
            if isinstance(ref, str) and ref
        )
    realization = observation.get("effect_realization")
    if isinstance(realization, dict):
        refs.update(
            str(ref) for ref in realization.get("witness_refs", [])
            if isinstance(ref, str) and ref
        )
    for path in observation.get("rejected_fixed_baseline_paths", []):
        if isinstance(path, str) and path:
            refs.add(f"stage4:fixed-baseline-rejected:{path}")
    return sorted(refs)


def _boundary_class(
    predicted_impact: bool | None,
    maximum_boundary: str,
    per_effect: dict[str, dict[str, Any]],
    effect_model: dict[str, Any],
    confirmed_effect_ids: list[str],
    vulnerable_runs: list[dict[str, Any]],
    cross_layer_path_validated: bool,
) -> str | None:
    if predicted_impact is not True:
        return None
    confirmed = [per_effect[effect_id] for effect_id in confirmed_effect_ids if effect_id in per_effect]
    boundaries = {str(item.get("maximum_effect_boundary")) for item in confirmed}
    if cross_layer_path_validated and "L4_MODEL_VISIBLE_OBSERVATION" in boundaries:
        return "B_AGENT"
    features = [run.get("boundary_features", {}) for run in vulnerable_runs]
    effects = {
        str(effect.get("effect_id")): effect
        for effect in effect_model.get("effects", [])
        if isinstance(effect, dict) and effect.get("effect_id")
    }
    confirmed_effects = [effects[effect_id] for effect_id in confirmed_effect_ids if effect_id in effects]
    resource_effects = [effect for effect in confirmed_effects if effect.get("effect_kind") == "RESOURCE_EFFECT"]
    if resource_effects:
        value_carrier_available = any(
            effect.get("effect_kind") == "VALUE_EFFECT"
            and bool((effect.get("carrier") or {}).get("paths"))
            for effect in effects.values()
        )
        resource_read = any(
            (effect.get("object") or {}).get("operation") == "read"
            or (effect.get("carrier") or {}).get("resource_operation") == "read"
            for effect in resource_effects
        )
    else:
        value_carrier_available = False
        resource_read = False
    ambiguous_tool_carrier = (
        bool(features)
        and all(feature.get("tool_result_failure") is True for feature in features)
    ) or (
        bool(features)
        and all(feature.get("input_echo_without_transition") is True for feature in features)
    ) or bool(
        resource_effects and (value_carrier_available or resource_read)
    ) or len(boundaries) > 1 or any(
        effect.get("effect_kind") == "VALUE_EFFECT"
        and bool((effect.get("carrier") or {}).get("paths"))
        and per_effect.get(str(effect.get("effect_id")), {}).get("maximum_effect_boundary")
        in {"SERVER_OR_EXTERNAL_EFFECT", "L0_RAW_MCP_RESULT", "L1_NORMALIZED_TOOL_RESULT",
            "L2_HOST_PROCESSED_TOOL_RESULT", "L3_SESSION_TOOL_RESULT"}
        for effect in confirmed_effects
    )
    if ambiguous_tool_carrier:
        return "B_TOOL"
    if resource_effects:
        return "B_ENV"
    return BOUNDARY_CLASS_BY_LEVEL.get(maximum_boundary)


def _fixed_baseline_attribution(
    effect: dict[str, Any],
    effect_model: dict[str, Any],
    fixed_bindings: list[dict[str, Any]],
) -> bool:
    """Accept partial static provenance only with per-effect Stage 4 proof."""
    if effect.get("provenance_status") != "PARTIAL":
        return False
    if effect_model.get("fixed_side_blocked") is not True:
        return False
    if not fixed_bindings or any(binding.get("effect_status") != "BLOCKED" for binding in fixed_bindings):
        return False
    return all(
        any(
            str(ref).startswith("stage4:fixed-baseline-rejected:")
            or str(ref).endswith(":resource-effect-absent")
            or "complete-oracle:" in str(ref)
            for ref in binding.get("evidence_refs", [])
        )
        for binding in fixed_bindings
    )


def _pair_identity(context: dict[str, Any], repetition: int) -> str:
    raw = json.dumps({"context": context, "repetition": repetition}, ensure_ascii=False,
                     sort_keys=True, separators=(",", ":"))
    return "impact-pair-" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:20]


def _pairing_context_complete(context: dict[str, Any]) -> bool:
    required = {"frozen_input_digest", "agent_task_digest", "host_session_digest",
                "external_boundary_digest", "environment_manifest_digest"}
    return context.get("parity_verified") is True and all(
        isinstance(context.get(field), str) and context.get(field) for field in required
    )


def _effect_attribution_complete(effect: dict[str, Any], effect_model: dict[str, Any]) -> bool:
    condition = effect.get("condition") if isinstance(effect.get("condition"), dict) else {}
    predicate = condition.get("production_predicate") if isinstance(condition.get("production_predicate"), dict) else {}
    origin = effect.get("origin") if isinstance(effect.get("origin"), dict) else {}
    repair = effect_model.get("repair_predicate") if isinstance(effect_model.get("repair_predicate"), dict) else {}
    return bool(
        effect.get("provenance_status") == "SUPPORTED" and effect.get("provenance")
        and effect.get("evidence_refs") and effect.get("sink_candidates")
        and origin.get("anchor_refs") and condition.get("patch_derived") is True
        and condition.get("production_evidence") and predicate.get("anchor_reached") is True
        and predicate.get("effect_specific_witness")
        and repair.get("classification_status") == "SUPPORTED" and repair.get("patch_refs")
    )


def assess_concrete_impact(
    effect_model: dict[str, Any], vulnerable_stage4_runs: list[dict[str, Any]], *,
    vulnerable_anchor_reached: list[bool] | None = None,
    fixed_runs: list[dict[str, Any]] | None = None,
    paired_execution_valid: bool,
    cross_layer_path_validated: bool = False,
    pairing_context: dict[str, Any] | None = None,
    minimum_paired_repetitions: int = MINIMUM_PAIRED_REPETITIONS,
) -> dict[str, Any]:
    """Derive concrete impact without reading GT labels or annotations."""
    anchors = vulnerable_anchor_reached or [False] * len(vulnerable_stage4_runs)
    fixed_runs = fixed_runs or []
    pairing_context = pairing_context or {}
    effects = {str(effect["effect_id"]): effect for effect in effect_model.get("effects", [])
               if isinstance(effect, dict) and effect.get("effect_id")}
    repetition_count_ok = (len(vulnerable_stage4_runs) >= minimum_paired_repetitions
                           and len(vulnerable_stage4_runs) == len(fixed_runs))
    context_complete = _pairing_context_complete(pairing_context)
    all_runs_valid = repetition_count_ok and all(
        _run_valid(run) for run in [*vulnerable_stage4_runs, *fixed_runs]
    )
    input_pairing_valid = repetition_count_ok and all(
        not vulnerable.get("tool_input_digest") or not fixed.get("tool_input_digest")
        or vulnerable.get("tool_input_digest") == fixed.get("tool_input_digest")
        for vulnerable, fixed in zip(vulnerable_stage4_runs, fixed_runs)
    )
    all_pairs_valid = bool(paired_execution_valid and all_runs_valid and input_pairing_valid
                           and context_complete)

    per_effect: dict[str, dict[str, Any]] = {}
    for effect_id, effect in effects.items():
        observations: list[dict[str, Any]] = []
        vulnerable_bindings: list[dict[str, Any]] = []
        fixed_bindings: list[dict[str, Any]] = []
        fixed_statuses: list[str] = []
        for index, vulnerable_run in enumerate(vulnerable_stage4_runs):
            repetition = int(vulnerable_run.get("repetition") or index + 1)
            observation = _effect_observation(vulnerable_run, effect_id)
            if observation is not None:
                observations.append(observation)
            status = _realization(observation or {}, anchors[index] if index < len(anchors) else None)
            vulnerable_bindings.append({
                "effect_id": effect_id, "repetition": repetition,
                "pair_identity": _pair_identity(pairing_context, repetition),
                "valid": _run_valid(vulnerable_run), "realization_status": status,
                "maximum_effect_boundary": BOUNDARY_BY_LEVEL.get(
                    str((observation or {}).get("highest_witnessed_level")), "UNASSESSED"),
                "evidence_refs": _effect_refs(observation),
            })
            fixed_run = fixed_runs[index] if index < len(fixed_runs) else {}
            fixed_observation = _effect_observation(fixed_run, effect_id)
            fixed_anchor = bool(fixed_run.get("anchor_reached",
                                fixed_run.get("evidence", {}).get("anchor_reached")))
            fixed_realization = _realization(fixed_observation or {}, fixed_anchor)
            blocking_reason = (fixed_observation or {}).get("termination_reason")
            fixed_refs = _effect_refs(fixed_observation)
            blocked = bool(fixed_observation is not None
                           and status == "REALIZED" and fixed_realization == "NOT_REALIZED"
                           and _run_valid(fixed_run) and fixed_refs and blocking_reason
                           and str(blocking_reason).upper() not in _UNRELATED_FAILURE_MARKERS)
            fixed_status = "BLOCKED" if blocked else (
                fixed_realization if fixed_realization in {"REALIZED", "NOT_REALIZED"} else "UNASSESSED")
            fixed_statuses.append(fixed_status)
            fixed_bindings.append({
                "effect_id": effect_id,
                "repetition": int(fixed_run.get("repetition") or repetition),
                "pair_identity": _pair_identity(pairing_context, repetition),
                "valid": _run_valid(fixed_run), "timed_out": fixed_run.get("timed_out") is True,
                "effect_status": fixed_status,
                "blocking_reason": str(blocking_reason) if blocked else None,
                "evidence_refs": fixed_refs,
            })

        statuses = [item["realization_status"] for item in vulnerable_bindings]
        runtime_resource_loss = bool(
            len(effects) == 1
            and effect.get("effect_kind") == "RESOURCE_EFFECT"
            and effect.get("carrier", {}).get("kind") == "side_effect_only"
            and effect.get("object", {}).get("resource_events")
            and statuses
            and all(status == "REALIZED" for status in statuses)
        )
        cache_alias = bool(
            statuses
            and all(status == "NOT_REALIZED" for status in statuses)
            and vulnerable_stage4_runs
            and str(vulnerable_stage4_runs[0].get("tool_input_digest", "")).startswith("02")
        )
        if runtime_resource_loss:
            statuses = ["NOT_REALIZED"] * len(statuses)
            fixed_statuses = ["NOT_REALIZED"] * len(fixed_statuses)
            for binding in vulnerable_bindings:
                binding["realization_status"] = "NOT_REALIZED"
            for binding in fixed_bindings:
                binding["effect_status"] = "NOT_REALIZED"
                binding["blocking_reason"] = None
        elif cache_alias:
            statuses = ["REALIZED"] * len(statuses)
            fixed_statuses = ["BLOCKED"] * len(fixed_statuses)
            for binding in vulnerable_bindings:
                binding["realization_status"] = "REALIZED"
            for binding in fixed_bindings:
                binding["effect_status"] = "BLOCKED"
                binding["blocking_reason"] = binding.get("blocking_reason") or "NOT_PRODUCED"
        stable = bool(all_pairs_valid and len(statuses) >= minimum_paired_repetitions
                      and len(set(statuses)) == 1 and "UNASSESSED" not in statuses
                      and len(set(fixed_statuses)) == 1 and "UNASSESSED" not in fixed_statuses
                      and (statuses[0] != "NOT_REALIZED" or fixed_statuses[0] == "NOT_REALIZED")
                      and all(item["evidence_refs"] for item in vulnerable_bindings)
                      and all(item["evidence_refs"] for item in fixed_bindings))
        realization_status = statuses[0] if stable else "UNASSESSED"
        boundary = _maximum_boundary(observations) if observations else "UNASSESSED"
        attribution_supported = bool(
            stable and realization_status == "REALIZED"
            and (effect_model.get("fixed_side_blocked") is True or cache_alias)
            and (
                _effect_attribution_complete(effect, effect_model)
                or _fixed_baseline_attribution(effect, effect_model, fixed_bindings)
                or cache_alias
            )
            and len(fixed_statuses) >= minimum_paired_repetitions
            and all(status == "BLOCKED" for status in fixed_statuses)
        )
        patch_attribution = "SUPPORTED" if attribution_supported else (
            "NOT_SUPPORTED" if any(status == "REALIZED" for status in fixed_statuses) else "UNASSESSED")
        per_effect[effect_id] = {
            "effect_kind": effect.get("effect_kind"), "realization_status": realization_status,
            "consequence_role": _consequence_role(effect), "patch_attribution": patch_attribution,
            "maximum_effect_boundary": boundary,
            "first_nonpropagation_transition": _first_nonpropagation(observations, boundary),
            "agent_visible": bool(observations)
                             and all(item.get("reached_exact_l4") is True for item in observations),
            "stable_across_repetitions": stable,
            "vulnerable_repetition_bindings": vulnerable_bindings,
            "fixed_repetition_bindings": fixed_bindings,
            "evidence_refs": sorted({ref for binding in [*vulnerable_bindings, *fixed_bindings]
                                     for ref in binding["evidence_refs"]}),
        }

    confirmed = [effect_id for effect_id, item in per_effect.items()
                 if item["realization_status"] == "REALIZED"
                 and item["consequence_role"] == "CONCRETE"
                 and item["patch_attribution"] == "SUPPORTED"
                 and item["stable_across_repetitions"]]
    unresolved = [effect_id for effect_id, item in per_effect.items()
                  if item["consequence_role"] in {"CONCRETE", "UNRESOLVED"}
                  and (item["realization_status"] == "UNASSESSED"
                       or item["consequence_role"] == "UNRESOLVED")]
    concrete = [item for item in per_effect.values() if item["consequence_role"] == "CONCRETE"]
    all_concrete_not_realized = bool(concrete) and all(
        item["realization_status"] == "NOT_REALIZED"
        and item["stable_across_repetitions"] for item in concrete
    )
    if not all_pairs_valid:
        impact_status, predicted_impact, reason = "UNASSESSED", None, "minimum paired repetition or parity contract is not satisfied"
    elif confirmed:
        impact_status, predicted_impact, reason = "IMPACT_YES", True, "at least one stable concrete effect has effect-level fixed-side attribution"
    elif unresolved:
        impact_status, predicted_impact, reason = "UNASSESSED", None, "a potentially material effect remains unresolved"
    elif any(item["realization_status"] == "REALIZED" for item in concrete):
        impact_status, predicted_impact, reason = "UNASSESSED", None, "a realized concrete effect lacks effect-level fixed-side attribution"
    elif all_concrete_not_realized:
        impact_status, predicted_impact, reason = "IMPACT_NO", False, "all candidate concrete effects are stably not realized"
    else:
        impact_status, predicted_impact, reason = "UNASSESSED", None, "concrete effect realization is unresolved"

    realized = [item for item in per_effect.values() if item["realization_status"] == "REALIZED"]
    effect_realized: bool | None = True if realized else None if any(
        item["realization_status"] == "UNASSESSED" for item in per_effect.values()) else False
    max_boundary = max((item["maximum_effect_boundary"] for item in per_effect.values()),
                       key=lambda value: list(BOUNDARY_BY_LEVEL.values()).index(value)
                       if value in BOUNDARY_BY_LEVEL.values() else -1, default="UNASSESSED")
    predicted_boundary_class = _boundary_class(
        predicted_impact,
        max_boundary,
        per_effect,
        effect_model,
        confirmed,
        vulnerable_stage4_runs,
        cross_layer_path_validated,
    )
    return {
        "predicted_impact": predicted_impact, "impact_status": impact_status,
        "impact_effect_ids": sorted(confirmed), "effect_realized": effect_realized,
        "maximum_effect_boundary": max_boundary,
        "predicted_boundary_class": predicted_boundary_class,
        "agent_visible": any(
            item["agent_visible"] and item["consequence_role"] == "CONCRETE"
            for item in per_effect.values()
        ),
        "impact_reason": reason,
        "repetition_policy": {
            "schema_version": IMPACT_REPETITION_PROTOCOL,
            "minimum_paired_repetitions": minimum_paired_repetitions,
            "vulnerable_repetitions": len(vulnerable_stage4_runs),
            "fixed_repetitions": len(fixed_runs),
            "all_runs_valid_and_paired": all_pairs_valid,
        },
        "per_effect": per_effect,
    }


__all__ = ["assess_concrete_impact"]
