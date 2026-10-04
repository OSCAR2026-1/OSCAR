"""Stage 1 source/patch localization for the blind OSCAR pipeline.

The localizer consumes only label-free case material.  A shared component
contract selects the source and patch pair; the resulting anchor and repair
predicate are identical for server, dependency, and framework origins.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from oscar.analysis.effect_modeling import (
    VULNERABILITY_CATEGORIES,
    _all_structures,
    _changed_structured_nodes,
    _contains_gt,
    _line_ref,
    _parse_patch,
    _patch_related_parse_errors,
    _patch_text,
    _read_sources,
    _structure_semantics,
)
from oscar.contracts.component_contract import (
    COMPONENT_ORIGINS,
    component_for_localization,
    component_from_spec,
    is_legacy_direct_runtime,
    validate_vulnerability_component,
)
try:
    from oscar.analysis.repair_predicate import build_repair_predicate, empty_repair_predicate, validate_repair_predicate
except ImportError:  # pragma: no cover
    from oscar.analysis.repair_predicate import build_repair_predicate, empty_repair_predicate, validate_repair_predicate


SCHEMA_VERSION = "vulveil-localization/v1"
DIRECT_RUNTIME_RELATION_STATUSES = {
    "affected_exact_direct_runtime",
    "affected_commit_direct_runtime",
}


def _digest(value: Any) -> str:
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def validate_direct_runtime_dependency(spec: dict[str, Any]) -> list[str]:
    """Compatibility name retained for callers that used the old validator."""
    return validate_vulnerability_component(spec)


def _analysis_spec(spec: dict[str, Any], component: dict[str, Any]) -> dict[str, Any]:
    """Select the component source pair without changing the public case shape."""
    origin = component.get("origin")
    source = spec.get("source") if isinstance(spec.get("source"), dict) else {}
    use_analysis = (
        origin == "MCP_FRAMEWORK"
        and ("analysis_source" in spec or source.get("role") in {"server_runtime", "framework_runtime"})
    ) or (
        origin == "DIRECT_RUNTIME_DEPENDENCY"
        and ("analysis_source" in spec or source.get("role") in {"server_runtime", "framework_runtime"})
    )
    if not use_analysis:
        return spec
    selected = dict(spec)
    selected["source"] = spec.get("analysis_source", {})
    selected["patch"] = spec.get("analysis_patch", {})
    return selected


def _unassessed(spec: dict[str, Any], reasons: list[str], evidence_refs: list[str] | None = None) -> dict[str, Any]:
    identity = spec.get("identity", {}) if isinstance(spec.get("identity"), dict) else {}
    result = {
        "schema_version": SCHEMA_VERSION,
        "status": "UNASSESSED",
        "case_identity": {
            key: identity.get(key)
            for key in ("advisory", "package", "vulnerable_version", "fixed_version")
            if identity.get(key) is not None
        },
        "component_origin": component_for_localization(spec).get("origin"),
        "vulnerability_component": {},
        "anchor_candidates": [],
        "repair_predicate": empty_repair_predicate(),
        "source_evidence": [],
        "patch_evidence": evidence_refs or [],
        "unresolved_reasons": sorted(set(reasons)),
    }
    result["localization_digest"] = _digest(result)
    return result


def build_localization(spec: dict[str, Any], *, base_dir: Path | None = None) -> dict[str, Any]:
    """Map a label-free source/patch pair to Stage 1 anchor candidates."""
    scope_errors = validate_vulnerability_component(spec)
    if scope_errors:
        return _unassessed(spec, scope_errors)
    component = component_for_localization(spec)
    selected_spec = _analysis_spec(spec, component)
    if component.get("origin") in {"DIRECT_RUNTIME_DEPENDENCY", "MCP_FRAMEWORK"} and (
        selected_spec is not spec and (
            not isinstance(selected_spec.get("source"), dict)
            or not selected_spec.get("source", {}).get("vulnerable")
            or not selected_spec.get("source", {}).get("fixed", selected_spec.get("source", {}).get("patched"))
        )
    ):
        source_label = "framework" if component.get("origin") == "MCP_FRAMEWORK" else "dependency"
        return _unassessed(spec, [f"analysis_source: {source_label} component analysis source pair is missing"])

    vulnerable_sources, vulnerable_errors = _read_sources(selected_spec, "vulnerable", base_dir)
    fixed_sources, fixed_errors = _read_sources(selected_spec, "fixed", base_dir)
    patch_text, patch_errors = _patch_text(selected_spec, base_dir)
    patch = _parse_patch(patch_text) if patch_text else {"parse_valid": False, "files": []}
    reasons = [*vulnerable_errors, *fixed_errors, *patch_errors]
    if not patch.get("parse_valid"):
        reasons.append("patch has no parseable added/deleted hunk")

    vulnerable_structures = _all_structures(vulnerable_sources)
    fixed_structures = _all_structures(fixed_sources)
    _, _, vulnerable_parse_errors = _structure_semantics(vulnerable_structures)
    _, _, fixed_parse_errors = _structure_semantics(fixed_structures)
    reasons.extend(_patch_related_parse_errors(vulnerable_parse_errors + fixed_parse_errors, patch))
    changed_nodes = _changed_structured_nodes(vulnerable_structures, fixed_structures, patch)
    if not changed_nodes:
        reasons.append("no structured source anchor maps to a changed patch hunk")
    if reasons:
        return _unassessed(
            spec,
            reasons,
            [f"patch:{item.get('path', 'unknown')}" for item in patch.get("files", [])],
        )

    declared_category = spec.get("vulnerability_category") or spec.get("experiment_type")
    anchors: list[dict[str, Any]] = []
    for node in changed_nodes[:8]:
        source_ref = node.get("source_ref") or _line_ref(node.get("path", "unknown"), node.get("line"))
        categories = sorted(set(node.get("categories", [])))
        anchors.append({
            "anchor_id": f"anchor-{len(anchors) + 1}",
            "kind": node.get("node_kind", "call"),
            "symbol": node.get("callee", node.get("name", node.get("predicate", ""))),
            "function": node.get("function"),
            "side": node.get("side"),
            "source_ref": source_ref,
            "source_path": node.get("path"),
            "source_line": node.get("line"),
            # Categories are optional sampling metadata. Preserve arbitrary
            # labels without turning the priority list into a runtime gate.
            "vulnerability_category": declared_category if isinstance(declared_category, str) and declared_category else None,
            "patch_change": node.get("change", "structural-diff"),
            "mapping": "patch-hunk-and-structured-node",
            "confidence": 0.9,
            "evidence_refs": [source_ref, f"patch:{node.get('path', 'unknown')}"],
        })

    fixed_nodes = [node for node in changed_nodes if node.get("side") == "fixed"]
    repair_predicate = build_repair_predicate(
        patch=patch,
        vulnerable_structures=vulnerable_structures,
        fixed_structures=fixed_structures,
        changed_nodes=changed_nodes,
        anchors=anchors,
        fixed_sources=fixed_sources,
    )
    predicate_errors = validate_repair_predicate(repair_predicate)
    if predicate_errors:
        repair_predicate["classification_status"] = "UNRESOLVED"
        repair_predicate.setdefault("unresolved_reasons", []).extend(predicate_errors)
    localized_component = dict(component)
    localized_component["source_evidence"] = sorted({item["source_ref"] for item in anchors})
    localized_component["patch_evidence"] = repair_predicate["patch_refs"]
    result = {
        "schema_version": SCHEMA_VERSION,
        "status": "LOCALIZED",
        "case_identity": {
            key: spec.get("identity", {}).get(key)
            for key in ("advisory", "package", "vulnerable_version", "fixed_version")
        },
        "component_origin": component.get("origin"),
        "vulnerability_component": localized_component,
        "anchor_candidates": anchors,
        "repair_predicate": repair_predicate,
        "source_evidence": sorted({item["source_ref"] for item in anchors}),
        "patch_evidence": repair_predicate["patch_refs"],
        "unresolved_reasons": [],
    }
    validation_errors = validate_localization(result)
    if validation_errors:
        return _unassessed(spec, validation_errors, result["patch_evidence"])
    result["localization_digest"] = _digest(result)
    return result


def validate_localization(localization: dict[str, Any]) -> list[str]:
    errors = _contains_gt(localization)
    if localization.get("schema_version") != SCHEMA_VERSION:
        errors.append(f"schema_version must be {SCHEMA_VERSION}")
    if localization.get("status") not in {"LOCALIZED", "PARTIAL", "UNASSESSED", "INVALID"}:
        errors.append("localization status is invalid")
    if localization.get("status") == "LOCALIZED":
        if not localization.get("anchor_candidates"):
            errors.append("LOCALIZED result requires anchor_candidates")
        if not localization.get("repair_predicate"):
            errors.append("LOCALIZED result requires repair_predicate")
        component_errors = validate_vulnerability_component(localization)
        errors.extend(component_errors)
        if localization.get("repair_predicate"):
            errors.extend(validate_repair_predicate(localization["repair_predicate"]))
    return sorted(set(errors))


__all__ = [
    "SCHEMA_VERSION",
    "DIRECT_RUNTIME_RELATION_STATUSES",
    "build_localization",
    "validate_direct_runtime_dependency",
    "validate_localization",
]
