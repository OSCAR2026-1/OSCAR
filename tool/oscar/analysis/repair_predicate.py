"""Structured patch-scoped repair predicates for Stage 1 and Stage 2.

This module deliberately stops at evidence-backed structure.  A predicate is
not a formal proof of semantic completeness: static conditions are extracted
from the patch and source, then paired traces can attest whether the same
effect was blocked.
"""

from __future__ import annotations

import ast
import copy
import hashlib
import json
from pathlib import Path
from typing import Any

try:
    from oscar.analysis.checker_analysis import analyze_checkers
except ImportError:  # pragma: no cover
    from oscar.analysis.checker_analysis import analyze_checkers


REPAIR_SCHEMA_VERSION = "vulveil-repair-predicate/v2"
REPAIR_KIND = "patch-scoped-repair-predicate"
CONDITION_KINDS = {
    "added_guard", "removed_guard", "changed_call", "changed_argument",
    "changed_return", "added_type_check", "added_boundary_check",
    "added_normalization", "added_sanitization", "changed_exception_behavior",
    "changed_resource_operation", "structural_difference",
}
SUPPORTED_CONDITION_KINDS = CONDITION_KINDS - {"structural_difference"}
_NORMALIZATION_NAMES = {"resolve", "realpath", "normpath", "abspath", "normalize", "absolute"}
_RESOURCE_CALL_NAMES = {
    "open", "read", "readfile", "write", "writefile", "unlink", "rename",
    "fetch", "get", "post", "put", "request", "send", "connect",
}
_EXCEPTION_CALL_NAMES = {"exception", "valueerror", "typeerror", "permissionerror", "runtimeerror", "httpserror"}
VALIDATION_CONCLUSIONS = {
    "CHECKER_SPECIFIC_VALIDATED",
    "PAIRED_EFFECT_DIFFERENCE_ONLY",
    "UNASSESSED",
}
_TRACE_LEVELS = {
    "L0_RAW_MCP_RESULT",
    "L1_NORMALIZED_TOOL_RESULT",
    "L2_HOST_PROCESSED_TOOL_RESULT",
    "L3_SESSION_TOOL_RESULT",
    "L4_MODEL_VISIBLE_OBSERVATION",
}
_IDENTITY_FIELDS = ("repetition", "tool_call_id", "invocation_id", "trace_id", "span_id", "session_id")


def _digest(value: Any) -> str:
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def _normalize_expression(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    try:
        return ast.unparse(ast.parse(text, mode="eval").body)
    except (SyntaxError, ValueError, TypeError):
        return " ".join(text.split())


def _file_matches(left: str, right: str) -> bool:
    left = Path(str(left)).as_posix().removeprefix("a/").removeprefix("b/")
    right = Path(str(right)).as_posix().removeprefix("a/").removeprefix("b/")
    return left == right or left.endswith(f"/{right}") or right.endswith(f"/{left}")


def _patch_refs(node: dict[str, Any], patch: dict[str, Any]) -> list[str]:
    path = str(node.get("path", "unknown"))
    side = str(node.get("side", ""))
    line = int(node.get("line") or 0)
    refs: list[str] = []
    for file in patch.get("files", []):
        if not isinstance(file, dict) or not _file_matches(path, str(file.get("path", ""))):
            continue
        changes = file.get("additions", []) if side == "fixed" else file.get("deletions", [])
        exact_change = any(int(change.get("line", 0)) == line for change in changes if isinstance(change, dict))
        node_end = int(node.get("end_line") or line)
        in_changed_hunk = any(
            int(hunk.get("new_start" if side == "fixed" else "old_start", 0)) <= node_end
            and line <= int(hunk.get("new_start" if side == "fixed" else "old_start", 0))
            + max(int(hunk.get("new_count" if side == "fixed" else "old_count", 0)) - 1, 0)
            for hunk in file.get("hunks", [])
            if isinstance(hunk, dict)
        )
        if not exact_change and not in_changed_hunk:
            continue
        refs.append(f"patch:{file.get('path', path)}")
        for index, hunk in enumerate(file.get("hunks", []), start=1):
            start = int(hunk.get("new_start" if side == "fixed" else "old_start", 0))
            count = int(hunk.get("new_count" if side == "fixed" else "old_count", 0))
            if start <= line <= start + max(count - 1, 0):
                refs.append(f"patch:{file.get('path', path)}#hunk-{index}:{'+' if side == 'fixed' else '-'}{line}")
                break
    return sorted(set(refs))


def _anchor_id(node: dict[str, Any], anchors: list[dict[str, Any]]) -> str | None:
    exact = str(node.get("source_ref", ""))
    for anchor in anchors:
        if anchor.get("source_ref") == exact:
            return str(anchor.get("anchor_id"))
    for anchor in anchors:
        if anchor.get("source_path") == node.get("path") and anchor.get("function") == node.get("function"):
            return str(anchor.get("anchor_id"))
    return None


def _checker_for_node(node: dict[str, Any], checkers: list[dict[str, Any]]) -> dict[str, Any] | None:
    path = str(node.get("path", ""))
    line = int(node.get("line") or 0)
    function = node.get("function")
    candidates = [
        checker for checker in checkers
        if _file_matches(path, str(checker.get("source_ref", "").rsplit(":", 1)[0]))
        and (
            int(str(checker.get("source_ref", "0")).rsplit(":", 1)[-1]) == line
            or int(node.get("line") or 0) <= int(str(checker.get("source_ref", "0")).rsplit(":", 1)[-1]) <= int(node.get("end_line") or line)
        )
    ]
    return sorted(candidates, key=lambda item: (item.get("source_ref", ""), item.get("checker_id", "")))[0] if candidates else None


def _condition_kind(node: dict[str, Any], checker: dict[str, Any] | None, paired_nodes: list[dict[str, Any]]) -> str:
    node_kind = node.get("node_kind")
    callee = str(node.get("callee", "")).rsplit(".", 1)[-1].lower()
    if node_kind == "call" and callee in _EXCEPTION_CALL_NAMES:
        return "changed_exception_behavior"
    if node_kind == "call" and callee in _RESOURCE_CALL_NAMES:
        return "changed_resource_operation"
    if checker:
        checker_kind = checker.get("checker_kind")
        if checker_kind == "type_check":
            return "added_type_check"
        if checker_kind in {"boundary_check", "path_containment", "url_redirect"}:
            return "added_boundary_check"
        if checker_kind == "path_normalization":
            return "added_normalization"
        if checker_kind == "sanitization":
            return "added_sanitization"
        if checker_kind == "command_argument":
            return "changed_argument"
    if node_kind == "guard":
        return "added_guard" if node.get("side") == "fixed" else "removed_guard"
    if node_kind == "return":
        return "changed_return"
    if node_kind == "call":
        same_callee = [
            other for other in paired_nodes
            if other.get("side") != node.get("side")
            and other.get("node_kind") == "call"
            and other.get("function") == node.get("function")
            and other.get("callee") == node.get("callee")
        ]
        if same_callee and any(other.get("arguments") != node.get("arguments") or other.get("keywords") != node.get("keywords") for other in same_callee):
            return "changed_argument"
        return "changed_call"
    return "structural_difference"


def _condition_expression(node: dict[str, Any]) -> str:
    return str(node.get("predicate") or node.get("callee") or node.get("value") or node.get("arguments") or "")


def _filter_checkers(checkers: list[dict[str, Any]], changed_nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    scopes = {(str(node.get("path")), node.get("function")) for node in changed_nodes if node.get("side") == "fixed"}
    result = []
    for checker in checkers:
        source_ref = str(checker.get("source_ref", ""))
        checker_path, _, raw_line = source_ref.rpartition(":")
        line = int(raw_line) if raw_line.isdigit() else 0
        in_scope = any(
            _file_matches(checker_path, path)
            and (checker.get("function") == function or any(
                int(node.get("line") or 0) <= line <= int(node.get("end_line") or node.get("line") or 0)
                for node in changed_nodes if node.get("side") == "fixed" and _file_matches(str(node.get("path", "")), checker_path)
            ))
            for path, function in scopes
        )
        if in_scope:
            result.append(copy.deepcopy(checker))
    return result


def build_repair_predicate(
    *,
    patch: dict[str, Any],
    vulnerable_structures: list[dict[str, Any]],
    fixed_structures: list[dict[str, Any]],
    changed_nodes: list[dict[str, Any]],
    anchors: list[dict[str, Any]],
    fixed_sources: list[dict[str, Any]],
) -> dict[str, Any]:
    """Create a v2 predicate from patch-mapped structured source nodes."""
    fixed_analysis = analyze_checkers(fixed_sources, side="fixed")
    all_nodes: list[dict[str, Any]] = []
    for structures, side in ((vulnerable_structures, "vulnerable"), (fixed_structures, "fixed")):
        for structure in structures:
            for kind in ("calls", "guards", "returns"):
                for raw in structure.get(kind, []):
                    node = dict(raw)
                    node.update({
                        "side": side,
                        "node_kind": kind[:-1],
                        "path": structure.get("path"),
                        "source_ref": f"{structure.get('path')}:{raw.get('line') or 1}",
                    })
                    all_nodes.append(node)
    scoped_checkers = _filter_checkers(fixed_analysis["checkers"], changed_nodes)
    conditions: list[dict[str, Any]] = []
    for node in changed_nodes:
        checker = _checker_for_node(node, scoped_checkers)
        refs = _patch_refs(node, patch)
        anchor = _anchor_id(node, anchors)
        kind = _condition_kind(node, checker, all_nodes)
        expression = _condition_expression(node)
        evidence = sorted(set([str(node.get("source_ref", "")), *refs, *(checker or {}).get("evidence_refs", [])]))
        status = "SUPPORTED" if kind in SUPPORTED_CONDITION_KINDS and anchor and refs and expression else "UNRESOLVED"
        condition = {
            "condition_id": f"condition-{len(conditions) + 1}",
            "kind": kind,
            "side": node.get("side"),
            "function": node.get("function"),
            "source_ref": node.get("source_ref"),
            "anchor_id": anchor,
            "expression": expression,
            "normalized_form": _normalize_expression(expression),
            "patch_refs": refs,
            "evidence_refs": evidence,
            "classification_status": status,
        }
        if checker:
            condition["checker_id"] = checker.get("checker_id")
        conditions.append(condition)

    path_constraints = []
    for constraint in fixed_analysis.get("path_constraints", []):
        linked = [condition for condition in conditions if condition.get("source_ref") in constraint.get("source_refs", []) or condition.get("checker_id") in {item.get("checker_id") for item in scoped_checkers}]
        if not linked:
            continue
        constraint = copy.deepcopy(constraint)
        constraint["anchor_ids"] = sorted({condition["anchor_id"] for condition in linked if condition.get("anchor_id")})
        path_constraints.append(constraint)

    patch_refs = sorted({ref for condition in conditions for ref in condition.get("patch_refs", []) if ref.startswith("patch:")})
    legacy_conditions = [condition.get("expression", "") for condition in conditions if condition.get("expression")]
    unresolved = [condition for condition in conditions if condition.get("classification_status") != "SUPPORTED"]
    if not conditions or all(condition.get("kind") == "structural_difference" for condition in conditions):
        classification_status = "UNRESOLVED"
    elif unresolved:
        classification_status = "PARTIAL"
    else:
        classification_status = "SUPPORTED"
    obligations = []
    for checker in scoped_checkers:
        obligations.append({
            "obligation": f"fixed checker {checker['checker_id']} must block the vulnerable effect before the localized sink",
            "required": True,
            "evidence_refs": sorted(set(checker.get("evidence_refs", []))),
        })
    if not obligations and conditions:
        obligations.append({
            "obligation": "fixed-side structural difference must block the same vulnerability-derived effect",
            "required": True,
            "evidence_refs": patch_refs,
        })
    return {
        "schema_version": REPAIR_SCHEMA_VERSION,
        "kind": REPAIR_KIND,
        "anchor_ids": sorted({str(anchor.get("anchor_id")) for anchor in anchors if anchor.get("anchor_id")}),
        "patch_refs": patch_refs,
        "conditions": conditions,
        "checkers": scoped_checkers,
        "path_constraints": path_constraints,
        "blocking_obligations": obligations,
        "classification_status": classification_status,
        "dynamic_checks": {},
        "fixed_side_validation": {},
        "fixed_side_blocked": None,
        "conditions_added_or_changed": legacy_conditions or ["fixed-side source structure differs at the localized anchor"],
    }


def empty_repair_predicate() -> dict[str, Any]:
    """Return a schema-valid, explicitly unresolved predicate placeholder."""
    return {
        "schema_version": REPAIR_SCHEMA_VERSION,
        "kind": REPAIR_KIND,
        "anchor_ids": [],
        "patch_refs": [],
        "conditions": [],
        "checkers": [],
        "path_constraints": [],
        "blocking_obligations": [],
        "classification_status": "UNRESOLVED",
        "dynamic_checks": {},
        "fixed_side_validation": {},
        "fixed_side_blocked": None,
        "conditions_added_or_changed": [],
    }


def normalize_repair_predicate(value: Any) -> dict[str, Any]:
    """Upgrade old predicate objects without treating them as verified v2."""
    if not isinstance(value, dict) or not value:
        return empty_repair_predicate()
    result = copy.deepcopy(value)
    if result.get("schema_version") == REPAIR_SCHEMA_VERSION:
        return result
    legacy = result.get("conditions_added_or_changed", [])
    if not isinstance(legacy, list):
        legacy = [legacy] if legacy else []
    result.update({
        "schema_version": REPAIR_SCHEMA_VERSION,
        "kind": REPAIR_KIND,
        "anchor_ids": list(result.get("anchor_ids", [])),
        "patch_refs": list(result.get("patch_refs", [])),
        "conditions": list(result.get("conditions", [])),
        "checkers": list(result.get("checkers", [])),
        "path_constraints": list(result.get("path_constraints", [])),
        "blocking_obligations": list(result.get("blocking_obligations", [])),
        "classification_status": "UNRESOLVED",
        "dynamic_checks": dict(result.get("dynamic_checks", {})),
        "fixed_side_validation": dict(result.get("fixed_side_validation", {})),
        "fixed_side_blocked": result.get("fixed_side_blocked"),
        "conditions_added_or_changed": legacy,
    })
    return result


def validate_repair_predicate(predicate: Any) -> list[str]:
    if not isinstance(predicate, dict):
        return ["repair_predicate must be an object"]
    errors: list[str] = []
    if predicate.get("schema_version") != REPAIR_SCHEMA_VERSION:
        errors.append(f"repair_predicate schema_version must be {REPAIR_SCHEMA_VERSION}")
    if predicate.get("kind") != REPAIR_KIND:
        errors.append("repair_predicate kind is invalid")
    if predicate.get("classification_status") not in {"SUPPORTED", "PARTIAL", "UNRESOLVED"}:
        errors.append("repair_predicate classification_status is invalid")
    for field in ("anchor_ids", "patch_refs", "conditions", "checkers", "path_constraints", "blocking_obligations", "conditions_added_or_changed"):
        if not isinstance(predicate.get(field), list):
            errors.append(f"repair_predicate.{field} must be a list")
    anchors = set(str(item) for item in predicate.get("anchor_ids", []))
    for condition in predicate.get("conditions", []):
        if not isinstance(condition, dict):
            errors.append("repair condition must be an object")
            continue
        if condition.get("kind") not in CONDITION_KINDS:
            errors.append("repair condition kind is invalid")
        if not condition.get("condition_id") or not condition.get("source_ref"):
            errors.append("repair condition requires condition_id and source_ref")
        if not isinstance(condition.get("patch_refs"), list) or not condition.get("patch_refs"):
            errors.append("repair condition requires patch_refs")
        if not isinstance(condition.get("evidence_refs"), list) or not condition.get("evidence_refs"):
            errors.append("repair condition requires evidence_refs")
        if condition.get("classification_status") == "SUPPORTED" and condition.get("anchor_id") not in anchors:
            errors.append("supported repair condition must reference a declared anchor")
    checker_ids = set()
    for checker in predicate.get("checkers", []):
        if not isinstance(checker, dict):
            errors.append("checker must be an object")
            continue
        checker_id = checker.get("checker_id")
        if not checker_id or checker_id in checker_ids:
            errors.append("checker IDs must be unique and non-empty")
        checker_ids.add(checker_id)
        if not checker.get("source_ref") or not checker.get("expression"):
            errors.append("checker requires source_ref and expression")
        if not isinstance(checker.get("evidence_refs"), list) or not checker.get("evidence_refs"):
            errors.append("checker requires evidence_refs")
        if not isinstance(checker.get("confidence"), (int, float)) or not 0 <= checker.get("confidence") <= 1:
            errors.append("checker confidence must be between 0 and 1")
    for constraint in predicate.get("path_constraints", []):
        if not isinstance(constraint, dict):
            errors.append("path constraint must be an object")
            continue
        normalization = {str(item).lower() for item in constraint.get("normalization", [])}
        if constraint.get("constraint_kind") != "root_containment":
            errors.append("unsupported path constraint kind")
        if not normalization & _NORMALIZATION_NAMES:
            errors.append("path constraint requires normalization evidence")
        if constraint.get("relation") != "within" or constraint.get("failure_action") != "reject":
            errors.append("path constraint must prove within/reject behavior")
        if not constraint.get("input") or not constraint.get("root"):
            errors.append("path constraint requires input and root")
        if not isinstance(constraint.get("source_refs"), list) or not constraint.get("source_refs"):
            errors.append("path constraint requires source_refs")
        if not isinstance(constraint.get("evidence_refs"), list) or not constraint.get("evidence_refs"):
            errors.append("path constraint requires evidence_refs")
    if predicate.get("classification_status") == "SUPPORTED" and any(
        condition.get("classification_status") != "SUPPORTED" for condition in predicate.get("conditions", []) if isinstance(condition, dict)
    ):
        errors.append("SUPPORTED repair predicate cannot contain unresolved conditions")
    return sorted(set(errors))


def _trace_levels(rows: list[dict[str, Any]]) -> set[str]:
    return {str(row.get("level")) for row in rows if isinstance(row, dict) and row.get("level")}


def _event_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result = []
    for row in rows or []:
        event = row.get("event") if isinstance(row.get("event"), dict) else None
        if event:
            result.append({"row": row, "event": event})
    return result


def _runtime_value(item: dict[str, Any], name: str) -> Any:
    event = item.get("event") if isinstance(item.get("event"), dict) else {}
    row = item.get("row") if isinstance(item.get("row"), dict) else {}
    value = event.get(name)
    return value if value not in (None, "") else row.get(name)


def _runtime_identity(item: dict[str, Any]) -> dict[str, Any]:
    """Read execution identity from event first, then its enclosing trace row."""
    return {
        name: _runtime_value(item, name)
        for name in _IDENTITY_FIELDS
        if _runtime_value(item, name) not in (None, "")
    }


def _source_parts(value: Any) -> tuple[str, int, int] | None:
    text = str(value or "").strip()
    if not text:
        return None
    path, separator, line_text = text.rpartition(":")
    if not separator or not path:
        return None
    first, separator, last = line_text.partition("-")
    if not first.isdigit() or (separator and not last.isdigit()):
        return None
    return path, int(first), int(last or first)


def _source_ref_compatible(left: Any, right: Any) -> bool:
    left_parts = _source_parts(left)
    right_parts = _source_parts(right)
    if not left_parts or not right_parts:
        return False
    left_path, left_start, left_end = left_parts
    right_path, right_start, right_end = right_parts
    if not _file_matches(left_path, right_path):
        return False
    return left_start <= right_end and right_start <= left_end


def _event_source_ref(item: dict[str, Any]) -> str | None:
    return _runtime_value(item, "source_ref") or _runtime_value(item, "location")


def _checker_event_matches(checker: dict[str, Any], item: dict[str, Any]) -> bool:
    """Scope an event to one checker without letting source/function aliases cross IDs."""
    checker_id = checker.get("checker_id")
    event_checker_id = _runtime_value(item, "checker_id")
    if event_checker_id not in (None, "") and event_checker_id != checker_id:
        return False
    event_ref = _event_source_ref(item)
    checker_ref = checker.get("source_ref")
    if event_ref and checker_ref and _source_ref_compatible(event_ref, checker_ref):
        return True
    if event_checker_id == checker_id:
        return True
    function = checker.get("function")
    return bool(
        not event_checker_id
        and not event_ref
        and function
        and _runtime_value(item, "function") == function
        and _runtime_value(item, "checker_executed") is True
    )


def _checker_event(
    checker: dict[str, Any],
    rows: list[dict[str, Any]],
    *,
    all_checkers: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Return events whose checker attribution is unique or explicitly keyed."""
    checkers = all_checkers or [checker]
    result = []
    for item in _event_rows(rows):
        event_checker_id = _runtime_value(item, "checker_id")
        if event_checker_id not in (None, ""):
            if event_checker_id == checker.get("checker_id") and _checker_event_matches(checker, item):
                result.append(item)
            continue
        event_ref = _event_source_ref(item)
        if event_ref:
            source_matches = [
                candidate for candidate in checkers
                if candidate.get("source_ref") and _source_ref_compatible(event_ref, candidate.get("source_ref"))
            ]
            if len(source_matches) == 1 and source_matches[0].get("checker_id") == checker.get("checker_id"):
                result.append(item)
            continue
        if _checker_event_matches(checker, item):
            function_matches = [
                candidate for candidate in checkers
                if candidate.get("function") and candidate.get("function") == checker.get("function")
            ]
            if len(function_matches) == 1:
                result.append(item)
    return result


def _blocked(event: dict[str, Any]) -> bool:
    if event.get("blocked") is True or event.get("rejected") is True:
        return True
    action = str(event.get("blocking_action") or event.get("outcome") or event.get("action") or event.get("status") or "").lower()
    return action in {"reject", "rejected", "blocked", "block", "deny", "denied", "forbidden"}


def _explicit_effect(event: dict[str, Any]) -> bool:
    return event.get("effect_observed") is True or event.get("effect_witness") is not None or event.get("caused_by_effect") is not None


def _event_effect(item: dict[str, Any]) -> dict[str, Any]:
    event = item.get("event") if isinstance(item.get("event"), dict) else {}
    witness = _runtime_value(item, "effect_witness")
    if isinstance(witness, str):
        witness = {"digest": witness}
    if not isinstance(witness, dict):
        witness = {}
    effect_id = _runtime_value(item, "effect_id") or witness.get("effect_id")
    digest = witness.get("digest") or _runtime_value(item, "effect_digest")
    kind = witness.get("kind") or _runtime_value(item, "effect_kind")
    return {
        "effect_id": str(effect_id) if effect_id not in (None, "") else None,
        "digest": str(digest) if digest not in (None, "") else None,
        "kind": str(kind) if kind not in (None, "") else None,
        "has_witness": bool(effect_id or digest or witness),
        "explicit": _explicit_effect(event),
    }


def _digest_values(value: Any) -> set[str]:
    if isinstance(value, dict):
        values: set[str] = set()
        for item in value.values():
            values.update(_digest_values(item))
        return values
    if isinstance(value, list):
        values: set[str] = set()
        for item in value:
            values.update(_digest_values(item))
        return values
    return {str(value)} if value not in (None, "") else set()


def _digest_difference(vulnerable: Any, fixed: Any) -> bool:
    vulnerable_values = _digest_values(vulnerable)
    fixed_values = _digest_values(fixed)
    return bool(vulnerable_values) and not vulnerable_values.issubset(fixed_values)


def _scoped_digest_entries(
    checker: dict[str, Any],
    scoped: Any,
    legacy: Any,
    *,
    events: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Return only digest records explicitly scoped to this checker or identity."""
    raw: list[Any] = []
    checker_id = checker.get("checker_id")
    source_ref = checker.get("source_ref")

    def add_records(records: Any, *, directly_scoped: bool = False) -> None:
        if not isinstance(records, list):
            return
        for item in records:
            if directly_scoped:
                raw.append(item)
                continue
            if not isinstance(item, dict):
                continue
            has_source_scope = bool(item.get("source_ref") and _source_ref_compatible(item["source_ref"], source_ref))
            event_bound = bool(events) and any(_digest_entry_matches_event(item, event) for event in events or [])
            if item.get("checker_id") == checker_id or (
                not item.get("checker_id") and (has_source_scope or event_bound)
            ):
                raw.append(item)

    if isinstance(scoped, dict):
        for key in (checker_id, source_ref):
            if key:
                add_records(scoped.get(key), directly_scoped=True)
        for value in scoped.values():
            add_records(value)
    if isinstance(legacy, dict):
        for key in (checker_id, source_ref):
            if key:
                add_records(legacy.get(key), directly_scoped=True)
        for value in legacy.values():
            add_records(value)
    result = []
    for item in raw:
        record = {"digest": item} if isinstance(item, str) else copy.deepcopy(item) if isinstance(item, dict) else {}
        if not record.get("digest") and isinstance(record.get("effect_witness"), dict):
            record["digest"] = record["effect_witness"].get("digest")
        if not record.get("digest") and not record.get("effect_id"):
            continue
        if record.get("checker_id") not in (None, checker_id):
            continue
        if record.get("source_ref") and not _source_ref_compatible(record["source_ref"], source_ref):
            continue
        result.append(record)
    return result


def _digest_entry_matches_event(entry: dict[str, Any], item: dict[str, Any]) -> bool:
    identity = _runtime_identity(item)
    for field in _IDENTITY_FIELDS:
        expected = entry.get(field)
        if expected not in (None, "") and identity.get(field) != expected:
            return False
    event_effect = _event_effect(item)
    if entry.get("effect_id") and event_effect.get("effect_id") not in (None, str(entry["effect_id"])):
        return False
    return True


def _effect_from_digest_entries(entries: list[dict[str, Any]], item: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {
            "effect_id": str(entry["effect_id"]) if entry.get("effect_id") not in (None, "") else None,
            "digest": str(entry["digest"]) if entry.get("digest") not in (None, "") else None,
            "kind": (entry.get("effect_witness") or {}).get("kind") if isinstance(entry.get("effect_witness"), dict) else entry.get("kind"),
            "has_witness": True,
            "explicit": True,
        }
        for entry in entries
        if _digest_entry_matches_event(entry, item)
    ]


def _event_effects(item: dict[str, Any], entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    effects = []
    direct = _event_effect(item)
    if direct.get("has_witness"):
        effects.append(direct)
    effects.extend(_effect_from_digest_entries(entries, item))
    return effects


def _effect_matches(left: dict[str, Any], right: dict[str, Any]) -> bool:
    if left.get("effect_id") and right.get("effect_id"):
        return left["effect_id"] == right["effect_id"]
    if left.get("digest") and right.get("digest"):
        return left["digest"] == right["digest"] and (
            not left.get("kind") or not right.get("kind") or left.get("kind") == right.get("kind")
        )
    return False


def _event_status(item: dict[str, Any]) -> str:
    value = _runtime_value(item, "status")
    return str(value).lower() if value not in (None, "") else ""


def _event_executed(item: dict[str, Any]) -> bool:
    return _event_status(item) in {"executed", "passed", "observed"} or _runtime_value(item, "checker_executed") is True


def _same_execution(left: dict[str, Any], right: dict[str, Any]) -> bool:
    left_identity = _runtime_identity(left)
    right_identity = _runtime_identity(right)
    left_checker_id = _runtime_value(left, "checker_id")
    right_checker_id = _runtime_value(right, "checker_id")
    if not left_checker_id or left_checker_id != right_checker_id:
        return False
    if left_identity.get("repetition") is None or right_identity.get("repetition") is None:
        return False
    try:
        if int(left_identity["repetition"]) != int(right_identity["repetition"]):
            return False
    except (TypeError, ValueError):
        return False
    if not (left_identity.get("tool_call_id") or left_identity.get("invocation_id")):
        return False
    if not (right_identity.get("tool_call_id") or right_identity.get("invocation_id")):
        return False
    for field in ("tool_call_id", "invocation_id", "trace_id", "span_id", "session_id"):
        left_value = left_identity.get(field)
        right_value = right_identity.get(field)
        if (left_value is None) != (right_value is None) or (left_value is not None and left_value != right_value):
            return False
    left_ref = _event_source_ref(left)
    right_ref = _event_source_ref(right)
    if not left_ref or not right_ref or not _source_ref_compatible(left_ref, right_ref):
        return False
    return True


def _sink_ref(item: dict[str, Any], checker: dict[str, Any] | None = None) -> str | None:
    return _runtime_value(item, "sink_ref")


def _same_sink(left: dict[str, Any], right: dict[str, Any], checker: dict[str, Any]) -> bool:
    left_sink = _sink_ref(left, checker)
    right_sink = _sink_ref(right, checker)
    if not left_sink or not right_sink or not _source_ref_compatible(left_sink, right_sink):
        return False
    expected = checker.get("sink_ref")
    return not expected or (_source_ref_compatible(left_sink, expected) and _source_ref_compatible(right_sink, expected))


def _event_before_sink(item: dict[str, Any]) -> bool:
    phase = str(_runtime_value(item, "phase") or "").lower()
    return phase in {"before_sink", "pre_sink", "before-sink"} or _runtime_value(item, "before_sink") is True


def _paired_events(
    checker: dict[str, Any],
    vulnerable_events: list[dict[str, Any]],
    fixed_events: list[dict[str, Any]],
    vulnerable_digest_entries: list[dict[str, Any]],
    fixed_digest_entries: list[dict[str, Any]],
) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    pairs = []
    for vulnerable in vulnerable_events:
        for fixed in fixed_events:
            if (
                _source_ref_compatible(_event_source_ref(vulnerable), checker.get("source_ref"))
                and _source_ref_compatible(_event_source_ref(fixed), checker.get("source_ref"))
                and _same_execution(vulnerable, fixed)
                and _same_sink(vulnerable, fixed, checker)
            ):
                if any(
                    _effect_matches(v_effect, f_effect)
                    for v_effect in _event_effects(vulnerable, vulnerable_digest_entries)
                    for f_effect in _event_effects(fixed, fixed_digest_entries)
                ):
                    pairs.append((vulnerable, fixed))
    return pairs


def _safe_case(
    checker: dict[str, Any],
    rows: list[dict[str, Any]] | None,
    *,
    all_checkers: list[dict[str, Any]] | None = None,
) -> str:
    if rows is None:
        return "not_assessed"
    events = _checker_event(checker, rows, all_checkers=all_checkers)
    if not events:
        return "unassessed"
    if any(_blocked(item["event"]) or _event_status(item) in {"blocked", "rejected", "denied"} for item in events):
        return "changed"
    if any(
        _runtime_value(item, "checker_id") != checker.get("checker_id")
        or _event_status(item) not in {"executed", "passed", "observed"}
        or _runtime_identity(item).get("repetition") is None
        or not (_runtime_identity(item).get("tool_call_id") or _runtime_identity(item).get("invocation_id"))
        for item in events
    ):
        return "unassessed"
    return "preserved"


def validate_paired_repair_predicate(
    predicate: dict[str, Any],
    vulnerable_rows: list[dict[str, Any]],
    fixed_rows: list[dict[str, Any]],
    *,
    vulnerable_value_digests: dict[str, list[str]] | None = None,
    fixed_value_digests: dict[str, list[str]] | None = None,
    scoped_vulnerable_value_digests: dict[str, list[Any]] | None = None,
    scoped_fixed_value_digests: dict[str, list[Any]] | None = None,
    safe_vulnerable_rows: list[dict[str, Any]] | None = None,
    safe_fixed_rows: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Validate one patch predicate against a label-free vulnerable/fixed pair.

    ``validation_conclusion`` is authoritative.  ``status=SUPPORTED`` is kept
    only as a legacy alias for a strict checker-specific result.
    """
    valid = _TRACE_LEVELS.issubset(_trace_levels(vulnerable_rows)) and _TRACE_LEVELS.issubset(_trace_levels(fixed_rows))
    vulnerable_value_digests = vulnerable_value_digests or {}
    fixed_value_digests = fixed_value_digests or {}
    scoped_vulnerable_value_digests = (
        predicate.get("scoped_vulnerable_value_digests", {})
        if scoped_vulnerable_value_digests is None else scoped_vulnerable_value_digests
    ) or {}
    scoped_fixed_value_digests = (
        predicate.get("scoped_fixed_value_digests", {})
        if scoped_fixed_value_digests is None else scoped_fixed_value_digests
    ) or {}
    global_difference = _digest_difference(vulnerable_value_digests, fixed_value_digests)
    results: list[dict[str, Any]] = []
    checkers = [item for item in predicate.get("checkers", []) if isinstance(item, dict)]
    for checker in checkers:
        vulnerable_events = _checker_event(checker, vulnerable_rows, all_checkers=checkers)
        fixed_events = _checker_event(checker, fixed_rows, all_checkers=checkers)
        scoped_v = _scoped_digest_entries(
            checker,
            scoped_vulnerable_value_digests,
            vulnerable_value_digests,
            events=vulnerable_events,
        )
        scoped_f = _scoped_digest_entries(
            checker,
            scoped_fixed_value_digests,
            fixed_value_digests,
            events=fixed_events,
        )
        vulnerable_effects = [effect for item in vulnerable_events for effect in _event_effects(item, scoped_v)]
        fixed_effects = [effect for item in fixed_events for effect in _event_effects(item, scoped_f)]
        vulnerable_effect = bool(vulnerable_effects)
        fixed_effect = bool(fixed_effects)
        scoped_difference = _digest_difference(scoped_v, scoped_f)
        event_difference = any(_explicit_effect(item["event"]) for item in vulnerable_events) and not any(
            _explicit_effect(item["event"]) for item in fixed_events
        )
        checker_has_scoped_evidence = bool(scoped_v or scoped_f or vulnerable_events or fixed_events)
        paired_difference = checker_has_scoped_evidence and (scoped_difference or event_difference)
        pairs = _paired_events(checker, vulnerable_events, fixed_events, scoped_v, scoped_f)
        blocked_pairs = [
            (vulnerable, fixed)
            for vulnerable, fixed in pairs
            if _event_executed(vulnerable) and _blocked(fixed["event"]) and _event_before_sink(fixed)
        ]
        safe_case = _safe_case(checker, safe_fixed_rows, all_checkers=checkers)
        safe_preserved = safe_case == "preserved"
        strict_effect = bool(blocked_pairs) and any(_event_executed(vulnerable) for vulnerable, _ in blocked_pairs)
        strict = bool(valid and blocked_pairs and strict_effect and safe_preserved)
        checker_attested = any(_runtime_value(item, "checker_id") == checker.get("checker_id") for item in vulnerable_events + fixed_events)
        identity_status = "MATCHED" if blocked_pairs else "MISSING_OR_MISMATCHED"
        if strict:
            validation_conclusion = "CHECKER_SPECIFIC_VALIDATED"
            trigger_case = "blocked"
        elif not valid or (vulnerable_events or fixed_events) and not pairs and not paired_difference:
            validation_conclusion = "UNASSESSED"
            trigger_case = "not_exercised"
        elif paired_difference:
            validation_conclusion = "PAIRED_EFFECT_DIFFERENCE_ONLY"
            trigger_case = "blocked" if vulnerable_effect and not fixed_effect else "not_exercised"
        else:
            validation_conclusion = "UNASSESSED"
            trigger_case = "not_blocked" if vulnerable_effect else "not_exercised"
        refs = sorted(set(
            [str(checker.get("source_ref"))]
            + [f"trace:vulnerable:{item['row'].get('level', 'event')}" for item in vulnerable_events]
            + [f"trace:fixed:{item['row'].get('level', 'event')}" for item in fixed_events]
        ))
        results.append({
            "checker_id": checker.get("checker_id"),
            "trigger_case": trigger_case,
            "safe_case": safe_case,
            "vulnerable_effect_observed": vulnerable_effect,
            "fixed_effect_observed": fixed_effect,
            "checker_has_scoped_evidence": checker_has_scoped_evidence,
            "paired_effect_difference_observed": paired_difference,
            "validation_conclusion": validation_conclusion,
            "blocking_supported": strict,
            "checker_execution_attested": checker_attested,
            "attestation_status": validation_conclusion if strict else "EXPLICIT_CHECKER_EVENT" if checker_attested else validation_conclusion,
            "execution_identity_status": identity_status,
            "matched_execution_pairs": len(pairs),
            "matched_blocking_pairs": len(blocked_pairs),
            "blocking_boundary": "before_sink" if blocked_pairs else "unresolved",
            "evidence_refs": refs,
        })
    checker_difference = any(item["paired_effect_difference_observed"] for item in results)
    if not valid:
        conclusion = "UNASSESSED"
    elif results and all(item["validation_conclusion"] == "CHECKER_SPECIFIC_VALIDATED" for item in results):
        conclusion = "CHECKER_SPECIFIC_VALIDATED"
    elif any(item["validation_conclusion"] == "PAIRED_EFFECT_DIFFERENCE_ONLY" for item in results) or _digest_difference(vulnerable_value_digests, fixed_value_digests):
        conclusion = "PAIRED_EFFECT_DIFFERENCE_ONLY"
    else:
        conclusion = "UNASSESSED"
    return {
        "status": "SUPPORTED" if conclusion == "CHECKER_SPECIFIC_VALIDATED" else conclusion,
        "validation_conclusion": conclusion,
        "global_paired_effect_difference": global_difference,
        "checker_attribution": (
            "MIXED" if global_difference and checker_difference
            else "SCOPED" if checker_difference
            else "UNSCOPED" if global_difference
            else "NONE"
        ),
        "valid_paired_trace": valid,
        "checkers": results,
        "evidence_refs": sorted({ref for item in results for ref in item.get("evidence_refs", [])}),
    }


__all__ = [
    "CONDITION_KINDS", "REPAIR_KIND", "REPAIR_SCHEMA_VERSION",
    "VALIDATION_CONCLUSIONS",
    "build_repair_predicate", "empty_repair_predicate", "normalize_repair_predicate",
    "validate_repair_predicate", "validate_paired_repair_predicate",
]
