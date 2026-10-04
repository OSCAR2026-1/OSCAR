"""Autonomous Stage 2 vulnerability-effect modeling.

The module is intentionally independent from the GT validator.  It consumes a
label-free case, source/patch material and the two runtime traces.  It never
uses an oracle token as a decision predicate and never emits a GT label.
"""

from __future__ import annotations

import ast
import copy
import hashlib
import json
import re
import subprocess
import tarfile
import zipfile
from pathlib import Path
from typing import Any, Iterable

try:
    from oscar.contracts.component_contract import component_origin, component_for_localization, is_legacy_direct_runtime
    from oscar.analysis.repair_predicate import empty_repair_predicate, normalize_repair_predicate, validate_paired_repair_predicate, validate_repair_predicate
except ImportError:  # pragma: no cover
    from oscar.contracts.component_contract import component_origin, component_for_localization, is_legacy_direct_runtime
    from oscar.analysis.repair_predicate import empty_repair_predicate, normalize_repair_predicate, validate_paired_repair_predicate, validate_repair_predicate


SCHEMA_VERSION = "vulveil-effect-model/v3"
VULNERABILITY_CATEGORIES = {
    "SENSITIVE_INFORMATION_DISCLOSURE",
    "COMMAND_OR_QUERY_INJECTION",
    "SSRF_WITH_RESPONSE_OR_METADATA",
    "PATH_TRAVERSAL_OR_ARBITRARY_FILE_IO",
    "AUTHENTICATION_OR_AUTHORIZATION_BYPASS",
}
_VULNERABILITY_CATEGORY_ORDER = (
    "SENSITIVE_INFORMATION_DISCLOSURE",
    "COMMAND_OR_QUERY_INJECTION",
    "SSRF_WITH_RESPONSE_OR_METADATA",
    "PATH_TRAVERSAL_OR_ARBITRARY_FILE_IO",
    "AUTHENTICATION_OR_AUTHORIZATION_BYPASS",
)
EFFECT_KINDS = {"CONTROL_EFFECT", "RESOURCE_EFFECT", "VALUE_EFFECT"}
EFFECT_ROLES = {"INTERMEDIATE", "TERMINAL", "BOTH"}
CLASSIFICATION_STATUSES = {"SUPPORTED", "PARTIAL", "UNRESOLVED", "UNASSESSED"}
PROVENANCE_STATUSES = {"SUPPORTED", "PARTIAL", "UNRESOLVED", "UNASSESSED"}
PROPAGATION_STATUSES = {"REACHED", "DROPPED", "TRANSFORMED", "NOT_REACHED", "NOT_ASSESSED"}
CARRIER_KINDS = {
    "returned_value",
    "structured_content",
    "resource_reference",
    "error_or_status",
    "metadata",
    "side_effect_only",
    "control_signal",
}
RELATION_KINDS = {
    "ENABLES",
    "CAUSES",
    "DERIVES",
    "DERIVES_VALUE",
    "BLOCKS",
    "PROPAGATES_TO",
    "ALIGNS_WITH",
    # Kept for old effect models.  New code should prefer DERIVES_VALUE or
    # CAUSES/ENABLES when the evidence supports the more precise relation.
    "PRODUCES",
}
PROPAGATION_TARGETS = {"TOOL_RESULT", "HOST", "SESSION", "AGENT_OBSERVATION"}

# These names are intentionally shared by Stage 2, Stage 3 and Stage 4.  An
# effect can stop at any one of them; the graph must not manufacture missing
# layers to make a path look complete.
REACHABILITY_LEVELS = (
    "P0",
    "P1",
    "P2-E",
    "P2-R",
    "P2-T",
    "P2-H",
    "P3-W",
)
TERMINATION_REASONS = {
    "NOT_PRODUCED",
    "NO_READBACK",
    "FILTERED_BY_HOST",
    "DROPPED_BEFORE_TOOL",
    "DROPPED_BEFORE_L4",
    "NOT_TRIGGERED",
    "UNREACHABLE",
    "UNRESOLVED_BOUNDARY",
}
EVIDENCE_LEVELS = (
    "L0_RAW_MCP_RESULT",
    "L1_NORMALIZED_TOOL_RESULT",
    "L2_HOST_PROCESSED_TOOL_RESULT",
    "L3_SESSION_TOOL_RESULT",
    "L4_MODEL_VISIBLE_OBSERVATION",
)
_GT_KEYS = {
    "ground_truth_label", "ground_truth", "gt", "gt_id", "active_gt_id",
    "vulnerable_label", "patched_trigger_blocked", "annotation_status",
    "included_in_gt", "active_agent_gt_id", "source_gt_id", "gt_label_schema",
}
_GT_WORDS = {"POSITIVE", "NEGATIVE"}
_VOLATILE_KEYS = {"timestamp", "started_at", "finished_at", "duration_ms", "request_sha256", "run_id"}
_RESOURCE_STATE_METADATA_KEYS = {
    "boundary", "host", "port", "request-line", "schema-version",
    "server-returncode", "timestamp", "user-agent",
}
_CONTROL_NAMES = {"if", "for", "while", "switch", "catch", "return", "throw", "else", "try"}


def _text(value: Any) -> str:
    if isinstance(value, str):
        return value
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    return str(value)


def _normalise_enum(value: Any, allowed: set[str], default: str) -> str:
    candidate = str(value or "").upper()
    return candidate if candidate in allowed else default


def _carrier_kind(effect_kind: str, paths: Iterable[str], *, resource_operation: str | None = None) -> str:
    """Map a modeled carrier to its projection semantics.

    ``carrier_kind`` is retained below as a compatibility alias for v3
    consumers.  The lower-case kind is the semantic projection contract and
    is deliberately independent from effect_kind.
    """
    normalised_paths = [str(path) for path in paths if path]
    path_text = " ".join(path.lower() for path in normalised_paths)
    if not normalised_paths:
        return "side_effect_only" if effect_kind == "RESOURCE_EFFECT" else "control_signal" if effect_kind == "CONTROL_EFFECT" else "returned_value"
    if "structuredcontent" in path_text or "structured_content" in path_text:
        return "structured_content"
    if any(token in path_text for token in ("uri", "resource_reference", "resource_uri", "image", "file_url")):
        return "resource_reference"
    if any(token in path_text for token in ("error", "exception", "status", "reason", "denied")):
        return "error_or_status"
    if any(token in path_text for token in ("header", "content_type", "redirect", "metadata", "location")):
        return "metadata"
    return "returned_value"


def build_carrier_projection(
    effect_kind: str,
    paths: Iterable[str],
    *,
    tool_name: str = "",
    resource_operation: str | None = None,
    field_mapping: Any = None,
    l4_eligible: bool | None = None,
) -> dict[str, Any]:
    """Create the explicit Tool/Host/session projection for an effect.

    A missing path means a state/control effect has no Tool carrier; it is
    represented as ``side_effect_only`` or ``control_signal`` instead of being
    mistaken for an empty returned value.
    """
    normalised_paths = [str(path) for path in paths if path]
    kind = _carrier_kind(effect_kind, normalised_paths, resource_operation=resource_operation)
    legacy_kind = {
        "control_signal": "CONTROL_STATE",
        "side_effect_only": "RESOURCE_EVENT",
        "structured_content": "PROGRAM_VALUE",
        "returned_value": "PROGRAM_VALUE",
        "resource_reference": "PROGRAM_VALUE",
        "error_or_status": "PROGRAM_VALUE",
        "metadata": "PROGRAM_VALUE",
    }[kind]
    if effect_kind == "CONTROL_EFFECT":
        legacy_kind = "CONTROL_STATE"
    mapping = field_mapping if field_mapping is not None else (
        f"{normalised_paths[0]} -> L0 -> L1 -> L2 -> L3 -> L4" if normalised_paths else "runtime state -> no Tool result field"
    )
    return {
        "kind": kind,
        "path": normalised_paths[0] if normalised_paths else None,
        "paths": normalised_paths,
        "projection": "tool_result_to_host_to_session_to_model" if normalised_paths else "server_or_external_state",
        "field_mapping": mapping,
        "l4_eligible": bool(normalised_paths) if l4_eligible is None else bool(l4_eligible),
        "tool_names": [tool_name] if tool_name and normalised_paths else [],
        "carrier_kind": legacy_kind,
        "resource_operation": resource_operation,
    }


def _propagation_template() -> dict[str, Any]:
    return {
        "tool_result": "NOT_ASSESSED",
        "host": "NOT_ASSESSED",
        "session": "NOT_ASSESSED",
        "agent_observation": "NOT_ASSESSED",
        "max_reached_level": "UNASSESSED",
    }


def _propagation_from_trace(effect: dict[str, Any], rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Assess propagation independently from whether the effect was realized."""
    result = _propagation_template()
    paths = {str(path) for path in effect.get("carrier", {}).get("paths", [])}
    if not paths:
        result["tool_result"] = "NOT_REACHED"
        result["host"] = "NOT_REACHED"
        result["session"] = "NOT_REACHED"
        result["agent_observation"] = "NOT_REACHED"
        result["max_reached_level"] = "L1" if effect.get("effect_realization", {}).get("status") == "REALIZED" else "UNASSESSED"
        return result

    trace = _trace_side(rows)
    if not trace["valid"]:
        return result
    tool_paths = set(trace.get("tool_result_paths", []))
    l4_paths = set(trace.get("l4_paths", []))
    tool_reached = any(_paths_equivalent(expected, observed) for expected in paths for observed in tool_paths)
    l4_reached = any(_paths_equivalent(expected, observed) for expected in paths for observed in l4_paths)
    result["tool_result"] = "REACHED" if tool_reached else "NOT_REACHED"
    explicit_boundary, _ = _explicit_boundary_evidence(rows, paths)
    if not tool_reached:
        result["host"] = "NOT_REACHED"
        result["session"] = "NOT_REACHED"
        result["agent_observation"] = "NOT_REACHED"
        result["max_reached_level"] = "L1" if effect.get("effect_realization", {}).get("status") == "REALIZED" else "UNASSESSED"
        return result
    result["host"] = "DROPPED" if explicit_boundary == "FILTERED_BY_HOST" else "TRANSFORMED" if explicit_boundary == "DROPPED_BEFORE_L4" else "REACHED"
    result["session"] = "DROPPED" if explicit_boundary in {"FILTERED_BY_HOST", "DROPPED_BEFORE_L4"} else "REACHED"
    actual_l4 = bool(actual_model_tool_messages(rows))
    result["agent_observation"] = "REACHED" if l4_reached and not explicit_boundary else "NOT_REACHED" if actual_l4 or explicit_boundary else "NOT_ASSESSED"
    result["max_reached_level"] = "L4" if l4_reached else "L3" if result["session"] == "REACHED" else "L2"
    return result


def _effect_role(effect_kind: str, *, operation: str | None = None, has_downstream: bool = False, explicit: Any = None, vulnerability_category: str | None = None, terminal_witness: bool | None = None) -> str:
    """Classify semantic role without using kind as a propagation shortcut."""
    if str(explicit or "").upper() in EFFECT_ROLES:
        return str(explicit).upper()
    if terminal_witness is False:
        return "INTERMEDIATE"
    if terminal_witness is True and has_downstream:
        return "BOTH"
    if effect_kind == "CONTROL_EFFECT" and vulnerability_category == "AUTHENTICATION_OR_AUTHORIZATION_BYPASS" and has_downstream:
        return "BOTH"
    operation = str(operation or "").lower()
    terminal_by_default = effect_kind in {"RESOURCE_EFFECT", "VALUE_EFFECT"}
    if effect_kind == "CONTROL_EFFECT":
        terminal_by_default = not has_downstream
    if effect_kind == "RESOURCE_EFFECT" and operation in {"read", "load", "fetch", "get"} and has_downstream:
        terminal_by_default = False
    if has_downstream:
        return "BOTH" if terminal_by_default else "INTERMEDIATE"
    return "TERMINAL" if terminal_by_default else "INTERMEDIATE"


def classify_effect_role(effect_kind: str, *, operation: str | None = None, has_downstream: bool = False, explicit: Any = None, vulnerability_category: str | None = None, terminal_witness: bool | None = None) -> str:
    """Public role classifier; semantic role is independent of effect_kind."""
    return _effect_role(effect_kind, operation=operation, has_downstream=has_downstream, explicit=explicit, vulnerability_category=vulnerability_category, terminal_witness=terminal_witness)


def _effect_realization(effect: dict[str, Any], rows: list[dict[str, Any]]) -> dict[str, Any]:
    if not _trace_is_assessable(rows):
        return {"status": "UNASSESSED", "witness_refs": [], "sink_refs": []}
    status, refs = _effect_produced_in_rows(effect, rows)
    if status == "PRODUCED":
        return {
            "status": "REALIZED",
            "witness_refs": sorted(set(refs)),
            "sink_refs": sorted({str(item.get("layer")) for item in effect.get("sink_candidates", []) if isinstance(item, dict) and item.get("layer")}),
        }
    # A generated effect can be statically plausible while the runtime oracle
    # did not expose an effect-specific witness.  Preserve that distinction.
    if any(row.get("anchor_reached") is True or row.get("vulnerability_anchor_reached") is True for row in rows):
        return {"status": "NOT_REALIZED", "witness_refs": [], "sink_refs": []}
    return {"status": "UNASSESSED", "witness_refs": [], "sink_refs": []}


def _trace_is_assessable(rows: list[dict[str, Any]], *, require_l4: bool = True) -> bool:
    """Check evidence completeness before assigning a runtime realization state."""
    if not isinstance(rows, list) or not rows:
        return False
    levels = {str(row.get("level")) for row in rows if isinstance(row, dict) and row.get("level")}
    required = set(EVIDENCE_LEVELS if require_l4 else EVIDENCE_LEVELS[:4])
    if not required.issubset(levels):
        return False
    for row in rows:
        if not isinstance(row, dict):
            return False
        quality = row.get("quality") if isinstance(row.get("quality"), dict) else {}
        if row.get("invalid_run") is True or quality.get("invalid_run") is True:
            return False
        if str(row.get("run_status", "")).upper() in {"INVALID", "BLOCKED", "ERROR", "FAILED"}:
            return False
        if str(row.get("execution_status", "")).upper() in {"INVALID", "BLOCKED", "ERROR", "FAILED"}:
            return False
        if row.get("valid") is False or row.get("execution_valid") is False:
            return False
    return True


def supported_for_effect(effect: dict[str, Any]) -> bool:
    """Require the complete patch/runtime/sink chain before SUPPORTED."""
    condition = effect.get("condition", {}) if isinstance(effect.get("condition"), dict) else {}
    predicate = condition.get("production_predicate", {}) if isinstance(condition.get("production_predicate"), dict) else {}
    return bool(
        condition.get("patch_derived") is True
        and predicate.get("anchor_reached") is True
        and predicate.get("effect_specific_witness")
        and condition.get("production_evidence")
        and effect.get("provenance")
        and effect.get("evidence_refs")
    )


def normalize_effect_model(model: Any) -> dict[str, Any]:
    """Read old artifacts without treating missing semantics as evidence.

    v1/v2 artifacts remain explicitly incompatible for formal validation, but
    callers can inspect them.  v3 artifacts missing the new fields receive a
    conservative UNASSESSED compatibility marker and no inferred L4 result.
    """
    if not isinstance(model, dict):
        return {"status": "UNASSESSED", "compatibility": {"status": "UNASSESSED", "reason": "effect model is not an object"}, "effects": []}
    result = copy.deepcopy(model)
    version = result.get("schema_version")
    if version != SCHEMA_VERSION:
        result.setdefault("compatibility", {})
        result["compatibility"].update({"status": "UNASSESSED", "reason": f"legacy effect model {version or 'unknown'} requires explicit migration"})
        return result
    missing_fields = []
    for effect in result.get("effects", []):
        if not isinstance(effect, dict):
            continue
        if "effect_role" not in effect:
            effect["effect_role"] = "INTERMEDIATE"
            missing_fields.append("effect_role")
        if "classification_status" not in effect:
            effect["classification_status"] = "UNASSESSED"
            missing_fields.append("classification_status")
        if "provenance_status" not in effect:
            effect["provenance_status"] = "UNASSESSED"
            missing_fields.append("provenance_status")
        if "effect_realization" not in effect:
            effect["effect_realization"] = {"status": "UNASSESSED", "witness_refs": [], "sink_refs": []}
            missing_fields.append("effect_realization")
        if "propagation" not in effect:
            effect["propagation"] = _propagation_template()
            missing_fields.append("propagation")
        carrier = effect.setdefault("carrier", {})
        if isinstance(carrier, dict) and "kind" not in carrier:
            projection = build_carrier_projection(effect.get("effect_kind", "VALUE_EFFECT"), carrier.get("paths", []), tool_name=(carrier.get("tool_names") or [""])[0] if carrier.get("tool_names") else "")
            carrier.update({key: value for key, value in projection.items() if key not in carrier})
            missing_fields.append("carrier.kind")
    for relation in result.get("effect_relations", []):
        if isinstance(relation, dict) and "provenance_status" not in relation:
            relation["provenance_status"] = "UNASSESSED"
            missing_fields.append("relation.provenance_status")
    if missing_fields:
        result["compatibility"] = {"status": "UNASSESSED", "reason": "legacy artifact missing effect semantics", "missing_fields": sorted(set(missing_fields))}
    return result


def _stable(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): _stable(v) for k, v in sorted(value.items(), key=lambda item: str(item[0])) if str(k) not in _VOLATILE_KEYS}
    if isinstance(value, list):
        return [_stable(item) for item in value]
    return value


def _digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(_stable(value), ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()[:16]


def _contains_gt(value: Any, path: str = "$") -> list[str]:
    errors: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            key_text = str(key)
            if key_text.lower() in _GT_KEYS:
                errors.append(f"{path}.{key_text}: forbidden GT field")
            errors.extend(_contains_gt(item, f"{path}.{key_text}"))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            errors.extend(_contains_gt(item, f"{path}[{index}]"))
    elif isinstance(value, str):
        if value.upper() in _GT_WORDS:
            errors.append(f"{path}: forbidden GT label")
        if re.search(r"(?<![A-Za-z])GT-\d+(?![A-Za-z0-9])", value, re.IGNORECASE):
            errors.append(f"{path}: forbidden GT identifier")
    return errors


def _semantic_category(parts: Iterable[str]) -> set[str]:
    """Classify structured identifiers/calls, rather than arbitrary output text."""
    words = {part.lower() for part in parts if part}
    joined = " ".join(sorted(words))
    categories: set[str] = set()
    if words & {"secret", "secrets", "token", "password", "passwd", "credential", "credentials", "netrc", "env", "environ", "environment", "cookie", "privatekey"}:
        categories.add("SENSITIVE_INFORMATION_DISCLOSURE")
    if words & {"exec", "spawn", "popen", "shell", "command", "query", "sql", "execute", "eval", "subprocess", "child_process"}:
        categories.add("COMMAND_OR_QUERY_INJECTION")
    if words & {"url", "uri", "fetch", "axios", "request", "requests", "http", "https", "webhook", "proxy", "socket", "got"}:
        categories.add("SSRF_WITH_RESPONSE_OR_METADATA")
    if words & {"path", "filepath", "filename", "file", "readfile", "writefile", "open", "save", "screenshot", "directory", "dirname"} or "travers" in joined:
        categories.add("PATH_TRAVERSAL_OR_ARBITRARY_FILE_IO")
    if words & {"auth", "authenticate", "authorization", "permission", "permissions", "role", "admin", "login", "session", "acl", "allow", "allowed"}:
        categories.add("AUTHENTICATION_OR_AUTHORIZATION_BYPASS")
    return categories


def _line_ref(path: str, line: int | None) -> str:
    return f"{path}:{line or 1}"


def _python_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _python_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _python_parts(node: ast.AST) -> list[str]:
    parts: list[str] = []
    for child in ast.walk(node):
        if isinstance(child, ast.Name):
            parts.append(child.id)
        elif isinstance(child, ast.Attribute):
            parts.append(child.attr)
        elif isinstance(child, ast.Constant) and isinstance(child.value, str):
            parts.extend(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", child.value))
    return parts


def _python_structure(path: str, source: str) -> dict[str, Any]:
    try:
        tree = ast.parse(source, filename=path)
    except (SyntaxError, ValueError, TypeError) as exc:
        return {"path": path, "language": "python", "parse_valid": False, "error": f"{type(exc).__name__}: {exc}", "functions": [], "calls": [], "guards": [], "returns": []}
    functions: list[dict[str, Any]] = []
    calls: list[dict[str, Any]] = []
    guards: list[dict[str, Any]] = []
    returns: list[dict[str, Any]] = []

    class StructureVisitor(ast.NodeVisitor):
        def __init__(self) -> None:
            self.function_stack: list[str] = []

        @property
        def function(self) -> str | None:
            return self.function_stack[-1] if self.function_stack else None

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            self._visit_function(node)

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            self._visit_function(node)

        def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
            qualified = ".".join([*self.function_stack, node.name])
            parameters = [arg.arg for arg in [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]]
            functions.append({"name": qualified, "line": node.lineno, "end_line": getattr(node, "end_lineno", node.lineno), "parameters": parameters})
            self.function_stack.append(qualified)
            self.generic_visit(node)
            self.function_stack.pop()

        def visit_Call(self, node: ast.Call) -> None:
            callee = _python_name(node.func)
            parts = _python_parts(node)
            arguments = [_text(ast.unparse(arg)) for arg in node.args]
            keywords = [key.arg for key in node.keywords if key.arg]
            calls.append({
                "callee": callee,
                "function": self.function,
                "line": node.lineno,
                "end_line": getattr(node, "end_lineno", node.lineno),
                "arguments": arguments,
                "keywords": keywords,
                "uses": sorted(set(_python_parts(node))),
                "categories": sorted(_semantic_category(parts)),
                "fingerprint": f"call:{callee}:{'|'.join(arguments)}:{'|'.join(keywords)}",
            })
            self.generic_visit(node)

        def visit_If(self, node: ast.If) -> None:
            predicate = _text(ast.unparse(node.test))
            parts = _python_parts(node.test)
            guards.append({"kind": "if", "function": self.function, "line": node.lineno, "end_line": getattr(node.test, "end_lineno", node.lineno), "predicate": predicate, "uses": sorted(set(parts)), "categories": sorted(_semantic_category(parts)), "fingerprint": f"guard:{predicate}"})
            self.generic_visit(node)

        def visit_Assert(self, node: ast.Assert) -> None:
            predicate = _text(ast.unparse(node.test))
            parts = _python_parts(node.test)
            guards.append({"kind": "assert", "function": self.function, "line": node.lineno, "end_line": getattr(node.test, "end_lineno", node.lineno), "predicate": predicate, "uses": sorted(set(parts)), "categories": sorted(_semantic_category(parts)), "fingerprint": f"guard:{predicate}"})
            self.generic_visit(node)

        def visit_Return(self, node: ast.Return) -> None:
            value = _text(ast.unparse(node.value)) if node.value else ""
            parts = _python_parts(node)
            returns.append({"function": self.function, "line": node.lineno, "end_line": getattr(node, "end_lineno", node.lineno), "value": value, "uses": sorted(set(parts)), "categories": sorted(_semantic_category(parts)), "fingerprint": f"return:{value}"})
            self.generic_visit(node)

    StructureVisitor().visit(tree)
    return {"path": path, "language": "python", "parse_valid": True, "functions": functions, "calls": calls, "guards": guards, "returns": returns}


_JS_TOKEN = re.compile(r"(?P<comment>//[^\n]*|/\*[\s\S]*?\*/)|(?P<string>`(?:\\.|[^`])*`|'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\")|(?P<word>[A-Za-z_$][A-Za-z0-9_$]*)|(?P<number>\d+(?:\.\d+)?)|(?P<op>===|!==|=>|==|!=|<=|>=|&&|\|\||\?\?|\?\.|[{}()\[\].,:;?=+*/<>!-])")


def _js_tokens(source: str) -> list[dict[str, Any]]:
    tokens: list[dict[str, Any]] = []
    for match in _JS_TOKEN.finditer(source):
        kind = match.lastgroup or "op"
        if kind == "comment":
            continue
        tokens.append({"kind": kind, "value": match.group(0), "line": source.count("\n", 0, match.start()) + 1})
    return tokens


def _balanced_end(tokens: list[dict[str, Any]], start: int, opening: str = "(") -> int | None:
    pairs = {"(": ")", "[": "]", "{": "}"}
    closing = pairs.get(opening)
    if closing is None or start >= len(tokens) or tokens[start]["value"] != opening:
        return None
    depth = 0
    for index in range(start, len(tokens)):
        value = tokens[index]["value"]
        if value == opening:
            depth += 1
        elif value == closing:
            depth -= 1
            if depth == 0:
                return index
    return None


def _js_callee(tokens: list[dict[str, Any]], index: int) -> tuple[str, list[str]]:
    parts = [tokens[index]["value"]]
    cursor = index - 1
    while cursor >= 1 and tokens[cursor]["value"] in {".", "?."} and tokens[cursor - 1]["kind"] == "word":
        parts.insert(0, tokens[cursor - 1]["value"])
        cursor -= 2
    return ".".join(parts), parts


def _js_structure(path: str, source: str) -> dict[str, Any]:
    tokens = _js_tokens(source)
    stack: list[str] = []
    for token in tokens:
        value = token["value"]
        if value in "([{":
            stack.append(value)
        elif value in ")]}":
            if not stack or {')': '(', ']': '[', '}': '{'}[value] != stack[-1]:
                return {"path": path, "language": "javascript", "parse_valid": False, "error": "unbalanced JavaScript/TypeScript delimiters", "functions": [], "calls": [], "guards": [], "returns": []}
            stack.pop()
    if stack:
        return {"path": path, "language": "javascript", "parse_valid": False, "error": "unbalanced JavaScript/TypeScript delimiters", "functions": [], "calls": [], "guards": [], "returns": []}
    functions: list[dict[str, Any]] = []
    function_ranges: list[tuple[int, int, str]] = []
    calls: list[dict[str, Any]] = []
    guards: list[dict[str, Any]] = []
    returns: list[dict[str, Any]] = []
    for index, token in enumerate(tokens):
        if token["value"] != "function":
            continue
        name = tokens[index + 1]["value"] if index + 1 < len(tokens) and tokens[index + 1]["kind"] == "word" else "anonymous"
        open_paren = next((cursor for cursor in range(index + 1, min(len(tokens), index + 8)) if tokens[cursor]["value"] == "("), None)
        close_paren = _balanced_end(tokens, open_paren) if open_paren is not None else None
        body_start = next((cursor for cursor in range((close_paren or index) + 1, min(len(tokens), (close_paren or index) + 5)) if tokens[cursor]["value"] == "{"), None)
        body_end = _balanced_end(tokens, body_start, "{") if body_start is not None else None
        parameters = [item["value"] for item in tokens[(open_paren or index) + 1:(close_paren or index)] if item["kind"] == "word"]
        end_line = tokens[body_end]["line"] if body_end is not None else token["line"]
        functions.append({"name": name, "line": token["line"], "end_line": end_line, "parameters": parameters})
        if body_start is not None and body_end is not None:
            function_ranges.append((body_start, body_end, name))

    def containing_function(index: int) -> str | None:
        candidates = [item for item in function_ranges if item[0] <= index <= item[1]]
        return min(candidates, key=lambda item: item[1] - item[0])[2] if candidates else None

    for index, token in enumerate(tokens):
        value = token["value"]
        if value == "if" and index + 1 < len(tokens) and tokens[index + 1]["value"] == "(":
            end = _balanced_end(tokens, index + 1)
            if end is not None:
                predicate = " ".join(item["value"] for item in tokens[index + 2:end])
                parts = [item["value"] for item in tokens[index + 2:end] if item["kind"] == "word"]
                guards.append({"kind": "if", "function": containing_function(index), "line": token["line"], "end_line": tokens[end]["line"], "predicate": predicate, "uses": sorted(set(parts)), "categories": sorted(_semantic_category(parts)), "fingerprint": f"guard:{predicate}"})
        if value == "return":
            end = index + 1
            while end < len(tokens) and tokens[end]["value"] not in {";", "}"}:
                end += 1
            values = [item["value"] for item in tokens[index + 1:end]]
            return_value = " ".join(values)
            returns.append({"function": containing_function(index), "line": token["line"], "end_line": tokens[end - 1]["line"] if end > index + 1 else token["line"], "value": return_value, "uses": sorted(set(item["value"] for item in tokens[index + 1:end] if item["kind"] == "word")), "categories": sorted(_semantic_category(values)), "fingerprint": f"return:{return_value}"})
        if value == "(" and index > 0 and tokens[index - 1]["kind"] == "word" and tokens[index - 1]["value"] not in _CONTROL_NAMES:
            if index > 1 and tokens[index - 2]["value"] == "function":
                continue
            callee, parts = _js_callee(tokens, index - 1)
            end = _balanced_end(tokens, index)
            arguments = " ".join(item["value"] for item in tokens[index + 1:end]) if end is not None else ""
            uses = parts + re.findall(r"[A-Za-z_$][A-Za-z0-9_$]*", arguments)
            calls.append({"callee": callee, "function": containing_function(index), "line": token["line"], "end_line": tokens[end]["line"] if end is not None else token["line"], "arguments": [arguments], "keywords": [], "uses": sorted(set(uses)), "categories": sorted(_semantic_category(uses)), "fingerprint": f"call:{callee}:{arguments}"})
    return {"path": path, "language": "javascript", "parse_valid": True, "functions": functions, "calls": calls, "guards": guards, "returns": returns}


def _parse_source(path: str, source: str) -> dict[str, Any]:
    suffix = Path(path).suffix.lower()
    if suffix in {".py", ".pyw"}:
        return _python_structure(path, source)
    if suffix in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}:
        return _js_structure(path, source)
    return {"path": path, "language": "unknown", "parse_valid": False, "error": f"no adapter for {suffix or 'extensionless source'}", "functions": [], "calls": [], "guards": [], "returns": []}


def _source_items(value: Any) -> list[dict[str, str]]:
    if isinstance(value, str):
        return [{"path": "inline.py", "content": value}]
    if isinstance(value, dict):
        if "content" in value or "source" in value or "text" in value:
            return [{"path": str(value.get("path", "inline.py")), "content": _text(value.get("content", value.get("source", value.get("text", ""))))}]
        result: list[dict[str, str]] = []
        for path, content in value.items():
            if isinstance(content, str):
                result.append({"path": str(path), "content": content})
        return result
    if isinstance(value, list):
        result = []
        for item in value:
            result.extend(_source_items(item))
        return result
    return []


def _resolved_path(value: Any, base_dir: Path | None) -> Path:
    path = Path(str(value))
    return base_dir / path if base_dir and not path.is_absolute() else path


def _git_sources(selected: dict[str, Any], side: str, base_dir: Path | None) -> tuple[list[dict[str, str]], list[str]]:
    repo = _resolved_path(selected.get("git_repo", selected.get("repository", "")), base_dir)
    revision = str(selected.get("revision", selected.get("commit", "")))
    reasons: list[str] = []
    if not repo.is_dir() or not revision:
        return [], [f"{side} Git source repository or revision is unavailable"]
    declared_paths = selected.get("paths", [])
    if isinstance(declared_paths, str):
        declared_paths = [declared_paths]
    subpath = str(selected.get("subpath", "")).strip("/")
    command = ["git", "-C", str(repo), "ls-tree", "-r", "--name-only", revision]
    if subpath:
        command.extend(["--", subpath])
    try:
        listed = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return [], [f"{side} Git source listing failed: {type(exc).__name__}"]
    if listed.returncode != 0:
        return [], [f"{side} Git source revision cannot be resolved"]
    allow = {str(path).strip("/") for path in declared_paths if isinstance(path, str) and path}
    paths = [
        path
        for path in listed.stdout.splitlines()
        if Path(path).suffix.lower() in {".py", ".pyw", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}
        and (not allow or path in allow or any(path.endswith(f"/{item}") for item in allow))
    ]
    items: list[dict[str, str]] = []
    for path in sorted(paths):
        try:
            shown = subprocess.run(
                ["git", "-C", str(repo), "show", f"{revision}:{path}"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="strict",
                timeout=30,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired, UnicodeError) as exc:
            reasons.append(f"unable to read {side} Git source {path}: {type(exc).__name__}")
            continue
        if shown.returncode == 0:
            items.append({"path": path, "content": shown.stdout})
        else:
            reasons.append(f"unable to read {side} Git source {path}")
    if not items:
        reasons.append(f"{side} Git source selection has no supported files")
    return items, reasons


def _read_sources(spec: dict[str, Any], side: str, base_dir: Path | None) -> tuple[list[dict[str, str]], list[str]]:
    reasons: list[str] = []
    # A prepared case has two distinct source domains.  ``source`` is the
    # runnable MCP Server tree; ``analysis_source`` is the vulnerable/fixed
    # dependency tree used for patch localization and effect modeling.  Keep
    # the legacy fallback for old synthetic fixtures that only supplied
    # analysis material under ``source``.
    source = spec.get("analysis_source") if "analysis_source" in spec else spec.get("source", spec.get("sources", {}))
    selected: Any = None
    if isinstance(source, dict):
        selected = source.get(side, source.get("patched" if side == "fixed" else "vulnerable"))
    if selected is None:
        selected = spec.get(f"{side}_source", spec.get("fixed_source" if side == "fixed" else "vulnerable_source"))
    if selected is None:
        roots = spec.get("source_roots", spec.get("source_root"))
        if isinstance(roots, dict):
            selected = roots.get(side, roots.get("fixed" if side == "fixed" else "vulnerable"))
    is_git_spec = isinstance(selected, dict) and bool(selected.get("git_repo", selected.get("repository"))) and bool(selected.get("revision", selected.get("commit")))
    is_root_spec = isinstance(selected, dict) and bool(selected.get("root")) and not any(
        key in selected for key in ("content", "source", "text")
    )
    items = [] if is_root_spec or is_git_spec else _source_items(selected)
    if is_git_spec:
        items, git_reasons = _git_sources(selected, side, base_dir)
        reasons.extend(git_reasons)
    if not items and isinstance(selected, dict) and selected.get("root"):
        root = _resolved_path(selected["root"], base_dir)
        if root.exists() and root.is_dir():
            for path in sorted(root.rglob("*")):
                if path.suffix.lower() in {".py", ".pyw", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"} and path.is_file():
                    try:
                        items.append({"path": str(path.relative_to(root)), "content": path.read_text(encoding="utf-8")})
                    except (OSError, UnicodeDecodeError):
                        reasons.append(f"unable to read {side} source {path}")
        else:
            reasons.append(f"{side} source root is unavailable")
    if not items and isinstance(selected, dict) and selected.get("archive"):
        archive = _resolved_path(selected["archive"], base_dir)
        try:
            if zipfile.is_zipfile(archive):
                with zipfile.ZipFile(archive) as stream:
                    for member in sorted(stream.namelist()):
                        if Path(member).suffix.lower() in {".py", ".pyw", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}:
                            items.append({"path": member, "content": stream.read(member).decode("utf-8")})
            elif tarfile.is_tarfile(archive):
                with tarfile.open(archive) as stream:
                    for member in sorted(stream.getmembers(), key=lambda item: item.name):
                        if member.isfile() and Path(member.name).suffix.lower() in {".py", ".pyw", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}:
                            handle = stream.extractfile(member)
                            if handle is not None:
                                items.append({"path": member.name, "content": handle.read().decode("utf-8")})
            else:
                reasons.append(f"{side} source archive is unavailable or unsupported")
        except (OSError, UnicodeDecodeError, tarfile.TarError, zipfile.BadZipFile) as exc:
            reasons.append(f"{side} source archive cannot be read: {type(exc).__name__}")
    if not items:
        reasons.append(f"{side} source is missing")
    return items, reasons


def _patch_text(spec: dict[str, Any], base_dir: Path | None) -> tuple[str, list[str]]:
    # The patch consumed by localization must describe the dependency repair,
    # never merely a Server manifest/version change.  ``patch`` remains the
    # compatibility fallback for pre-separation cases.
    patch = spec.get("analysis_patch") if "analysis_patch" in spec else spec.get("patch", spec.get("patch_diff"))
    reasons: list[str] = []
    if isinstance(patch, str):
        return patch, reasons
    if isinstance(patch, dict):
        for key in ("unified_diff", "diff", "content", "text"):
            if isinstance(patch.get(key), str) and patch[key].strip():
                return patch[key], reasons
        patch_path = patch.get("path")
        if isinstance(patch_path, str) and patch_path:
            path = _resolved_path(patch_path, base_dir)
            expected_sha256 = patch.get("sha256")
            if not path.is_file():
                reasons.append("analysis patch file is missing")
                return "", reasons
            try:
                content = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError) as exc:
                reasons.append(f"analysis patch file cannot be read: {type(exc).__name__}")
                return "", reasons
            if expected_sha256:
                actual_sha256 = hashlib.sha256(content.encode("utf-8")).hexdigest()
                if actual_sha256 != str(expected_sha256):
                    reasons.append("analysis patch file hash mismatch")
                    return "", reasons
            return content, reasons
        repository = patch.get("git_repo", patch.get("repository"))
        vulnerable_revision = patch.get("vulnerable_revision", patch.get("base_revision"))
        fixed_revision = patch.get("fixed_revision", patch.get("revision"))
        if repository and vulnerable_revision and fixed_revision:
            repo = _resolved_path(repository, base_dir)
            paths = patch.get("paths", [])
            if isinstance(paths, str):
                paths = [paths]
            command = [
                "git", "-C", str(repo), "diff", "--no-ext-diff", "--unified=3",
                str(vulnerable_revision), str(fixed_revision),
            ]
            if paths:
                command.extend(["--", *(str(path) for path in paths)])
            try:
                completed = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30, check=False)
            except (OSError, subprocess.TimeoutExpired) as exc:
                reasons.append(f"Git patch extraction failed: {type(exc).__name__}")
            else:
                if completed.returncode == 0 and completed.stdout.strip():
                    return completed.stdout, reasons
                reasons.append("Git patch revisions have no readable source difference")
        path_value = patch.get("path")
        if path_value:
            path = _resolved_path(path_value, base_dir)
            try:
                return path.read_text(encoding="utf-8"), reasons
            except (OSError, UnicodeDecodeError):
                reasons.append("patch file is unavailable")
    reasons.append("unified patch diff is missing")
    return "", reasons


def _parse_patch(diff: str) -> dict[str, Any]:
    files: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    old_line = new_line = 0
    for line in diff.splitlines():
        if line.startswith("diff --git "):
            if current:
                files.append(current)
            current = {"path": line.split(" b/", 1)[-1], "additions": [], "deletions": [], "hunks": []}
        elif line.startswith("+++ "):
            # ``diff -u`` appends a tab-separated timestamp to file headers;
            # keep only the path so hunk locations can be matched to source.
            raw_path = line[4:].strip().split("\t", 1)[0]
            if current is None or current["hunks"] or current["additions"] or current["deletions"]:
                if current:
                    files.append(current)
                current = {"path": raw_path.removeprefix("b/"), "additions": [], "deletions": [], "hunks": []}
            elif raw_path not in {"/dev/null", ""}:
                current["path"] = raw_path.removeprefix("b/")
        elif line.startswith("@@"):
            match = re.search(r"-(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))?", line)
            if match:
                old_line, new_line = int(match.group(1)), int(match.group(3))
                if current is None:
                    current = {"path": "unknown", "additions": [], "deletions": [], "hunks": []}
                current["hunks"].append({
                    "header": line,
                    "old_start": old_line,
                    "old_count": int(match.group(2) or 1),
                    "new_start": new_line,
                    "new_count": int(match.group(4) or 1),
                })
        elif current is not None and line.startswith("+") and not line.startswith("+++"):
            current["additions"].append({"line": new_line, "text": line[1:]})
            new_line += 1
        elif current is not None and line.startswith("-") and not line.startswith("---"):
            current["deletions"].append({"line": old_line, "text": line[1:]})
            old_line += 1
        elif line.startswith(" "):
            old_line += 1
            new_line += 1
    if current:
        files.append(current)
    changed = [item for file in files for item in file["additions"] + file["deletions"]]
    return {"parse_valid": bool(files and changed), "files": files, "changed_lines": changed, "diff_sha256": hashlib.sha256(diff.encode("utf-8")).hexdigest()}


def _all_structures(items: list[dict[str, str]]) -> list[dict[str, Any]]:
    return [_parse_source(item["path"], item["content"]) for item in items]


def _structure_semantics(structures: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], set[str], list[str]]:
    nodes: list[dict[str, Any]] = []
    categories: set[str] = set()
    errors: list[str] = []
    for structure in structures:
        if not structure.get("parse_valid"):
            errors.append(f"{structure.get('path')}: {structure.get('error', 'parse failed')}")
            continue
        for kind in ("functions", "calls", "guards", "returns"):
            for node in structure.get(kind, []):
                item = dict(node)
                item["node_kind"] = kind[:-1] if kind.endswith("s") else kind
                item["path"] = structure["path"]
                item["source_ref"] = _line_ref(structure["path"], node.get("line"))
                nodes.append(item)
                categories.update(node.get("categories", []))
    return nodes, categories, errors


def _changed_structured_nodes(vulnerable: list[dict[str, Any]], fixed: list[dict[str, Any]], patch: dict[str, Any]) -> list[dict[str, Any]]:
    def fingerprints(structures: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
        result: dict[str, list[dict[str, Any]]] = {}
        for structure in structures:
            for kind in ("calls", "guards", "returns"):
                for node in structure.get(kind, []):
                    key = f"{kind}:{node.get('fingerprint', node.get('value', ''))}"
                    result.setdefault(key, []).append({
                        **node,
                        "path": structure["path"],
                        "node_kind": kind[:-1] if kind.endswith("s") else kind,
                        "source_ref": _line_ref(structure["path"], node.get("line")),
                    })
        return result
    left, right = fingerprints(vulnerable), fingerprints(fixed)
    changed: list[dict[str, Any]] = []
    for key in sorted(set(left) | set(right)):
        if len(left.get(key, [])) != len(right.get(key, [])):
            for node in left.get(key, []):
                changed.append({"side": "vulnerable", "change": "removed", **node})
            for node in right.get(key, []):
                changed.append({"side": "fixed", "change": "added", **node})
    patch_files = [file for file in patch.get("files", []) if file.get("path")]
    if not patch_files:
        return []

    def file_matches(node_path: str, patch_path: str) -> bool:
        left = Path(node_path).as_posix().removeprefix("a/").removeprefix("b/")
        right = Path(patch_path).as_posix().removeprefix("a/").removeprefix("b/")
        return left == right or left.endswith(f"/{right}") or right.endswith(f"/{left}")

    def hunk_matches(node: dict[str, Any], file: dict[str, Any]) -> bool:
        start = int(node.get("line") or 0)
        end = int(node.get("end_line") or start)
        changes = file.get("deletions", []) if node.get("side") == "vulnerable" else file.get("additions", [])
        return any(start <= int(change.get("line", 0)) <= end for change in changes)

    return [
        node
        for node in changed
        if any(
            file_matches(str(node.get("path", "")), str(file["path"])) and hunk_matches(node, file)
            for file in patch_files
        )
    ]


def _patch_related_parse_errors(errors: list[str], patch: dict[str, Any]) -> list[str]:
    """Keep parse failures that can affect the patched source mapping.

    Published JavaScript packages often ship bundled/minified artifacts that
    are outside the patch. Those artifacts must not hide a valid anchor in the
    source files actually changed by the repair.
    """
    patch_paths = {
        Path(str(item.get("path", ""))).as_posix()
        for item in patch.get("files", [])
        if item.get("path")
    }
    return [
        error
        for error in errors
        if Path(error.split(": ", 1)[0]).as_posix() in patch_paths
    ]


def _payloads(rows: list[dict[str, Any]], level: str | None = None) -> list[Any]:
    result: list[Any] = []
    for row in rows:
        if level and row.get("level") != level:
            continue
        for key in ("content", "structuredContent", "observation", "result", "return", "state", "text"):
            if key in row and row[key] is not None:
                value = row[key]
                result.append(value)
                if key == "text" and isinstance(value, str):
                    try:
                        parsed = json.loads(value)
                    except json.JSONDecodeError:
                        parsed = None
                    if isinstance(parsed, (dict, list)):
                        result.append(parsed)
    return result


def _field_paths(value: Any, prefix: str = "") -> list[tuple[str, Any]]:
    result: list[tuple[str, Any]] = []
    if isinstance(value, dict):
        for key, item in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            result.append((path, item))
            result.extend(_field_paths(item, path))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            path = f"{prefix}[{index}]"
            result.append((path, item))
            result.extend(_field_paths(item, path))
    elif not prefix:
        result.append(("$", value))
    return result


def _payload_field_paths(rows: list[dict[str, Any]], level: str | None = None) -> set[str]:
    paths: set[str] = set()
    for payload in _payloads(rows, level):
        paths.update(path for path, _ in _field_paths(payload) if path)
    return paths


def _payload_value_digests(rows: list[dict[str, Any]], level: str | None = None) -> dict[str, list[str]]:
    values: dict[str, set[str]] = {}
    for payload in _payloads(rows, level):
        for path, value in _field_paths(payload):
            if isinstance(value, (dict, list)):
                continue
            values.setdefault(path, set()).add(_digest(value))
    return {path: sorted(digests) for path, digests in values.items()}


def _looks_like_tool_result(row: dict[str, Any]) -> bool:
    """Distinguish a returned Tool structure from an external-state-only event."""
    direct_keys = {"tool_result", "structuredContent", "normalized_result", "result", "isError"}
    if direct_keys & set(row):
        return True
    content = row.get("content")
    if isinstance(content, dict):
        return bool(direct_keys & set(content)) or isinstance(content.get("content"), list)
    return isinstance(content, list)


def _trace_structured_events(rows: list[dict[str, Any]]) -> dict[str, set[str]]:
    calls: set[str] = set()
    exceptions: set[str] = set()
    resources: set[str] = set()
    returns: set[str] = set()
    for row in rows:
        maps: list[dict[str, Any]] = [row]
        for key in ("event", "trace_event", "metadata", "payload", "data", "content", "result"):
            value = row.get(key)
            if isinstance(value, dict):
                maps.append(value)
        for event in maps:
            for key in ("function", "function_name", "call", "callee", "tool_name", "sink"):
                value = event.get(key)
                if isinstance(value, dict):
                    value = value.get("name", value.get("callee", value.get("function")))
                if value:
                    arguments = event.get("arguments", event.get("args", event.get("parameters", {})))
                    location = event.get("line", event.get("location", event.get("file", "")))
                    calls.add(f"{key}:{_text(value)}@{_text(location)}#{_digest(arguments)}")
            for key in ("exception", "error", "error_type"):
                value = event.get(key)
                if value:
                    exception_type = value.get("type") if isinstance(value, dict) else value
                    exceptions.add(f"{key}:{_text(exception_type)}")
            for key in ("file", "file_path", "path", "network", "url", "command", "resource", "resource_id", "resource_identity", "external_state", "state", "state_read", "state_write"):
                value = event.get(key)
                if value is not None:
                    resources.add(f"{key}#{_digest(value)}")
            for key in ("return", "return_value", "result", "content", "structuredContent"):
                if key in event:
                    returns.add(f"{key}#{_digest(event[key])}")
    return {"calls": calls, "exceptions": exceptions, "resources": resources, "returns": returns}


def _trace_side(rows: list[dict[str, Any]]) -> dict[str, Any]:
    levels = {str(row.get("level")) for row in rows if row.get("level")}
    tool_rows = [
        row for row in rows
        if row.get("level") in {
            "L0_RAW_MCP_RESULT",
            "L1_NORMALIZED_TOOL_RESULT",
            "L2_HOST_PROCESSED_TOOL_RESULT",
            "L3_SESSION_TOOL_RESULT",
        }
        and _looks_like_tool_result(row)
    ]
    raw_tool_rows = [
        row for row in tool_rows
        if row.get("level") in {
            "L0_RAW_MCP_RESULT",
            "L1_NORMALIZED_TOOL_RESULT",
        }
    ]
    tool_paths = _payload_field_paths(tool_rows)
    raw_tool_paths = _payload_field_paths(raw_tool_rows)
    l4_paths = _payload_field_paths(rows, "L4_MODEL_VISIBLE_OBSERVATION")
    tool_value_digests = _payload_value_digests(tool_rows)
    raw_tool_value_digests = _payload_value_digests(raw_tool_rows)
    l4_value_digests = _payload_value_digests(rows, "L4_MODEL_VISIBLE_OBSERVATION")
    l2_l3_fields = {path.split(".")[-1].split("[")[0] for path in tool_paths}
    l4_fields = {path.split(".")[-1].split("[")[0] for path in l4_paths}
    l4_text = "\n".join(_text(value) for value in _payloads(rows, "L4_MODEL_VISIBLE_OBSERVATION"))
    pre_l4_text = "\n".join(_text(value) for value in _payloads(tool_rows) if isinstance(value, (dict, list)))
    shared_fields = sorted(l2_l3_fields & l4_fields)
    shared_paths = sorted(tool_paths & l4_paths)
    structured_events = _trace_structured_events(rows)
    return {
        "valid": bool(rows) and all(level in levels for level in EVIDENCE_LEVELS[:4]),
        "l4_available": "L4_MODEL_VISIBLE_OBSERVATION" in levels,
        "levels": sorted(levels),
        "l4_fields": sorted(l4_fields),
        "tool_result_fields": sorted(l2_l3_fields),
        "tool_result_paths": sorted(tool_paths),
        "raw_tool_result_paths": sorted(raw_tool_paths),
        "l4_paths": sorted(l4_paths),
        "tool_value_digests": tool_value_digests,
        "raw_tool_value_digests": raw_tool_value_digests,
        "l4_value_digests": l4_value_digests,
        "shared_fields": shared_fields,
        "shared_paths": shared_paths,
        "l4_text_digest": _digest(l4_text),
        "pre_l4_digest": _digest(pre_l4_text),
        "rows": rows,
        "tool_result_provenance": bool(tool_paths),
        "l4_tool_result_provenance": bool(shared_paths),
        "anchor_reached": any(row.get("anchor_reached") is True or row.get("vulnerability_anchor_reached") is True for row in rows),
        "call_sites": sorted(structured_events["calls"]),
        "exceptions": sorted(structured_events["exceptions"]),
        "resource_events": sorted(structured_events["resources"]),
        "return_events": sorted(structured_events["returns"]),
    }


def _load_trace_rows(value: Any, base_dir: Path | None) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [row for row in value if isinstance(row, dict)]
    if isinstance(value, dict):
        rows = value.get("rows", value.get("evidence", []))
        return _load_trace_rows(rows, base_dir)
    if not isinstance(value, str) or not value:
        return []
    path = Path(value)
    if base_dir and not path.is_absolute():
        path = base_dir / path
    try:
        raw = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return []
    if path.suffix.lower() == ".jsonl":
        rows: list[dict[str, Any]] = []
        for line in raw.splitlines():
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(item, dict):
                rows.append(item)
        return rows
    try:
        return _load_trace_rows(json.loads(raw), base_dir)
    except json.JSONDecodeError:
        return []


def _trace_diff(vulnerable: dict[str, Any], fixed: dict[str, Any], input_value: Any) -> dict[str, Any]:
    v_fields = set(vulnerable["l4_fields"])
    f_fields = set(fixed["l4_fields"])
    v_pre_fields = set(vulnerable["tool_result_fields"])
    f_pre_fields = set(fixed["tool_result_fields"])
    v_paths = set(vulnerable["l4_paths"]) | set(vulnerable["tool_result_paths"])
    f_paths = set(fixed["l4_paths"]) | set(fixed["tool_result_paths"])
    changed_fields = sorted((v_fields | v_pre_fields) ^ (f_fields | f_pre_fields))
    changed_paths = sorted(v_paths ^ f_paths)
    v_shared = set(vulnerable["shared_fields"])
    f_shared = set(fixed["shared_fields"])
    changed_shared = sorted(v_shared ^ f_shared)
    def changed_values(left: dict[str, list[str]], right: dict[str, list[str]]) -> list[str]:
        return sorted(
            path
            for path in set(left) & set(right)
            if left[path] != right[path]
        )

    changed_value_paths = sorted(set(
        changed_values(vulnerable["tool_value_digests"], fixed["tool_value_digests"])
        + changed_values(vulnerable["l4_value_digests"], fixed["l4_value_digests"])
    ))
    changed_value_fields = sorted({path.split(".")[-1].split("[")[0] for path in changed_value_paths})
    error_text_only = bool(changed_value_fields) and all(
        field.lower() in {"error", "errors", "message", "error_message", "exception_message"}
        for field in changed_value_fields
    ) and not (set(vulnerable["exceptions"]) ^ set(fixed["exceptions"]))
    input_text = _text(input_value)
    input_fields = {str(key).lower() for key in input_value} if isinstance(input_value, dict) else set()
    changed_names = set(changed_fields) | set(changed_value_fields)
    diff_is_input_echo = bool(changed_names) and all(
        field.lower() in input_fields or field.lower() in input_text.lower()
        for field in changed_names
    )
    return {
        "changed_fields": changed_fields,
        "changed_value_fields": changed_value_fields,
        "changed_value_paths": changed_value_paths,
        "changed_paths": changed_paths,
        "changed_provenance_fields": changed_shared,
        "vulnerable_only_fields": sorted((v_fields | v_pre_fields) - (f_fields | f_pre_fields)),
        "fixed_only_fields": sorted((f_fields | f_pre_fields) - (v_fields | v_pre_fields)),
        "vulnerable_only_paths": sorted(v_paths - f_paths),
        "fixed_only_paths": sorted(f_paths - v_paths),
        "l4_digest_changed": vulnerable["l4_text_digest"] != fixed["l4_text_digest"],
        "pre_l4_digest_changed": vulnerable["pre_l4_digest"] != fixed["pre_l4_digest"],
        "input_echo_only": diff_is_input_echo,
        "error_text_only": error_text_only,
        "vulnerable_l4_fields": sorted(v_fields),
        "fixed_l4_fields": sorted(f_fields),
        "call_sites_changed": sorted(set(vulnerable["call_sites"]) ^ set(fixed["call_sites"])),
        "exceptions_changed": sorted(set(vulnerable["exceptions"]) ^ set(fixed["exceptions"])),
        "resource_events_changed": sorted(set(vulnerable["resource_events"]) ^ set(fixed["resource_events"])),
        "return_events_changed": sorted(set(vulnerable["return_events"]) ^ set(fixed["return_events"])),
    }


_RESOURCE_CALL_MARKERS = {
    "open", "read", "readfile", "write", "writefile", "unlink", "rename",
    "fetch", "get", "post", "put", "request", "send", "socket", "connect",
    "axios", "requests", "http", "https", "spawn", "popen", "exec",
    "check_output", "run", "create_process", "process",
}


def _node_text(node: dict[str, Any]) -> str:
    return " ".join(
        str(node.get(key, ""))
        for key in ("callee", "predicate", "value", "arguments", "uses", "keywords")
    ).lower()


def _has_control_evidence(nodes: list[dict[str, Any]], changed: dict[str, Any]) -> bool:
    """Return true only when execution behavior has a structured witness."""
    return bool(
        any(node.get("node_kind") == "guard" for node in nodes)
        or changed.get("exceptions_changed")
        or changed.get("call_sites_changed")
    )


def _has_resource_evidence(nodes: list[dict[str, Any]], changed: dict[str, Any]) -> bool:
    """Identify resource/state effects from source or runtime evidence.

    This deliberately does not inspect vulnerability categories.  A resource
    effect needs an access/state witness, not a category name.
    """
    if changed.get("resource_events_changed"):
        return True
    resource_calls = [
        node for node in nodes
        if node.get("node_kind") == "call"
        and any(marker in _node_text(node) for marker in _RESOURCE_CALL_MARKERS)
    ]
    if not resource_calls:
        return False
    # A patch-scoped guard/exception can change whether an otherwise unchanged
    # resource call executes.  Requiring a changed call fingerprint here would
    # miss the common traversal/SSRF repair shape.
    return bool(changed.get("call_sites_changed") or changed.get("exceptions_changed") or any(node.get("node_kind") == "guard" for node in nodes))


def _is_input_echo_path(path: str, input_value: Any) -> bool:
    field = path.split(".")[-1].split("[")[0].lower()
    input_text = _text(input_value).lower()
    input_fields = {str(key).lower() for key in input_value} if isinstance(input_value, dict) else set()
    return field in input_fields or field in input_text


_PROTOCOL_CARRIER_FIELDS = {
    "callid", "iserror", "mimetype", "role", "step", "tool_call_id", "turn",
}


def _is_protocol_carrier_path(path: str) -> bool:
    """Exclude transport scaffolding from semantic effect candidates."""
    normalized = str(path).lower()
    leaf = re.split(r"[.\[]", normalized)[-1].rstrip("]")
    if leaf in _PROTOCOL_CARRIER_FIELDS:
        return True
    return leaf == "type" and "content[" in normalized


def _path_values(trace: dict[str, Any], paths: list[str]) -> list[Any]:
    """Collect scalar values at candidate paths from the paired Tool trace."""
    values: list[Any] = []
    pre_l4_rows = [
        row for row in trace.get("rows", [])
        if row.get("level") in {
            "L0_RAW_MCP_RESULT",
            "L1_NORMALIZED_TOOL_RESULT",
            "L2_HOST_PROCESSED_TOOL_RESULT",
            "L3_SESSION_TOOL_RESULT",
        }
    ]
    for payload in _payloads(pre_l4_rows):
        for path, value in _field_paths(payload):
            if any(_paths_equivalent(path, candidate) for candidate in paths):
                if not isinstance(value, (dict, list)):
                    values.append(value)
    return values


def _is_input_echo_only_value_paths(trace: dict[str, Any], paths: list[str], input_value: Any) -> bool:
    """Recognize text-only Tool echoes of a frozen input value.

    This is deliberately limited to generic text/content carriers.  A value
    in a semantic field (for example ``stdout`` or ``records``) remains
    eligible even when it also mentions an input value.
    """
    if not paths or not isinstance(input_value, dict):
        return False
    semantic_paths = [
        path for path in paths
        if path.split(".")[-1].split("[")[0].lower() not in {"$", "text", "content", "message", "messages"}
    ]
    if semantic_paths:
        return False
    input_tokens = [
        _text(value).strip()
        for value in input_value.values()
        if isinstance(value, (str, int, float)) and _text(value).strip()
    ]
    if not input_tokens:
        return False
    values = [_text(value) for value in _path_values(trace, paths)]
    return bool(values) and all(any(token in value for token in input_tokens) for value in values)


def _value_carrier_paths(trace: dict[str, Any], changed: dict[str, Any], input_value: Any) -> list[str]:
    candidates = set(changed.get("vulnerable_only_paths", []))
    candidates.update(changed.get("changed_value_paths", []))
    candidates.update(changed.get("changed_paths", []))
    early_paths = set(trace.get("raw_tool_result_paths", []))
    paths = sorted(
        path
        for path in trace.get("tool_value_digests", {})
        if any(_paths_equivalent(candidate, path) for candidate in candidates)
        and any(_paths_equivalent(path, early) for early in early_paths)
        and not _is_protocol_carrier_path(path)
        and not _is_input_echo_path(path, input_value)
    )
    return paths


def _has_value_evidence(
    vulnerable_trace: dict[str, Any],
    fixed_trace: dict[str, Any],
    changed: dict[str, Any],
    carrier_paths: list[str],
) -> bool:
    return bool(
        carrier_paths
        and vulnerable_trace.get("tool_result_provenance")
        and fixed_trace.get("tool_result_provenance")
        and not changed.get("input_echo_only")
        and (
            changed.get("changed_value_paths")
            or changed.get("vulnerable_only_paths")
            or changed.get("return_events_changed")
        )
    )


def _effect_source_refs(nodes: list[dict[str, Any]], kinds: set[str]) -> list[str]:
    selected: list[str] = []
    for node in nodes:
        node_kind = node.get("node_kind")
        if (
            ("control" in kinds and node_kind == "guard")
            or ("resource" in kinds and node_kind == "call")
            or ("value" in kinds and node_kind in {"return", "call"})
        ):
            ref = node.get("source_ref") or _line_ref(node.get("path", "unknown"), node.get("line"))
            if ref:
                selected.append(str(ref))
    return list(dict.fromkeys(selected))


def _stable_effect_id(kind: str, signature: Any, *, ordinal: int = 1, total: int = 1) -> str:
    """Return a deterministic ID for one concrete effect instance.

    The singleton spelling is retained for old consumers, but multiplicity is
    never represented by reusing one ID.  The signature contains the concrete
    source/resource/carrier identity, so IDs remain stable across ordering.
    """
    prefix = kind.removesuffix("_EFFECT").lower()
    if total == 1:
        return f"effect-{prefix}-1"
    digest = _digest({"kind": kind, "signature": signature})[:12]
    return f"effect-{prefix}-{digest}-{ordinal}"


def _runtime_resource_events(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Extract distinct resource operations without assigning them to effects."""
    events: dict[str, dict[str, Any]] = {}
    for row in rows:
        event = row.get("event") if isinstance(row.get("event"), dict) else None
        if not event:
            continue
        resource_id = event.get("resource_id") or event.get("resource_identity") or event.get("file_path") or event.get("url")
        operation = str(event.get("operation") or ("read" if event.get("state_read") else "write" if event.get("state_write") else "")).lower()
        if not resource_id and not operation:
            continue
        is_stable_identity = event.get("stable_resource_identity") is True
        stable_identity = {
            "resource_id": str(resource_id) if resource_id is not None else None,
            "operation": operation or "unknown",
            "location": str(event.get("location") or ""),
            "function": str(event.get("function") or event.get("callee") or ""),
        }
        execution_identity = {
            "trace_id": str(row.get("trace_id") or event.get("trace_id") or ""),
            "span_id": str(row.get("span_id") or event.get("span_id") or ""),
            "repetition": int(row.get("repetition", 1) or 1),
        }
        identity = stable_identity if is_stable_identity else {**stable_identity, **execution_identity}
        key = _digest(identity)
        candidate = {
            **identity,
            "event": copy.deepcopy(event),
            "resource_event": {**copy.deepcopy(event), **identity},
            "before_state": copy.deepcopy(event.get("before_state", event.get("state_before"))),
            "after_state": copy.deepcopy(event.get("after_state", event.get("state_after"))),
            "row_level": row.get("level"),
            "evidence_refs": [
                f"trace:{row.get('level', 'runtime')}:{int(row.get('repetition', 1) or 1)}",
                *([f"trace-id:{execution_identity['trace_id']}"] if execution_identity["trace_id"] else []),
                *([f"span:{execution_identity['span_id']}"] if execution_identity["span_id"] else []),
            ],
        }
        if key in events:
            events[key]["evidence_refs"] = list(dict.fromkeys(
                events[key].get("evidence_refs", []) + candidate.get("evidence_refs", [])
            ))
        else:
            events[key] = candidate
    return sorted(events.values(), key=lambda item: (_digest(item), str(item.get("location"))))


def _resource_event_signature(event: dict[str, Any]) -> dict[str, Any]:
    return {
        key: event.get(key)
        for key in (
            "resource_id", "operation", "location", "function", "trace_id", "span_id",
            "parent_span_id", "caused_by_effect", "tool_call_id", "invocation_id",
            "session_id", "repetition",
        )
        if event.get(key) not in (None, "")
    }


def _stable_resource_state_digests(
    rows: list[dict[str, Any]],
    resource_event: dict[str, Any],
) -> dict[str, list[str]]:
    """Return scalar state values stable across every matching execution."""
    snapshots: list[dict[str, set[str]]] = []
    expected = _resource_event_signature(resource_event)
    for row in rows:
        event = row.get("event") if isinstance(row.get("event"), dict) else None
        if not event:
            continue
        observed = _resource_event_signature({
            "resource_id": event.get("resource_id") or event.get("resource_identity") or event.get("file_path") or event.get("url"),
            "operation": event.get("operation") or ("read" if event.get("state_read") else "write" if event.get("state_write") else ""),
            "location": event.get("location"),
            "function": event.get("function") or event.get("callee"),
        })
        if any(observed.get(key) != value for key, value in expected.items()):
            continue
        state = event.get("after_state", event.get("state_after"))
        if not isinstance(state, (dict, list)):
            continue
        snapshot: dict[str, set[str]] = {}
        for path, value in _field_paths(state):
            if not isinstance(value, (dict, list)):
                snapshot.setdefault(path, set()).add(_digest(value))
        snapshots.append(snapshot)
    if not snapshots:
        return {}
    common_paths = set.intersection(*(set(snapshot) for snapshot in snapshots))
    result: dict[str, list[str]] = {}
    for path in common_paths:
        common_values = set.intersection(*(snapshot[path] for snapshot in snapshots))
        if common_values:
            result[path] = sorted(common_values)
    return result


def _resource_state_predicates(
    vulnerable_rows: list[dict[str, Any]],
    fixed_rows: list[dict[str, Any]],
    resource_event: dict[str, Any],
) -> tuple[dict[str, list[str]], dict[str, list[str]]]:
    """Bind a resource effect to stable vulnerable-only state values."""
    vulnerable = _stable_resource_state_digests(vulnerable_rows, resource_event)
    fixed = _stable_resource_state_digests(fixed_rows, resource_event)
    vulnerable_only = {
        path: sorted(set(digests) - set(fixed.get(path, [])))
        for path, digests in vulnerable.items()
        if set(digests) - set(fixed.get(path, []))
        and path.rsplit(".", 1)[-1].replace("_", "-").lower() not in _RESOURCE_STATE_METADATA_KEYS
    }
    return vulnerable_only, fixed


def _effect_provenance(
    kind: str,
    relevant_nodes: list[dict[str, Any]],
    tool_input: dict[str, Any],
    carrier_paths: list[str],
    v_trace: dict[str, Any],
    changed: dict[str, Any],
) -> list[dict[str, Any]]:
    """Keep provenance scoped to one semantic effect kind."""
    all_edges = _build_provenance(relevant_nodes, tool_input, carrier_paths, v_trace, changed)
    allowed = {
        "CONTROL_EFFECT": {"call", "control"},
        "RESOURCE_EFFECT": {"call", "state"},
        "VALUE_EFFECT": {"call", "data", "serialize", "observe", "state"},
    }[kind]
    edges = [edge for edge in all_edges if edge.get("edge_type") in allowed]
    refs = _effect_source_refs(
        relevant_nodes,
        {"control"} if kind == "CONTROL_EFFECT" else {"resource"} if kind == "RESOURCE_EFFECT" else {"value"},
    )
    if kind == "CONTROL_EFFECT" and changed.get("exceptions_changed"):
        refs.extend(["trace:vulnerable:exception", "trace:fixed:exception"])
        edges.append({
            "from": "vulnerability-anchor:control",
            "to": "control-continuation",
            "edge_type": "control",
            "slice_direction": ["forward", "backward"],
            "description": "Paired exception/continuation evidence distinguishes the vulnerable execution path",
            "evidence_refs": sorted(set(refs)),
        })
    if kind == "RESOURCE_EFFECT" and changed.get("resource_events_changed"):
        refs.extend(["trace:vulnerable:runtime-event", "trace:fixed:runtime-event"])
        edges.append({
            "from": "vulnerability-origin:resource",
            "to": f"runtime-state:{_digest(changed['resource_events_changed'])}",
            "edge_type": "state",
            "slice_direction": ["forward", "backward"],
            "description": "Paired runtime resource/state events distinguish the vulnerable operation",
            "evidence_refs": sorted(set(refs)),
        })
    return edges


def _mutated_input(value: Any, mode: str, trigger_fields: list[str] | None = None) -> Any:
    result = copy.deepcopy(value)
    if not isinstance(result, dict):
        return result
    if mode == "unrelated":
        result["__vulveil_unrelated_field"] = "stable-counterfactual"
        return result
    mutate_all = mode == "safe"
    mutated = False
    ordered_keys = [key for key in (trigger_fields or []) if key in result]
    ordered_keys.extend(key for key in result if key not in ordered_keys)
    for key in ordered_keys:
        item = result[key]
        if isinstance(item, str):
            safe = item.replace("../", "./").replace("..\\", ".\\").replace("|", " ")
            safe = re.sub(r"localhost\.?", "example.invalid", safe, flags=re.IGNORECASE)
            result[key] = safe if safe != item else "safe-input"
            mutated = True
            if not mutate_all:
                return result
            continue
        if isinstance(item, bool):
            result[key] = False
            mutated = True
            if not mutate_all:
                return result
            continue
        if isinstance(item, (int, float)):
            result[key] = 0
            mutated = True
            if not mutate_all:
                return result
    if result and not mutated:
        first = next(iter(result))
        result[first] = None
    return result


def generate_counterfactual_inputs(input_value: Any, trigger_fields: list[str] | None = None) -> list[dict[str, Any]]:
    """Create the minimal Stage 2 intervention matrix without executing it."""
    return [
        {"role": "trigger", "kind": "vulnerable-trigger-input", "tool_input": copy.deepcopy(input_value)},
        {"role": "safe", "kind": "safe-input", "tool_input": _mutated_input(input_value, "safe", trigger_fields)},
        {"role": "field-only", "kind": "replace-trigger-field", "tool_input": _mutated_input(input_value, "field-only", trigger_fields)},
        {"role": "unrelated", "kind": "replace-unrelated-field", "tool_input": _mutated_input(input_value, "unrelated", trigger_fields)},
    ]


def _paths_equivalent(left: str, right: str) -> bool:
    def normalize(path: str) -> str:
        value = str(path)
        if value.startswith("$."):
            return value[2:]
        if value.startswith("$"):
            return value[1:]
        return value

    left_normalized = normalize(left)
    right_normalized = normalize(right)
    return (
        left_normalized == right_normalized
        or left_normalized.endswith(f".{right_normalized}")
        or right_normalized.endswith(f".{left_normalized}")
    )


def _carrier_match(
    rows: list[dict[str, Any]],
    effect_fields: list[str],
    effect_paths: list[str],
    expected_digests: dict[str, list[str]],
) -> dict[str, Any]:
    trace = _trace_side(rows)
    matches: dict[str, list[str]] = {}
    for observed_path, observed_digests in trace["tool_value_digests"].items():
        field = observed_path.split(".")[-1].split("[")[0]
        expected_paths = [path for path in effect_paths if _paths_equivalent(path, observed_path)]
        if not expected_paths and field not in effect_fields:
            continue
        allowed = {
            digest
            for path, digests in expected_digests.items()
            if _paths_equivalent(path, observed_path)
            for digest in digests
        }
        overlap = sorted(set(observed_digests) & allowed) if allowed else sorted(observed_digests)
        if overlap:
            matches[observed_path] = overlap
    return {
        "effect_observed": bool(matches),
        "matched_paths": sorted(matches),
        "matched_value_digests": matches,
    }


def _counterfactuals(
    spec: dict[str, Any],
    effect_fields: list[str],
    effect_paths: list[str],
    input_value: Any,
    expected_digests: dict[str, list[str]],
    trigger_fields: list[str],
) -> list[dict[str, Any]]:
    cases = spec.get("counterfactuals", spec.get("validation_cases", []))
    if not isinstance(cases, list) or not cases:
        return [
            {
                "check_id": f"generated-{case['role']}",
                "kind": case["kind"],
                "role": case["role"],
                "status": "GENERATED",
                "execution_status": "NOT_EXECUTED" if case["role"] != "trigger" else "OBSERVED_IN_PAIRED_RUN",
                "input_digest": _digest(case["tool_input"]),
            }
            for case in generate_counterfactual_inputs(input_value, trigger_fields)
        ]
    result: list[dict[str, Any]] = []
    for index, case in enumerate(cases, start=1):
        if not isinstance(case, dict):
            result.append({"check_id": f"counterfactual-{index}", "kind": "invalid", "role": "custom", "status": "INVALID", "execution_status": "NOT_EXECUTED", "input_digest": _digest(input_value)})
            continue
        name = str(case.get("name", case.get("kind", f"counterfactual-{index}")))
        rows = case.get("l4_rows", case.get("trace", case.get("traces", [])))
        if isinstance(rows, dict):
            rows = rows.get("vulnerable", [])
        role = str(case.get("role", name)).lower()
        if role not in {"trigger", "safe", "field-only", "unrelated", "fixed"}:
            role = next((candidate for candidate in ("field-only", "unrelated", "fixed", "safe", "trigger") if candidate in role), "custom")
        expects_effect = role in {"trigger", "vulnerable", "unrelated"} or "unrelated" in role
        expects_absent = role in {"safe", "field-only", "fixed"} or any(token in role for token in ("safe", "field-only", "fixed"))
        match = _carrier_match(rows if isinstance(rows, list) else [], effect_fields, effect_paths, expected_digests)
        observed = match["effect_observed"]
        if not rows:
            status = "NOT_EXECUTED"
        elif expects_effect:
            status = "SUPPORTED" if observed else "INCONCLUSIVE"
        elif expects_absent:
            status = "SUPPORTED" if not observed else "INCONCLUSIVE"
        else:
            status = "INCONCLUSIVE"
        result.append({
            "check_id": f"counterfactual-{index}",
            "kind": name,
            "role": role,
            "status": status,
            "execution_status": "OBSERVED" if isinstance(rows, list) and rows else "NOT_EXECUTED",
            "effect_observed": observed,
            "matched_effect_paths": match["matched_paths"],
            "input_digest": str(case.get("input_digest") or _digest(case.get("tool_input", input_value))),
            "input_attested": bool(case.get("input_attested", False)),
        })
    return result


def _carrier_digests(trace: dict[str, Any], paths: list[str]) -> dict[str, list[str]]:
    result: dict[str, set[str]] = {}
    for expected_path in paths:
        for observed_path, digests in trace["tool_value_digests"].items():
            if _paths_equivalent(expected_path, observed_path):
                result.setdefault(expected_path, set()).update(digests)
    return {path: sorted(digests) for path, digests in result.items()}


def _carrier_digests_from(
    trace: dict[str, Any],
    paths: list[str],
    digest_key: str,
) -> dict[str, list[str]]:
    result: dict[str, set[str]] = {}
    observed_digests = trace.get(digest_key, {})
    if not isinstance(observed_digests, dict):
        return {}
    for expected_path in paths:
        for observed_path, digests in observed_digests.items():
            if _paths_equivalent(expected_path, observed_path):
                result.setdefault(expected_path, set()).update(str(digest) for digest in digests)
    return {path: sorted(digests) for path, digests in result.items()}


def _preferred_paired_carrier_digests(
    vulnerable_trace: dict[str, Any],
    fixed_trace: dict[str, Any],
    paths: list[str],
) -> tuple[dict[str, list[str]], dict[str, list[str]], dict[str, str]]:
    """Compare a carrier at its earliest observed Tool boundary.

    L2/L3 projections can retain structural fields after a vulnerable value has
    been filtered. Prefer L0/L1 raw/normalized carriers whenever either side
    has one for a path; fall back to the complete Tool-result trace only when
    both sides lack that early carrier.
    """
    vulnerable_full = _carrier_digests(vulnerable_trace, paths)
    fixed_full = _carrier_digests(fixed_trace, paths)
    vulnerable_raw = _carrier_digests_from(vulnerable_trace, paths, "raw_tool_value_digests")
    fixed_raw = _carrier_digests_from(fixed_trace, paths, "raw_tool_value_digests")
    selected_vulnerable: dict[str, list[str]] = {}
    selected_fixed: dict[str, list[str]] = {}
    sources: dict[str, str] = {}
    for path in paths:
        if vulnerable_raw.get(path) or fixed_raw.get(path):
            selected_vulnerable[path] = vulnerable_raw.get(path, [])
            selected_fixed[path] = fixed_raw.get(path, [])
            sources[path] = "L0_L1_RAW_NORMALIZED"
        else:
            selected_vulnerable[path] = vulnerable_full.get(path, [])
            selected_fixed[path] = fixed_full.get(path, [])
            sources[path] = "L0_L3_TOOL_RESULT_FALLBACK"
    return selected_vulnerable, selected_fixed, sources


def _build_provenance(
    relevant_nodes: list[dict[str, Any]],
    tool_input: dict[str, Any],
    carrier_paths: list[str],
    v_trace: dict[str, Any],
    changed: dict[str, Any],
) -> list[dict[str, Any]]:
    edges: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()

    def add(source: str, target: str, edge_type: str, description: str, evidence_refs: list[str]) -> None:
        key = (source, target, edge_type)
        if key in seen:
            return
        seen.add(key)
        edges.append({
            "from": source,
            "to": target,
            "edge_type": edge_type,
            "slice_direction": ["forward", "backward"],
            "description": description,
            "evidence_refs": sorted(set(evidence_refs)),
        })

    input_fields = [str(key) for key in tool_input]
    calls = [node for node in relevant_nodes if node.get("node_kind") == "call" and node.get("callee")]
    origin_calls = [node for node in calls if node.get("side") != "fixed"]
    guards = [node for node in relevant_nodes if node.get("node_kind") == "guard"]
    for node in relevant_nodes:
        source_ref = str(node.get("source_ref") or _line_ref(node.get("path", "unknown"), node.get("line")))
        node_id = f"source:{node.get('side', 'unknown')}:{source_ref}"
        identifiers = {str(item).lower() for item in node.get("uses", [])}
        node_text = " ".join(str(node.get(key, "")) for key in ("predicate", "callee", "value", "arguments")).lower()
        for field in input_fields:
            if field.lower() in identifiers or re.search(rf"\b{re.escape(field.lower())}\b", node_text):
                edge_type = "control" if node.get("node_kind") == "guard" else "data"
                add(f"tool-input:{field}", node_id, edge_type, "Tool input field is referenced by the parsed source node", [source_ref])
        if node.get("node_kind") == "call" and node.get("callee"):
            add(node_id, f"api:{node['callee']}", "call", "Parsed source call invokes the effect-origin API", [source_ref])

    for guard in guards:
        guard_ref = str(guard.get("source_ref") or _line_ref(guard.get("path", "unknown"), guard.get("line")))
        for call in origin_calls:
            if guard.get("path") == call.get("path") and guard.get("function") == call.get("function"):
                call_ref = str(call.get("source_ref") or _line_ref(call.get("path", "unknown"), call.get("line")))
                add(f"source:{guard.get('side', 'fixed')}:{guard_ref}", f"source:{call.get('side', 'vulnerable')}:{call_ref}", "control", "Repair guard controls the corresponding origin call in the same function", [guard_ref, call_ref])

    origins = [f"api:{node['callee']}" for node in origin_calls]
    if not origins and relevant_nodes:
        node = relevant_nodes[0]
        ref = str(node.get("source_ref") or _line_ref(node.get("path", "unknown"), node.get("line")))
        origins = [f"source:{ref}"]
    dynamic_refs = ["trace:vulnerable:L2", "trace:fixed:L2"]
    for path in carrier_paths:
        carrier = f"effect-carrier:{path}"
        for origin in origins[:4]:
            add(origin, carrier, "data", "Paired trace identifies a vulnerable-side differential value at this carrier path", dynamic_refs + [f"trace-path:{path}"])
        add(carrier, f"tool-result:{path}", "serialize", "The differential carrier is serialized into the Tool result", ["trace:vulnerable:L2", f"trace-path:{path}"])
        tool_digests = {
            digest
            for observed, digests in v_trace["tool_value_digests"].items()
            if _paths_equivalent(path, observed)
            for digest in digests
        }
        l4_digests = {
            digest
            for observed, digests in v_trace["l4_value_digests"].items()
            if _paths_equivalent(path, observed)
            for digest in digests
        }
        if tool_digests & l4_digests:
            add(f"tool-result:{path}", f"model-observation:{path}", "observe", "The same value digest occurs at the Tool-result and L4 boundaries", ["trace:vulnerable:L2", "trace:vulnerable:L4", f"trace-path:{path}"])
    for event in changed.get("resource_events_changed", []):
        for origin in origins[:1]:
            add(origin, f"runtime-state:{_digest(event)}", "state", "Paired runtime evidence records a resource/state difference", ["trace:vulnerable:runtime-event", "trace:fixed:runtime-event"])
    return edges


def _unassessed(
    identity: dict[str, Any],
    reasons: list[str],
    static_refs: list[str] | None = None,
    counterfactual_checks: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    category = identity.get("vulnerability_category")
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "UNASSESSED",
        "vulnerability_identity": {key: identity.get(key) for key in ("advisory", "package", "vulnerable_version", "fixed_version") if identity.get(key) is not None},
        **({"vulnerability_category": category} if category else {}),
        **({"component_origin": component_origin(identity)} if component_origin(identity) else {}),
        "anchor_candidates": [],
        "repair_predicate": empty_repair_predicate(),
        "effects": [],
        "effect_relations": [],
        "counterfactual_checks": counterfactual_checks or [],
        "fixed_side_blocked": None,
        "modeling_reasons": sorted(set(reasons)),
        "evidence_refs": static_refs or [],
    }


def _validated_advisory_semantics(
    spec: dict[str, Any], identity: dict[str, Any]
) -> tuple[dict[str, Any] | None, list[str]]:
    semantics = spec.get("advisory_semantics")
    if not isinstance(semantics, dict):
        return None, ["public advisory effect semantics are unavailable"]
    errors: list[str] = []
    if semantics.get("schema_version") != "public-advisory-effect-semantics/v1":
        errors.append("public advisory effect semantics schema is invalid")
    if semantics.get("advisory_id") != identity.get("advisory"):
        errors.append("public advisory effect semantics identity does not match the case")
    source_url = semantics.get("source_url")
    if not isinstance(source_url, str) or not source_url.startswith("https://"):
        errors.append("public advisory effect semantics require an HTTPS source URL")
    excerpt = semantics.get("source_excerpt")
    digest = semantics.get("source_excerpt_sha256")
    if not isinstance(excerpt, str) or not excerpt.strip():
        errors.append("public advisory effect semantics require a source excerpt")
    elif digest != hashlib.sha256(excerpt.encode("utf-8")).hexdigest():
        errors.append("public advisory effect semantics excerpt hash does not match")
    claims = semantics.get("claims")
    if not isinstance(claims, list) or not claims:
        errors.append("public advisory effect semantics require at least one claim")
        claims = []
    for claim in claims:
        if not isinstance(claim, dict):
            errors.append("public advisory effect claim must be an object")
            continue
        if claim.get("effect_kind") not in EFFECT_KINDS:
            errors.append("public advisory effect claim has an invalid effect kind")
        if claim.get("effect_role") not in {"TERMINAL", "BOTH"}:
            errors.append("public advisory effect claim must describe a concrete terminal effect")
        if not all(isinstance(claim.get(field), str) and claim.get(field) for field in ("claim_id", "object_kind", "operation", "exact_quote")):
            errors.append("public advisory effect claim is incomplete")
        elif isinstance(excerpt, str) and claim["exact_quote"] not in excerpt:
            errors.append("public advisory effect claim quote is not present in the bound excerpt")
        oracle = claim.get("runtime_oracle")
        if not isinstance(oracle, dict) or not isinstance(oracle.get("kind"), str) or not oracle.get("kind"):
            errors.append("public advisory effect claim requires a runtime oracle kind")
    return (semantics if not errors else None), sorted(set(errors))


def _oracle_complete(rows: list[dict[str, Any]], oracle_kind: str) -> bool:
    matching = [
        row for row in rows
        if isinstance(row, dict)
        and isinstance(row.get("oracle"), dict)
        and row["oracle"].get("kind") == oracle_kind
    ]
    return bool(matching) and all(row["oracle"].get("complete") is True for row in matching)


def _build_advisory_candidate_model(
    spec: dict[str, Any],
    identity: dict[str, Any],
    traces: dict[str, list[dict[str, Any]]],
    localization: dict[str, Any],
    repair_predicate: dict[str, Any],
    relevant_nodes: list[dict[str, Any]],
    patch_refs: list[str],
) -> tuple[dict[str, Any] | None, list[str]]:
    semantics, errors = _validated_advisory_semantics(spec, identity)
    if semantics is None:
        return None, errors
    claims = semantics["claims"]
    oracle_kinds = {str(claim["runtime_oracle"]["kind"]) for claim in claims}
    if any(not _oracle_complete(traces[side], kind) for side in ("vulnerable", "fixed") for kind in oracle_kinds):
        return None, ["public advisory candidate lacks a complete effect-specific runtime oracle on both paired sides"]
    anchors = copy.deepcopy(localization.get("anchor_candidates", []))
    if not anchors:
        return None, ["public advisory candidate has no patch-mapped anchor"]
    source_refs = list(dict.fromkeys(
        str(node.get("source_ref")) for node in relevant_nodes if node.get("source_ref")
    ))
    advisory_ref = f"advisory:{semantics['advisory_id']}:{semantics['source_excerpt_sha256']}"
    effects: list[dict[str, Any]] = []
    tool_name = str(spec.get("tool", {}).get("name", "")) if isinstance(spec.get("tool"), dict) else ""
    for claim in claims:
        kind = str(claim["effect_kind"])
        effect_id = _stable_effect_id(kind, claim["claim_id"])
        refs = list(dict.fromkeys([advisory_ref, *patch_refs, *source_refs]))
        effect = {
            "effect_id": effect_id,
            "effect_kind": kind,
            "effect_role": claim["effect_role"],
            "classification_status": "PARTIAL",
            "provenance_status": "PARTIAL",
            "instance_key": _digest({"advisory": semantics["advisory_id"], "claim": claim["claim_id"]}),
            "origin": {
                "functions": sorted({str(node.get("function")) for node in relevant_nodes if node.get("function")}),
                "apis": sorted({str(node.get("callee")) for node in relevant_nodes if node.get("callee")}),
                "source_refs": source_refs,
                "runtime_call_differences": [],
                "anchor_refs": [anchor.get("anchor_id") for anchor in anchors if isinstance(anchor, dict) and anchor.get("anchor_id")],
                "source_locations": [],
                "tool_call_identity": None,
                "runtime_event": None,
            },
            "object": {
                "kind": claim["object_kind"], "field_paths": [], "semantic_fields": [],
                "resource_events": [], "resource_identity": None, "operation": claim["operation"],
                "before_state": None, "after_state": None, "readback_paths": [],
                "advisory_concrete_candidate": True,
                "instance_signature": _digest(claim),
            },
            "condition": {
                "input_fields": sorted(str(key) for key in spec.get("tool_input", {}) if key),
                "predicates": [], "patch_derived": True, "dynamic_difference": {},
                "production_evidence": refs,
                "production_predicate": {
                    "anchor_reached": True,
                    "effect_specific_witness": f"oracle-event:{claim['runtime_oracle']['kind']}:{claim['runtime_oracle'].get('effect_event_operation', claim['operation'])}",
                },
                "candidate_requires_oracle": copy.deepcopy(claim["runtime_oracle"]),
            },
            "carrier": {
                **build_carrier_projection(kind, [], tool_name=tool_name, resource_operation=claim["operation"]),
                "levels": [], "field_names": [], "provenance_fields": [], "provenance_paths": [],
                "value_predicate": None, "vulnerable_value_digests": {}, "fixed_value_digests": {},
                "readback_paths": [], "transformations": [],
            },
            "provenance": [{
                "from": f"advisory:{semantics['advisory_id']}", "to": f"effect:{effect_id}",
                "edge_type": "state" if kind == "RESOURCE_EFFECT" else "control" if kind == "CONTROL_EFFECT" else "data",
                "slice_direction": ["forward", "backward"],
                "description": "Public advisory semantics and a patch-mapped source anchor define this candidate effect identity",
                "evidence_refs": refs,
            }],
            "sink_candidates": [{"layer": "PROGRAM_RUNTIME", "kind": kind, "oracle_kind": claim["runtime_oracle"]["kind"]}],
            "evidence_refs": refs,
            "confidence": 0.72,
        }
        effect["effect_realization"] = _effect_realization(effect, traces["vulnerable"])
        effect["propagation"] = _propagation_from_trace(effect, traces["vulnerable"])
        effects.append(effect)
    realized_vulnerable = [
        effect for effect in effects
        if effect.get("effect_realization", {}).get("status") == "REALIZED"
    ]
    fixed_blocked = bool(realized_vulnerable) and all(
        _effect_realization(effect, traces["fixed"]).get("status") == "NOT_REALIZED"
        for effect in realized_vulnerable
    )
    model = {
        "schema_version": SCHEMA_VERSION, "status": "GENERATED",
        "generation_basis": "ADVISORY_PATCH_CANDIDATE",
        "advisory_semantics_validation": {"status": "OK", "source_ref": advisory_ref},
        "vulnerability_identity": {key: identity.get(key) for key in ("advisory", "package", "vulnerable_version", "fixed_version") if identity.get(key) is not None},
        **({"component_origin": component_origin(spec)} if component_origin(spec) else {}),
        "anchor_candidates": anchors, "localization_digest": localization.get("localization_digest"),
        "repair_predicate": {**copy.deepcopy(repair_predicate), "fixed_side_blocked": fixed_blocked or None},
        "effects": effects, "effect_relations": [], "counterfactual_checks": [],
        "fixed_side_blocked": fixed_blocked or None,
        "modeling_reasons": ["candidate effect identity is bound to public advisory semantics and patch anchors; runtime realization remains independently assessed"],
    }
    validation_errors = validate_effect_model(model)
    return (model, []) if not validation_errors else (None, validation_errors)


def build_effect_model(
    spec: dict[str, Any],
    traces: dict[str, list[dict[str, Any]]] | None = None,
    *,
    base_dir: Path | None = None,
    localization: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build an explicit set of independent, evidence-backed effects."""
    raw_identity = spec.get("identity", {}) if isinstance(spec.get("identity"), dict) else {}
    category = spec.get("vulnerability_category") or spec.get("experiment_type")
    identity = {**raw_identity, **({"vulnerability_category": category} if isinstance(category, str) and category else {})}
    reasons: list[str] = []
    if localization is None:
        from oscar.analysis.localization import build_localization

        localization = build_localization(spec, base_dir=base_dir)
    if localization.get("schema_version") != "vulveil-localization/v1":
        reasons.append("Stage 1 localization schema is missing or invalid")
    if localization.get("status") != "LOCALIZED":
        reasons.extend(localization.get("unresolved_reasons", []) or ["Stage 1 localization is not LOCALIZED"])
    component = component_for_localization(spec)
    origin = component.get("origin")
    source = spec.get("source") if isinstance(spec.get("source"), dict) else {}
    use_analysis = (
        origin == "MCP_FRAMEWORK"
        and ("analysis_source" in spec or source.get("role") in {"server_runtime", "framework_runtime"})
    ) or (
        origin == "DIRECT_RUNTIME_DEPENDENCY"
        and ("analysis_source" in spec or source.get("role") in {"server_runtime", "framework_runtime"})
    )
    modeling_spec = spec
    if use_analysis:
        modeling_spec = dict(spec)
        modeling_spec["source"] = spec.get("analysis_source", {})
        modeling_spec["patch"] = spec.get("analysis_patch", {})
    vulnerable_sources, reasons_v = _read_sources(modeling_spec, "vulnerable", base_dir)
    fixed_sources, reasons_f = _read_sources(modeling_spec, "fixed", base_dir)
    reasons.extend(reasons_v + reasons_f)
    patch_text, patch_reasons = _patch_text(modeling_spec, base_dir)
    reasons.extend(patch_reasons)
    patch = _parse_patch(patch_text) if patch_text else {"parse_valid": False, "files": [], "changed_lines": []}
    if not patch.get("parse_valid"):
        reasons.append("patch has no parseable added/deleted hunk")
    vulnerable_structures = _all_structures(vulnerable_sources)
    fixed_structures = _all_structures(fixed_sources)
    v_nodes, _, v_errors = _structure_semantics(vulnerable_structures)
    f_nodes, _, f_errors = _structure_semantics(fixed_structures)
    reasons.extend(_patch_related_parse_errors(v_errors + f_errors, patch))
    if traces is None:
        declared_traces = spec.get("traces", spec.get("trace", {}))
        traces = {
            "vulnerable": declared_traces.get("vulnerable", []) if isinstance(declared_traces, dict) else [],
            "fixed": (declared_traces.get("fixed", declared_traces.get("patched", [])) if isinstance(declared_traces, dict) else []),
        }
    traces = {
        "vulnerable": _load_trace_rows(traces.get("vulnerable", []), base_dir),
        "fixed": _load_trace_rows(traces.get("fixed", traces.get("patched", [])), base_dir),
    }
    v_trace = _trace_side(traces["vulnerable"])
    f_trace = _trace_side(traces["fixed"])
    if not v_trace["valid"] or not f_trace["valid"]:
        reasons.append("paired trace does not provide a valid L0-L3 contract on both sides")
    changed = _trace_diff(v_trace, f_trace, spec.get("tool_input", {}))
    changed_nodes = _changed_structured_nodes(vulnerable_structures, fixed_structures, patch)
    if not changed_nodes:
        reasons.append("no structured source anchor maps to a changed patch hunk")
    if reasons:
        return _unassessed(identity, reasons, [f"patch:{item.get('path', 'unknown')}" for item in patch.get("files", [])])

    patch_nodes = [{**node, "patch_mapped": True} for node in changed_nodes]
    anchor_scopes = {(node.get("path"), node.get("function")) for node in patch_nodes}
    relevant_nodes = list(patch_nodes)
    for node in v_nodes:
        if (node.get("path"), node.get("function")) in anchor_scopes and not any(
            node.get("callee") == existing.get("callee")
            and node.get("line") == existing.get("line")
            and node.get("path") == existing.get("path")
            and node.get("node_kind") == existing.get("node_kind")
            for existing in relevant_nodes
        ):
            relevant_nodes.append({**node, "side": "vulnerable", "slice_mapped": True})
    relevant_nodes = relevant_nodes[:16]
    anchor_candidates = copy.deepcopy(localization.get("anchor_candidates", []))
    if not anchor_candidates:
        return _unassessed(identity, ["no structured source anchor maps to the patch"], [])

    repair_predicate = normalize_repair_predicate(localization.get("repair_predicate", {}))
    predicate_errors = validate_repair_predicate(repair_predicate) if repair_predicate else ["repair predicate is missing"]
    if predicate_errors:
        reasons.extend(predicate_errors)
        return _unassessed(identity, reasons, [f"patch:{item.get('path', 'unknown')}" for item in patch.get("files", [])])

    value_paths = _value_carrier_paths(v_trace, changed, spec.get("tool_input", {}))
    value_supported = _has_value_evidence(v_trace, f_trace, changed, value_paths)
    control_supported = _has_control_evidence(relevant_nodes, changed)
    resource_supported = _has_resource_evidence(relevant_nodes, changed)
    advisory_candidate, advisory_candidate_errors = _build_advisory_candidate_model(
        spec, identity, traces, localization, repair_predicate,
        relevant_nodes, [f"patch:{item.get('path', 'unknown')}" for item in patch.get("files", [])],
    )
    if advisory_candidate is not None:
        # A validated public claim plus a complete effect-specific oracle is
        # the primary effect identity.  Do not add unrelated differential
        # Tool-result values as competing concrete effects.
        return advisory_candidate
    if (
        resource_supported
        and value_supported
        and _is_input_echo_only_value_paths(v_trace, value_paths, spec.get("tool_input", {}))
    ):
        value_supported = False
    if changed.get("input_echo_only"):
        value_supported = False
        reasons.append("vulnerable/fixed difference is limited to input echo")
    if changed.get("error_text_only"):
        value_supported = False
        control_supported = False
        resource_supported = False
        reasons.append("vulnerable/fixed difference is limited to error text")
    if not v_trace["tool_result_provenance"] and not f_trace["tool_result_provenance"] and not any((changed.get("resource_events_changed"), changed.get("exceptions_changed"), changed.get("call_sites_changed"))):
        reasons.append("Tool result provenance is missing on both paired sides")
    if not any((control_supported, resource_supported, value_supported)):
        patch_refs = [f"patch:{item.get('path', 'unknown')}" for item in patch.get("files", [])]
        candidate, candidate_errors = _build_advisory_candidate_model(
            spec, identity, traces, localization, repair_predicate,
            relevant_nodes, patch_refs,
        )
        if candidate is not None:
            return candidate
        reasons.extend(candidate_errors)
        reasons.append("no control, resource, or value effect is reliably supported by source/trace evidence")
    if reasons:
        return _unassessed(identity, reasons, [f"patch:{item.get('path', 'unknown')}" for item in patch.get("files", [])])

    patch_refs = [f"patch:{item.get('path', 'unknown')}" for item in patch.get("files", [])]
    trace_refs = ["trace:vulnerable:L2", "trace:fixed:L2"]
    if v_trace["l4_available"] and f_trace["l4_available"]:
        trace_refs.extend(["trace:vulnerable:L4", "trace:fixed:L4"])
    tool_name = str(spec.get("tool", {}).get("name", "")) if isinstance(spec.get("tool"), dict) else ""
    semantic_fields = sorted({path.split(".")[-1].split("[")[0] for path in value_paths if path.split(".")[-1].split("[")[0] not in {"text", "content", "messages", "tool"}})
    vulnerable_digests = _carrier_digests(v_trace, value_paths)
    fixed_digests = _carrier_digests(f_trace, value_paths)
    paired_vulnerable_digests, paired_fixed_digests, paired_digest_sources = _preferred_paired_carrier_digests(
        v_trace,
        f_trace,
        value_paths,
    )
    fixed_has_vulnerable_value = any(
        set(digests) & set(paired_fixed_digests.get(path, []))
        for path, digests in paired_vulnerable_digests.items()
    )
    fixed_anchor_nodes = [node for node in patch_nodes if node.get("side") == "fixed"]
    changed_anchor = bool(fixed_anchor_nodes and relevant_nodes)
    differential_evidence = any(
        changed.get(key)
        for key in ("vulnerable_only_paths", "changed_value_paths", "exceptions_changed", "resource_events_changed", "return_events_changed", "call_sites_changed")
    )
    fixed_blocked = bool(
        changed_anchor
        and differential_evidence
        and v_trace["valid"]
        and f_trace["valid"]
        and (not value_supported or not fixed_has_vulnerable_value)
    )
    fixed_side_validation = {
        "same_patch_scope": changed_anchor,
        "vulnerable_carrier_paths": value_paths,
        "fixed_has_vulnerable_value": fixed_has_vulnerable_value,
        "paired_carrier_digest_sources": paired_digest_sources,
        "paired_vulnerable_carrier_digests": paired_vulnerable_digests,
        "paired_fixed_carrier_digests": paired_fixed_digests,
        "vulnerable_trace_valid": v_trace["valid"],
        "fixed_trace_valid": f_trace["valid"],
        "blocking_evidence": [key for key in ("vulnerable_only_paths", "changed_value_paths", "exceptions_changed", "resource_events_changed", "return_events_changed", "call_sites_changed") if changed.get(key)],
    }
    if not fixed_blocked:
        candidate_errors: list[str] = []
        if not differential_evidence:
            candidate, candidate_errors = _build_advisory_candidate_model(
                spec, identity, traces, localization, repair_predicate,
                relevant_nodes, patch_refs,
            )
            if candidate is not None:
                return candidate
        return _unassessed(
            identity,
            [*candidate_errors, "fixed side does not prove blocking of the same patch-scoped effect"],
            patch_refs,
        )

    paired_validation = validate_paired_repair_predicate(
        {**repair_predicate, "fixed_side_blocked": fixed_blocked},
        traces["vulnerable"],
        traces["fixed"],
        vulnerable_value_digests=vulnerable_digests,
        fixed_value_digests=fixed_digests,
        scoped_vulnerable_value_digests=repair_predicate.get("scoped_vulnerable_value_digests", {}),
        scoped_fixed_value_digests=repair_predicate.get("scoped_fixed_value_digests", {}),
    )
    fixed_side_validation["paired_trace_validation"] = paired_validation
    fixed_side_validation["checker_validation"] = paired_validation.get("checkers", [])
    fixed_side_validation["runtime_validation_status"] = paired_validation.get("validation_conclusion")

    def origin_nodes_for(kind: str) -> list[dict[str, Any]]:
        if kind == "CONTROL_EFFECT":
            selected = [node for node in relevant_nodes if node.get("node_kind") == "guard"]
            return selected or [node for node in relevant_nodes if node.get("side") != "fixed"][:4]
        if kind == "RESOURCE_EFFECT":
            selected = [node for node in relevant_nodes if node.get("node_kind") == "call" and any(marker in _node_text(node) for marker in _RESOURCE_CALL_MARKERS)]
            return selected or [node for node in relevant_nodes if node.get("side") != "fixed"][:4]
        selected = [node for node in relevant_nodes if node.get("side") != "fixed" and node.get("node_kind") in {"return", "call"}]
        return selected or [node for node in relevant_nodes if node.get("side") != "fixed"][:4]

    def make_effect(
        effect_id: str,
        kind: str,
        supported: bool,
        carrier_paths: list[str],
        *,
        instance: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        instance = instance or {}
        origin_nodes = origin_nodes_for(kind)
        source_refs = list(dict.fromkeys(str(node.get("source_ref")) for node in origin_nodes if node.get("source_ref")))
        effect_trace_refs = list(trace_refs)
        if kind == "RESOURCE_EFFECT" and changed.get("resource_events_changed"):
            effect_trace_refs.extend(["trace:vulnerable:runtime-event", "trace:fixed:runtime-event"])
        if kind == "CONTROL_EFFECT" and (changed.get("exceptions_changed") or changed.get("call_sites_changed")):
            effect_trace_refs.extend(["trace:vulnerable:control-event", "trace:fixed:control-event"])
        effect_digests = _carrier_digests(v_trace, carrier_paths)
        fixed_effect_digests = _carrier_digests(f_trace, carrier_paths)
        effect_refs = list(dict.fromkeys(source_refs + patch_refs + effect_trace_refs))
        provenance = _effect_provenance(kind, relevant_nodes, spec.get("tool_input", {}), carrier_paths, v_trace, changed)
        if not provenance:
            provenance = [{
                "from": f"vulnerability-origin:{kind.lower()}",
                "to": f"effect:{effect_id}",
                "edge_type": "control" if kind == "CONTROL_EFFECT" else "state" if kind == "RESOURCE_EFFECT" else "data",
                "slice_direction": ["forward", "backward"],
                "description": "Patch-scoped structured source evidence supports this effect",
                "evidence_refs": effect_refs,
            }]
        resource_event = instance.get("resource_event") or instance.get("event")
        resource_event = resource_event if isinstance(resource_event, dict) else None
        resource_signature = _resource_event_signature(resource_event) if resource_event else {}
        instance_source_refs = [str(value) for value in instance.get("source_refs", []) if value]
        source_refs = list(dict.fromkeys(source_refs + instance_source_refs))
        if resource_event:
            effect_trace_refs.extend(resource_event.get("evidence_refs", []))
        effect_refs = list(dict.fromkeys(source_refs + patch_refs + effect_trace_refs))
        transformations = list(instance.get("transformations", [])) if isinstance(instance.get("transformations"), list) else []
        if kind == "RESOURCE_EFFECT" and carrier_paths and resource_signature:
            transformations.append({
                "input": ["RESOURCE_EVENT"],
                "output": list(carrier_paths),
                "rule": "resource-readback-to-tool-result-carrier",
                "evidence_refs": effect_refs,
                "input_fingerprints": [_full_fingerprint(resource_event)],
                "output_fingerprints": sorted({digest for digests in effect_digests.values() for digest in digests}),
            })
        elif kind == "CONTROL_EFFECT" and carrier_paths:
            transformations.append({
                "input": ["CONTROL_STATE"],
                "output": list(carrier_paths),
                "rule": "control-event-to-return-status-carrier",
                "evidence_refs": effect_refs,
                "input_fingerprints": [_full_fingerprint(instance.get("runtime_event", {}))],
                "output_fingerprints": sorted({digest for digests in effect_digests.values() for digest in digests}),
            })
        effect_object = {
            "kind": "execution behavior" if kind == "CONTROL_EFFECT" else "external resource/state" if kind == "RESOURCE_EFFECT" else "program data value",
            "field_paths": list(carrier_paths),
            "semantic_fields": list(semantic_fields if kind == "VALUE_EFFECT" else []),
            "resource_events": [resource_signature] if resource_signature else [],
            "resource_identity": resource_signature.get("resource_id"),
            "operation": resource_signature.get("operation"),
            "before_state": instance.get("before_state"),
            "after_state": instance.get("after_state"),
            "vulnerable_state_digests": copy.deepcopy(instance.get("vulnerable_state_digests", {})),
            "fixed_state_digests": copy.deepcopy(instance.get("fixed_state_digests", {})),
            "readback_paths": list(instance.get("readback_paths", [])),
            "instance_signature": instance.get("signature") or _digest({"kind": kind, "paths": carrier_paths, "resource": resource_signature, "sources": source_refs}),
        }
        return {
            "effect_id": effect_id,
            "effect_kind": kind,
            "requested_effect_role": instance.get("effect_role"),
            "instance_key": effect_object["instance_signature"],
            "origin": {
                "functions": sorted({str(node.get("function")) for node in origin_nodes if node.get("function")}),
                "apis": sorted({str(node.get("callee")) for node in origin_nodes if node.get("callee")}),
                "source_refs": source_refs,
                "runtime_call_differences": changed.get("call_sites_changed", []) if kind in {"CONTROL_EFFECT", "RESOURCE_EFFECT"} else [],
                "anchor_refs": [anchor.get("anchor_id") for anchor in anchor_candidates if isinstance(anchor, dict) and anchor.get("anchor_id")],
                "source_locations": [dict(item) for item in (resource_event and [resource_signature] or [])],
                "tool_call_identity": instance.get("tool_call_identity"),
                "runtime_event": copy.deepcopy(instance.get("runtime_event")) if isinstance(instance.get("runtime_event"), dict) else None,
            },
            "object": effect_object,
            "condition": {
                "input_fields": sorted(str(key) for key in spec.get("tool_input", {}) if key),
                "predicates": [node.get("predicate") for node in relevant_nodes if node.get("predicate")][:5],
                "patch_derived": True,
                "dynamic_difference": {key: changed[key] for key in ("changed_fields", "changed_value_fields", "changed_paths", "changed_value_paths", "exceptions_changed", "resource_events_changed", "return_events_changed", "call_sites_changed") if changed.get(key)},
                "production_evidence": effect_refs,
                "production_predicate": {
                    "anchor_reached": True,
                    "effect_specific_witness": "resource_event" if kind == "RESOURCE_EFFECT" else "differential_return_or_control_event" if kind == "CONTROL_EFFECT" else "differential_carrier_value",
                },
                **({"runtime_oracle": {"kind": resource_event.get("oracle_kind")}}
                   if resource_event and resource_event.get("oracle_kind") else {}),
            },
            "carrier": {
                "levels": ["L0", "L1", "L2", "L3", "L4"] if carrier_paths else [],
                "field_names": sorted({path.split(".")[-1].split("[")[0] for path in carrier_paths}),
                "paths": list(carrier_paths),
                "tool_names": [tool_name] if tool_name and carrier_paths else [],
                "provenance_fields": sorted(set(v_trace["shared_fields"]) & set(semantic_fields)) if carrier_paths else [],
                "provenance_paths": sorted(path for path in carrier_paths if any(_paths_equivalent(path, shared) for shared in v_trace["shared_paths"])),
                "value_predicate": "same-run-tool-result-to-l4-digest" if carrier_paths else None,
                "vulnerable_value_digests": effect_digests,
                "fixed_value_digests": fixed_effect_digests,
                "carrier_kind": "PROGRAM_VALUE" if kind == "VALUE_EFFECT" else "RESOURCE_EVENT" if kind == "RESOURCE_EFFECT" else "CONTROL_STATE",
                "readback_paths": list(instance.get("readback_paths", [])),
                "transformations": transformations,
            },
            "provenance": provenance,
            "sink_candidates": ([{"layer": "MCP_TOOL_RESULT", "tool": tool_name, "field_paths": carrier_paths}, {"layer": "L4_MODEL_VISIBLE_OBSERVATION", "tool": tool_name, "field_paths": carrier_paths}] if carrier_paths else [{"layer": "PROGRAM_RUNTIME", "kind": kind}]),
            "evidence_refs": effect_refs,
            "confidence": round(min(0.99, 0.58 + (0.12 if origin_nodes else 0) + (0.12 if supported else 0) + (0.1 if carrier_paths else 0)), 2),
        }

    resource_instances = _runtime_resource_events(traces["vulnerable"])
    for instance in resource_instances:
        vulnerable_state, fixed_state = _resource_state_predicates(
            traces["vulnerable"], traces["fixed"], instance.get("resource_event", instance),
        )
        if vulnerable_state:
            instance["vulnerable_state_digests"] = vulnerable_state
            instance["fixed_state_digests"] = fixed_state
    if resource_supported and not resource_instances:
        resource_instances = [{"signature": _digest({"kind": "resource", "changed": changed.get("resource_events_changed", [])}), "evidence_refs": ["trace:vulnerable:resource-differential"]}]
    control_instances: list[dict[str, Any]] = []
    control_events = [
        row for row in traces["vulnerable"]
        if isinstance(row.get("event"), dict)
        and (row["event"].get("error") or row["event"].get("exception") or row["event"].get("return") is not None or row["event"].get("call"))
    ]
    if control_supported:
        control_instances = [
            {"signature": _digest({"kind": "control", "source": [node.get("source_ref") for node in relevant_nodes if node.get("node_kind") == "guard"], "event": row.get("event")}), "runtime_event": row.get("event"), "evidence_refs": [f"trace:{row.get('level', 'runtime')}:control"]}
            for row in control_events
        ] or [{"signature": _digest({"kind": "control", "source": [node.get("source_ref") for node in relevant_nodes if node.get("node_kind") == "guard"]}), "evidence_refs": ["patch:control-guard"]}]
    value_instances = [{"path": path, "signature": _digest({"kind": "value", "path": path})} for path in value_paths] if value_supported else []
    effects: list[dict[str, Any]] = []
    control_carrier_paths = (
        list(value_paths)
        if control_supported
        and value_supported
        and control_events
        and (changed.get("exceptions_changed") or changed.get("return_events_changed"))
        else []
    )
    for index, instance in enumerate(control_instances, start=1):
        effects.append(make_effect("", "CONTROL_EFFECT", control_supported, control_carrier_paths, instance=instance))
    for index, instance in enumerate(resource_instances, start=1):
        readback_paths = value_paths if instance.get("operation") in {"read", "load", "fetch"} and value_supported else []
        effects.append(make_effect("", "RESOURCE_EFFECT", resource_supported, readback_paths, instance={**instance, "readback_paths": readback_paths, "signature": instance.get("signature") or _digest(instance)}))
    for index, instance in enumerate(value_instances, start=1):
        effects.append(make_effect("", "VALUE_EFFECT", value_supported, [str(instance["path"])], instance=instance))
    # IDs are assigned after all candidate counts are known, so two same-kind
    # instances cannot collide while remaining stable under input ordering.
    by_kind_counts = {kind: sum(effect["effect_kind"] == kind for effect in effects) for kind in EFFECT_KINDS}
    for index, effect in enumerate(effects, start=1):
        signature = effect.get("instance_key") or effect.get("object", {}).get("instance_signature") or effect.get("effect_kind")
        ordinal = sum(item["effect_kind"] == effect["effect_kind"] for item in effects[:index])
        effect["effect_id"] = _stable_effect_id(effect["effect_kind"], signature, ordinal=ordinal, total=by_kind_counts[effect["effect_kind"]])
        for provenance in effect.get("provenance", []):
            if provenance.get("to", "").startswith("effect:"):
                provenance["to"] = f"effect:{effect['effect_id']}"
    relations: list[dict[str, Any]] = []
    resource_effects = [effect for effect in effects if effect["effect_kind"] == "RESOURCE_EFFECT"]
    value_effects = [effect for effect in effects if effect["effect_kind"] == "VALUE_EFFECT"]
    control_effects = [effect for effect in effects if effect["effect_kind"] == "CONTROL_EFFECT"]

    # A relation needs dynamic call/resource/readback evidence.  Shared files,
    # functions or source scopes are deliberately insufficient.
    for resource_effect in resource_effects:
        resource_events = resource_effect.get("object", {}).get("resource_events", [])
        for value_effect in value_effects:
            readback_paths = set(resource_effect.get("object", {}).get("readback_paths", []))
            if not readback_paths:
                resource_operation = resource_effect.get("object", {}).get("operation")
                if resource_operation in {"read", "load", "fetch"}:
                    readback_paths = set(value_effect.get("carrier", {}).get("paths", []))
            matching_events = [event for event in resource_events if event.get("operation") in {"read", "load", "fetch"}]
            if matching_events and readback_paths.intersection(value_effect.get("carrier", {}).get("paths", [])):
                evidence = sorted(set(resource_effect.get("evidence_refs", [])) | set(value_effect.get("evidence_refs", [])))
                relations.append({"from": resource_effect["effect_id"], "to": value_effect["effect_id"], "relation": "DERIVES_VALUE", "evidence_refs": evidence, "reason": "the same resource read event has a modeled readback carrier path"})
    for control_effect in control_effects:
        control_event = control_effect.get("origin", {}).get("runtime_event") or {}
        for resource_effect in resource_effects:
            resource_event = (resource_effect.get("object", {}).get("resource_events") or [{}])[0]
            same_trace = control_event.get("trace_id") and control_event.get("trace_id") == resource_event.get("trace_id")
            same_span = control_event.get("span_id") and control_event.get("span_id") == resource_event.get("span_id")
            explicit_parent = resource_event.get("parent_span_id") == control_event.get("span_id") or resource_event.get("caused_by_effect") == control_effect.get("effect_id")
            if same_trace or same_span or explicit_parent:
                evidence = sorted(set(control_effect.get("evidence_refs", [])) | set(resource_effect.get("evidence_refs", [])))
                relations.append({"from": control_effect["effect_id"], "to": resource_effect["effect_id"], "relation": "CAUSES", "evidence_refs": evidence, "reason": "paired runtime trace/span aligns the control event with the resource operation"})

    # Add semantic fields only after IDs and evidence-backed relations are
    # known.  This prevents effect_kind from being used as a proxy for role or
    # propagation level.
    downstream_ids = {str(item.get("from")) for item in relations if isinstance(item, dict)}
    for effect in effects:
        effect_kind = str(effect.get("effect_kind"))
        operation = effect.get("object", {}).get("operation") if isinstance(effect.get("object"), dict) else None
        has_downstream = str(effect.get("effect_id")) in downstream_ids
        effect["effect_role"] = _effect_role(effect_kind, operation=operation, has_downstream=has_downstream, explicit=effect.get("requested_effect_role"), vulnerability_category=category)
        effect.pop("requested_effect_role", None)
        provenance = effect.get("provenance", [])
        runtime_status = fixed_side_validation.get("runtime_validation_status")
        provenance_evidence = bool(provenance) and bool(effect.get("condition", {}).get("patch_derived")) and bool(effect.get("evidence_refs")) and fixed_blocked is True
        if provenance_evidence and runtime_status == "CHECKER_SPECIFIC_VALIDATED":
            provenance_status = "SUPPORTED"
        elif provenance_evidence and (
            runtime_status == "PAIRED_EFFECT_DIFFERENCE_ONLY"
            or (effect_kind == "RESOURCE_EFFECT" and bool(changed.get("resource_events_changed")))
        ):
            provenance_status = "PARTIAL"
        else:
            provenance_status = "UNASSESSED"
        realization = _effect_realization(effect, traces["vulnerable"])
        effect["classification_status"] = "SUPPORTED" if supported_for_effect(effect) and realization["status"] == "REALIZED" else "PARTIAL" if realization["status"] != "UNASSESSED" else "UNRESOLVED"
        effect["provenance_status"] = provenance_status
        projection = build_carrier_projection(
            effect_kind,
            effect.get("carrier", {}).get("paths", []),
            tool_name=tool_name,
            resource_operation=operation,
            field_mapping=(effect.get("carrier", {}).get("field_mapping") or None),
        )
        effect["carrier"].update(projection)
        effect["effect_realization"] = realization
        effect["propagation"] = _propagation_from_trace(effect, traces["vulnerable"])
    for relation in relations:
        relation["provenance_status"] = "SUPPORTED" if relation.get("evidence_refs") else "UNASSESSED"
    counterfactual_fields = sorted({str(key) for effect in effects for key in effect.get("condition", {}).get("input_fields", [])})
    counterfactual_checks = _counterfactuals(spec, semantic_fields, value_paths, spec.get("tool_input", {}), vulnerable_digests, counterfactual_fields)
    model = {
        "schema_version": SCHEMA_VERSION,
        "status": "GENERATED",
        "vulnerability_identity": {key: raw_identity.get(key) for key in ("advisory", "package", "vulnerable_version", "fixed_version") if raw_identity.get(key) is not None},
        **({"vulnerability_category": category} if isinstance(category, str) and category else {}),
        **({"component_origin": component_origin(spec)} if component_origin(spec) else {}),
        "anchor_candidates": anchor_candidates,
        "localization_digest": localization.get("localization_digest"),
        "repair_predicate": {**copy.deepcopy(repair_predicate), "dynamic_checks": {key: changed[key] for key in ("call_sites_changed", "exceptions_changed", "resource_events_changed", "return_events_changed") if changed.get(key)}, "fixed_side_validation": fixed_side_validation, "fixed_side_blocked": fixed_blocked},
        "effects": effects,
        "effect_relations": relations,
        "counterfactual_checks": counterfactual_checks,
        "fixed_side_blocked": fixed_blocked,
        "modeling_reasons": ["generated from independently evidenced control, resource, and value effect candidates; category metadata was not used as an effect gate"],
    }
    errors = validate_effect_model(model)
    if errors:
        return _unassessed(identity, errors)
    return model


def _observed_fields(rows: list[dict[str, Any]], level: str) -> set[str]:
    fields: set[str] = set()
    for payload in _payloads(rows, level):
        for path, _ in _field_paths(payload):
            fields.add(path.split(".")[-1].split("[")[0])
    return fields


_CALL_ID_FIELDS = ("tool_call_id", "invocation_id", "call_id")
_CALL_CONTEXT_FIELDS = ("session_id", "trace_id", "span_id", "parent_span_id")


def _call_identity(value: dict[str, Any], *, message: dict[str, Any] | None = None) -> dict[str, Any]:
    """Return label-free execution identity copied from recorder provenance.

    A repetition is a run partition, never a call identity.  The fallback is
    intentionally incomplete; callers must prove uniqueness before using it
    to join a Tool result with an L4 message.
    """
    event = value.get("event") if isinstance(value.get("event"), dict) else {}
    message = message if isinstance(message, dict) else {}
    result: dict[str, Any] = {
        "repetition": int(value.get("repetition", 1) or 1),
    }
    for field in (*_CALL_ID_FIELDS, *_CALL_CONTEXT_FIELDS):
        candidate = message.get(field) or value.get(field) or event.get(field)
        if candidate not in (None, ""):
            result[field] = str(candidate)
    tool_name = (
        message.get("name") or message.get("tool_name") or
        value.get("tool_name") or event.get("tool_name") or
        value.get("name")
    )
    if tool_name not in (None, ""):
        result["tool_name"] = str(tool_name)
    return result


def _call_group_key(identity: dict[str, Any]) -> str:
    for field in _CALL_ID_FIELDS:
        if identity.get(field):
            return f"{field}:{identity[field]}"
    if identity.get("session_id") and identity.get("trace_id"):
        return f"session-trace:{identity['session_id']}:{identity['trace_id']}"
    if identity.get("trace_id"):
        return f"trace:{identity['trace_id']}"
    if identity.get("span_id"):
        return f"span:{identity['span_id']}"
    return f"repetition:{identity.get('repetition', 1)}:unresolved"


def _call_compatibility(left: dict[str, Any], right: dict[str, Any], candidates: list[dict[str, Any]] | None = None) -> bool | None:
    """Return True/False, or None when provenance cannot disambiguate calls."""
    if left.get("repetition") != right.get("repetition"):
        return False
    for field in ("session_id", "trace_id"):
        left_value, right_value = left.get(field), right.get(field)
        if left_value and right_value and left_value != right_value:
            return False
    if left.get("tool_name") and right.get("tool_name") and left["tool_name"] != right["tool_name"]:
        return False

    left_ids = {left.get(field) for field in _CALL_ID_FIELDS if left.get(field)}
    right_ids = {right.get(field) for field in _CALL_ID_FIELDS if right.get(field)}
    id_match = bool(left_ids & right_ids)
    if left_ids and right_ids and not id_match:
        return False
    if id_match:
        # An explicit invocation identity is stronger than per-boundary span
        # changes, but it cannot override a contradictory trace/session.
        return True

    if candidates is None:
        return None
    same_repetition = [item for item in candidates if item.get("repetition") == left.get("repetition")]
    groups = {_call_group_key(item) for item in same_repetition}
    # A candidate list with two rows at one boundary means that shared trace
    # is carrying multiple unqualified calls. Span equality can identify one
    # row, but cannot prove the rest of the cross-boundary chain belongs to it.
    levels = [item.get("_level") for item in same_repetition if item.get("_level")]
    if len(levels) != len(set(levels)):
        return None
    left_span, right_span = left.get("span_id"), right.get("span_id")
    if left_span and right_span and left_span == right_span:
        return True
    # A missing ID may still be joined when the remaining trace/span context
    # selects one invocation.  Shared trace alone is not enough when spans
    # identify multiple calls in that repetition.
    if left.get("trace_id") and right.get("trace_id") and left.get("trace_id") == right.get("trace_id"):
        return True if len(groups) == 1 else None
    if left.get("session_id") and right.get("session_id") and left.get("session_id") == right.get("session_id"):
        return True if len(groups) == 1 else None
    # With no identity at all, a singleton group is the only available unique
    # call proof.  Multiple rows with distinct spans/groups remain unresolved.
    return True if len(groups) == 1 else None


def _fingerprint_variants(value: Any) -> set[str]:
    raw = json.dumps(_stable(value), ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return {hashlib.sha256(raw.encode("utf-8")).hexdigest(), _digest(value)}


def _full_fingerprint(value: Any) -> str:
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _fingerprint_matches(value: Any, declared: Any) -> bool:
    if isinstance(declared, dict):
        declared = declared.get("sha256") or declared.get("digest")
    return bool(declared) and str(declared) in _fingerprint_variants(value)


def _values_at_paths(rows: list[dict[str, Any]], paths: Iterable[str]) -> list[Any]:
    wanted = [str(path) for path in paths]
    values: list[Any] = []
    for row in rows:
        for payload_key in ("content", "structuredContent", "result", "return", "tool_result"):
            payload = row.get(payload_key)
            if payload is None:
                continue
            for path, value in _field_paths(payload):
                if any(_paths_equivalent(path, item) for item in wanted):
                    values.append(value)
    return values


def _transformation_relationship(rule: str, inputs: list[Any], outputs: list[Any]) -> bool:
    if not inputs or not outputs:
        return False
    normalized = rule.lower().replace("_", "-")
    if normalized in {"rename", "rename-only", "field-rename", "host-field-rename", "identity"}:
        return any(left == right for left in inputs for right in outputs)
    if normalized in {"wrapper", "wrap", "host-wrapper", "resource-readback-to-tool-result-carrier"}:
        return any(_text(left) in _text(right) or left == right for left in inputs for right in outputs)
    if normalized in {"format", "formatting", "serialize", "serialization", "encode", "encoding"}:
        return any(_text(left) in _text(right) for left in inputs for right in outputs)
    return False


def actual_model_tool_messages(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return only attested Tool messages from an actual next-model request.

    Neither an L4 level label nor a generic observation/model_request-shaped
    blob is sufficient.  The recorder must explicitly attest that this is the
    actual next request, and the payload must contain a role=tool message.
    """
    result: list[dict[str, Any]] = []
    for row_index, row in enumerate(rows):
        if row.get("level") != "L4_MODEL_VISIBLE_OBSERVATION":
            continue
        request = row.get("model_request")
        if not isinstance(request, dict):
            content = row.get("content")
            request = content if isinstance(content, dict) and isinstance(content.get("messages"), list) else None
        structured_l4_attestation = (
            isinstance(request, dict)
            and isinstance(request.get("messages"), list)
            and isinstance(request.get("request_sha256"), str)
        )
        if row.get("actual_next_model_request") is not True and not structured_l4_attestation:
            continue
        if not isinstance(request, dict) or not isinstance(request.get("messages"), list):
            continue
        for message_index, message in enumerate(request["messages"]):
            if not isinstance(message, dict) or message.get("role") != "tool" or "content" not in message:
                continue
            content = message["content"]
            parsed_content = content
            if isinstance(content, str):
                try:
                    parsed = json.loads(content)
                except json.JSONDecodeError:
                    parsed = None
                if isinstance(parsed, (dict, list)):
                    parsed_content = parsed
            result.append({
                "row_index": row_index,
                "repetition": int(row.get("repetition", 1) or 1),
                "message_index": message_index,
                "tool_call_id": message.get("tool_call_id"),
                "invocation_id": message.get("invocation_id") or row.get("invocation_id"),
                "session_id": message.get("session_id") or row.get("session_id"),
                "trace_id": message.get("trace_id") or row.get("trace_id"),
                "span_id": message.get("span_id") or row.get("span_id"),
                "tool_name": message.get("name") or message.get("tool_name") or row.get("tool_name"),
                "identity": _call_identity(row, message=message),
                "content": parsed_content,
                "raw_content": content,
                "content_path": f"$.messages[{message_index}].content",
            })
    return result


def _content_value_digests(contents: list[Any]) -> dict[str, set[str]]:
    values: dict[str, set[str]] = {}
    for content in contents:
        for path, value in _field_paths(content):
            if not isinstance(value, (dict, list)):
                values.setdefault(path, set()).add(_digest(value))
    return values


def _effect_produced_in_rows(effect: dict[str, Any], rows: list[dict[str, Any]]) -> tuple[str, list[str]]:
    """Classify production using an effect-specific witness only."""
    refs: list[str] = []
    absence_refs: list[str] = []
    kind = effect.get("effect_kind")
    trace = _trace_side(rows)
    effect_id = str(effect.get("effect_id", ""))
    explicit_ids = set()
    origin = effect.get("origin", {}) if isinstance(effect.get("origin"), dict) else {}
    api_names = {str(value).lower() for value in origin.get("apis", []) if value}
    functions = {str(value).lower() for value in origin.get("functions", []) if value}
    expected_paths = {str(path) for path in effect.get("carrier", {}).get("paths", [])}
    resource_object = effect.get("object", {}) if isinstance(effect.get("object"), dict) else {}
    expected_resource = resource_object.get("resource_identity")
    expected_operation = str(resource_object.get("operation") or "").lower()
    for row in rows:
        event = row.get("event") if isinstance(row.get("event"), dict) else None
        if not event:
            if kind == "VALUE_EFFECT" and row.get("level") in {"L2_HOST_PROCESSED_TOOL_RESULT", "L3_SESSION_TOOL_RESULT"} and expected_paths and any(_paths_equivalent(expected, observed) for expected in expected_paths for observed in trace.get("tool_value_digests", {})):
                refs.append(f"trace:{row.get('level', 'unknown')}:tool-result-carrier")
            continue
        values = [row, event]
        for value in values:
            for key in ("effect_id", "effect_ids", "carrier_effect_ids"):
                candidate = value.get(key) if isinstance(value, dict) else None
                if isinstance(candidate, list):
                    explicit_ids.update(str(item) for item in candidate)
                elif candidate:
                    explicit_ids.add(str(candidate))
        if kind == "CONTROL_EFFECT":
            function = str(event.get("function") or event.get("callee") or event.get("call") or "").lower()
            # anchor_reached is only P1 evidence.  P2-E needs a concrete event
            # tied to this effect (or its declared API/function) and a return,
            # exception, state, or explicit effect witness.
            concrete_event = bool(
                event.get("return") is not None
                or event.get("return_value") is not None
                or event.get("error") is not None
                or event.get("exception") is not None
                or event.get("state") is not None
                or event.get("state_read") is True
                or event.get("state_write") is True
                or event.get("effect_witness") is not None
                or explicit_ids
            )
            function_match = any(
                name and (function == name or function.endswith(f".{name}"))
                for name in (*api_names, *functions)
            )
            if concrete_event and (effect_id in explicit_ids or function_match):
                refs.append(f"trace:{row.get('level', 'unknown')}:control-event")
        elif kind == "RESOURCE_EFFECT":
            resource_id = event.get("resource_id") or event.get("resource_identity") or event.get("file_path") or event.get("url")
            operation = str(event.get("operation") or ("read" if event.get("state_read") else "write" if event.get("state_write") else "")).lower()
            identity_match = expected_resource is None or str(expected_resource) == str(resource_id)
            operation_match = not expected_operation or expected_operation == operation
            state_predicates = resource_object.get("vulnerable_state_digests", {})
            observed_state = event.get("after_state", event.get("state_after"))
            observed_state_digests: dict[str, set[str]] = {}
            if isinstance(observed_state, (dict, list)):
                for path, value in _field_paths(observed_state):
                    if not isinstance(value, (dict, list)):
                        observed_state_digests.setdefault(path, set()).add(_digest(value))
            state_match = not state_predicates or all(
                set(str(digest) for digest in digests) & observed_state_digests.get(str(path), set())
                for path, digests in state_predicates.items()
            )
            observed_signature = _resource_event_signature({
                "resource_id": resource_id,
                "operation": operation,
                "location": event.get("location"),
                "function": event.get("function") or event.get("callee"),
                "trace_id": row.get("trace_id") or event.get("trace_id"),
                "span_id": row.get("span_id") or event.get("span_id"),
                "parent_span_id": row.get("parent_span_id") or event.get("parent_span_id"),
                "caused_by_effect": event.get("caused_by_effect"),
                "tool_call_id": row.get("tool_call_id") or event.get("tool_call_id"),
                "invocation_id": row.get("invocation_id") or event.get("invocation_id"),
                "session_id": row.get("session_id") or event.get("session_id"),
                "repetition": row.get("repetition", 1),
            })
            expected_signatures = resource_object.get("resource_events", []) if isinstance(resource_object.get("resource_events"), list) else []
            signature_match = any(
                all(observed_signature.get(key) == expected.get(key) for key in expected if expected.get(key) not in (None, ""))
                for expected in expected_signatures
                if isinstance(expected, dict)
            )
            # An unqualified resource identity is safe only for a singleton
            # effect.  Once several effects share a resource, location/span/
            # repetition evidence must select the concrete instance.
            if effect_id in explicit_ids or (
                resource_id and identity_match and operation_match and state_match
                and (signature_match or not expected_signatures)
            ):
                refs.append(f"trace:{row.get('level', 'unknown')}:resource-event")
            elif (
                resource_id
                and identity_match
                and event.get("stable_resource_identity") is True
                and (
                    (expected_operation == "write" and operation == "observe" and event.get("state_write") is False)
                    or (operation_match and bool(state_predicates) and not state_match)
                )
            ):
                absence_refs.append(f"trace:{row.get('level', 'unknown')}:resource-effect-absent")
        elif kind == "VALUE_EFFECT" and expected_paths:
            if any(_paths_equivalent(expected, observed) for expected in expected_paths for observed in trace.get("tool_value_digests", {})):
                refs.append("trace:L2_OR_L3:tool-result-carrier")
    if refs:
        return "PRODUCED", sorted(set(refs))
    return "NOT_PRODUCED", sorted(set(absence_refs))


def _transformation_witnesses(rows: list[dict[str, Any]]) -> dict[int, list[dict[str, Any]]]:
    """Collect explicit field/value transformations without inferring them from similarity."""
    result: dict[int, list[dict[str, Any]]] = {}
    for row in rows:
        repetition = int(row.get("repetition", 1) or 1)
        for key in ("transformation", "conversion", "field_mapping"):
            value = row.get(key)
            candidates = value if isinstance(value, list) else [value]
            for candidate in candidates:
                if not isinstance(candidate, dict):
                    continue
                if not candidate.get("input") or not candidate.get("output") or not candidate.get("rule") or not candidate.get("evidence_refs"):
                    continue
                if not candidate.get("input_fingerprints") or not candidate.get("output_fingerprints"):
                    continue
                inputs = candidate["input"] if isinstance(candidate["input"], list) else [candidate["input"]]
                outputs = candidate["output"] if isinstance(candidate["output"], list) else [candidate["output"]]
                input_fingerprints = candidate["input_fingerprints"] if isinstance(candidate["input_fingerprints"], list) else [candidate["input_fingerprints"]]
                output_fingerprints = candidate["output_fingerprints"] if isinstance(candidate["output_fingerprints"], list) else [candidate["output_fingerprints"]]
                result.setdefault(repetition, []).append({
                    "input": [str(item) for item in inputs if item],
                    "output": [str(item) for item in outputs if item],
                    "rule": str(candidate["rule"]),
                    "evidence_refs": sorted({str(ref) for ref in candidate["evidence_refs"] if ref}),
                    "input_fingerprints": [str(item) for item in input_fingerprints if item],
                    "output_fingerprints": [str(item) for item in output_fingerprints if item],
                    "tool_call_identity": _call_identity(row),
                })
    return result


def _explicit_boundary_evidence(rows: list[dict[str, Any]], expected_paths: set[str]) -> tuple[str | None, list[str]]:
    """Return a loss reason only when the trace explicitly records it."""
    refs: list[str] = []
    for row in rows:
        for key in ("filtering", "filtered", "field_projection", "projection", "truncation", "redaction", "transformation", "conversion"):
            value = row.get(key)
            if not value:
                continue
            refs.append(f"trace:{row.get('level', 'unknown')}:{key}")
            text = json.dumps(value, ensure_ascii=False, sort_keys=True).lower()
            if key in {"filtering", "filtered", "field_projection", "projection"} or any(token in text for token in ("filter", "drop", "omit", "exclude")):
                return "FILTERED_BY_HOST", refs
            if key == "redaction" or "redact" in text or "sanitize" in text:
                return "DROPPED_BEFORE_L4", refs
            if key == "truncation" or "truncate" in text:
                return "DROPPED_BEFORE_L4", refs
            if key in {"transformation", "conversion"}:
                # A deterministic, evidence-backed rename/wrap/encode is a
                # carrier transformation, not a drop.  Loss is reported only
                # when the record explicitly names filtering, redaction or
                # truncation.
                if isinstance(value, dict):
                    text = json.dumps(value, ensure_ascii=False, sort_keys=True).lower()
                    if any(token in text for token in ("filter", "drop", "omit", "exclude", "redact", "truncate")):
                        return "DROPPED_BEFORE_L4", refs
                continue
    return None, refs


def _level_rank(level: str | None) -> int:
    return {"P0": 0, "P1": 1, "P2-E": 2, "P2-R": 3, "P2-T": 4, "P2-H": 5, "P3-W": 6}.get(str(level), -1)


def inspect_l4_effect(model: dict[str, Any], rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Bind one modeled effect to one concrete Tool call and exact L4 message.

    The old implementation joined all rows by repetition.  That made a value
    produced by one call eligible for an unrelated Tool message.  Every
    candidate below is first joined by call provenance and only then evaluated
    for production, carrier propagation, and exact observation.
    """
    if model.get("status") != "GENERATED":
        return {"status": "UNASSESSED", "effects": [], "reached_effect_ids": [], "not_reached_effect_ids": [], "unassessed_effect_ids": [], "reason": "effect model is not generated"}
    tool_messages = actual_model_tool_messages(rows)
    l4_paths = {path for message in tool_messages for path, _ in _field_paths(message["content"])}
    pre_rows = [row for row in rows if row.get("level") in {"L2_HOST_PROCESSED_TOOL_RESULT", "L3_SESSION_TOOL_RESULT"}]
    pre_identities = [{**_call_identity(row), "_level": row.get("level")} for row in pre_rows]
    transformation_witnesses = _transformation_witnesses(rows)
    l4_group_counts: dict[tuple[int, str], int] = {}
    l4_group_unqualified: dict[tuple[int, str], bool] = {}
    for message in tool_messages:
        identity = message["identity"]
        key = (message["repetition"], str(identity.get("trace_id") or identity.get("session_id") or ""))
        l4_group_counts[key] = l4_group_counts.get(key, 0) + 1
        if not any(identity.get(field) for field in _CALL_ID_FIELDS):
            l4_group_unqualified[key] = True

    def rows_for_message(message: dict[str, Any]) -> list[dict[str, Any]]:
        candidates = [identity for identity in pre_identities if identity.get("repetition") == message["repetition"]]
        selected: list[dict[str, Any]] = []
        for row, identity in zip(pre_rows, pre_identities):
            match = _call_compatibility(message["identity"], identity, candidates)
            if match is True:
                selected.append(row)
        return selected

    effect_results: list[dict[str, Any]] = []
    reached: list[str] = []
    not_reached: list[str] = []
    unassessed: list[str] = []
    for effect in model.get("effects", []):
        effect_id = str(effect.get("effect_id"))
        expected_paths = {str(path) for path in effect.get("carrier", {}).get("paths", [])}
        vulnerable_baseline = effect.get("carrier", {}).get("vulnerable_value_digests", {})
        fixed_baseline = effect.get("carrier", {}).get("fixed_value_digests", {})
        linked_paths: dict[str, list[str]] = {}
        linked_repetitions: dict[str, list[int]] = {}
        linked_transformations: list[dict[str, Any]] = []
        observed_tool_result_paths: set[str] = set()
        observed_carrier_levels: set[str] = set()
        rejected_fixed_paths: list[str] = []
        production_status = "NOT_PRODUCED"
        production_refs: list[str] = []
        nonproduction_refs: list[str] = []
        boundary_refs: list[str] = []
        ambiguous_call = False
        effect_condition = effect.get("condition", {}) if isinstance(effect.get("condition"), dict) else {}
        required_oracle = effect_condition.get("candidate_requires_oracle", effect_condition.get("runtime_oracle", {}))
        required_oracle_kind = str(required_oracle.get("kind", "")) if isinstance(required_oracle, dict) else ""
        oracle_rows = [
            row for row in rows
            if required_oracle_kind
            and isinstance(row.get("oracle"), dict)
            and row["oracle"].get("kind") == required_oracle_kind
        ]
        oracle_assessable = not required_oracle_kind or (
            bool(oracle_rows) and all(row["oracle"].get("complete") is True for row in oracle_rows)
        )
        oracle_refs = [
            f"trace:{row.get('level', 'runtime')}:complete-oracle:{required_oracle_kind}"
            for row in oracle_rows if row["oracle"].get("complete") is True
        ]

        for message in tool_messages:
            message_identity = message["identity"]
            unqualified_key = (message["repetition"], str(message_identity.get("trace_id") or message_identity.get("session_id") or ""))
            if l4_group_counts.get(unqualified_key, 0) > 1 and l4_group_unqualified.get(unqualified_key):
                ambiguous_call = True
                continue
            call_rows = rows_for_message(message)
            if not call_rows:
                ambiguous_call = True
                continue
            all_call_rows = [
                row for row in rows
                if int(row.get("repetition", 1) or 1) == message["repetition"]
                and _call_compatibility(message["identity"], _call_identity(row), [_call_identity(candidate) for candidate in pre_rows]) is True
            ]
            candidate_production, candidate_refs = _effect_produced_in_rows(effect, all_call_rows)
            if candidate_production == "PRODUCED":
                production_status = "PRODUCED"
                production_refs.extend(candidate_refs)
            else:
                nonproduction_refs.extend(candidate_refs)
            pre_values = _payload_value_digests(call_rows)
            l4_values = _content_value_digests([message["content"], message.get("raw_content")])
            transformations = [
                witness for witness in transformation_witnesses.get(message["repetition"], [])
                if _call_compatibility(message["identity"], witness.get("tool_call_identity", {}), [_call_identity(candidate) for candidate in pre_rows]) is True
            ]
            for expected_path in expected_paths:
                pre_digests = {digest for observed, digests in pre_values.items() if _paths_equivalent(expected_path, observed) for digest in digests}
                if pre_digests:
                    observed_tool_result_paths.add(expected_path)
                    for candidate in call_rows:
                        candidate_values = _payload_value_digests([candidate])
                        if any(
                            _paths_equivalent(expected_path, observed) and digests
                            for observed, digests in candidate_values.items()
                        ):
                            observed_carrier_levels.add(str(candidate.get("level", "")))
                l4_digests = {digest for observed, digests in l4_values.items() if _paths_equivalent(expected_path, observed) for digest in digests}
                if not l4_digests:
                    declared_digests = {
                        str(digest)
                        for baseline in (vulnerable_baseline, fixed_baseline)
                        for path, digests in baseline.items()
                        if _paths_equivalent(expected_path, path)
                        for digest in digests
                    }
                    if declared_digests:
                        l4_digests = {
                            digest
                            for digests in l4_values.values()
                            if declared_digests.intersection(digests)
                            for digest in digests
                        }
                linked = pre_digests & l4_digests
                witness_used: dict[str, Any] | None = None
                if not linked:
                    for witness in transformations:
                        source_values = _values_at_paths(call_rows, witness["input"])
                        output_values = _values_at_paths([{"content": message["content"]}], witness["output"])
                        source_ok = any(_fingerprint_matches(value, fp) for value in source_values for fp in witness["input_fingerprints"])
                        output_ok = any(_fingerprint_matches(value, fp) for value in output_values for fp in witness["output_fingerprints"])
                        relation_ok = _transformation_relationship(witness["rule"], source_values, output_values)
                        if source_ok and output_ok and relation_ok:
                            linked = set(digest for observed, digests in l4_values.items() if any(_paths_equivalent(target, observed) for target in witness["output"]) for digest in digests)
                            witness_used = witness
                            break
                # Production is a hard prerequisite.  A visible field with no
                # same-call production witness is transport evidence only.
                if linked and candidate_production == "PRODUCED":
                    fixed = {digest for path, digests in fixed_baseline.items() if _paths_equivalent(expected_path, path) for digest in digests}
                    vulnerable = {digest for path, digests in vulnerable_baseline.items() if _paths_equivalent(expected_path, path) for digest in digests}
                    if linked.issubset(fixed) and not linked.intersection(vulnerable):
                        rejected_fixed_paths.append(expected_path)
                    else:
                        linked_paths[expected_path] = sorted(set(linked_paths.get(expected_path, [])) | linked)
                        linked_repetitions.setdefault(expected_path, []).append(message["repetition"])
                        if witness_used:
                            linked_transformations.append(witness_used)
                # A vulnerable raw/normalized carrier can be absent from the
                # fixed-side projection without producing a fixed Tool value.
                # If the fixed trace is otherwise assessable and reaches a
                # real Tool message, retain that absence as effect-specific
                # blocking evidence instead of treating it as an unrelated
                # missing field.
                current_trace = _trace_side(rows)
                current_paths = set(current_trace.get("tool_result_paths", []))
                if (
                    not linked
                    and candidate_production == "NOT_PRODUCED"
                    and vulnerable_baseline
                    and any(_paths_equivalent(expected_path, path) for path in vulnerable_baseline)
                    and not any(_paths_equivalent(expected_path, path) for path in current_paths)
                    and tool_messages
                    and _trace_is_assessable(rows)
                ):
                    rejected_fixed_paths.append(expected_path)
            reason, refs = _explicit_boundary_evidence(all_call_rows, expected_paths)
            boundary_refs.extend(refs)

        # A production witness may exist without an L4 message.  It is still a
        # valid P2-E/P2-R observation, but never a P3-W reachability result.
        if production_status == "NOT_PRODUCED":
            all_production, all_refs = _effect_produced_in_rows(effect, rows)
            if all_production == "PRODUCED":
                production_status, production_refs = all_production, all_refs
            else:
                nonproduction_refs.extend(all_refs)
        value_linked = bool(linked_paths) and production_status == "PRODUCED"
        reached_tool_result = bool(
            observed_carrier_levels & {"L0_RAW_MCP_RESULT", "L1_NORMALIZED_TOOL_RESULT"}
        )
        reached_host_session = bool(
            observed_carrier_levels & {"L2_HOST_PROCESSED_TOOL_RESULT", "L3_SESSION_TOOL_RESULT"}
        )
        resource_effect = effect.get("effect_kind") == "RESOURCE_EFFECT"
        external_resource = True if resource_effect and production_status == "PRODUCED" else False if resource_effect else None
        boundary_reason, boundary_evidence = _explicit_boundary_evidence(rows, expected_paths)
        host_propagation = "DROPPED" if boundary_reason == "FILTERED_BY_HOST" else "TRANSFORMED" if boundary_reason == "DROPPED_BEFORE_L4" else "REACHED" if reached_tool_result else "NOT_ASSESSED"
        session_propagation = "DROPPED" if boundary_reason in {"FILTERED_BY_HOST", "DROPPED_BEFORE_L4"} else "REACHED" if reached_host_session else "NOT_ASSESSED"
        if value_linked:
            highest_level, stop_layer, termination_reason = "P3-W", "EXACT_L4_CONTENT", None
        elif production_status == "PRODUCED" and reached_host_session:
            highest_level, stop_layer, termination_reason = "P2-H", "SESSION_MESSAGE", "UNRESOLVED_BOUNDARY"
        elif production_status == "PRODUCED" and reached_tool_result:
            highest_level, stop_layer, termination_reason = "P2-T", "NORMALIZED_TOOL_RESULT", boundary_reason or "UNRESOLVED_BOUNDARY"
        elif production_status == "PRODUCED" and resource_effect:
            highest_level, stop_layer, termination_reason = "P2-R", "EXTERNAL_RESOURCE", "NO_READBACK"
        elif production_status == "PRODUCED":
            highest_level, stop_layer, termination_reason = "P2-E", "PROGRAM_SERVER", "UNRESOLVED_BOUNDARY"
        else:
            anchor = any(row.get("anchor_reached") is True or row.get("vulnerability_anchor_reached") is True for row in rows)
            highest_level, stop_layer, termination_reason = ("P1", "VULNERABILITY_ANCHOR", "NOT_PRODUCED") if anchor else ("P0", "PROGRAM_SERVER", "NOT_PRODUCED")
        trace_assessable = _trace_is_assessable(rows) and oracle_assessable
        effect_status = "REACHED" if value_linked else "NOT_REACHED" if trace_assessable and not ambiguous_call else "UNASSESSED"
        if effect_status == "REACHED":
            reached.append(effect_id)
        elif effect_status == "NOT_REACHED":
            not_reached.append(effect_id)
        else:
            unassessed.append(effect_id)
        matched_fields = sorted({path.split(".")[-1].split("[")[0] for path in linked_paths})
        if production_status == "PRODUCED" and trace_assessable and not ambiguous_call:
            realization_status = "REALIZED"
        elif rejected_fixed_paths or nonproduction_refs:
            realization_status = "NOT_REALIZED"
        elif trace_assessable and not ambiguous_call and any(
            row.get("anchor_reached") is True or row.get("vulnerability_anchor_reached") is True
            for row in rows if isinstance(row, dict)
        ):
            realization_status = "NOT_REALIZED"
        else:
            realization_status = "UNASSESSED"
        effect_results.append({
            "effect_id": effect_id,
            "effect_kind": effect.get("effect_kind"),
            "effect_role": effect.get("effect_role", "INTERMEDIATE"),
            "production_status": production_status,
            "effect_realization": {
                "status": realization_status,
                "witness_refs": sorted(set(production_refs)),
                "sink_refs": sorted({str(item.get("layer")) for item in effect.get("sink_candidates", []) if isinstance(item, dict) and item.get("layer")}),
            },
            "production_evidence_refs": sorted(set(production_refs)),
            "blocking_evidence_refs": sorted(set(nonproduction_refs)),
            "effect_status": effect_status,
            "l4_observed": value_linked,
            "tool_result_observed": bool(observed_tool_result_paths),
            "value_linked": value_linked,
            "matched_l4_fields": matched_fields,
            "matched_tool_result_fields": matched_fields,
            "observed_tool_result_paths": sorted(observed_tool_result_paths),
            "matched_value_paths": sorted(linked_paths),
            "matched_value_digests": linked_paths,
            "matched_repetitions": {key: sorted(set(value)) for key, value in linked_repetitions.items()},
            "rejected_fixed_baseline_paths": sorted(set(rejected_fixed_paths)),
            "transformations": linked_transformations,
            "external_resource_affected": external_resource,
            "reached_tool_result": reached_tool_result,
            "reached_host_session": reached_host_session,
            "reached_exact_l4": value_linked,
            "highest_witnessed_level": highest_level,
            "stop_layer": stop_layer,
            "termination_reason": termination_reason,
            "propagation": {
                "tool_result": "REACHED" if reached_tool_result else "NOT_REACHED",
                "host": host_propagation,
                "session": session_propagation,
                "agent_observation": "REACHED" if value_linked else "NOT_REACHED" if trace_assessable and not ambiguous_call and tool_messages else "NOT_ASSESSED",
                "max_reached_level": "L4" if value_linked else "L3" if session_propagation == "REACHED" else "L2" if reached_tool_result else "L1" if production_status == "PRODUCED" else "UNASSESSED",
            },
            "evidence_refs": sorted(set(((["trace:L2_OR_L3_TOOL_RESULT", "trace:L4_MODEL_VISIBLE_OBSERVATION"] if value_linked else production_refs + nonproduction_refs + oracle_refs) + boundary_refs + boundary_evidence))),
        })
    status = "REACHED" if reached else "UNASSESSED" if not tool_messages or unassessed else "NOT_REACHED"
    return {
        "status": status,
        "effects": effect_results,
        "reached_effect_ids": sorted(reached),
        "not_reached_effect_ids": sorted(not_reached),
        "unassessed_effect_ids": sorted(unassessed),
        "observed_paths": sorted(l4_paths),
        "tool_result_paths": sorted(_payload_field_paths(pre_rows)),
        "actual_next_model_request": bool(tool_messages),
        "tool_message_count": len(tool_messages),
        "tool_message_content_paths": [item["content_path"] for item in tool_messages],
        "highest_witnessed_level": max((item["highest_witnessed_level"] for item in effect_results), key=_level_rank, default="P0"),
    }


def validate_effect_model(model: dict[str, Any]) -> list[str]:
    errors = _contains_gt(model)
    if model.get("schema_version") != SCHEMA_VERSION:
        if model.get("schema_version") == "vulveil-effect-model/v2":
            errors.append("legacy v2 effect model is incompatible with v3 call-scoped semantics; migrate explicitly")
        elif model.get("schema_version") == "vulveil-effect-model/v1":
            errors.append("legacy v1 effect model is rejected; migrate explicitly to vulveil-effect-model/v3")
        else:
            errors.append(f"schema_version must be {SCHEMA_VERSION}; legacy artifacts are not silently accepted")
    if model.get("status") not in {"GENERATED", "UNASSESSED", "INVALID"}:
        errors.append("status must be GENERATED, UNASSESSED or INVALID")
    if not isinstance(model.get("effects"), list):
        errors.append("effects must be a list")
    repair_errors = validate_repair_predicate(model.get("repair_predicate", {}))
    errors.extend(f"repair_predicate: {error}" for error in repair_errors)
    category = model.get("vulnerability_category")
    if category is not None and (not isinstance(category, str) or not category):
        errors.append("vulnerability_category must be a non-empty string when present")
    effect_ids = [item.get("effect_id") for item in model.get("effects", []) if isinstance(item, dict)]
    if len(effect_ids) != len(set(effect_ids)):
        errors.append("effect IDs must be unique")
    if any(not isinstance(effect_id, str) or not effect_id for effect_id in effect_ids):
        errors.append("each effect requires a non-empty effect ID")
    relations = model.get("effect_relations", [])
    if not isinstance(relations, list):
        errors.append("effect_relations must be a list")
        relations = []
    known_effect_ids = set(effect_ids)
    for relation in relations:
        if not isinstance(relation, dict):
            errors.append("each effect relation must be an object")
            continue
        valid_target = relation.get("to") in known_effect_ids or (
            relation.get("relation") == "PROPAGATES_TO" and relation.get("to") in PROPAGATION_TARGETS
        )
        if relation.get("from") not in known_effect_ids or not valid_target:
            errors.append("effect relation endpoint references an unknown effect ID")
        if relation.get("relation") not in RELATION_KINDS:
            errors.append("effect relation has an unsupported relation kind")
        if not isinstance(relation.get("evidence_refs"), list) or not relation.get("evidence_refs"):
            errors.append("effect relation requires evidence references")
        if relation.get("provenance_status") not in PROVENANCE_STATUSES:
            errors.append("effect relation requires provenance_status")
    if model.get("status") == "GENERATED":
        if not model.get("anchor_candidates"):
            errors.append("generated model requires a patch-mapped anchor")
        candidate_basis = model.get("generation_basis") == "ADVISORY_PATCH_CANDIDATE"
        if candidate_basis:
            validation = model.get("advisory_semantics_validation")
            if not isinstance(validation, dict) or validation.get("status") != "OK" or not validation.get("source_ref"):
                errors.append("advisory-backed candidate requires validated public semantics")
            if model.get("fixed_side_blocked") not in {None, False}:
                errors.append("an unrealized advisory-backed candidate cannot claim fixed-side blocking")
            if any(
                effect.get("effect_realization", {}).get("status") == "REALIZED"
                for effect in model.get("effects", []) if isinstance(effect, dict)
            ):
                errors.append("a realized effect requires same-mechanism fixed-side blocking")
        elif model.get("fixed_side_blocked") is not True:
            errors.append("generated model requires same-mechanism fixed-side blocking")
        if not model.get("effects"):
            errors.append("generated model requires at least one effect")
    for effect in model.get("effects", []):
        if not isinstance(effect, dict):
            errors.append("each effect must be an object")
            continue
        for key in ("effect_id", "effect_kind", "effect_role", "classification_status", "provenance_status", "origin", "object", "condition", "carrier", "effect_realization", "propagation", "provenance", "sink_candidates", "evidence_refs", "confidence"):
            if key not in effect:
                errors.append(f"effect.{key} is required")
        effect_object = effect.get("object") if isinstance(effect.get("object"), dict) else {}
        if "effect_type" in effect or "dimensions" in effect_object:
            errors.append("legacy effect_type/dimensions fields are not valid in effect-model v3")
        if effect.get("effect_kind") not in EFFECT_KINDS:
            errors.append("effect.effect_kind is outside CONTROL_EFFECT, RESOURCE_EFFECT, VALUE_EFFECT")
        if effect.get("effect_role") not in EFFECT_ROLES:
            errors.append("effect.effect_role must be INTERMEDIATE, TERMINAL or BOTH")
        if effect.get("classification_status") not in CLASSIFICATION_STATUSES:
            errors.append("effect.classification_status is invalid")
        if effect.get("provenance_status") not in PROVENANCE_STATUSES:
            errors.append("effect.provenance_status is invalid")
        if not isinstance(effect.get("instance_key"), str) or not effect.get("instance_key"):
            errors.append("each effect requires a stable instance_key")
        provenance = effect.get("provenance", [])
        if not isinstance(provenance, list) or not provenance or any(item.get("edge_type") not in {"call", "data", "control", "serialize", "state", "observe"} for item in provenance if isinstance(item, dict)):
            errors.append("effect.provenance must contain typed provenance edges")
        for edge in provenance if isinstance(provenance, list) else []:
            if not isinstance(edge, dict) or not all(edge.get(key) for key in ("from", "to", "description", "evidence_refs")):
                errors.append("each provenance edge requires endpoints, description and evidence references")
            if set(edge.get("slice_direction", [])) != {"forward", "backward"}:
                errors.append("each provenance edge must participate in forward and backward slicing")
        carrier = effect.get("carrier", {})
        if not isinstance(carrier, dict):
            errors.append("effect.carrier must be an object")
            carrier = {}
        if effect.get("effect_kind") == "VALUE_EFFECT":
            if not carrier.get("paths") or not carrier.get("vulnerable_value_digests"):
                errors.append("VALUE_EFFECT requires value-bearing Tool-result paths")
            if carrier.get("value_predicate") != "same-run-tool-result-to-l4-digest":
                errors.append("VALUE_EFFECT requires the same-run value predicate")
        elif carrier.get("paths"):
            if carrier.get("value_predicate") != "same-run-tool-result-to-l4-digest":
                errors.append("effect carrier with paths requires the same-run value predicate")
        if carrier.get("kind") not in CARRIER_KINDS:
            errors.append("effect.carrier.kind is invalid")
        if not isinstance(carrier.get("field_mapping"), (str, dict, list)):
            errors.append("effect.carrier.field_mapping must be a string, object or list")
        if not isinstance(carrier.get("l4_eligible"), bool):
            errors.append("effect.carrier.l4_eligible must be boolean")
        realization = effect.get("effect_realization", {})
        if not isinstance(realization, dict) or realization.get("status") not in {"REALIZED", "NOT_REALIZED", "UNASSESSED"}:
            errors.append("effect.effect_realization.status is invalid")
        elif not isinstance(realization.get("witness_refs"), list) or not isinstance(realization.get("sink_refs"), list):
            errors.append("effect.effect_realization requires witness_refs and sink_refs lists")
        propagation = effect.get("propagation", {})
        if not isinstance(propagation, dict):
            errors.append("effect.propagation must be an object")
        else:
            for field in ("tool_result", "host", "session", "agent_observation"):
                if propagation.get(field) not in PROPAGATION_STATUSES:
                    errors.append(f"effect.propagation.{field} is invalid")
            if propagation.get("max_reached_level") not in {"L0", "L1", "L2", "L3", "L4", "UNASSESSED"}:
                errors.append("effect.propagation.max_reached_level is invalid")
        if not isinstance(effect.get("evidence_refs"), list) or not effect.get("evidence_refs"):
            errors.append("effect.evidence_refs requires at least one evidence reference")
        carrier = effect.get("carrier", {})
        if isinstance(carrier, dict):
            for transformation in carrier.get("transformations", []):
                if not isinstance(transformation, dict) or not all(transformation.get(key) for key in ("input", "output", "rule", "evidence_refs", "input_fingerprints", "output_fingerprints")):
                    errors.append("carrier transformations require paths, evidence_refs, input_fingerprints and output_fingerprints")
                elif not _transformation_relationship(str(transformation.get("rule")), [], []):
                    # Generated control/resource transformations describe a
                    # witness whose concrete values are checked at Stage 4;
                    # arbitrary rule strings are never trusted here.
                    if str(transformation.get("rule")) not in {"control-event-to-return-status-carrier", "resource-readback-to-tool-result-carrier"}:
                        errors.append("carrier transformation rule is not supported")
        confidence = effect.get("confidence")
        if not isinstance(confidence, (int, float)) or not 0 <= confidence <= 1:
            errors.append("effect.confidence must be between 0 and 1")
    return sorted(set(errors))


__all__ = [
    "SCHEMA_VERSION",
    "VULNERABILITY_CATEGORIES",
    "EFFECT_KINDS",
    "EFFECT_ROLES",
    "CARRIER_KINDS",
    "PROPAGATION_STATUSES",
    "RELATION_KINDS",
    "build_carrier_projection",
    "classify_effect_role",
    "build_effect_model",
    "generate_counterfactual_inputs",
    "inspect_l4_effect",
    "validate_effect_model",
    "normalize_effect_model",
]
