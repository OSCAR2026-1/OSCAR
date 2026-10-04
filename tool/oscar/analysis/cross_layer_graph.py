"""Stage 3 cross-layer graph construction for the blind OSCAR runtime.

The graph is deliberately evidence-first.  Static source structure and Stage 2
effect provenance provide candidate edges; paired runtime rows attest dynamic
edges.  Missing boundaries remain explicit instead of being inferred from
similar text or external sink activity.
"""

from __future__ import annotations

import ast
import hashlib
import json
import re
from pathlib import Path
from pathlib import PurePosixPath
from typing import Any, Iterable

try:
    from oscar.contracts.component_contract import component_origin, component_revision
except ImportError:  # pragma: no cover
    from oscar.contracts.component_contract import component_origin, component_revision


SCHEMA_VERSION = "vulveil-cross-layer-graph/v3"
VIEW_SCHEMA_VERSION = "vulveil-cross-layer-graph-view/v1"
LAYERS = {
    "EXECUTION",
    "EFFECT",
    "PROGRAM_DEPENDENCY",
    "PROGRAM_SERVER",
    "MCP",
    "PROTOCOL_HOST",
    "AGENT_OBSERVATION",
    "EXTERNAL_RESOURCE",
}
NODE_KINDS = {
    "function", "call_site", "parameter", "return_value", "variable", "branch",
    "exception", "file", "network_response", "command", "tool_argument",
    "tool_result_field", "json_rpc_field", "host_normalized_field", "session_event",
    "model_request_message", "exact_l4_content_block", "resource", "mcp_tool", "input_schema",
    "dependency",
    "vulnerability_component",
    "vulnerability_anchor", "effect_instance", "control_state", "program_value",
    "resource_state", "resource_event", "readback_value", "agent_task", "tool_call", "tool_handler",
}
EDGE_KINDS = {
    "CALL", "CALLS", "RETURN", "RETURNS", "DATA", "CONTROL", "BIND", "BINDS",
    "TASK_INVOKES", "PASSES_ARGUMENT", "SERIALIZE", "SERIALIZES", "DESERIALIZE",
    "STATE_WRITE", "WRITES_RESOURCE", "STATE_READ", "READS_RESOURCE", "FILTER", "FILTERS",
    "TRANSFORM", "TRANSFORMS", "PRESERVES", "PROJECTS_TO_SESSION", "OBSERVE", "OBSERVES",
    "CAUSES", "PRODUCES", "DERIVES", "CARRIED_BY", "DERIVES_VALUE", "BLOCKS", "ALIGNS_WITH", "ENABLES", "PROPAGATES_TO",
}
EDGE_PLANES = {"EXECUTION", "EFFECT", "ALIGNMENT"}
EDGE_STATUSES = {"PRESERVED", "TRANSFORMED", "DROPPED", "UNASSESSED"}
SIDES = {"vulnerable", "fixed"}
# ``annotations`` is a standard MCP tool-schema key, not a GT annotation.
# Keep exact GT field names protected without rejecting that protocol field.
_FORBIDDEN = ("ground_truth", "groundtruth", "active_agent_gt", "hidden_gt", "gt_linux", "gt_framework", "03_gt", "/gt/", "\\gt\\", "patched_triggered", "patched_trigger_blocked", "annotation_status", "recorder", "GT-")


def _contains_forbidden_graph_content(serialized: str) -> bool:
    """Detect label/evaluator content while allowing MCP's ``annotations`` key."""
    lowered = serialized.lower()
    if any(token.lower() in lowered for token in _FORBIDDEN):
        return True
    # An exact ``annotation`` field remains forbidden; the plural protocol key
    # ``annotations`` is intentionally excluded.
    return bool(re.search(r'"annotation"\s*:', lowered))

SIMPLIFIED_NODE_KINDS = {
    "vulnerability_anchor", "effect_instance", "program_value", "control_state",
    "resource_event", "resource_state", "readback_value", "tool_result_field",
    "json_rpc_field", "host_normalized_field", "session_event",
    "exact_l4_content_block", "tool_call", "tool_handler", "agent_task",
}
SIMPLIFIED_EDGE_KINDS = {
    "PRODUCES", "CARRIED_BY", "DERIVES_VALUE", "RETURNS", "SERIALIZE", "SERIALIZES",
    "PRESERVES", "TRANSFORMS", "FILTERS", "OBSERVE", "OBSERVES", "PROJECTS_TO_SESSION",
    "WRITES_RESOURCE", "READS_RESOURCE", "STATE_WRITE", "STATE_READ", "ALIGNS_WITH",
    "CALLS", "TASK_INVOKES", "ENABLES", "PROPAGATES_TO",
}
_DISPLAY_BOUNDARIES = {
    "L0_RAW_MCP_RESULT->L1_NORMALIZED_TOOL_RESULT",
    "L1_NORMALIZED_TOOL_RESULT->L2_HOST_PROCESSED_TOOL_RESULT",
    "L2_HOST_PROCESSED_TOOL_RESULT->L3_SESSION_TOOL_RESULT",
    "L3_SESSION_TOOL_RESULT->L4_MODEL_VISIBLE_OBSERVATION",
}
_VIEW_EDGE_REQUIRED_FIELDS = (
    "effect_ids", "carrier_effect_ids", "plane", "status", "effect_value_linked",
    "transport_observed", "effect_carrier_observed", "exact_l4_observed",
    "evidence_refs", "repetition", "tool_call_id", "invocation_id", "session_id",
    "trace_id", "span_id", "boundary",
)
_VIEW_EDGE_CONTEXT_FIELDS = (
    "repetition", "tool_call_id", "invocation_id", "session_id", "trace_id", "span_id", "boundary",
)


def _digest(value: Any) -> str:
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _fingerprint(value: Any) -> dict[str, Any]:
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
    return {"type": type(value).__name__, "length": len(raw), "sha256": hashlib.sha256(raw.encode("utf-8")).hexdigest()}


def _stable_id(*parts: Any) -> str:
    return "n-" + hashlib.sha256("|".join(str(part) for part in parts).encode("utf-8")).hexdigest()[:20]


def _edge_id(*parts: Any) -> str:
    return "e-" + hashlib.sha256("|".join(str(part) for part in parts).encode("utf-8")).hexdigest()[:20]


def copy_effect_relations(relations: Any, effect_ids: Iterable[str]) -> list[dict[str, Any]]:
    if not isinstance(relations, list):
        return []
    allowed = {str(item) for item in effect_ids}
    copied = []
    for item in relations:
        if not isinstance(item, dict):
            continue
        relation = dict(item)
        if relation.get("from") in allowed and (
            relation.get("to") in allowed
            or (relation.get("relation") == "PROPAGATES_TO" and relation.get("to") in {"TOOL_RESULT", "HOST", "SESSION", "AGENT_OBSERVATION"})
        ):
            relation.setdefault("provenance_status", "UNASSESSED")
            copied.append(relation)
    return copied


def _source_rows(spec: dict[str, Any], side: str, base_dir: Path | None = None) -> list[dict[str, str]]:
    source = spec.get("source", {})
    value = source.get(side, []) if isinstance(source, dict) else []
    if isinstance(value, list):
        return [row for row in value if isinstance(row, dict) and row.get("path") and isinstance(row.get("content"), str)]
    if isinstance(value, dict) and isinstance(value.get("files"), list):
        return [row for row in value["files"] if isinstance(row, dict) and row.get("path") and isinstance(row.get("content"), str)]
    if isinstance(value, dict):
        root_value = value.get("root") or value.get("source_root") or value.get("path")
        if root_value:
            root = Path(str(root_value))
            if base_dir is not None and not root.is_absolute():
                root = base_dir / root
            selected = value.get("paths") if isinstance(value.get("paths"), list) else None
            paths = [root / str(item) for item in selected] if selected else [item for item in root.rglob("*") if item.is_file()]
            rows: list[dict[str, str]] = []
            for path in paths:
                if not path.is_file() or path.suffix.lower() not in {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}:
                    continue
                try:
                    rows.append({"path": str(path.relative_to(root)), "content": path.read_text(encoding="utf-8")})
                except (OSError, UnicodeDecodeError, ValueError):
                    continue
            return rows
    return []


def _norm_path(path: str) -> str:
    return str(PurePosixPath(str(path).replace("\\", "/")))


def _node(layer: str, kind: str, *, side: str | None = None, path: str = "", symbol: str = "", line: int | None = None,
          field_path: str | None = None, effect_ids: Iterable[str] = (), dynamic: dict[str, Any] | None = None,
          identity_extra: str = "", **extra: Any) -> dict[str, Any]:
    identity = ":".join(part for part in (layer, kind, _norm_path(path), symbol, field_path or "", identity_extra) if part)
    item: dict[str, Any] = {
        "node_id": _stable_id(identity), "layer": layer, "kind": kind,
        "side": side, "identity": identity, "effect_ids": sorted(set(str(x) for x in effect_ids)),
        "static_provenance": bool(path or symbol or field_path), "dynamic_provenance": bool(dynamic),
        "statically_reachable": bool(path or symbol or field_path) and not bool(dynamic),
        "dynamically_observed": bool(dynamic),
        "observed_repetitions": sorted({int(dynamic.get("repetition"))} if dynamic and dynamic.get("repetition") is not None else set()),
    }
    if path:
        item["source"] = {"path": _norm_path(path), **({"line": int(line)} if line is not None else {}), **({"symbol": symbol} if symbol else {})}
    if field_path is not None:
        item["field_path"] = field_path
    if dynamic:
        item["dynamic"] = dynamic
    item.update({key: value for key, value in extra.items() if value is not None})
    return item


def _add_node(nodes: dict[str, dict[str, Any]], item: dict[str, Any]) -> str:
    node_id = item["node_id"]
    if node_id in nodes:
        existing = nodes[node_id]
        existing["effect_ids"] = sorted(set(existing.get("effect_ids", [])) | set(item.get("effect_ids", [])))
        existing_sides = set(existing.get("sides", []))
        if existing.get("side") in SIDES:
            existing_sides.add(existing["side"])
        if item.get("side") in SIDES:
            existing_sides.add(item["side"])
        if len(existing_sides) > 1:
            existing["side"] = "both"
            existing["sides"] = sorted(existing_sides)
        if item.get("dynamic_provenance"):
            existing["dynamic_provenance"] = True
            existing["dynamically_observed"] = True
            existing["observed_repetitions"] = sorted(set(existing.get("observed_repetitions", [])) | set(item.get("observed_repetitions", [])))
        if item.get("statically_reachable"):
            existing["statically_reachable"] = True
    else:
        nodes[node_id] = item
    return node_id


def _add_edge(edges: dict[str, dict[str, Any]], source: str, target: str, kind: str, *, side: str | None,
              field_mapping: dict[str, Any] | None = None, effect_ids: Iterable[str] = (), static: bool = False,
              dynamic: bool = False, confidence: float = 0.5, evidence_refs: Iterable[str] = (),
              repetition: int | None = None, unresolved_reason: str | None = None, trace_id: str | None = None,
              span_id: str | None = None, parent_span_id: str | None = None,
              transport_observed: bool = False, effect_carrier_observed: bool = False,
              effect_value_linked: bool = False, exact_l4_observed: bool = False,
              carrier_effect_ids: Iterable[str] = (), plane: str | None = None,
              status: str | None = None, transformation: dict[str, Any] | None = None,
              boundary: str | None = None) -> str:
    eid = _edge_id(source, target, kind, side or "", repetition or "", field_mapping or {}, sorted(effect_ids), trace_id or "")
    effect_kinds = {"PRODUCES", "CARRIED_BY", "DERIVES_VALUE", "WRITES_RESOURCE", "READS_RESOURCE", "FILTERS", "PRESERVES", "TRANSFORMS", "PROJECTS_TO_SESSION", "OBSERVES", "BLOCKS"}
    edge_plane = plane or ("EFFECT" if kind in effect_kinds or effect_ids or carrier_effect_ids else "EXECUTION")
    edge_status = status or ("PRESERVED" if dynamic and (effect_ids or carrier_effect_ids) and not unresolved_reason else "UNASSESSED")
    item = {
        "edge_id": eid, "source": source, "target": target, "kind": kind, "side": side,
        "field_mapping": field_mapping or {}, "effect_ids": sorted(set(str(x) for x in effect_ids)),
        "static_provenance": bool(static), "dynamic_provenance": bool(dynamic),
        "statically_reachable": bool(static), "dynamically_observed": bool(dynamic),
        "observed_repetitions": [int(repetition)] if dynamic and repetition is not None else [],
        "confidence": max(0.0, min(1.0, float(confidence))), "evidence_refs": sorted(set(str(x) for x in evidence_refs)),
        "transport_observed": bool(transport_observed),
        "effect_carrier_observed": bool(effect_carrier_observed),
        "carrier_effect_ids": sorted(set(str(x) for x in carrier_effect_ids)),
        "effect_value_linked": bool(effect_value_linked),
        "exact_l4_observed": bool(exact_l4_observed),
        "plane": edge_plane,
        "status": edge_status if edge_status in EDGE_STATUSES else "UNASSESSED",
    }
    if dynamic:
        item["repetition"] = repetition
        item["trace_id"] = trace_id or f"trace:{side}:{repetition}"
        item["span_id"] = span_id or item["trace_id"]
        item["parent_span_id"] = parent_span_id
    if unresolved_reason:
        item["unresolved_reason"] = unresolved_reason
    if transformation is not None:
        item["transformation"] = transformation
    if boundary:
        item["boundary"] = boundary
    edges[eid] = item
    return eid


def _python_static(spec: dict[str, Any], side: str, nodes: dict[str, dict[str, Any]], edges: dict[str, dict[str, Any]], effect_ids: list[str], base_dir: Path | None = None, seed_symbols: set[str] | None = None) -> dict[str, list[str]]:
    functions: dict[str, str] = {}
    handlers: dict[str, str] = {}
    returns: dict[str, list[str]] = {}
    for row in _source_rows(spec, side, base_dir):
        path = _norm_path(row["path"])
        file_id = _add_node(nodes, _node("PROGRAM_SERVER", "file", side=side, path=path, identity_extra="source"))
        try:
            tree = ast.parse(row["content"], filename=path)
        except SyntaxError:
            continue
        for current in ast.walk(tree):
            if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if seed_symbols and current.name not in seed_symbols:
                    continue
                fn_id = _add_node(nodes, _node("PROGRAM_SERVER", "function", side=side, path=path, symbol=current.name, line=current.lineno, effect_ids=effect_ids))
                functions[current.name] = fn_id
                _add_edge(edges, file_id, fn_id, "CALL", side=side, static=True, confidence=0.72, evidence_refs=[f"source:{path}:{current.lineno}"])
                for arg in [*current.args.args, *current.args.kwonlyargs]:
                    arg_id = _add_node(nodes, _node("PROGRAM_SERVER", "parameter", side=side, path=path, symbol=current.name, line=getattr(arg, "lineno", current.lineno), field_path=arg.arg))
                    _add_edge(edges, fn_id, arg_id, "BIND", side=side, static=True, confidence=0.8, evidence_refs=[f"source:{path}:{getattr(arg, 'lineno', current.lineno)}"])
                for child in ast.walk(current):
                    if isinstance(child, ast.Return):
                        ret_id = _add_node(nodes, _node("PROGRAM_SERVER", "return_value", side=side, path=path, symbol=current.name, line=child.lineno, effect_ids=effect_ids))
                        returns.setdefault(current.name, []).append(ret_id)
                        _add_edge(edges, fn_id, ret_id, "RETURN", side=side, static=True, confidence=0.82, evidence_refs=[f"source:{path}:{child.lineno}"])
                    elif isinstance(child, ast.Call):
                        callee = ""
                        if isinstance(child.func, ast.Attribute):
                            base = getattr(child.func.value, "id", "")
                            callee = f"{base}.{child.func.attr}" if base else child.func.attr
                        elif isinstance(child.func, ast.Name):
                            callee = child.func.id
                        call_id = _add_node(nodes, _node("PROGRAM_SERVER", "call_site", side=side, path=path, symbol=current.name, line=child.lineno, identity_extra=callee, effect_ids=effect_ids, callee=callee))
                        _add_edge(edges, fn_id, call_id, "CALL", side=side, static=True, confidence=0.78, evidence_refs=[f"source:{path}:{child.lineno}"])
                        if callee in functions:
                            _add_edge(edges, call_id, functions[callee], "CALL", side=side, static=True, confidence=0.65, evidence_refs=[f"source:{path}:{child.lineno}"])
                    elif isinstance(child, ast.If):
                        branch_id = _add_node(nodes, _node("PROGRAM_SERVER", "branch", side=side, path=path, symbol=current.name, line=child.lineno, effect_ids=effect_ids, predicate=ast.unparse(child.test) if hasattr(ast, "unparse") else "if"))
                        _add_edge(edges, fn_id, branch_id, "CONTROL", side=side, static=True, confidence=0.78, evidence_refs=[f"source:{path}:{child.lineno}"])
                    elif isinstance(child, ast.Assign):
                        for target in child.targets:
                            if isinstance(target, ast.Name):
                                variable_id = _add_node(nodes, _node("PROGRAM_SERVER", "variable", side=side, path=path, symbol=current.name, line=child.lineno, field_path=target.id, effect_ids=effect_ids))
                                _add_edge(edges, fn_id, variable_id, "DATA", side=side, static=True, confidence=0.62, evidence_refs=[f"source:{path}:{child.lineno}"])
        # Decorators and common SDK registrations establish real binding edges.
        for current in ast.walk(tree):
            if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for dec in current.decorator_list:
                    text = ast.unparse(dec) if hasattr(ast, "unparse") else ""
                    if "tool" in text.lower():
                        tool_name = current.name
                        if isinstance(dec, ast.Call) and dec.args and isinstance(dec.args[0], ast.Constant):
                            tool_name = str(dec.args[0].value)
                        handlers[tool_name] = functions.get(current.name, "")
            elif isinstance(current, ast.Call):
                text = ast.unparse(current.func) if hasattr(ast, "unparse") else ""
                if text.endswith(".tool") or text in {"tool", "mcp.tool"}:
                    if current.args and isinstance(current.args[0], ast.Constant):
                        tool_name = str(current.args[0].value)
                        handler_arg = next((item for item in reversed(current.args[1:]) if isinstance(item, ast.Name)), None)
                        if handler_arg is not None:
                            handlers[tool_name] = functions.get(handler_arg.id, "")
    return {"functions": list(functions.values()), "handlers": handlers, "returns": returns}


def _typescript_static(spec: dict[str, Any], side: str, nodes: dict[str, dict[str, Any]], edges: dict[str, dict[str, Any]], effect_ids: list[str], base_dir: Path | None = None, seed_symbols: set[str] | None = None) -> dict[str, list[str]]:
    """Structured token fallback for JS/TS when TypeScript is not installed."""
    handlers: dict[str, str] = {}
    returns: dict[str, list[str]] = {}
    for row in _source_rows(spec, side, base_dir):
        path = _norm_path(row["path"])
        if not path.endswith((".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")):
            continue
        file_id = _add_node(nodes, _node("PROGRAM_SERVER", "file", side=side, path=path, identity_extra="source"))
        content = row["content"]
        fn_matches = list(re.finditer(r"(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(([^)]*)\)|(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\(([^)]*)\)\s*=>", content))
        fn_ids: dict[str, str] = {}
        for match in fn_matches:
            name = match.group(1) or match.group(3) or "anonymous_handler"
            args = match.group(2) if match.group(1) else (match.group(4) or "")
            line = content.count("\n", 0, match.start()) + 1
            fn_id = _add_node(nodes, _node("PROGRAM_SERVER", "function", side=side, path=path, symbol=name, line=line, effect_ids=effect_ids))
            fn_ids[name] = fn_id
            _add_edge(edges, file_id, fn_id, "CALL", side=side, static=True, confidence=0.7, evidence_refs=[f"source:{path}:{line}"])
            for arg in [x.strip() for x in args.split(",") if x.strip()]:
                arg_name = re.sub(r"[:?].*$", "", arg).strip()
                arg_id = _add_node(nodes, _node("PROGRAM_SERVER", "parameter", side=side, path=path, symbol=name, line=line, field_path=arg_name))
                _add_edge(edges, fn_id, arg_id, "BIND", side=side, static=True, confidence=0.78, evidence_refs=[f"source:{path}:{line}"])
            for ret in re.finditer(r"\breturn\s+([^;\n]+)", content[match.start():], re.S):
                ret_line = line + content[match.start():match.start() + ret.start()].count("\n")
                ret_id = _add_node(nodes, _node("PROGRAM_SERVER", "return_value", side=side, path=path, symbol=name, line=ret_line, effect_ids=effect_ids))
                returns.setdefault(name, []).append(ret_id)
                _add_edge(edges, fn_id, ret_id, "RETURN", side=side, static=True, confidence=0.78, evidence_refs=[f"source:{path}:{ret_line}"])
                break
        for match in re.finditer(r"(?:server|mcp)\.tool\s*\(\s*[\"']([^\"']+)[\"']", content):
            tool_name = match.group(1)
            line = content.count("\n", 0, match.start()) + 1
            tool_id = _add_node(nodes, _node("MCP", "mcp_tool", side=side, path=path, symbol=tool_name, line=line, effect_ids=effect_ids, tool_name=tool_name))
            _add_edge(edges, file_id, tool_id, "BIND", side=side, static=True, confidence=0.8, field_mapping={"source_symbol": tool_name, "target_tool": tool_name}, evidence_refs=[f"source:{path}:{line}"])
            after = content[match.end():]
            call_tail = after.split(")", 1)[0]
            identifiers = re.findall(r"\b([A-Za-z_$][\w$]*)\b", call_tail)
            candidate_name = next((name for name in reversed(identifiers) if name in fn_ids), None)
            # The schema argument can contain calls such as z.number().  An
            # inline callback arrow is the binding signal for this registration
            # and must take precedence over those unrelated calls.
            arrow_candidate = re.search(r"=>", after)
            candidate = None if candidate_name or arrow_candidate else re.search(r"(?:async\s*)?(?:function\s+)?([A-Za-z_$][\w$]*)\s*\(", after)
            if candidate_name:
                handlers[tool_name] = fn_ids[candidate_name]
                _add_edge(edges, tool_id, fn_ids[candidate_name], "BIND", side=side, static=True, confidence=0.82, field_mapping={"tool_name": tool_name, "handler": candidate_name}, evidence_refs=[f"source:{path}:{line}"])
            elif candidate and candidate.group(1) in fn_ids:
                handlers[tool_name] = fn_ids[candidate.group(1)]
                _add_edge(edges, tool_id, fn_ids[candidate.group(1)], "BIND", side=side, static=True, confidence=0.7, field_mapping={"tool_name": tool_name, "handler": candidate.group(1)}, evidence_refs=[f"source:{path}:{line}"])
            elif arrow_candidate:
                # MCP SDKs commonly register an inline async arrow handler.
                # Give it a stable source node so Tool binding and return
                # serialization remain explicit in the graph.
                handler_symbol = tool_name
                handler_line = content.count("\n", 0, match.end() + arrow_candidate.start()) + 1
                handler_id = _add_node(nodes, _node("PROGRAM_SERVER", "function", side=side, path=path, symbol=handler_symbol, line=handler_line, effect_ids=effect_ids))
                handlers[tool_name] = handler_id
                fn_ids[handler_symbol] = handler_id
                _add_edge(edges, file_id, handler_id, "CALL", side=side, static=True, confidence=0.7, evidence_refs=[f"source:{path}:{handler_line}"])
                return_match = re.search(r"\breturn\s+([^;\n]+)", after, re.S)
                if return_match:
                    return_line = handler_line + after[:return_match.start()].count("\n")
                    return_id = _add_node(nodes, _node("PROGRAM_SERVER", "return_value", side=side, path=path, symbol=handler_symbol, line=return_line, effect_ids=effect_ids))
                    returns.setdefault(handler_symbol, []).append(return_id)
                    _add_edge(edges, handler_id, return_id, "RETURN", side=side, static=True, confidence=0.78, evidence_refs=[f"source:{path}:{return_line}"])
            else:
                # Keep genuinely unbound registrations explicit.
                _add_edge(edges, tool_id, tool_id, "BIND", side=side, static=True, confidence=0.35, evidence_refs=[f"source:{path}:{line}"], unresolved_reason="inline TypeScript handler symbol unresolved")
        component = spec.get("vulnerability_component", {}) if isinstance(spec.get("vulnerability_component"), dict) else {}
        dependency_name = str(component.get("name") or spec.get("identity", {}).get("package") or "")
        dependency_aliases = {dependency_name, dependency_name.split("/")[-1]}
        for call in re.finditer(r"\b([A-Za-z_$][\w$]*)\s*\.\s*([A-Za-z_$][\w$]*)\s*\(", content):
            receiver, method = call.group(1), call.group(2)
            if receiver not in dependency_aliases:
                continue
            call_line = content.count("\n", 0, call.start()) + 1
            call_id = _add_node(nodes, _node("PROGRAM_SERVER", "call_site", side=side, path=path, symbol=receiver, line=call_line, effect_ids=effect_ids, callee=f"{receiver}.{method}"))
            _add_edge(edges, file_id, call_id, "CALL", side=side, static=True, confidence=0.78, evidence_refs=[f"source:{path}:{call_line}"])
    return {"handlers": handlers, "returns": returns}


def _payload(row: dict[str, Any]) -> Any:
    for key in ("content", "observation", "text", "tool_result", "result"):
        if key in row:
            return row[key]
    return None


def _payload_paths(value: Any, prefix: str = "$") -> list[str]:
    paths = [prefix]
    if isinstance(value, dict):
        for key, child in value.items():
            paths.extend(_payload_paths(child, f"{prefix}.{key}"))
    elif isinstance(value, list):
        for index, child in enumerate(value[:32]):
            paths.extend(_payload_paths(child, f"{prefix}[{index}]"))
    return paths


def _call_identity(value: dict[str, Any], *, message: dict[str, Any] | None = None) -> dict[str, Any]:
    event = value.get("event") if isinstance(value.get("event"), dict) else {}
    message = message if isinstance(message, dict) else {}
    identity = {"repetition": int(value.get("repetition", 1) or 1)}
    for field in ("tool_call_id", "invocation_id", "call_id", "session_id", "trace_id", "span_id", "parent_span_id"):
        item = message.get(field) or value.get(field) or event.get(field)
        if item not in (None, ""):
            identity[field] = str(item)
    tool_name = message.get("name") or message.get("tool_name") or value.get("tool_name") or event.get("tool_name")
    if tool_name not in (None, ""):
        identity["tool_name"] = str(tool_name)
    return identity


def _call_group_key(identity: dict[str, Any]) -> str:
    for field in ("tool_call_id", "invocation_id", "call_id"):
        if identity.get(field):
            return f"{field}:{identity[field]}"
    if identity.get("session_id") and identity.get("trace_id"):
        return f"session-trace:{identity['session_id']}:{identity['trace_id']}"
    if identity.get("trace_id"):
        return f"trace:{identity['trace_id']}"
    if identity.get("span_id"):
        return f"span:{identity['span_id']}"
    return f"repetition:{identity.get('repetition', 1)}:unresolved"


def _call_compatible(left: dict[str, Any], right: dict[str, Any], candidates: list[dict[str, Any]]) -> bool | None:
    if left.get("repetition") != right.get("repetition"):
        return False
    for field in ("session_id", "trace_id"):
        if left.get(field) and right.get(field) and left[field] != right[field]:
            return False
    if left.get("tool_name") and right.get("tool_name") and left["tool_name"] != right["tool_name"]:
        return False

    left_ids = {left.get(field) for field in ("tool_call_id", "invocation_id", "call_id") if left.get(field)}
    right_ids = {right.get(field) for field in ("tool_call_id", "invocation_id", "call_id") if right.get(field)}
    id_match = bool(left_ids & right_ids)
    if left_ids and right_ids and not id_match:
        return False
    if id_match:
        return True

    same_repetition = [item for item in candidates if item.get("repetition") == left.get("repetition")]
    groups = {_call_group_key(item) for item in same_repetition}
    levels = [item.get("_level") for item in same_repetition if item.get("_level")]
    if len(levels) != len(set(levels)):
        return None
    if left.get("span_id") and right.get("span_id") and left["span_id"] == right["span_id"]:
        return True
    if left.get("trace_id") and right.get("trace_id") and left.get("trace_id") == right.get("trace_id"):
        return True if len(groups) == 1 else None
    if left.get("session_id") and right.get("session_id") and left.get("session_id") == right.get("session_id"):
        return True if len(groups) == 1 else None
    return True if len(groups) == 1 else None


def _actual_tool_contents(row: dict[str, Any]) -> list[dict[str, Any]]:
    request = row.get("model_request")
    if not isinstance(request, dict):
        payload = row.get("content")
        request = payload if isinstance(payload, dict) and isinstance(payload.get("messages"), list) else None
    explicitly_attested = row.get("actual_next_model_request") is True
    structured_l4_attestation = (
        row.get("level") == "L4_MODEL_VISIBLE_OBSERVATION"
        and isinstance(request, dict)
        and isinstance(request.get("messages"), list)
        and isinstance(request.get("request_sha256"), str)
    )
    if not explicitly_attested and not structured_l4_attestation:
        return []
    if not isinstance(request, dict) or not isinstance(request.get("messages"), list):
        return []
    result: list[dict[str, Any]] = []
    for index, message in enumerate(request["messages"]):
        if not isinstance(message, dict) or message.get("role") != "tool" or "content" not in message:
            continue
        content = message["content"]
        if isinstance(content, str):
            try:
                parsed = json.loads(content)
            except json.JSONDecodeError:
                parsed = None
            if isinstance(parsed, (dict, list)):
                content = parsed
        result.append({"message_index": index, "content": content, "identity": _call_identity(row, message=message), "tool_call_id": message.get("tool_call_id"), "tool_name": message.get("name") or message.get("tool_name") or row.get("tool_name")})
    return result


def _normalized_path(path: str) -> str:
    value = str(path)
    if value == "$":
        return ""
    if value.startswith("$."):
        return value[2:]
    if value.startswith("$"):
        return value[1:]
    return value


def _paths_equivalent(left: str, right: str) -> bool:
    a = _normalized_path(left)
    b = _normalized_path(right)
    return a == b or a.endswith("." + b) or b.endswith("." + a)


def _scalar_digests(value: Any, prefix: str = "$") -> dict[str, set[str]]:
    result: dict[str, set[str]] = {}
    if isinstance(value, dict):
        for key, child in value.items():
            path = f"{prefix}.{key}"
            if isinstance(child, (dict, list)):
                nested = _scalar_digests(child, path)
                for nested_path, digests in nested.items():
                    result.setdefault(nested_path, set()).update(digests)
            else:
                result.setdefault(path, set()).add(_fingerprint(child)["sha256"])
    elif isinstance(value, list):
        for index, child in enumerate(value[:32]):
            path = f"{prefix}[{index}]"
            if isinstance(child, (dict, list)):
                nested = _scalar_digests(child, path)
                for nested_path, digests in nested.items():
                    result.setdefault(nested_path, set()).update(digests)
            else:
                result.setdefault(path, set()).add(_fingerprint(child)["sha256"])
    else:
        result.setdefault(prefix, set()).add(_fingerprint(value)["sha256"])
    return result


def _field_values(value: Any, prefix: str = "$") -> list[tuple[str, Any]]:
    result: list[tuple[str, Any]] = []
    if isinstance(value, dict):
        for key, child in value.items():
            path = f"{prefix}.{key}"
            if isinstance(child, (dict, list)):
                result.extend(_field_values(child, path))
            else:
                result.append((path, child))
    elif isinstance(value, list):
        for index, child in enumerate(value[:32]):
            path = f"{prefix}[{index}]"
            if isinstance(child, (dict, list)):
                result.extend(_field_values(child, path))
            else:
                result.append((path, child))
    else:
        result.append((prefix, value))
    return result


def _effect_payload_observation(payload: Any, effects: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    values = _scalar_digests(payload)
    observations: dict[str, dict[str, Any]] = {}
    for effect in effects:
        effect_id = str(effect.get("effect_id", ""))
        if not effect_id:
            continue
        expected = [str(path) for path in effect.get("carrier", {}).get("paths", [])]
        matched = sorted({path for path in values if any(_paths_equivalent(path, candidate) for candidate in expected)})
        if not matched:
            declared_digests = {
                str(digest)
                for key in ("vulnerable_value_digests", "fixed_value_digests")
                for digest_list in [effect.get("carrier", {}).get(key, {}).get(path, []) for path in expected]
                for digest in (digest_list if isinstance(digest_list, list) else [])
            }
            if declared_digests:
                matched = sorted(
                    path
                    for path, value in _field_values(payload)
                    if not isinstance(value, (dict, list))
                    and declared_digests.intersection(_fingerprint_variants(value))
                )
        observations[effect_id] = {
            "carrier": bool(matched),
            "paths": matched,
            "values": {path: values[path] for path in matched},
            "payload": payload,
        }
    return observations


def _transformation_witness(conversions: dict[str, Any], evidence_refs: list[str]) -> dict[str, Any] | None:
    """Extract a value-verifiable, evidence-backed carrier transformation."""
    candidates: list[dict[str, Any]] = []

    def visit(value: Any, key: str = "") -> None:
        if isinstance(value, dict):
            if value.get("input") and value.get("output") and value.get("rule") and value.get("evidence_refs") and value.get("input_fingerprints") and value.get("output_fingerprints"):
                candidates.append(value)
            for child_key, child in value.items():
                if child_key in {"input", "output", "rule", "evidence_refs"}:
                    continue
                visit(child, child_key)

    visit(conversions)
    if not candidates:
        return None
    witness = candidates[0]
    inputs = witness.get("input") if isinstance(witness.get("input"), list) else [witness.get("input")]
    outputs = witness.get("output") if isinstance(witness.get("output"), list) else [witness.get("output")]
    refs = sorted({str(ref) for ref in [*witness.get("evidence_refs", []), *evidence_refs] if ref})
    if not inputs or not outputs or not refs:
        return None
    return {
        "input": [str(item) for item in inputs if item],
        "output": [str(item) for item in outputs if item],
        "rule": str(witness["rule"]),
        "evidence_refs": refs,
        "input_fingerprints": [str(item) for item in (witness.get("input_fingerprints") if isinstance(witness.get("input_fingerprints"), list) else [witness.get("input_fingerprints")]) if item],
        "output_fingerprints": [str(item) for item in (witness.get("output_fingerprints") if isinstance(witness.get("output_fingerprints"), list) else [witness.get("output_fingerprints")]) if item],
    }


def _fingerprint_variants(value: Any) -> set[str]:
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
    return {hashlib.sha256(raw.encode("utf-8")).hexdigest(), hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True, default=str).encode("utf-8")).hexdigest()[:16]}


def _transformation_values(value: Any, paths: list[str]) -> list[Any]:
    result: list[Any] = []
    for path, item in _scalar_digests(value).items():
        normalized = path[2:] if path.startswith("$.") else path
        for wanted in paths:
            wanted_normalized = wanted[2:] if wanted.startswith("$.") else wanted
            if normalized == wanted_normalized or normalized.endswith("." + wanted_normalized) or wanted_normalized.endswith("." + normalized):
                result.append(item)
    return result


def _witness_value_valid(witness: dict[str, Any], source_value: Any, target_value: Any) -> bool:
    source_scalars = {path: value for path, value in _field_values(source_value)}
    target_scalars = {path: value for path, value in _field_values(target_value)}
    input_values = [value for path, value in source_scalars.items() if any(_paths_equivalent(path, item) for item in witness["input"])]
    output_values = [value for path, value in target_scalars.items() if any(_paths_equivalent(path, item) for item in witness["output"])]
    input_ok = any(fingerprint in _fingerprint_variants(value) for value in input_values for fingerprint in witness["input_fingerprints"])
    output_ok = any(fingerprint in _fingerprint_variants(value) for value in output_values for fingerprint in witness["output_fingerprints"])
    rule = witness["rule"].lower().replace("_", "-")
    relationship = rule in {"rename", "rename-only", "field-rename", "host-field-rename", "identity"} and bool(set(input_values) & set(output_values))
    if rule in {"wrapper", "wrap", "format", "formatting", "serialize", "serialization", "encode", "encoding"}:
        relationship = any(str(left) in str(right) for left in input_values for right in output_values)
    return input_ok and output_ok and relationship


def _linked_effects(source: dict[str, dict[str, Any]], target: dict[str, dict[str, Any]], effects: list[dict[str, Any]] | None = None, witness: dict[str, Any] | None = None) -> tuple[list[str], list[str], list[str]]:
    # A source carrier remains attributed when the next boundary does not
    # expose it.  That is how an unresolved/drop boundary is represented
    # without inventing a downstream carrier.
    carrier_ids: list[str] = sorted(effect_id for effect_id, item in source.items() if item.get("carrier"))
    value_ids: list[str] = []
    transformed_ids: list[str] = []
    for effect_id in carrier_ids:
        left = source[effect_id]
        right = target.get(effect_id)
        if not right or not right.get("carrier"):
            continue
        path_linked = any(
            left_digests & right_digests
            for left_path, left_digests in left.get("values", {}).items()
            for right_path, right_digests in right.get("values", {}).items()
            if _paths_equivalent(left_path, right_path)
        )
        if path_linked:
            value_ids.append(effect_id)
            continue
        if witness:
            effect = next((item for item in effects or [] if str(item.get("effect_id")) == effect_id), None)
            expected_paths = [str(path) for path in (effect or {}).get("carrier", {}).get("paths", [])]
            source_paths = list(source[effect_id].get("paths", []))
            target_paths = list(target[effect_id].get("paths", []))
            input_match = any(_paths_equivalent(left, right) for left in witness["input"] for right in [*expected_paths, *source_paths])
            output_match = any(_paths_equivalent(left, right) for left in witness["output"] for right in [*expected_paths, *target_paths])
            source_payload = left.get("payload")
            target_payload = right.get("payload")
            if input_match and output_match and source_payload is not None and target_payload is not None and _witness_value_valid(witness, source_payload, target_payload):
                value_ids.append(effect_id)
                transformed_ids.append(effect_id)
                continue
        # A Host/session projection can unwrap a sequence element, changing
        # its JSON path while preserving the exact scalar carrier value.
        digest_linked = any(
            left_digests & right_digests
            for left_digests in left.get("values", {}).values()
            for right_digests in right.get("values", {}).values()
        )
        if digest_linked:
            value_ids.append(effect_id)
    return carrier_ids, value_ids, transformed_ids


def _dynamic_protocol(spec: dict[str, Any], side: str, rows: list[dict[str, Any]], nodes: dict[str, dict[str, Any]], edges: dict[str, dict[str, Any]], effects: list[dict[str, Any]], carrier_paths: list[str]) -> tuple[list[str], list[str]]:
    effect_ids = [str(effect.get("effect_id")) for effect in effects if effect.get("effect_id")]
    level_nodes: dict[tuple[int, str], str] = {}
    level_observations: dict[tuple[int, str], dict[str, dict[str, Any]]] = {}
    l4_real = False
    dynamic_refs: list[str] = []
    for index, row in enumerate(rows):
        level = str(row.get("level", ""))
        if level not in {"L0_RAW_MCP_RESULT", "L1_NORMALIZED_TOOL_RESULT", "L2_HOST_PROCESSED_TOOL_RESULT", "L3_SESSION_TOOL_RESULT", "L4_MODEL_VISIBLE_OBSERVATION"}:
            continue
        repetition = int(row.get("repetition", 1) or 1)
        tool_contents = _actual_tool_contents(row) if level == "L4_MODEL_VISIBLE_OBSERVATION" else []
        actual_l4 = bool(tool_contents)
        row_payload = [content for _, content in tool_contents] if len(tool_contents) > 1 else tool_contents[0][1] if tool_contents else _payload(row)
        effect_observation = _effect_payload_observation(row_payload, effects)
        row_conversion = {key: row.get(key) for key in ("filtering", "filtered", "field_projection", "projection", "truncation", "redaction", "transformation", "conversion") if row.get(key) is not None}
        row_witness = _transformation_witness(row_conversion, [f"trace:{side}:{level}:{repetition}"])
        if row_witness:
            row_values = _scalar_digests(row_payload)
            for effect in effects:
                effect_id = str(effect.get("effect_id", ""))
                expected_paths = [str(path) for path in effect.get("carrier", {}).get("paths", [])]
                if not effect_id or effect_observation.get(effect_id, {}).get("carrier") or not expected_paths:
                    continue
                input_matches = any(_paths_equivalent(expected, source) for expected in expected_paths for source in row_witness["input"])
                output_matches = sorted({path for path in row_values if any(_paths_equivalent(path, output) for output in row_witness["output"])})
                if input_matches and output_matches:
                    effect_observation[effect_id] = {
                        "carrier": True,
                        "paths": output_matches,
                        "values": {path: row_values[path] for path in output_matches},
                    }
        observed_effect_ids = sorted(effect_id for effect_id, item in effect_observation.items() if item["carrier"])
        field_path = carrier_paths[0] if carrier_paths else None
        if level == "L4_MODEL_VISIBLE_OBSERVATION" and actual_l4:
            l4_real = True
        if actual_l4:
            layer, boundary_kind = "AGENT_OBSERVATION", "EXACT_L4_CONTENT"
        elif level == "L0_RAW_MCP_RESULT":
            layer, boundary_kind = "MCP", "RAW_TOOL_RESULT"
        elif level == "L1_NORMALIZED_TOOL_RESULT":
            layer, boundary_kind = "MCP", "MCP_PROTOCOL_FIELD"
        elif level == "L2_HOST_PROCESSED_TOOL_RESULT":
            layer, boundary_kind = "PROTOCOL_HOST", "HOST_PROCESSED_RESULT"
        else:
            layer, boundary_kind = "PROTOCOL_HOST", "SESSION_MESSAGE"
        field_paths = _payload_paths(row_payload)
        exact_paths = [
            f"$.messages[{message_index}].content{path[1:] if path.startswith('$') else '.' + path}"
            for message_index, content in tool_contents
            for path in _payload_paths(content)
        ] if actual_l4 else field_paths
        dynamic_meta = {"trace_id": row.get("trace_id", f"trace:{side}:{repetition}"), "span_id": row.get("span_id", f"span:{side}:{repetition}:{index}"), "parent_span_id": row.get("parent_span_id"), "repetition": repetition, "operation": row.get("operation", level), "value_fingerprint": _fingerprint(row_payload), "json_paths": exact_paths, "content_json_paths": field_paths, "conversion": {key: row.get(key) for key in ("filtering", "formatting", "truncation", "transformation") if row.get(key) is not None}}
        kind = "exact_l4_content_block" if actual_l4 else ("json_rpc_field" if level.startswith("L0") else "host_normalized_field" if level.startswith("L1") or level.startswith("L2") else "session_event")
        node_id = _add_node(nodes, _node(layer, kind, side=side, symbol=level, field_path=field_path, identity_extra=f"dynamic:{side}:{repetition}:{level}", effect_ids=observed_effect_ids, dynamic=dynamic_meta, field_paths=exact_paths, carrier_effect_ids=observed_effect_ids, model_request=actual_l4, actual_next_model_request=actual_l4, tool_message_role="tool" if actual_l4 else None, boundary_kind=boundary_kind, boundary_level=boundary_kind))
        if actual_l4:
            message_id = _add_node(nodes, _node("AGENT_OBSERVATION", "model_request_message", side=side, symbol=level, field_path="$.messages[*]", identity_extra=f"dynamic:{side}:{repetition}:model-request", effect_ids=[], dynamic=dynamic_meta, field_paths=exact_paths, carrier_effect_ids=observed_effect_ids, model_request=True, actual_next_model_request=True, tool_message_role="tool"))
            exact_id = node_id
            _add_edge(edges, message_id, exact_id, "OBSERVE", side=side, effect_ids=[], dynamic=True, confidence=0.98, field_mapping={"source_jsonpaths": [f"$.messages[{message_index}].content" for message_index, _ in tool_contents], "target_jsonpaths": exact_paths, "transformation": "exact role=tool message content"}, evidence_refs=[f"trace:{side}:{level}:{repetition}"], repetition=repetition, trace_id=dynamic_meta["trace_id"], span_id=dynamic_meta["span_id"], parent_span_id=dynamic_meta["parent_span_id"], transport_observed=True, effect_carrier_observed=bool(observed_effect_ids), effect_value_linked=False, exact_l4_observed=False, carrier_effect_ids=observed_effect_ids)
            node_id = exact_id
        level_nodes[(repetition, level)] = node_id
        level_observations[(repetition, level)] = effect_observation
        dynamic_refs.append(f"trace:{side}:{level}:{repetition}")
        event = row.get("event") if isinstance(row.get("event"), dict) else None
        if event:
            location = str(event.get("location", ""))
            event_path = location.split(":", 1)[0]
            line_text = location.rsplit(":", 1)[-1] if ":" in location else ""
            event_line = int(line_text) if line_text.isdigit() else None
            operation = str(event.get("function") or event.get("operation") or "runtime-event")
            event_kind = "exception" if event.get("error") or event.get("exception") else "return_value" if event.get("return") is not None else "call_site"
            event_id = _add_node(nodes, _node("PROGRAM_DEPENDENCY", event_kind, side=side, path=event_path, symbol=operation, line=event_line, effect_ids=[], carrier_effect_ids=observed_effect_ids, dynamic={"repetition": repetition, "trace_id": row.get("trace_id", f"trace:{side}:{repetition}"), "value_fingerprint": _fingerprint(event.get("return", event.get("error", event.get("arguments"))))}))
            _add_edge(edges, event_id, node_id, "CONTROL" if event_kind == "exception" else "RETURN" if event_kind == "return_value" else "CALL", side=side, effect_ids=[], dynamic=True, confidence=0.72, field_mapping={"operation": operation, "target_level": level, "source_jsonpaths": ["$.event"], "target_jsonpaths": nodes[node_id].get("field_paths", [])}, evidence_refs=[f"trace:{side}:{level}:{repetition}"], repetition=repetition, transport_observed=True, effect_carrier_observed=bool(observed_effect_ids), carrier_effect_ids=observed_effect_ids)
    order = ["L0_RAW_MCP_RESULT", "L1_NORMALIZED_TOOL_RESULT", "L2_HOST_PROCESSED_TOOL_RESULT", "L3_SESSION_TOOL_RESULT", "L4_MODEL_VISIBLE_OBSERVATION"]
    edge_kind = {0: "DESERIALIZE", 1: "TRANSFORM", 2: "SERIALIZE", 3: "OBSERVE"}
    for repetition in sorted({rep for rep, _ in level_nodes}):
        for idx in range(len(order) - 1):
            source = level_nodes.get((repetition, order[idx]))
            target = level_nodes.get((repetition, order[idx + 1]))
            if not source or not target:
                continue
            target_is_real_l4 = idx == 3 and nodes[target].get("model_request") is True
            source_paths = nodes[source].get("field_paths", []) if source in nodes else []
            target_paths = nodes[target].get("field_paths", []) if target in nodes else []
            source_observation = level_observations.get((repetition, order[idx]), {})
            target_observation = level_observations.get((repetition, order[idx + 1]), {})
            source_conversion = nodes[source].get("dynamic", {}).get("conversion", {}) if source in nodes else {}
            target_conversion = nodes[target].get("dynamic", {}).get("conversion", {}) if target in nodes else {}
            conversions = {**source_conversion, **target_conversion}
            witness = _transformation_witness(
                conversions,
                [f"trace:{side}:{order[idx]}:{repetition}", f"trace:{side}:{order[idx + 1]}:{repetition}"],
            )
            carrier_ids, linked_ids, transformed_ids = _linked_effects(source_observation, target_observation, effects, witness)
            mapping = {"source": carrier_paths[0] if carrier_paths else (source_paths[0] if source_paths else ""), "target": carrier_paths[0] if carrier_paths else (target_paths[0] if target_paths else ""), "source_jsonpaths": source_paths, "target_jsonpaths": target_paths, "source_paths": carrier_paths, "target_paths": carrier_paths, "transformation": "identity" if idx == 3 else "host projection", "conversion": nodes[target].get("dynamic", {}).get("conversion", {}) if target in nodes else {}} if (carrier_paths or source_paths or target_paths) else {}
            reason = None if mapping else "no Stage 2 carrier field mapping"
            if idx == 3 and not target_is_real_l4:
                reason = "L4 row is not attested as an actual next model request Tool message"
            explicit_loss = any(conversions.get(key) for key in ("filtering", "filtered", "field_projection", "projection", "truncation", "redaction"))
            if carrier_ids and not linked_ids and reason is None and not explicit_loss:
                reason = "effect carrier paths exist but adjacent values/provenance are not linked"
            if explicit_loss and not carrier_ids:
                carrier_ids = sorted({effect_id for effect_id, item in source_observation.items() if item.get("carrier")})
            edge_effect_ids = linked_ids or carrier_ids
            boundary_status = "TRANSFORMED" if transformed_ids else "PRESERVED" if linked_ids else "DROPPED" if explicit_loss and carrier_ids else "UNASSESSED"
            relation = "TRANSFORMS" if transformed_ids else "OBSERVES" if idx == 3 else "PROJECTS_TO_SESSION" if idx == 2 else "SERIALIZES" if idx == 1 else "TRANSFORMS"
            transformation = {
                "input": source_paths,
                "output": target_paths,
                "rule": witness.get("rule") if witness else "identity" if linked_ids and idx == 3 else "explicit host conversion" if conversions else "unresolved boundary mapping",
                "source_conversion": conversions,
                "evidence_refs": witness.get("evidence_refs", [f"trace:{side}:{order[idx]}:{repetition}", f"trace:{side}:{order[idx + 1]}:{repetition}"]) if witness else [f"trace:{side}:{order[idx]}:{repetition}", f"trace:{side}:{order[idx + 1]}:{repetition}"],
            }
            _add_edge(edges, source, target, "FILTERS" if explicit_loss and carrier_ids else edge_kind[idx], side=side, field_mapping={**mapping, "relation": relation} if mapping else {}, effect_ids=edge_effect_ids, dynamic=True, confidence=0.9 if reason is None else 0.25, evidence_refs=[f"trace:{side}:{order[idx]}:{repetition}", f"trace:{side}:{order[idx + 1]}:{repetition}"], repetition=repetition, trace_id=f"trace:{side}:{repetition}", span_id=nodes[target].get("dynamic", {}).get("span_id"), parent_span_id=nodes[source].get("dynamic", {}).get("parent_span_id"), unresolved_reason=reason, transport_observed=True, effect_carrier_observed=bool(carrier_ids), effect_value_linked=bool(linked_ids), exact_l4_observed=bool(linked_ids) and idx == 3 and target_is_real_l4, carrier_effect_ids=carrier_ids, plane="EFFECT" if carrier_ids else "EXECUTION", status=boundary_status, transformation=transformation, boundary=f"{order[idx]}->{order[idx + 1]}")
    return dynamic_refs, ["L4 actual model request not attested" ] if not l4_real else []


def _dynamic_protocol_v3(spec: dict[str, Any], side: str, rows: list[dict[str, Any]], nodes: dict[str, dict[str, Any]], edges: dict[str, dict[str, Any]], effects: list[dict[str, Any]], carrier_paths: list[str]) -> tuple[list[str], list[str]]:
    """Build one dynamic protocol chain per concrete Tool invocation.

    The legacy implementation keyed nodes by repetition and level.  This
    implementation first assigns a call group from tool_call/invocation or
    trace/span provenance, and refuses an L4 join when more than one group is
    possible.
    """
    levels = ["L0_RAW_MCP_RESULT", "L1_NORMALIZED_TOOL_RESULT", "L2_HOST_PROCESSED_TOOL_RESULT", "L3_SESSION_TOOL_RESULT", "L4_MODEL_VISIBLE_OBSERVATION"]
    effect_ids = [str(effect.get("effect_id")) for effect in effects if effect.get("effect_id")]
    regular = []
    for index, row in enumerate(rows):
        level = str(row.get("level", ""))
        if level not in levels or level == "L4_MODEL_VISIBLE_OBSERVATION":
            continue
        identity = {**_call_identity(row), "_level": level}
        regular.append({"row": row, "level": level, "index": index, "identity": identity, "group": _call_group_key(identity)})
    groups_by_rep: dict[int, set[str]] = {}
    group_level_counts: dict[tuple[int, str, str], int] = {}
    for record in regular:
        key = (record["identity"]["repetition"], record["group"], record["level"])
        group_level_counts[key] = group_level_counts.get(key, 0) + 1
    ambiguous_groups = {
        (repetition, group)
        for (repetition, group, _level), count in group_level_counts.items()
        if count > 1
    }
    for record in regular:
        if (record["identity"]["repetition"], record["group"]) in ambiguous_groups:
            record["group"] = f"unresolved:{side}:{record['identity']['repetition']}:{record['index']}"
        groups_by_rep.setdefault(record["identity"]["repetition"], set()).add(record["group"])

    records = list(regular)
    l4_real = False
    ambiguous_tool_identity = False
    l4_group_counts: dict[tuple[int, str], int] = {}
    l4_group_unqualified: dict[tuple[int, str], bool] = {}
    for row in rows:
        if row.get("level") != "L4_MODEL_VISIBLE_OBSERVATION":
            continue
        for message in _actual_tool_contents(row):
            identity = message["identity"]
            key = (identity["repetition"], str(identity.get("trace_id") or identity.get("session_id") or ""))
            l4_group_counts[key] = l4_group_counts.get(key, 0) + 1
            if not any(identity.get(field) for field in ("tool_call_id", "invocation_id", "call_id")):
                l4_group_unqualified[key] = True
    for index, row in enumerate(rows):
        if row.get("level") != "L4_MODEL_VISIBLE_OBSERVATION":
            continue
        messages = _actual_tool_contents(row)
        for message in messages:
            identity = message["identity"]
            rep = identity["repetition"]
            unqualified_key = (rep, str(identity.get("trace_id") or identity.get("session_id") or ""))
            if l4_group_counts.get(unqualified_key, 0) > 1 and l4_group_unqualified.get(unqualified_key):
                ambiguous_tool_identity = True
                group = f"unresolved:{side}:{rep}:{message['message_index']}"
                records.append({"row": row, "level": "L4_MODEL_VISIBLE_OBSERVATION", "index": index, "message": message, "identity": identity, "group": group})
                continue
            candidate_groups = set()
            rep_records = [item for item in regular if item["identity"]["repetition"] == rep]
            for group in groups_by_rep.get(rep, set()):
                group_records = [item for item in rep_records if item["group"] == group]
                if any(_call_compatible(identity, item["identity"], [candidate["identity"] for candidate in rep_records]) is True for item in group_records):
                    candidate_groups.add(group)
            if len(candidate_groups) == 1:
                group = next(iter(candidate_groups))
                message_observation = _effect_payload_observation(message["content"], effects)
                group_records = [item for item in rep_records if item["group"] == group]
                lower_call_is_qualified = any(
                    any(item["identity"].get(field) for field in ("tool_call_id", "invocation_id", "call_id"))
                    for item in group_records
                )
                if not any(item.get("carrier") for item in message_observation.values()) and not lower_call_is_qualified:
                    # Keep an unrelated setup Tool message out of the
                    # sequence-level carrier chain when lower boundaries do
                    # not expose per-call IDs.
                    group = f"unlinked:{side}:{rep}:{message['message_index']}"
            elif len(candidate_groups) == 0 and len(groups_by_rep.get(rep, set())) == 1:
                group = next(iter(groups_by_rep[rep]))
            else:
                group = f"unresolved:{side}:{rep}:{message['message_index']}"
            records.append({"row": row, "level": "L4_MODEL_VISIBLE_OBSERVATION", "index": index, "message": message, "identity": identity, "group": group})

    level_nodes: dict[tuple[int, str, str], str] = {}
    level_observations: dict[tuple[int, str, str], dict[str, dict[str, Any]]] = {}
    payloads: dict[tuple[int, str, str], Any] = {}
    dynamic_refs: list[str] = []
    for record in records:
        row, level, identity, group = record["row"], record["level"], record["identity"], record["group"]
        repetition = identity["repetition"]
        message = record.get("message")
        actual_l4 = message is not None
        row_payload = message["content"] if actual_l4 else _payload(row)
        observation = _effect_payload_observation(row_payload, effects)
        row_conversion = {key: row.get(key) for key in ("filtering", "filtered", "field_projection", "projection", "truncation", "redaction", "transformation", "conversion") if row.get(key) is not None}
        witness = _transformation_witness(row_conversion, [f"trace:{side}:{level}:{repetition}:{group}"])
        if witness:
            row_values = _scalar_digests(row_payload)
            for effect in effects:
                effect_id = str(effect.get("effect_id", ""))
                expected_paths = [str(path) for path in effect.get("carrier", {}).get("paths", [])]
                output_paths = sorted(path for path in row_values if any(_paths_equivalent(path, target) for target in witness["output"]))
                input_matches = any(_paths_equivalent(expected, source) for expected in expected_paths for source in witness["input"])
                output_matches = any(fingerprint in _fingerprint_variants(value) for path, value in _field_values(row_payload) if path in output_paths for fingerprint in witness["output_fingerprints"])
                if effect_id and expected_paths and input_matches and output_matches:
                    observation[effect_id] = {"carrier": True, "paths": output_paths, "values": {path: row_values[path] for path in output_paths}, "payload": row_payload}
        observed_effect_ids = sorted(effect_id for effect_id, item in observation.items() if item.get("carrier"))
        field_paths = _payload_paths(row_payload)
        exact_paths = [
            f"$.messages[{message['message_index']}].content{path[1:] if path.startswith('$') else '.' + path}"
            for path in _payload_paths(row_payload)
        ] if actual_l4 else field_paths
        if actual_l4:
            l4_real = True
            layer, boundary_kind, kind = "AGENT_OBSERVATION", "EXACT_L4_CONTENT", "exact_l4_content_block"
        elif level == "L0_RAW_MCP_RESULT":
            layer, boundary_kind, kind = "MCP", "RAW_TOOL_RESULT", "json_rpc_field"
        elif level == "L1_NORMALIZED_TOOL_RESULT":
            layer, boundary_kind, kind = "MCP", "MCP_PROTOCOL_FIELD", "host_normalized_field"
        elif level == "L2_HOST_PROCESSED_TOOL_RESULT":
            layer, boundary_kind, kind = "PROTOCOL_HOST", "HOST_PROCESSED_RESULT", "host_normalized_field"
        else:
            layer, boundary_kind, kind = "PROTOCOL_HOST", "SESSION_MESSAGE", "session_event"
        dynamic = {
            "trace_id": identity.get("trace_id", f"trace:{side}:{repetition}"),
            "span_id": identity.get("span_id", f"span:{side}:{repetition}:{record['index']}"),
            "parent_span_id": identity.get("parent_span_id"),
            "repetition": repetition,
            "call_key": group,
            "call_identity": identity,
            "tool_call_id": identity.get("tool_call_id"),
            "invocation_id": identity.get("invocation_id"),
            "tool_name": identity.get("tool_name") or str((spec.get("tool") or {}).get("name", "")),
            "operation": row.get("operation", level),
            "value_fingerprint": _fingerprint(row_payload),
            "json_paths": exact_paths,
            "content_json_paths": field_paths,
            "conversion": {key: row.get(key) for key in ("filtering", "formatting", "truncation", "transformation") if row.get(key) is not None},
        }
        node_id = _add_node(nodes, _node(layer, kind, side=side, symbol=level, field_path=carrier_paths[0] if carrier_paths else None, identity_extra=f"dynamic:{side}:{repetition}:{group}:{level}:{record['index']}:{message['message_index'] if message else ''}", effect_ids=observed_effect_ids, dynamic=dynamic, field_paths=exact_paths, carrier_effect_ids=observed_effect_ids, model_request=actual_l4, actual_next_model_request=actual_l4, tool_message_role="tool" if actual_l4 else None, boundary_kind=boundary_kind, boundary_level=boundary_kind))
        key = (repetition, group, level)
        if key in level_nodes:
            # Two rows for the same level/call are not silently folded.
            group = f"{group}:duplicate:{record['index']}"
            key = (repetition, group, level)
        level_nodes[key] = node_id
        level_observations[key] = observation
        payloads[key] = row_payload
        dynamic_refs.append(f"trace:{side}:{level}:{repetition}:{group}")
        if actual_l4:
            message_id = _add_node(nodes, _node("AGENT_OBSERVATION", "model_request_message", side=side, symbol=level, field_path=f"$.messages[{message['message_index']}]", identity_extra=f"dynamic:{side}:{repetition}:{group}:model-request:{message['message_index']}", effect_ids=[], dynamic=dynamic, field_paths=[f"$.messages[{message['message_index']}]"], carrier_effect_ids=observed_effect_ids, model_request=True, actual_next_model_request=True, tool_message_role="tool"))
            _add_edge(edges, message_id, node_id, "OBSERVE", side=side, effect_ids=[], dynamic=True, confidence=0.98, field_mapping={"source_jsonpaths": [f"$.messages[{message['message_index']}].content"], "target_jsonpaths": exact_paths, "call_key": group, "call_identity": identity, "transformation": "exact role=tool message content"}, evidence_refs=[f"trace:{side}:{level}:{repetition}:{group}"], repetition=repetition, trace_id=dynamic["trace_id"], span_id=dynamic["span_id"], parent_span_id=dynamic["parent_span_id"], transport_observed=True, effect_carrier_observed=bool(observed_effect_ids), carrier_effect_ids=observed_effect_ids)
        event = row.get("event") if isinstance(row.get("event"), dict) else None
        if event:
            location = str(event.get("location", ""))
            event_path = location.split(":", 1)[0]
            line_text = location.rsplit(":", 1)[-1] if ":" in location else ""
            event_line = int(line_text) if line_text.isdigit() else None
            operation = str(event.get("function") or event.get("operation") or event.get("call") or "runtime-event")
            event_kind = "exception" if event.get("error") or event.get("exception") else "return_value" if event.get("return") is not None or event.get("return_value") is not None else "call_site"
            event_id = _add_node(nodes, _node("PROGRAM_DEPENDENCY", event_kind, side=side, path=event_path, symbol=operation, line=event_line, identity_extra=f"dynamic:{side}:{repetition}:{group}:{record['index']}", effect_ids=observed_effect_ids, carrier_effect_ids=observed_effect_ids, dynamic={"repetition": repetition, "call_key": group, "call_identity": identity, "trace_id": dynamic["trace_id"], "span_id": dynamic["span_id"], "value_fingerprint": _fingerprint(event.get("return", event.get("error", event.get("arguments"))))}))
            _add_edge(edges, event_id, node_id, "CONTROL" if event_kind == "exception" else "RETURN" if event_kind == "return_value" else "CALL", side=side, effect_ids=observed_effect_ids, dynamic=True, confidence=0.78, field_mapping={"operation": operation, "target_level": level, "call_key": group, "source_jsonpaths": ["$.event"], "target_jsonpaths": exact_paths}, evidence_refs=[f"trace:{side}:{level}:{repetition}:{group}"], repetition=repetition, trace_id=dynamic["trace_id"], span_id=dynamic["span_id"], parent_span_id=dynamic["parent_span_id"], transport_observed=True, effect_carrier_observed=bool(observed_effect_ids), carrier_effect_ids=observed_effect_ids, effect_value_linked=bool(observed_effect_ids))

    edge_kind = {0: "DESERIALIZE", 1: "TRANSFORM", 2: "SERIALIZE", 3: "OBSERVE"}
    for repetition, group in sorted({(key[0], key[1]) for key in level_nodes}):
        for index in range(len(levels) - 1):
            source_key = (repetition, group, levels[index])
            target_key = (repetition, group, levels[index + 1])
            source = level_nodes.get(source_key)
            target = level_nodes.get(target_key)
            if not source or not target:
                continue
            source_observation = level_observations[source_key]
            target_observation = level_observations[target_key]
            source_payload, target_payload = payloads[source_key], payloads[target_key]
            source_paths, target_paths = nodes[source].get("field_paths", []), nodes[target].get("field_paths", [])
            source_dynamic, target_dynamic = nodes[source].get("dynamic", {}), nodes[target].get("dynamic", {})
            conversions = {**source_dynamic.get("conversion", {}), **target_dynamic.get("conversion", {})}
            witness = _transformation_witness(conversions, [f"trace:{side}:{levels[index]}:{repetition}:{group}", f"trace:{side}:{levels[index + 1]}:{repetition}:{group}"])
            carrier_ids, linked_ids, transformed_ids = _linked_effects(source_observation, target_observation, effects, witness)
            real_l4 = index == 3 and nodes[target].get("model_request") is True
            explicit_loss = any(conversions.get(key) for key in ("filtering", "filtered", "field_projection", "projection", "truncation", "redaction"))
            reason = None
            if index == 3 and not real_l4:
                reason = "L4 row is not attested as an actual next model request Tool message"
            elif carrier_ids and not linked_ids and not explicit_loss:
                reason = "effect carrier paths exist but adjacent values/provenance are not linked"
            if group.startswith("unresolved:"):
                reason = "Tool call identity is ambiguous within repetition"
            status = "TRANSFORMED" if transformed_ids else "PRESERVED" if linked_ids else "DROPPED" if explicit_loss and carrier_ids else "UNASSESSED"
            field_mapping = {"source_jsonpaths": source_paths, "target_jsonpaths": target_paths, "source_paths": carrier_paths, "target_paths": carrier_paths, "call_key": group, "call_identity": target_dynamic.get("call_identity", {}), "relation": "TRANSFORMS" if transformed_ids else "OBSERVES" if index == 3 else "PROJECTS_TO_SESSION" if index == 2 else "SERIALIZES"}
            transformation = {"input": source_paths, "output": target_paths, "rule": witness.get("rule") if witness else "value-preserved" if linked_ids else "unresolved boundary mapping", "source_conversion": conversions, "evidence_refs": witness.get("evidence_refs", [f"trace:{side}:{levels[index]}:{repetition}:{group}", f"trace:{side}:{levels[index + 1]}:{repetition}:{group}"]) if witness else [f"trace:{side}:{levels[index]}:{repetition}:{group}", f"trace:{side}:{levels[index + 1]}:{repetition}:{group}"]}
            if witness:
                transformation.update({"input_fingerprints": witness["input_fingerprints"], "output_fingerprints": witness["output_fingerprints"]})
            _add_edge(edges, source, target, "FILTERS" if explicit_loss and carrier_ids else edge_kind[index], side=side, field_mapping=field_mapping, effect_ids=linked_ids or carrier_ids, dynamic=True, confidence=0.9 if reason is None else 0.2, evidence_refs=transformation["evidence_refs"], repetition=repetition, trace_id=target_dynamic.get("trace_id"), span_id=target_dynamic.get("span_id"), parent_span_id=source_dynamic.get("parent_span_id"), unresolved_reason=reason, transport_observed=True, effect_carrier_observed=bool(carrier_ids), effect_value_linked=bool(linked_ids), exact_l4_observed=bool(linked_ids) and real_l4, carrier_effect_ids=carrier_ids, plane="EFFECT" if carrier_ids else "EXECUTION", status=status, transformation=transformation, boundary=f"{levels[index]}->{levels[index + 1]}")
    unresolved = []
    if not l4_real:
        unresolved.append("L4 actual model request not attested")
    if ambiguous_tool_identity:
        unresolved.append("Tool call identity is ambiguous within repetition")
    return dynamic_refs, unresolved


def _resource_edges(rows: list[dict[str, Any]], side: str, nodes: dict[str, dict[str, Any]], edges: dict[str, dict[str, Any]], effects: list[dict[str, Any]]) -> None:
    """Add resource state/event nodes with effect-specific attribution."""
    writes: dict[str, str] = {}
    resource_effects = [effect for effect in effects if effect.get("effect_kind") == "RESOURCE_EFFECT"]

    def event_signature(event: dict[str, Any], row: dict[str, Any], resource_id: Any, operation: str) -> dict[str, Any]:
        return {
            key: value
            for key, value in {
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
                "repetition": int(row.get("repetition", 1) or 1),
            }.items()
            if value not in (None, "")
        }

    def matching_effects(event: dict[str, Any], row: dict[str, Any]) -> list[dict[str, Any]]:
        explicit = event.get("effect_id") or row.get("effect_id")
        explicit_ids = set(event.get("effect_ids", [])) if isinstance(event.get("effect_ids"), list) else set()
        if explicit:
            explicit_ids.add(str(explicit))
        matches = [effect for effect in resource_effects if str(effect.get("effect_id")) in explicit_ids]
        if matches:
            return matches
        resource_id = event.get("resource_id") or event.get("resource_identity") or event.get("file_path") or event.get("url")
        operation = str(event.get("operation") or ("read" if event.get("state_read") else "write" if event.get("state_write") else "")).lower()
        observed = event_signature(event, row, resource_id, operation)
        candidates = []
        for effect in resource_effects:
            obj = effect.get("object", {}) if isinstance(effect.get("object"), dict) else {}
            expected_id = obj.get("resource_identity")
            expected_operation = str(obj.get("operation") or "").lower()
            signatures = obj.get("resource_events", []) if isinstance(obj.get("resource_events"), list) else []
            signature_match = any(
                all(observed.get(key) == item.get(key) for key in item if item.get(key) not in (None, ""))
                for item in signatures if isinstance(item, dict)
            )
            if (expected_id is None or str(expected_id) == str(resource_id)) and (not expected_operation or expected_operation == operation) and (signature_match or not signatures):
                candidates.append(effect)
        return candidates if len(candidates) == 1 else []

    for index, row in enumerate(rows):
        event = row.get("event") if isinstance(row.get("event"), dict) else row
        resource_id = event.get("resource_id") or event.get("resource_identity") or event.get("file_path") or event.get("url")
        if not resource_id:
            continue
        repetition = int(row.get("repetition", 1) or 1)
        resource_fingerprint = _fingerprint(str(resource_id))
        attributed = matching_effects(event, row)
        attributed_ids = [str(effect.get("effect_id")) for effect in attributed if effect.get("effect_id")]
        resource_node = _add_node(nodes, _node("EXTERNAL_RESOURCE", "resource", side=side, symbol=resource_fingerprint["sha256"], identity_extra="resource", effect_ids=attributed_ids, resource_identity=resource_fingerprint))
        operation = str(event.get("operation", "") or ("read" if event.get("state_read") else "write" if event.get("state_write") else "unknown")).lower()
        is_read = bool(event.get("state_read") or operation in {"read", "load", "fetch"})
        source_jsonpaths = ["$.event"]
        resource_jsonpaths = ["$.event.resource_id", "$.event.resource_identity", "$.event.file_path", "$.event.url"]
        if operation:
            resource_jsonpaths.append("$.event.operation")
        readback_jsonpaths = [
            "$.event.return", "$.event.return_value", "$.event.readback_value",
            "$.event.content", "$.event.structuredContent",
        ]
        event_id = _add_node(nodes, _node("EXTERNAL_RESOURCE", "resource_event", side=side, symbol=operation, identity_extra=f"event:{side}:{repetition}:{index}:{resource_fingerprint['sha256']}", effect_ids=attributed_ids, dynamic={"repetition": repetition, "trace_id": row.get("trace_id", f"trace:{side}:{repetition}"), "span_id": row.get("span_id"), "resource_identity": resource_fingerprint, "operation": operation}, resource_identity=resource_fingerprint, operation=operation, resource_event_index=index))
        before = event.get("before_state", event.get("state_before"))
        after = event.get("after_state", event.get("state_after"))
        for state_name, state_value in (("before", before), ("after", after)):
            if state_value is None:
                continue
            state_id = _add_node(nodes, _node("EXTERNAL_RESOURCE", "resource_state", side=side, symbol=state_name, identity_extra=f"{state_name}:{side}:{repetition}:{index}:{resource_fingerprint['sha256']}", effect_ids=attributed_ids, dynamic={"repetition": repetition, "state": state_name, "value_fingerprint": _fingerprint(state_value)}, state_position=state_name, state_fingerprint=_fingerprint(state_value)))
            _add_edge(edges, state_id if state_name == "before" else event_id, event_id if state_name == "before" else state_id, "ALIGNS_WITH", side=side, effect_ids=attributed_ids, dynamic=True, confidence=0.82, plane="EFFECT" if attributed_ids else "EXECUTION", status="PRESERVED" if attributed_ids else "UNASSESSED", field_mapping={"state": state_name, "resource_id": resource_fingerprint, "source_jsonpaths": [f"$.event.{state_name}_state", f"$.event.state_{state_name}"], "target_jsonpaths": source_jsonpaths}, evidence_refs=[f"trace:{side}:runtime-event:{repetition}"], repetition=repetition, carrier_effect_ids=attributed_ids, effect_carrier_observed=bool(attributed_ids), effect_value_linked=bool(attributed_ids))
        if event.get("state_write") or operation in {"write", "create", "send", "execute"} or (event.get("file_path") and not is_read):
            location = str(event.get("location", ""))
            line_text = location.rsplit(":", 1)[-1] if ":" in location else ""
            line = int(line_text) if line_text.isdigit() else None
            source = _add_node(nodes, _node("PROGRAM_DEPENDENCY", "call_site", side=side, symbol=str(event.get("function", event.get("operation", "resource-write"))), path=location.split(":", 1)[0], line=line, effect_ids=attributed_ids))
            writes[str(resource_id)] = source
            for edge_kind in ("STATE_WRITE", "WRITES_RESOURCE"):
                _add_edge(edges, source, resource_node, edge_kind, side=side, effect_ids=attributed_ids, dynamic=True, confidence=0.8, plane="EFFECT" if attributed_ids else "EXECUTION", status="PRESERVED" if attributed_ids else "UNASSESSED", field_mapping={"resource_id": resource_fingerprint, "operation": "write", "source_jsonpaths": source_jsonpaths, "target_jsonpaths": resource_jsonpaths}, evidence_refs=[f"trace:{side}:runtime-event:{repetition}"], repetition=repetition, transport_observed=True, effect_carrier_observed=bool(attributed_ids), effect_value_linked=bool(attributed_ids), carrier_effect_ids=attributed_ids)
        if is_read:
            read_id = _add_node(nodes, _node("PROGRAM_SERVER", "return_value", side=side, symbol=str(event.get("function", "resource-read")), effect_ids=attributed_ids, dynamic={"repetition": repetition, "resource_id": resource_fingerprint}))
            for edge_kind in ("STATE_READ", "READS_RESOURCE"):
                _add_edge(edges, resource_node, read_id, edge_kind, side=side, effect_ids=attributed_ids, dynamic=True, confidence=0.75, plane="EFFECT" if attributed_ids else "EXECUTION", status="PRESERVED" if attributed_ids else "UNASSESSED", field_mapping={"resource_id": resource_fingerprint, "operation": "read", "source_jsonpaths": resource_jsonpaths, "target_jsonpaths": readback_jsonpaths}, evidence_refs=[f"trace:{side}:runtime-event:{repetition}"], repetition=repetition, transport_observed=True, effect_carrier_observed=bool(attributed_ids), effect_value_linked=bool(attributed_ids), carrier_effect_ids=attributed_ids)
            readback = event.get("return", event.get("readback_value", event.get("content", event.get("structuredContent"))))
            if readback is not None and attributed_ids:
                readback_id = _add_node(nodes, _node("EXTERNAL_RESOURCE", "readback_value", side=side, symbol=operation, identity_extra=f"readback:{side}:{repetition}:{index}", effect_ids=attributed_ids, dynamic={"repetition": repetition, "value_fingerprint": _fingerprint(readback)}, value_fingerprint=_fingerprint(readback)))
                _add_edge(edges, event_id, readback_id, "DERIVES_VALUE", side=side, effect_ids=attributed_ids, dynamic=True, confidence=0.86, plane="EFFECT", status="PRESERVED", field_mapping={"resource_id": resource_fingerprint, "operation": "read", "readback": True, "source_jsonpaths": source_jsonpaths, "target_jsonpaths": readback_jsonpaths}, evidence_refs=[f"trace:{side}:runtime-event:{repetition}"], repetition=repetition, transport_observed=True, effect_carrier_observed=True, effect_value_linked=True, carrier_effect_ids=attributed_ids)


def _graph_digest(graph: dict[str, Any]) -> str:
    payload = {key: graph.get(key) for key in ("schema_version", "graph_id", "case_identity", "effect_model_digest", "nodes", "edges", "status")}
    return _digest(payload)


def _paired_parity(spec: dict[str, Any], vulnerable_results: list[dict[str, Any]] | None, fixed_results: list[dict[str, Any]] | None) -> dict[str, Any]:
    """Summarize parity without copying runner paths or raw input values."""
    expected = _digest(spec.get("tool_input", {}))
    sides = {}
    for side, results in (("vulnerable", vulnerable_results or []), ("fixed", fixed_results or [])):
        sides[side] = {
            "repetitions": sorted({int(item.get("repetition", 1) or 1) for item in results}),
            "tool_input_digests": sorted({str(item.get("tool_input_digest")) for item in results if item.get("tool_input_digest")}),
            "valid": bool(results) and all(bool(item.get("valid")) and not bool(item.get("timed_out")) for item in results),
        }
    v = sides["vulnerable"]
    f = sides["fixed"]
    valid = (not vulnerable_results and not fixed_results) or (
        v["valid"] and f["valid"] and v["repetitions"] == f["repetitions"]
        and v["tool_input_digests"] == f["tool_input_digests"]
        and (not v["tool_input_digests"] or v["tool_input_digests"] == [expected])
    )
    return {"tool_name": str((spec.get("tool") or {}).get("name", "")) if isinstance(spec.get("tool"), dict) else "", "tool_input_digest": expected, "host_profile_digest": _digest(spec.get("host_profile", {})), "environment_digest": _digest(spec.get("environment", spec.get("environment_manifest", {}))), "shared_boundary": True, "valid": valid, "sides": sides}


def _stage1_anchor_refs(localization: dict[str, Any]) -> list[dict[str, Any]]:
    candidates = localization.get("anchor_candidates", []) if isinstance(localization, dict) else []
    refs: list[dict[str, Any]] = []
    for value in candidates:
        if isinstance(value, dict):
            refs.append({"source_ref": value.get("source_ref") or value.get("location"), "symbol": value.get("symbol") or value.get("function"), "digest": _digest(value)})
        else:
            refs.append({"source_ref": None, "symbol": None, "digest": _fingerprint(value)})
    return refs


def _continuous_effect_path(effect_id: str, nodes: dict[str, dict[str, Any]], edges: dict[str, dict[str, Any]], stage4_effect: dict[str, Any]) -> dict[str, Any]:
    """Require an effect-specific, same-call chain through every boundary."""
    if stage4_effect.get("effect_status") != "REACHED" or stage4_effect.get("reached_exact_l4") is not True:
        return {
            "status": "UNASSESSED" if stage4_effect.get("effect_status") == "UNASSESSED" else "NOT_REACHED",
            "missing_boundaries": ["exact L4 effect witness"],
            "breakpoints": ["Stage 4 did not establish a reached effect instance for this call chain"],
            "exact_l4_observed": False,
            "observed_repetitions": [],
        }
    production = stage4_effect.get("production_status") == "PRODUCED"
    if not production:
        return {"status": "UNASSESSED" if stage4_effect.get("effect_status") == "UNASSESSED" else "NOT_REACHED", "missing_boundaries": ["effect production"], "breakpoints": ["production witness is absent for this effect instance"], "exact_l4_observed": False, "observed_repetitions": []}
    static_anchor = any(
        edge.get("side") in {"vulnerable", "both"}
        and edge.get("kind") == "PRODUCES" and edge.get("effect_ids") == [effect_id]
        and nodes.get(edge.get("source"), {}).get("kind") == "vulnerability_anchor"
        and nodes.get(edge.get("target"), {}).get("kind") == "effect_instance"
        for edge in edges.values()
    )
    static_carrier = any(
        edge.get("side") in {"vulnerable", "both"}
        and effect_id in edge.get("effect_ids", []) and edge.get("kind") == "CARRIED_BY"
        and nodes.get(edge.get("source"), {}).get("kind") == "effect_instance"
        for edge in edges.values()
    )
    # Stage 4 is evaluated on the vulnerable execution. A complete fixed-side
    # chain cannot repair a missing vulnerable-side causal boundary.
    dynamic = [
        edge for edge in edges.values()
        if edge.get("side") == "vulnerable"
        and edge.get("dynamic_provenance")
        and effect_id in edge.get("effect_ids", [])
    ]
    chains: dict[tuple[int, str], set[str]] = {}
    for edge in dynamic:
        if edge.get("repetition") is None:
            continue
        call_key = str(edge.get("field_mapping", {}).get("call_key", ""))
        chains.setdefault((int(edge["repetition"]), call_key), set()).add(str(edge.get("boundary", "")))
    required = {"L0_RAW_MCP_RESULT->L1_NORMALIZED_TOOL_RESULT", "L1_NORMALIZED_TOOL_RESULT->L2_HOST_PROCESSED_TOOL_RESULT", "L2_HOST_PROCESSED_TOOL_RESULT->L3_SESSION_TOOL_RESULT", "L3_SESSION_TOOL_RESULT->L4_MODEL_VISIBLE_OBSERVATION"}
    complete_chains = []
    failed_boundaries: set[str] = set()
    failed_boundary_reasons: list[str] = []
    for chain, boundaries in chains.items():
        chain_edges = [edge for edge in dynamic if int(edge.get("repetition", -1)) == chain[0] and str(edge.get("field_mapping", {}).get("call_key", "")) == chain[1]]
        boundary_edges = {str(edge.get("boundary")): edge for edge in chain_edges if edge.get("boundary") in required}
        for boundary in sorted(required - boundaries):
            failed_boundaries.add(boundary)
            failed_boundary_reasons.append(f"{boundary}: evidence edge is missing")
        for boundary, edge in sorted(boundary_edges.items()):
            if edge.get("status") not in {"PRESERVED", "TRANSFORMED"} or not edge.get("effect_value_linked"):
                failed_boundaries.add(boundary)
                failed_boundary_reasons.append(
                    f"{boundary}: status={edge.get('status', 'UNASSESSED')} lacks same-effect value linkage"
                )
        if required.issubset(boundaries) and all(edge.get("status") in {"PRESERVED", "TRANSFORMED"} and edge.get("effect_value_linked") for edge in boundary_edges.values()) and any(edge.get("exact_l4_observed") for edge in chain_edges):
            complete_chains.append(chain)
    missing = []
    if not static_anchor:
        missing.append("vulnerability anchor -> effect production")
    if not static_carrier:
        missing.append("effect production -> carrier")
    if missing:
        return {
            "status": "UNASSESSED" if any(edge.get("status") == "UNASSESSED" for edge in dynamic) else "PARTIAL",
            "missing_boundaries": sorted(set(missing)),
            "breakpoints": ["effect-specific anchor/carrier evidence is not connected to the observed call chain"],
            "exact_l4_observed": False,
            "observed_repetitions": sorted({chain[0] for chain in chains}),
        }
    if not complete_chains:
        missing.extend(sorted(failed_boundaries or required))
        breakpoints = ["no single repetition/call identity covers production, carrier, and exact L4"]
        breakpoints.extend(sorted(set(failed_boundary_reasons)))
        return {"status": "UNASSESSED" if any(edge.get("status") == "UNASSESSED" for edge in dynamic) else "PARTIAL", "missing_boundaries": sorted(set(missing)), "breakpoints": breakpoints, "exact_l4_observed": False, "observed_repetitions": sorted({chain[0] for chain in chains})}
    return {"status": "COMPLETE", "missing_boundaries": [], "breakpoints": [], "exact_l4_observed": True, "observed_repetitions": sorted({chain[0] for chain in complete_chains}), "call_chains": [{"repetition": rep, "call_key": key} for rep, key in complete_chains]}


def build_cross_layer_graph(spec: dict[str, Any], effect_model: dict[str, Any], traces: dict[str, list[dict[str, Any]]] | None = None, *, vulnerable_results: list[dict[str, Any]] | None = None, fixed_results: list[dict[str, Any]] | None = None, base_dir: Path | None = None, localization: dict[str, Any] | None = None) -> dict[str, Any]:
    """Construct an attributed directed multigraph from Stage 2 and blind evidence."""
    identity = spec.get("identity", {}) if isinstance(spec.get("identity"), dict) else {}
    case_identity = {key: identity.get(key) for key in ("advisory", "package", "vulnerable_version", "fixed_version") if identity.get(key) is not None}
    effect_digest = _digest(effect_model)
    parity = _paired_parity(spec, vulnerable_results, fixed_results)
    if localization is None:
        from oscar.analysis.localization import build_localization

        localization = build_localization(spec, base_dir=base_dir)
    stage1_anchor_refs = _stage1_anchor_refs(localization)
    component = localization.get("vulnerability_component", localization.get("direct_runtime_dependency", {}))
    origin = component.get("origin") or component_origin(spec) or "DIRECT_RUNTIME_DEPENDENCY"
    base = {"schema_version": SCHEMA_VERSION, "case_identity": case_identity, "component_origin": origin, "vulnerability_component": {key: component.get(key) for key in ("origin", "name", "purl", "repository", "relation_status") if component.get(key) is not None}, "localization_digest": localization.get("localization_digest"), "effect_model_digest": effect_digest}
    if localization.get("status") != "LOCALIZED" or effect_model.get("status") != "GENERATED" or effect_model.get("schema_version") != "vulveil-effect-model/v3":
        if localization.get("status") != "LOCALIZED":
            unavailable = "Stage 1 localization is not LOCALIZED"
        elif effect_model.get("schema_version") != "vulveil-effect-model/v3":
            unavailable = "Stage 2 effect model uses legacy/incompatible schema; migrate to vulveil-effect-model/v3"
        else:
            unavailable = "Stage 2 effect model is not GENERATED"
        graph = {**base, "graph_id": "graph-" + _digest(base)[:20], "status": "UNASSESSED", "effect_ids": [], "effect_relations": [], "nodes": [], "edges": [], "sides": {}, "parity": parity, "stage1_anchor_refs": stage1_anchor_refs, "effect_observation": {}, "effect_path_status": {}, "unresolved_boundaries": [unavailable], "graph_validation": {"status": "UNASSESSED", "errors": [unavailable]}, "evidence_references": []}
        graph["graph_digest"] = _graph_digest(graph)
        return graph
    traces = traces or {"vulnerable": [], "fixed": []}
    # Evidence rows are often emitted without run metadata; restore it from the
    # side summaries so every dynamic edge carries an auditable repetition.
    for side, results in (("vulnerable", vulnerable_results or []), ("fixed", fixed_results or [])):
        if not results:
            continue
        enriched: list[dict[str, Any]] = []
        for run in results:
            repetition = int(run.get("repetition", 1) or 1)
            for row in run.get("evidence", {}).get("rows", []):
                item = dict(row)
                item.setdefault("repetition", repetition)
                item.setdefault("trace_id", f"trace:{side}:{repetition}")
                enriched.append(item)
        if enriched:
            traces[side] = enriched
    nodes: dict[str, dict[str, Any]] = {}
    edges: dict[str, dict[str, Any]] = {}
    modeled_effects = [item for item in effect_model.get("effects", []) if item.get("effect_id")]
    effect_ids = [str(item.get("effect_id")) for item in modeled_effects]
    carrier_paths = sorted({str(path) for effect in modeled_effects for path in effect.get("carrier", {}).get("paths", [])})
    carrier_effect_ids = [str(effect.get("effect_id")) for effect in modeled_effects if effect.get("carrier", {}).get("paths")]
    resource_effect_ids = [str(effect.get("effect_id")) for effect in modeled_effects if effect.get("effect_kind") == "RESOURCE_EFFECT"]
    tool_name = str(spec.get("tool", {}).get("name", "")) if isinstance(spec.get("tool"), dict) else ""
    seed_symbols = {tool_name} if tool_name else set()
    for effect in effect_model.get("effects", []):
        seed_symbols.update(str(name) for name in effect.get("origin", {}).get("functions", []) if name)
    construction_unresolved: list[str] = []
    effect_nodes_by_side: dict[str, dict[str, str]] = {"vulnerable": {}, "fixed": {}}
    anchor_nodes_by_side: dict[str, list[str]] = {"vulnerable": [], "fixed": []}
    dependency_contract = localization.get("vulnerability_component", localization.get("direct_runtime_dependency", {}))
    dependency_name = str(dependency_contract.get("name", dependency_contract.get("dependency_name", "")))
    dependency_purl = str(dependency_contract.get("purl", dependency_contract.get("dependency_purl", "")))
    dependency_tokens = {
        token.replace("-", "_").lower()
        for token in (dependency_name, dependency_purl.rsplit("/", 1)[-1].split("@", 1)[0])
        if token
    }
    for side in ("vulnerable", "fixed"):
        static = _python_static(spec, side, nodes, edges, [], base_dir, seed_symbols)
        if not static.get("handlers"):
            static = _typescript_static(spec, side, nodes, edges, [], base_dir, seed_symbols)
        task_id = _add_node(nodes, _node("EXECUTION", "agent_task", side=side, symbol=str(spec.get("agent_task", ""))[:80], identity_extra=f"task:{side}", task_digest=_digest(spec.get("agent_task", "")), task_projection="frozen AgentTask"))
        repetitions = sorted({int(row.get("repetition", 1) or 1) for row in traces.get(side, [])}) or [1]
        handler = static.get("handlers", {}).get(tool_name)
        handler_node = None
        if handler:
            handler_source = nodes.get(handler, {}).get("source", {})
            handler_node = _add_node(nodes, _node("EXECUTION", "tool_handler", side=side, path=handler_source.get("path", ""), symbol=handler_source.get("symbol", tool_name), line=handler_source.get("line"), identity_extra=f"handler:{tool_name}", handler_for=tool_name))
            _add_edge(edges, handler_node, handler, "BINDS", side=side, effect_ids=nodes.get(handler, {}).get("effect_ids", []), static=True, confidence=0.9, field_mapping={"tool_name": tool_name, "handler_node": handler_node}, evidence_refs=[f"source:tool-handler:{tool_name}"])
        for repetition in repetitions:
            call_rows = [row for row in traces.get(side, []) if int(row.get("repetition", 1) or 1) == repetition]
            grouped_calls: dict[str, dict[str, Any]] = {}
            raw_call_groups = [(_call_group_key(_call_identity(row)), row) for row in call_rows]
            level_counts: dict[tuple[str, str], int] = {}
            for group, row in raw_call_groups:
                level = str(row.get("level", ""))
                level_counts[(group, level)] = level_counts.get((group, level), 0) + 1
            ambiguous_groups = {group for (group, _level), count in level_counts.items() if count > 1}
            for index, (group, row) in enumerate(raw_call_groups):
                if group in ambiguous_groups:
                    # Without a call ID, repeated evidence at the same level
                    # cannot be assigned to one invocation. Keep each row as
                    # an unresolved dynamic node instead of folding calls.
                    group = f"unresolved:{side}:{repetition}:{index}"
                grouped_calls.setdefault(group, row)
            if not grouped_calls:
                grouped_calls[f"tool:{tool_name}:{side}:{repetition}"] = {"repetition": repetition, "trace_id": f"trace:{side}:{repetition}"}
            for call_key, first_row in sorted(grouped_calls.items()):
                call_identity = _call_identity(first_row)
                call_identity.setdefault("tool_name", tool_name)
                call_identity.setdefault("invocation_id", call_key)
                call_id = _add_node(nodes, _node("EXECUTION", "tool_call", side=side, symbol=tool_name, identity_extra=f"call:{side}:{repetition}:{call_key}", effect_ids=[], dynamic={"repetition": repetition, "call_key": call_key, **call_identity}, invocation_identity=call_identity, tool_name=tool_name))
                _add_edge(edges, task_id, call_id, "TASK_INVOKES", side=side, dynamic=True, confidence=0.95, field_mapping={"task": task_id, "tool_name": tool_name, "call_key": call_key, "call_identity": call_identity, "repetition": repetition, "source_jsonpaths": ["$.agent_task"], "target_jsonpaths": ["$.tool_call"]}, evidence_refs=[f"trace:{side}:tool-call:{repetition}:{call_key}"], repetition=repetition, trace_id=call_identity.get("trace_id", f"trace:{side}:{repetition}"), span_id=call_identity.get("span_id"), plane="EXECUTION", status="PRESERVED")
                if handler_node:
                    _add_edge(edges, call_id, handler_node, "CALLS", side=side, dynamic=True, confidence=0.88, field_mapping={"tool_call_id": call_identity.get("tool_call_id"), "invocation_id": call_identity.get("invocation_id"), "call_key": call_key, "handler": handler_node, "source_jsonpaths": ["$.tool_call"], "target_jsonpaths": ["$.handler"]}, evidence_refs=[f"trace:{side}:tool-call:{repetition}:{call_key}", f"source:tool-handler:{tool_name}"], repetition=repetition, trace_id=call_identity.get("trace_id", f"trace:{side}:{repetition}"), span_id=call_identity.get("span_id"), plane="EXECUTION", status="PRESERVED")
        # Attribute static program structure by the effect's own source refs;
        # shared Tool/protocol nodes remain un attributed unless that effect has
        # an evidence-backed carrier.
        for node in nodes.values():
            if node.get("side") not in {side, "both"} or node.get("layer") not in {"PROGRAM_SERVER", "PROGRAM_DEPENDENCY"}:
                continue
            source = node.get("source", {})
            node_path = _norm_path(str(source.get("path", "")))
            node_line = source.get("line")
            for effect in modeled_effects:
                refs = effect.get("origin", {}).get("source_refs", [])
                matches = any(
                    _norm_path(str(ref).split(":", 1)[0]) == node_path
                    and (node_line is None or str(ref).rsplit(":", 1)[-1] == str(node_line))
                    for ref in refs
                )
                if matches:
                    node["effect_ids"] = sorted(set(node.get("effect_ids", [])) | {str(effect["effect_id"])})
        for edge in edges.values():
            if not edge.get("static_provenance"):
                continue
            source_effects = set(nodes.get(edge.get("source"), {}).get("effect_ids", []))
            target_effects = set(nodes.get(edge.get("target"), {}).get("effect_ids", []))
            edge["effect_ids"] = sorted(set(edge.get("effect_ids", [])) | (source_effects & target_effects))
        component_layer = "PROGRAM_SERVER" if origin == "MCP_SERVER_SELF" else "PROGRAM_DEPENDENCY"
        for anchor in effect_model.get("anchor_candidates", []):
            if not isinstance(anchor, dict) or str(anchor.get("side", "")) != side:
                continue
            source_ref = str(anchor.get("source_ref", ""))
            anchor_path, _, anchor_line = source_ref.partition(":")
            line = int(anchor_line) if anchor_line.isdigit() else None
            anchor_kind = "branch" if str(anchor.get("kind")) == "guard" else "call_site"
            anchor_effect_ids = [
                str(effect.get("effect_id"))
                for effect in modeled_effects
                if any(
                    _norm_path(str(ref).rsplit(":", 1)[0]) == _norm_path(anchor_path)
                    and (not str(ref).rsplit(":", 1)[-1].isdigit() or line is None or int(str(ref).rsplit(":", 1)[-1]) == line)
                    for ref in effect.get("origin", {}).get("source_refs", [])
                )
            ]
            anchor_id = _add_node(nodes, _node("PROGRAM_SERVER", anchor_kind, side=side, path=anchor_path, symbol=str(anchor.get("function") or anchor.get("symbol") or "anchor"), line=line, identity_extra=f"anchor:{anchor.get('anchor_id', '')}", effect_ids=anchor_effect_ids, anchor_id=anchor.get("anchor_id"), anchor_kind=anchor.get("kind"), patch_change=anchor.get("patch_change")))
            vulnerability_anchor_id = _add_node(nodes, _node(component_layer, "vulnerability_anchor", side=side, path=anchor_path, symbol=str(anchor.get("function") or anchor.get("symbol") or "anchor"), line=line, identity_extra=f"vulnerability-anchor:{anchor.get('anchor_id', '')}", effect_ids=anchor_effect_ids, anchor_id=anchor.get("anchor_id"), anchor_kind=anchor.get("kind"), patch_change=anchor.get("patch_change"), evidence_refs=anchor.get("evidence_refs", [f"source:{source_ref}"]), vulnerability_component=dependency_name))
            anchor_nodes_by_side[side].append(vulnerability_anchor_id)
            _add_edge(edges, anchor_id, vulnerability_anchor_id, "ALIGNS_WITH", side=side, effect_ids=anchor_effect_ids, static=True, confidence=0.96, plane="ALIGNMENT", status="PRESERVED", field_mapping={"anchor_id": anchor.get("anchor_id"), "source_ref": source_ref}, evidence_refs=[f"anchor:{anchor.get('anchor_id', '')}", f"source:{source_ref}"])
            handler_id = static.get("handlers", {}).get(tool_name)
            if handler_id:
                _add_edge(edges, handler_id, anchor_id, "CONTROL" if anchor_kind == "branch" else "CALL", side=side, effect_ids=anchor_effect_ids, static=True, confidence=0.78, field_mapping={"anchor_id": anchor.get("anchor_id"), "source_ref": source_ref}, evidence_refs=[f"anchor:{anchor.get('anchor_id', '')}", f"source:{source_ref}"])
        dependency_version = component_revision(dependency_contract, side)
        component_layer = "PROGRAM_SERVER" if origin == "MCP_SERVER_SELF" else "PROGRAM_DEPENDENCY"
        component_kind = "vulnerability_component"
        component_id = _add_node(nodes, _node(component_layer, component_kind, side=side, symbol=dependency_name, identity_extra=origin.lower(), effect_ids=[], component_origin=origin, component_name=dependency_name, component_purl=dependency_purl, component_version=dependency_version, relation_status=dependency_contract.get("relation_status")))
        for effect in modeled_effects:
            effect_id = str(effect["effect_id"])
            effect_node = _add_node(nodes, _node("EFFECT", "effect_instance", side=side, symbol=effect_id, identity_extra=f"effect:{side}:{effect_id}", effect_ids=[effect_id], effect_kind=effect.get("effect_kind"), effect_role=effect.get("effect_role"), classification_status=effect.get("classification_status"), provenance_status=effect.get("provenance_status"), effect_realization=effect.get("effect_realization", {}), propagation=effect.get("propagation", {}), instance_key=effect.get("instance_key"), effect_origin=effect.get("origin", {}), effect_object=effect.get("object", {}), production_predicate=effect.get("condition", {}).get("production_predicate", {}), evidence_refs=effect.get("evidence_refs", [])))
            effect_nodes_by_side[side][effect_id] = effect_node
            matching_anchors = [anchor_id for anchor_id in anchor_nodes_by_side[side] if effect_id in nodes.get(anchor_id, {}).get("effect_ids", [])]
            # A patch-added fixed-side guard often has no byte-identical node
            # on the vulnerable side.  Recover the vulnerable anchor from the
            # effect's structured source reference and component call node;
            # never borrow an unrelated anchor merely because one exists in
            # the side's graph.
            if not matching_anchors:
                origin_ref = next((str(ref) for ref in effect.get("origin", {}).get("source_refs", []) if ":" in str(ref)), "")
                origin_path, _, origin_line = origin_ref.rpartition(":")
                if origin_path and origin_line.isdigit():
                    origin_anchor_id = _add_node(nodes, _node("PROGRAM_SERVER", "call_site", side=side, path=origin_path, symbol=str((effect.get("origin", {}).get("apis") or effect.get("origin", {}).get("functions") or ["vulnerability-anchor"])[0]), line=int(origin_line), identity_extra=f"origin-anchor:{side}:{effect_id}", effect_ids=[effect_id], anchor_id=f"origin-{side}-{effect_id}", anchor_kind="effect-origin", patch_change="source-evidence"))
                    origin_vulnerability_id = _add_node(nodes, _node(component_layer, "vulnerability_anchor", side=side, path=origin_path, symbol=str((effect.get("origin", {}).get("apis") or effect.get("origin", {}).get("functions") or ["vulnerability-anchor"])[0]), line=int(origin_line), identity_extra=f"origin-vulnerability-anchor:{side}:{effect_id}", effect_ids=[effect_id], anchor_id=f"origin-{side}-{effect_id}", anchor_kind="effect-origin", patch_change="source-evidence", evidence_refs=list(effect.get("evidence_refs", [])), vulnerability_component=dependency_name))
                    anchor_nodes_by_side[side].append(origin_vulnerability_id)
                    _add_edge(edges, origin_anchor_id, origin_vulnerability_id, "ALIGNS_WITH", side=side, effect_ids=[effect_id], static=True, confidence=0.88, plane="ALIGNMENT", status="PRESERVED", field_mapping={"effect_id": effect_id, "source_ref": origin_ref}, evidence_refs=list(effect.get("evidence_refs", [])))
                    handler_id = static.get("handlers", {}).get(tool_name)
                    if handler_id:
                        _add_edge(edges, handler_id, origin_anchor_id, "CALL", side=side, effect_ids=[effect_id], static=True, confidence=0.78, field_mapping={"effect_id": effect_id, "source_ref": origin_ref}, evidence_refs=list(effect.get("evidence_refs", [])))
                    matching_anchors = [origin_vulnerability_id]
            for anchor_node in matching_anchors:
                _add_edge(edges, anchor_node, effect_node, "PRODUCES", side=side, effect_ids=[effect_id], static=True, confidence=float(effect.get("confidence", 0.5)), plane="EFFECT", status="PRESERVED", field_mapping={"anchor_id": nodes.get(anchor_node, {}).get("anchor_id"), "effect_id": effect_id}, evidence_refs=effect.get("evidence_refs", []))
            if not matching_anchors and not anchor_nodes_by_side[side]:
                construction_unresolved.append(f"{side} effect {effect_id} has no vulnerability anchor node")
            carrier_kind = effect.get("carrier", {}).get("carrier_kind")
            semantic_carrier_kind = effect.get("carrier", {}).get("kind")
            if semantic_carrier_kind == "side_effect_only":
                carrier_kind = "RESOURCE_EVENT"
            elif semantic_carrier_kind == "control_signal":
                carrier_kind = "CONTROL_STATE"
            elif semantic_carrier_kind in {"returned_value", "structured_content", "resource_reference", "error_or_status", "metadata"}:
                carrier_kind = "PROGRAM_VALUE"
            if carrier_kind == "CONTROL_STATE":
                state_id = _add_node(nodes, _node("EFFECT", "control_state", side=side, symbol=effect_id, identity_extra=f"control-state:{side}:{effect_id}", effect_ids=[effect_id], state_kind="control", state_predicate=effect.get("condition", {}).get("predicates", [])))
                _add_edge(edges, effect_node, state_id, "CARRIED_BY", side=side, effect_ids=[effect_id], static=True, confidence=float(effect.get("confidence", 0.5)), plane="EFFECT", status="PRESERVED", field_mapping={"carrier_kind": "CONTROL_STATE"}, evidence_refs=effect.get("evidence_refs", []))
            elif carrier_kind == "PROGRAM_VALUE":
                for path in effect.get("carrier", {}).get("paths", []):
                    value_id = _add_node(nodes, _node("EFFECT", "program_value", side=side, symbol=str(path), field_path=str(path), identity_extra=f"program-value:{side}:{effect_id}:{path}", effect_ids=[effect_id], carrier_path=str(path), value_digests=effect.get("carrier", {}).get("vulnerable_value_digests", {}).get(path, [])))
                    _add_edge(edges, effect_node, value_id, "CARRIED_BY", side=side, effect_ids=[effect_id], static=True, confidence=float(effect.get("confidence", 0.5)), plane="EFFECT", status="PRESERVED", field_mapping={"carrier_kind": "PROGRAM_VALUE", "path": path}, evidence_refs=effect.get("evidence_refs", []))
        matched_dependency_calls = []
        for call_id, call_node in list(nodes.items()):
            if call_node.get("side") not in {side, "both"} or call_node.get("kind") != "call_site":
                continue
            callee = str(call_node.get("callee", ""))
            callee_root = callee.split(".", 1)[0].replace("-", "_").lower()
            if callee_root and callee_root in dependency_tokens:
                source = call_node.get("source", {})
                _add_edge(edges, component_id, call_id, "CALL", side=side, effect_ids=call_node.get("effect_ids", []), static=True, confidence=0.9, field_mapping={"caller_source_path": source.get("path"), "caller_line": source.get("line"), "caller_symbol": source.get("symbol"), "component_api_identity": callee, "component_origin": origin, "component_purl": dependency_purl, **({"dependency_api_identity": callee, "dependency_purl": dependency_purl} if origin == "DIRECT_RUNTIME_DEPENDENCY" else {})}, evidence_refs=[f"source:{source.get('path')}:{source.get('line')}", f"component:{dependency_purl}"])
                matched_dependency_calls.append(call_id)
        if not matched_dependency_calls and origin == "DIRECT_RUNTIME_DEPENDENCY":
            construction_unresolved.append(f"{side} direct dependency API call site is unresolved")
        elif not matched_dependency_calls and origin == "MCP_FRAMEWORK":
            construction_unresolved.append(f"{side} framework API call site is unresolved")
        elif origin == "MCP_SERVER_SELF":
            # Server-self vulnerabilities are represented by the Server
            # component node and patch-mapped anchor, never as a dependency.
            for anchor_id in [node_id for node_id, item in nodes.items() if item.get("side") in {side, "both"} and item.get("kind") in {"call_site", "branch"} and item.get("effect_ids")]:
                _add_edge(edges, component_id, anchor_id, "CALL", side=side, effect_ids=nodes[anchor_id].get("effect_ids", []), static=True, confidence=0.72, field_mapping={"component_origin": origin, "anchor": anchor_id}, evidence_refs=[f"component:{dependency_purl}", f"anchor:{anchor_id}"])
        tool_id = _add_node(nodes, _node("MCP", "mcp_tool", side=side, symbol=tool_name, field_path=tool_name, effect_ids=carrier_effect_ids, tool_name=tool_name))
        handler = static.get("handlers", {}).get(tool_name)
        if handler:
            _add_edge(edges, tool_id, handler, "BIND", side=side, effect_ids=nodes.get(handler, {}).get("effect_ids", []), static=True, confidence=0.85, field_mapping={"tool_name": tool_name, "handler": handler}, evidence_refs=[f"source:tool:{tool_name}"])
            _add_edge(edges, tool_id, handler, "BINDS", side=side, effect_ids=nodes.get(handler, {}).get("effect_ids", []), static=True, confidence=0.9, field_mapping={"tool_name": tool_name, "handler": handler, "binding": "static capability to handler"}, evidence_refs=[f"source:tool:{tool_name}"])
        else:
            _add_edge(edges, tool_id, tool_id, "BIND", side=side, effect_ids=[], static=True, confidence=0.2, evidence_refs=[f"source:tool:{tool_name}"], unresolved_reason="MCP Tool handler binding unresolved")
        arg_id = _add_node(nodes, _node("MCP", "tool_argument", side=side, symbol=tool_name, field_path="$", dynamic={"value_fingerprint": _fingerprint(spec.get("tool_input", {}))}, effect_ids=[]))
        schema_id = _add_node(nodes, _node("MCP", "input_schema", side=side, symbol=tool_name, field_path="inputSchema", effect_ids=[], schema_digest=_digest((spec.get("tool") or {}).get("input_schema", {}) if isinstance(spec.get("tool"), dict) else {})))
        result_id = _add_node(nodes, _node("MCP", "tool_result_field", side=side, symbol=tool_name, field_path=carrier_paths[0] if carrier_paths else None, effect_ids=carrier_effect_ids))
        for effect in modeled_effects:
            effect_id = str(effect["effect_id"])
            for value_node_id, value_node in nodes.items():
                if value_node.get("side") in {side, "both"} and value_node.get("kind") == "program_value" and effect_id in value_node.get("effect_ids", []):
                    path = value_node.get("carrier_path")
                    _add_edge(edges, value_node_id, result_id, "RETURNS", side=side, effect_ids=[effect_id], static=True, confidence=float(effect.get("confidence", 0.5)), plane="EFFECT", status="PRESERVED", field_mapping={"source_path": path, "target_paths": [path]}, evidence_refs=effect.get("evidence_refs", []))
        _add_edge(edges, tool_id, schema_id, "BIND", side=side, effect_ids=[], static=True, confidence=0.72, field_mapping={"tool_name": tool_name, "field": "inputSchema"}, evidence_refs=[f"schema:{tool_name}"])
        _add_edge(edges, schema_id, arg_id, "BIND", side=side, effect_ids=[], static=True, confidence=0.75, field_mapping={"schema": "inputSchema", "argument": "$"}, evidence_refs=[f"schema:{tool_name}"])
        _add_edge(edges, arg_id, tool_id, "BIND", side=side, effect_ids=[], static=True, confidence=0.82, evidence_refs=[f"input:{tool_name}"])
        for call_node_id, call_node in nodes.items():
            if call_node.get("side") in {side, "both"} and call_node.get("kind") == "tool_call":
                _add_edge(edges, call_node_id, arg_id, "PASSES_ARGUMENT", side=side, effect_ids=[], dynamic=True, confidence=0.92, field_mapping={"tool_call_id": call_node.get("invocation_identity", {}).get("tool_call_id"), "argument": "$", "source_jsonpaths": ["$.tool_call.arguments"], "target_jsonpaths": ["$.tool_input"]}, evidence_refs=[f"trace:{side}:tool-call:{call_node.get('dynamic', {}).get('repetition', 1)}"], repetition=call_node.get("dynamic", {}).get("repetition"), trace_id=call_node.get("dynamic", {}).get("trace_id"), span_id=call_node.get("dynamic", {}).get("span_id"), plane="EXECUTION", status="PRESERVED")
        handler_symbol = nodes.get(handler, {}).get("source", {}).get("symbol") if handler else None
        handler_returns = static.get("returns", {}).get(handler_symbol, []) if handler_symbol else []
        if handler_returns:
            for return_id in handler_returns:
                return_source = nodes.get(return_id, {}).get("source", {})
                _add_edge(edges, return_id, result_id, "SERIALIZE", side=side, effect_ids=nodes.get(return_id, {}).get("effect_ids", []), static=True, confidence=0.88, field_mapping={"handler": handler_symbol, "return_source_path": return_source.get("path"), "return_line": return_source.get("line"), "target_paths": carrier_paths}, evidence_refs=[f"source:{return_source.get('path')}:{return_source.get('line')}"])
        else:
            construction_unresolved.append(f"{side} handler return to Tool result serialization is unresolved")
        _, dynamic_unresolved = _dynamic_protocol_v3(spec, side, traces.get(side, []), nodes, edges, effect_model.get("effects", []), carrier_paths)
        construction_unresolved.extend(f"{side}: {reason}" for reason in dynamic_unresolved)
        for protocol_id, protocol_node in list(nodes.items()):
            if protocol_node.get("side") == side and protocol_node.get("kind") == "json_rpc_field":
                repetition = protocol_node.get("dynamic", {}).get("repetition", 1)
                observed_ids = protocol_node.get("effect_ids", [])
                l0_rows = [row for row in traces.get(side, []) if row.get("level") == "L0_RAW_MCP_RESULT" and int(row.get("repetition", 1) or 1) == int(repetition)]
                jointly_instrumented = any(
                    isinstance(row.get("event"), dict)
                    and row["event"].get("return") is not None
                    and _fingerprint(row["event"].get("return")) == _fingerprint(_payload(row))
                    for row in l0_rows
                )
                raw_payload = _payload(next(iter(l0_rows), {}))
                raw_content_attested = (
                    bool(handler_returns)
                    and raw_payload not in (None, "", [], {})
                )
                serialization_attested = jointly_instrumented or raw_content_attested
                attestation = (
                    "handler-return-and-l0-fingerprint"
                    if jointly_instrumented
                    else "static-handler-return-plus-nonempty-l0-carrier"
                    if raw_content_attested
                    else None
                )
                _add_edge(edges, result_id, protocol_id, "SERIALIZE", side=side, effect_ids=observed_ids, dynamic=True, confidence=0.88 if jointly_instrumented else 0.72 if raw_content_attested else 0.35, field_mapping={"source_jsonpaths": carrier_paths, "target_jsonpaths": protocol_node.get("field_paths", []), "source_paths": carrier_paths, "target_paths": protocol_node.get("field_paths", []), "jointly_instrumented": jointly_instrumented, "serialization_attestation": attestation}, evidence_refs=[f"trace:{side}:L0_RAW_MCP_RESULT:{repetition}"], repetition=repetition, unresolved_reason=None if serialization_attested else "handler return and L0 value fingerprints were not jointly instrumented", transport_observed=True, effect_carrier_observed=bool(observed_ids), effect_value_linked=bool(observed_ids) and serialization_attested, carrier_effect_ids=observed_ids, status="PRESERVED" if serialization_attested else "UNASSESSED")
        _resource_edges(traces.get(side, []), side, nodes, edges, modeled_effects)
        # A resource readback is a concrete effect carrier.  Keep this edge
        # explicit so a ResourceEffect can reach the same Tool-result field as
        # a direct ProgramValue without being reclassified as a ValueEffect.
        for readback_id, readback_node in list(nodes.items()):
            if readback_node.get("side") not in {side, "both"} or readback_node.get("kind") != "readback_value":
                continue
            for effect_id in readback_node.get("effect_ids", []):
                effect = next((item for item in modeled_effects if str(item.get("effect_id")) == str(effect_id)), None)
                if not effect or not effect.get("carrier", {}).get("paths"):
                    continue
                repetition = readback_node.get("dynamic", {}).get("repetition", 1)
                _add_edge(
                    edges,
                    readback_id,
                    result_id,
                    "RETURNS",
                    side=side,
                    effect_ids=[effect_id],
                    dynamic=True,
                    confidence=float(effect.get("confidence", 0.5)),
                    plane="EFFECT",
                    status="PRESERVED",
                    field_mapping={
                        "source_jsonpaths": ["$.event.return", "$.event.readback_value", "$.event.content"],
                        "target_jsonpaths": list(effect.get("carrier", {}).get("paths", [])),
                        "resource_readback": True,
                    },
                    evidence_refs=effect.get("evidence_refs", []),
                    repetition=repetition,
                    trace_id=readback_node.get("dynamic", {}).get("trace_id"),
                    span_id=readback_node.get("dynamic", {}).get("span_id"),
                    transport_observed=True,
                    effect_carrier_observed=True,
                    effect_value_linked=True,
                    carrier_effect_ids=[effect_id],
                )
        for effect in modeled_effects:
            effect_id = str(effect["effect_id"])
            effect_node = effect_nodes_by_side[side].get(effect_id)
            if not effect_node:
                continue
            for event_node_id, event_node in nodes.items():
                if event_node.get("side") in {side, "both"} and event_node.get("kind") == "resource_event" and effect_id in event_node.get("effect_ids", []):
                    _add_edge(edges, effect_node, event_node_id, "CARRIED_BY", side=side, effect_ids=[effect_id], dynamic=bool(event_node.get("dynamic_provenance")), static=not bool(event_node.get("dynamic_provenance")), confidence=float(effect.get("confidence", 0.5)), plane="EFFECT", status="PRESERVED", field_mapping={"carrier_kind": "RESOURCE_EVENT", "operation": event_node.get("operation")}, evidence_refs=effect.get("evidence_refs", []), repetition=event_node.get("dynamic", {}).get("repetition"), trace_id=event_node.get("dynamic", {}).get("trace_id"), span_id=event_node.get("dynamic", {}).get("span_id"), transport_observed=True, effect_carrier_observed=True, effect_value_linked=True, carrier_effect_ids=[effect_id])
        # Connect the modeled effect origin to the MCP carrier using explicit effect IDs.
        for effect in effect_model.get("effects", []):
            effect_carrier_paths = [str(path) for path in effect.get("carrier", {}).get("paths", [])]
            if not effect_carrier_paths:
                continue
            origin_refs = effect.get("origin", {}).get("source_refs", [])
            def matches_origin(item: dict[str, Any]) -> bool:
                source = item.get("source", {})
                item_path = _norm_path(str(source.get("path", "")))
                item_line = source.get("line")
                for ref in origin_refs:
                    ref_path, separator, ref_line = str(ref).rpartition(":")
                    if not separator or item_path != _norm_path(ref_path):
                        continue
                    if ref_line.isdigit() and item_line is not None and int(item_line) != int(ref_line):
                        continue
                    return True
                return False
            origin_nodes = [node_id for node_id, item in nodes.items() if item.get("side") in {side, "both"} and item.get("kind") in {"function", "call_site", "return_value"} and matches_origin(item)]
            for origin in origin_nodes[:4]:
                _add_edge(edges, origin, result_id, "DATA", side=side, effect_ids=[effect.get("effect_id")], static=True, confidence=float(effect.get("confidence", 0.5)), field_mapping={"source": effect.get("object", {}).get("field_paths", effect_carrier_paths)[0] if effect.get("object", {}).get("field_paths", effect_carrier_paths) else "", "target": effect_carrier_paths[0]}, evidence_refs=effect.get("evidence_refs", []))
    relation_edge_kinds = {"CAUSES": "CAUSES", "PRODUCES": "PRODUCES", "DERIVES": "DERIVES_VALUE", "DERIVES_VALUE": "DERIVES_VALUE", "ENABLES": "ENABLES", "PROPAGATES_TO": "PROPAGATES_TO", "BLOCKS": "BLOCKS", "ALIGNS_WITH": "ALIGNS_WITH"}
    for relation in effect_model.get("effect_relations", []):
        if not isinstance(relation, dict):
            continue
        left = str(relation.get("from", ""))
        right = str(relation.get("to", ""))
        if left not in effect_ids:
            continue
        for side in ("vulnerable", "fixed"):
            source = effect_nodes_by_side[side].get(left)
            relation_kind = str(relation.get("relation"))
            target_ids = [effect_nodes_by_side[side].get(right)] if right in effect_ids else []
            if relation_kind == "PROPAGATES_TO" and right not in effect_ids:
                target_kind = {
                    "TOOL_RESULT": "tool_result_field",
                    "HOST": "host_normalized_field",
                    "SESSION": "session_event",
                    "AGENT_OBSERVATION": "exact_l4_content_block",
                }.get(right)
                target_ids = [node_id for node_id, node in nodes.items() if node.get("side") in {side, "both"} and node.get("kind") == target_kind]
            for target in target_ids:
                if source and target:
                    _add_edge(edges, source, target, relation_edge_kinds.get(relation_kind, "ALIGNS_WITH"), side=side, effect_ids=[left], static=True, confidence=0.88, plane="EFFECT", status="PRESERVED", field_mapping={"relation": relation_kind, "from_effect": left, "to": right}, evidence_refs=relation.get("evidence_refs", []))
    unresolved = sorted(set(construction_unresolved) | {edge.get("unresolved_reason") for edge in edges.values() if edge.get("unresolved_reason")})
    result_nodes = {node_id for node_id, node in nodes.items() if node.get("kind") == "tool_result_field"}
    for effect in modeled_effects:
        effect_id = str(effect.get("effect_id"))
        if effect.get("carrier", {}).get("paths") and not any(effect_id in edge.get("effect_ids", []) and edge.get("target") in result_nodes and edge.get("kind") in {"DATA", "RETURN"} for edge in edges.values()):
            unresolved.append(f"effect {effect_id} has no evidence-backed edge to Tool result field")
    dynamic_edges = [edge for edge in edges.values() if edge.get("dynamic_provenance")]
    cross_layer_edges = [edge for edge in edges.values() if nodes.get(edge.get("source"), {}).get("layer") != nodes.get(edge.get("target"), {}).get("layer")]
    # The graph status is finalized after per-effect continuous paths have
    # been computed below.  A complete positive path may coexist with other
    # effects that have an explicit NOT_REACHED terminal state; those states
    # are not unresolved evidence for the effect that did reach L4.
    status = "PARTIAL" if nodes else "UNASSESSED"
    node_identities = {"vulnerable": {item.get("identity") for item in nodes.values() if item.get("side") in {"vulnerable", "both"}}, "fixed": {item.get("identity") for item in nodes.values() if item.get("side") in {"fixed", "both"}}}
    edge_identities = {"vulnerable": {(item.get("source"), item.get("target"), item.get("kind")) for item in edges.values() if item.get("side") == "vulnerable"}, "fixed": {(item.get("source"), item.get("target"), item.get("kind")) for item in edges.values() if item.get("side") == "fixed"}}
    edge_only_v = sorted(edge_identities["vulnerable"] - edge_identities["fixed"])
    edge_only_f = sorted(edge_identities["fixed"] - edge_identities["vulnerable"])
    effect_observation = {}
    for effect_id in effect_ids:
        effect_nodes = [item for item in nodes.values() if effect_id in item.get("effect_ids", [])]
        effect_edges = [item for item in edges.values() if effect_id in item.get("effect_ids", [])]
        transport_edges = [item for item in edges.values() if item.get("dynamic_provenance") and item.get("transport_observed") and (effect_id in item.get("effect_ids", []) or effect_id in item.get("carrier_effect_ids", []))]
        carrier_edges = [item for item in edges.values() if item.get("dynamic_provenance") and item.get("effect_carrier_observed") and effect_id in item.get("carrier_effect_ids", [])]
        dynamic_effect_edges = [item for item in effect_edges if item.get("dynamic_provenance") and item.get("effect_value_linked")]
        exact_observed = any(item.get("exact_l4_observed") for item in dynamic_effect_edges)
        boundary_statuses = sorted({str(item.get("status")) for item in effect_edges if item.get("dynamic_provenance")})
        observation = {"statically_reachable": bool(any(item.get("statically_reachable") for item in effect_nodes) or any(item.get("statically_reachable") for item in effect_edges)), "transport_observed": bool(transport_edges), "effect_carrier_observed": bool(carrier_edges), "effect_value_linked": bool(dynamic_effect_edges), "dynamically_observed": bool(dynamic_effect_edges), "observed_repetitions": sorted({int(rep) for item in dynamic_effect_edges for rep in item.get("observed_repetitions", [])}), "exact_l4_observed": exact_observed, "boundary_statuses": boundary_statuses, "path_status": "COMPLETE" if exact_observed else "PARTIAL" if boundary_statuses and "UNASSESSED" not in boundary_statuses else "UNASSESSED"}
        observation["by_side"] = {}
        for observed_side in SIDES:
            side_edges = [item for item in effect_edges if item.get("side") == observed_side]
            side_nodes = [item for item in effect_nodes if item.get("side") in {observed_side, "both"}]
            side_transport = [item for item in transport_edges if item.get("side") == observed_side]
            side_carrier = [item for item in carrier_edges if item.get("side") == observed_side]
            side_dynamic = [item for item in side_edges if item.get("dynamic_provenance") and item.get("effect_value_linked")]
            observation["by_side"][observed_side] = {"statically_reachable": bool(any(item.get("statically_reachable") for item in side_nodes) or any(item.get("statically_reachable") for item in side_edges)), "transport_observed": bool(side_transport), "effect_carrier_observed": bool(side_carrier), "effect_value_linked": bool(side_dynamic), "dynamically_observed": bool(side_dynamic), "observed_repetitions": sorted({int(rep) for item in side_dynamic for rep in item.get("observed_repetitions", [])}), "exact_l4_observed": any(item.get("exact_l4_observed") for item in side_dynamic)}
        effect_observation[effect_id] = observation
    graph = {**base, "graph_id": "graph-" + _digest(base)[:20], "status": status, "effect_ids": sorted(effect_ids), "effect_relations": copy_effect_relations(effect_model.get("effect_relations", []), effect_ids), "stage1_anchor_refs": stage1_anchor_refs, "nodes": sorted(nodes.values(), key=lambda item: item["node_id"]), "edges": sorted(edges.values(), key=lambda item: item["edge_id"]), "sides": {"vulnerable": {"node_count": sum(item.get("side") in {"vulnerable", "both"} for item in nodes.values()), "edge_count": sum(item.get("side") == "vulnerable" for item in edges.values())}, "fixed": {"node_count": sum(item.get("side") in {"fixed", "both"} for item in nodes.values()), "edge_count": sum(item.get("side") == "fixed" for item in edges.values())}}, "parity": parity, "alignment": {"matched_node_identities": sorted(node_identities["vulnerable"] & node_identities["fixed"]), "vulnerable_only": sorted(node_identities["vulnerable"] - node_identities["fixed"]), "fixed_only": sorted(node_identities["fixed"] - node_identities["vulnerable"]), "matched_edge_keys": sorted(edge_identities["vulnerable"] & edge_identities["fixed"]), "vulnerable_only_edges": edge_only_v, "fixed_only_edges": edge_only_f, "unresolved": []}, "repair_alignment": {"predicate": effect_model.get("repair_predicate", {}), "fixed_side_blocked": effect_model.get("fixed_side_blocked"), "cutpoint_edges": edge_only_v, "fixed_replacement_edges": edge_only_f, "status": "SUPPORTED" if effect_model.get("fixed_side_blocked") is True and parity.get("valid", True) else "UNRESOLVED"}, "unresolved_boundaries": [], "diagnostic_unresolved_boundaries": unresolved, "evidence_references": sorted({ref for edge in edges.values() for ref in edge.get("evidence_refs", [])})}
    graph["effect_observation"] = effect_observation
    try:
        from oscar.analysis.effect_modeling import inspect_l4_effect
    except ImportError:  # pragma: no cover
        from oscar.analysis.effect_modeling import inspect_l4_effect
    stage4 = inspect_l4_effect(effect_model, traces.get("vulnerable", []))
    graph["stage4_effect_observation"] = stage4
    graph["effect_path_status"] = {}
    graph_nodes = {item["node_id"]: item for item in graph["nodes"]}
    graph_edges = {item["edge_id"]: item for item in graph["edges"]}
    stage4_by_id = {str(item.get("effect_id")): item for item in stage4.get("effects", []) if isinstance(item, dict)}
    for effect_id, observation in effect_observation.items():
        continuous = _continuous_effect_path(effect_id, graph_nodes, graph_edges, stage4_by_id.get(effect_id, {}))
        observation["path_status"] = continuous["status"]
        observation["exact_l4_observed"] = continuous["exact_l4_observed"]
        observation["path_missing_boundaries"] = continuous.get("missing_boundaries", [])
        observation["path_breakpoints"] = continuous.get("breakpoints", [])
        for observed_side in SIDES:
            if observed_side in observation.get("by_side", {}):
                observation["by_side"][observed_side]["exact_l4_observed"] = bool(continuous["exact_l4_observed"] and observed_side == "vulnerable")
        graph["effect_path_status"][effect_id] = {
            **continuous,
            "boundary_statuses": observation.get("boundary_statuses", []),
            "unresolved_boundaries": sorted({edge.get("unresolved_reason") for edge in graph_edges.values() if effect_id in edge.get("effect_ids", []) and edge.get("unresolved_reason")}),
        }
    complete_effect_ids = {
        effect_id for effect_id, item in graph["effect_path_status"].items()
        if isinstance(item, dict) and item.get("status") == "COMPLETE"
    }
    terminal_effect_ids = {
        effect_id for effect_id, item in graph["effect_path_status"].items()
        if isinstance(item, dict) and item.get("status") in {"COMPLETE", "NOT_REACHED", "DROPPED", "FILTERED"}
    }
    blocking_unresolved: list[str] = []
    for reason in unresolved:
        match = re.search(r"effect ([^ ]+)", str(reason))
        if match and match.group(1) in graph["effect_path_status"] and match.group(1) not in complete_effect_ids:
            continue
        blocking_unresolved.append(str(reason))
    graph["unresolved_boundaries"] = sorted(set(blocking_unresolved))
    if parity.get("valid", True) and dynamic_edges and cross_layer_edges and complete_effect_ids and len(terminal_effect_ids) == len(graph["effect_path_status"]) and not graph["unresolved_boundaries"]:
        graph["status"] = "COMPLETE"
    elif nodes:
        graph["status"] = "PARTIAL"
    else:
        graph["status"] = "UNASSESSED"
    for edge in graph["edges"]:
        if edge.get("dynamic_provenance"):
            source_dynamic = nodes.get(edge.get("source"), {}).get("dynamic", {})
            target_dynamic = nodes.get(edge.get("target"), {}).get("dynamic", {})
            edge["value_fingerprints"] = {"source": source_dynamic.get("value_fingerprint"), "target": target_dynamic.get("value_fingerprint")}
    if not parity.get("valid", True):
        graph["unresolved_boundaries"].append("vulnerable/fixed paired execution parity or validity contract failed")
        graph["status"] = "INVALID"
    errors = validate_cross_layer_graph(graph, effect_model=effect_model)
    graph["graph_validation"] = {"status": "OK" if not errors else "ERROR", "errors": errors}
    if errors:
        graph["status"] = "INVALID"
    graph["graph_digest"] = _graph_digest(graph)
    return graph


def validate_cross_layer_graph(graph: dict[str, Any], *, effect_model: dict[str, Any] | None = None) -> list[str]:
    errors: list[str] = []
    if graph.get("schema_version") != SCHEMA_VERSION:
        if graph.get("schema_version") == "vulveil-cross-layer-graph/v2":
            errors.append("legacy v2 graph is incompatible with v3 call-scoped semantics; migrate explicitly")
        else:
            errors.append(f"schema_version must be {SCHEMA_VERSION}; legacy graph artifacts are not silently accepted")
    if graph.get("status") not in {"COMPLETE", "PARTIAL", "UNASSESSED", "INVALID"}:
        errors.append("invalid graph status")
    parity = graph.get("parity", {})
    for key in ("tool_input_digest", "host_profile_digest", "environment_digest"):
        if not isinstance(parity, dict) or not parity.get(key):
            errors.append(f"parity.{key} is required")
    if isinstance(parity, dict) and parity.get("valid") is False:
        errors.append("vulnerable/fixed parity contract failed")
    nodes = graph.get("nodes", [])
    edges = graph.get("edges", [])
    node_by_id = {item.get("node_id"): item for item in nodes if isinstance(item, dict)}
    node_ids = [item.get("node_id") for item in nodes if isinstance(item, dict)]
    edge_ids = [item.get("edge_id") for item in edges if isinstance(item, dict)]
    if len(node_ids) != len(set(node_ids)):
        errors.append("node IDs must be unique")
    if len(edge_ids) != len(set(edge_ids)):
        errors.append("edge IDs must be unique")
    node_set = set(node_ids)
    allowed_effects = {str(item.get("effect_id")) for item in (effect_model or {}).get("effects", []) if item.get("effect_id")}
    if effect_model is None:
        allowed_effects.update(str(item) for item in graph.get("effect_ids", []) if item)
    declared_effect_ids = [str(item) for item in graph.get("effect_ids", [])]
    if len(declared_effect_ids) != len(set(declared_effect_ids)):
        errors.append("graph effect IDs must be unique")
    if set(declared_effect_ids) != allowed_effects and effect_model is not None:
        errors.append("graph effect_ids do not match the effect model")
    relations = graph.get("effect_relations", [])
    if not isinstance(relations, list):
        errors.append("graph effect_relations must be a list")
        relations = []
    for relation in relations:
        if not isinstance(relation, dict):
            errors.append("graph effect relation must be an object")
            continue
        valid_target = relation.get("to") in allowed_effects or (
            relation.get("relation") == "PROPAGATES_TO"
            and relation.get("to") in {"TOOL_RESULT", "HOST", "SESSION", "AGENT_OBSERVATION"}
        )
        if relation.get("from") not in allowed_effects or not valid_target:
            errors.append("graph effect relation references unknown effect ID")
        if relation.get("relation") not in {"ENABLES", "CAUSES", "DERIVES", "DERIVES_VALUE", "BLOCKS", "PROPAGATES_TO", "ALIGNS_WITH", "PRODUCES"}:
            errors.append("graph effect relation has invalid relation kind")
        if not relation.get("evidence_refs"):
            errors.append("graph effect relation lacks evidence reference")
        if relation.get("provenance_status") not in {"SUPPORTED", "PARTIAL", "UNRESOLVED", "UNASSESSED"}:
            errors.append("graph effect relation lacks valid provenance_status")
    for node in nodes:
        if node.get("layer") not in LAYERS:
            errors.append(f"node {node.get('node_id')} has invalid layer")
        if node.get("kind") not in NODE_KINDS:
            errors.append(f"node {node.get('node_id')} has invalid kind")
        if node.get("effect_ids") and not set(node.get("effect_ids", [])).issubset(allowed_effects):
            errors.append(f"node {node.get('node_id')} references unknown effect ID")
    for edge in edges:
        if edge.get("source") not in node_set or edge.get("target") not in node_set:
            errors.append(f"edge {edge.get('edge_id')} references missing endpoint")
        if edge.get("kind") not in EDGE_KINDS:
            errors.append(f"edge {edge.get('edge_id')} has invalid kind")
        if edge.get("plane") not in EDGE_PLANES:
            errors.append(f"edge {edge.get('edge_id')} has invalid plane")
        if edge.get("status") not in EDGE_STATUSES:
            errors.append(f"edge {edge.get('edge_id')} has invalid propagation status")
        if not edge.get("evidence_refs"):
            errors.append(f"edge {edge.get('edge_id')} lacks evidence reference")
        if edge.get("effect_ids") and not set(edge.get("effect_ids", [])).issubset(allowed_effects):
            errors.append(f"edge {edge.get('edge_id')} references unknown effect ID")
        if edge.get("dynamic_provenance") and (not edge.get("side") or edge.get("repetition") is None or not edge.get("evidence_refs")):
            errors.append(f"dynamic edge {edge.get('edge_id')} lacks side/repetition/evidence")
        if edge.get("dynamic_provenance") and node_by_id.get(edge.get("source"), {}).get("kind") in {"json_rpc_field", "host_normalized_field", "session_event", "exact_l4_content_block"} and not edge.get("field_mapping", {}).get("call_key"):
            errors.append(f"dynamic protocol edge {edge.get('edge_id')} lacks call identity")
        source_layer = next((item.get("layer") for item in nodes if item.get("node_id") == edge.get("source")), None)
        target_layer = next((item.get("layer") for item in nodes if item.get("node_id") == edge.get("target")), None)
        if source_layer != target_layer and not edge.get("field_mapping") and not edge.get("unresolved_reason"):
            errors.append(f"cross-layer edge {edge.get('edge_id')} lacks field mapping or unresolved reason")
        if edge.get("dynamic_provenance") and edge.get("side") not in SIDES:
            errors.append(f"dynamic edge {edge.get('edge_id')} has invalid side")
        if edge.get("dynamic_provenance") and edge.get("effect_ids") and not edge.get("effect_value_linked") and edge.get("status") not in {"DROPPED", "UNASSESSED"}:
            errors.append(f"dynamic edge {edge.get('edge_id')} attributes an effect without value/provenance linkage")
        if edge.get("dynamic_provenance") and edge.get("effect_ids") and not set(edge.get("effect_ids", [])).issubset(set(edge.get("carrier_effect_ids", []))):
            errors.append(f"dynamic edge {edge.get('edge_id')} attributes an effect outside its carrier evidence")
        if edge.get("status") == "DROPPED" or edge.get("kind") in {"FILTER", "FILTERS"}:
            conversion = edge.get("transformation", {}).get("source_conversion", {}) if isinstance(edge.get("transformation"), dict) else {}
            if not isinstance(conversion, dict) or not any(conversion.get(key) for key in ("filtering", "filtered", "field_projection", "projection", "truncation", "redaction")):
                errors.append(f"edge {edge.get('edge_id')} marks a filter/drop without direct filtering evidence")
    observation_ids = set(graph.get("effect_observation", {}))
    if observation_ids != set(declared_effect_ids):
        errors.append("effect_observation keys must match graph effect IDs")
    path_status = graph.get("effect_path_status", {})
    if set(path_status) != set(declared_effect_ids):
        errors.append("effect_path_status keys must match graph effect IDs")
    serialized = json.dumps(graph, ensure_ascii=False)
    if _contains_forbidden_graph_content(serialized):
        errors.append("graph contains forbidden GT content")
    for node in nodes:
        if node.get("kind") == "exact_l4_content_block":
            paths = node.get("dynamic", {}).get("json_paths", []) if isinstance(node.get("dynamic"), dict) else []
            dynamic = node.get("dynamic", {}) if isinstance(node.get("dynamic"), dict) else {}
            if not node.get("model_request") or node.get("actual_next_model_request") is not True or node.get("tool_message_role") != "tool" or node.get("boundary_kind") != "EXACT_L4_CONTENT" or not dynamic.get("call_key") or not any(".content" in str(path) for path in paths):
                errors.append("L4 node is not attested as a real model request Tool message")
    for edge in edges:
        if edge.get("status") == "TRANSFORMED":
            transformation = edge.get("transformation", {})
            if not transformation.get("input_fingerprints") or not transformation.get("output_fingerprints"):
                errors.append(f"transformed edge {edge.get('edge_id')} lacks value fingerprints")
    if graph.get("status") == "COMPLETE" and graph.get("unresolved_boundaries"):
        errors.append("COMPLETE graph cannot contain unresolved boundaries")
    if graph.get("status") == "COMPLETE":
        paths = [item for item in graph.get("effect_path_status", {}).values() if isinstance(item, dict)]
        if not any(item.get("status") == "COMPLETE" for item in paths):
            errors.append("COMPLETE graph requires at least one continuous COMPLETE effect path")
        if any(item.get("status") not in {"COMPLETE", "NOT_REACHED", "DROPPED", "FILTERED"} for item in paths):
            errors.append("COMPLETE graph cannot contain unresolved effect paths")
    return sorted(set(errors))


def graph_summary(graph: dict[str, Any]) -> dict[str, Any]:
    layers = []
    for edge in graph.get("edges", []):
        for node_id in (edge.get("source"), edge.get("target")):
            node = next((item for item in graph.get("nodes", []) if item.get("node_id") == node_id), None)
            if node and node.get("layer") not in layers:
                layers.append(node["layer"])
    return {"graph_id": graph.get("graph_id"), "status": graph.get("status"), "layers": layers, "node_count": len(graph.get("nodes", [])), "edge_count": len(graph.get("edges", [])), "dynamic_edge_count": sum(bool(edge.get("dynamic_provenance")) for edge in graph.get("edges", [])), "unresolved_boundaries": graph.get("unresolved_boundaries", [])}


def _view_copy(value: Any) -> Any:
    """Copy JSON-compatible graph material without sharing mutable evidence."""
    return json.loads(json.dumps(value, ensure_ascii=False, default=str))


def _view_effect_scope(node: dict[str, Any], declared_effects: set[str], resource_effects: set[str]) -> list[str]:
    effect_ids = [str(item) for item in node.get("effect_ids", []) if str(item) in declared_effects]
    if node.get("kind") in {"resource_event", "resource_state", "readback_value"}:
        effect_ids = [item for item in effect_ids if item in resource_effects]
    return sorted(set(effect_ids))


def _view_dynamic_key(node: dict[str, Any]) -> tuple[str, int | None, str, str]:
    dynamic = node.get("dynamic") if isinstance(node.get("dynamic"), dict) else {}
    identity = node.get("invocation_identity") if isinstance(node.get("invocation_identity"), dict) else {}
    call_key = str(dynamic.get("call_key") or identity.get("tool_call_id") or identity.get("invocation_id") or "")
    repetition = dynamic.get("repetition")
    try:
        repetition = int(repetition) if repetition is not None else None
    except (TypeError, ValueError):
        repetition = None
    return (call_key, repetition, str(dynamic.get("trace_id") or identity.get("trace_id") or ""), str(dynamic.get("span_id") or identity.get("span_id") or ""))


def _view_node_matches(left: dict[str, Any], right: dict[str, Any], effect_id: str | None = None) -> bool:
    if left.get("side") not in {right.get("side"), "both"} and right.get("side") not in {left.get("side"), "both"}:
        return False
    if effect_id and effect_id not in set(left.get("effect_ids", [])) and effect_id not in set(left.get("source_effect_ids", [])):
        return False
    left_dynamic = left.get("dynamic") if isinstance(left.get("dynamic"), dict) else {}
    right_dynamic = right.get("dynamic") if isinstance(right.get("dynamic"), dict) else {}
    if left_dynamic.get("repetition") is not None and right_dynamic.get("repetition") is not None and int(left_dynamic["repetition"]) != int(right_dynamic["repetition"]):
        return False
    left_resource = left.get("resource_identity") or (left_dynamic.get("resource_identity") if isinstance(left_dynamic, dict) else None)
    right_resource = right.get("resource_identity") or (right_dynamic.get("resource_identity") if isinstance(right_dynamic, dict) else None)
    return left_resource is None or right_resource is None or left_resource == right_resource


def _view_resource_replacement(
    node: dict[str, Any],
    *,
    edge: dict[str, Any],
    effect_id: str | None,
    core_candidates: dict[str, list[dict[str, Any]]],
    is_source: bool,
) -> dict[str, Any] | None:
    """Map resource implementation nodes to their effect-centered boundary node."""
    kind = str(node.get("kind", ""))
    edge_kind = str(edge.get("kind", ""))
    if kind == "resource":
        replacement_kind = "resource_event"
        if not is_source and edge_kind in {"STATE_WRITE", "WRITES_RESOURCE"}:
            replacement_kind = "resource_state"
        candidates = [item for item in core_candidates.get(replacement_kind, []) if _view_node_matches(item, node, effect_id)]
        if replacement_kind == "resource_state":
            after = [item for item in candidates if item.get("state_position") == "after"]
            candidates = after or candidates
        if not candidates and replacement_kind == "resource_state":
            candidates = [item for item in core_candidates.get("resource_event", []) if _view_node_matches(item, node, effect_id)]
        return candidates[0] if len(candidates) == 1 else None
    if kind in {"call_site", "function", "return_value"} and edge_kind in {"STATE_WRITE", "WRITES_RESOURCE", "STATE_READ", "READS_RESOURCE"}:
        replacement_kind = "readback_value" if kind == "return_value" and edge_kind in {"STATE_READ", "READS_RESOURCE"} else "resource_event"
        candidates = [item for item in core_candidates.get(replacement_kind, []) if _view_node_matches(item, node, effect_id)]
        return candidates[0] if len(candidates) == 1 else None
    return None


def _view_boundary_kind(edge: dict[str, Any]) -> str:
    boundary = str(edge.get("boundary", ""))
    original_kind = str(edge.get("kind", ""))
    transformation = edge.get("transformation") if isinstance(edge.get("transformation"), dict) else {}
    if original_kind in {"FILTER", "FILTERS"} or edge.get("status") == "DROPPED" or any(
        transformation.get(key) for key in ("filtering", "filtered", "field_projection", "projection", "truncation", "redaction")
    ):
        return "FILTERS"
    # OBSERVE is the L3 -> exact-L4 boundary relation.  A value may be
    # transformed while crossing that boundary; the boundary must remain
    # visible as OBSERVE and retain status=TRANSFORMED.
    if original_kind in {"OBSERVE", "OBSERVES"} or boundary == "L3_SESSION_TOOL_RESULT->L4_MODEL_VISIBLE_OBSERVATION":
        return "OBSERVE"
    if original_kind in {"TRANSFORM", "TRANSFORMS"} or edge.get("status") == "TRANSFORMED":
        return "TRANSFORMS"
    return "PRESERVES"


def _view_edge_scope(edge: dict[str, Any], source: dict[str, Any], target: dict[str, Any], declared_effects: set[str]) -> list[str]:
    direct = {str(item) for item in edge.get("effect_ids", []) if str(item) in declared_effects}
    direct.update(str(item) for item in edge.get("carrier_effect_ids", []) if str(item) in declared_effects)
    if direct:
        return sorted(direct)
    source_effects = {str(item) for item in source.get("effect_ids", []) if str(item) in declared_effects}
    target_effects = {str(item) for item in target.get("effect_ids", []) if str(item) in declared_effects}
    return sorted(source_effects & target_effects)


def _view_edge_context(edge: dict[str, Any]) -> dict[str, Any]:
    """Expose dynamic attribution fields without inventing an invocation."""
    dynamic = edge.get("dynamic") if isinstance(edge.get("dynamic"), dict) else {}
    mapping = edge.get("field_mapping") if isinstance(edge.get("field_mapping"), dict) else {}
    identity = mapping.get("call_identity") if isinstance(mapping.get("call_identity"), dict) else {}

    def first(*names: str) -> Any:
        for name in names:
            for container in (edge, dynamic, mapping, identity):
                value = container.get(name) if isinstance(container, dict) else None
                if value not in (None, ""):
                    return value
        return None

    repetition = first("repetition")
    if repetition is not None:
        try:
            repetition = int(repetition)
        except (TypeError, ValueError):
            repetition = None
    return {
        "repetition": repetition,
        "tool_call_id": _string_or_none(first("tool_call_id")),
        "invocation_id": _string_or_none(first("invocation_id", "call_id")),
        "session_id": _string_or_none(first("session_id")),
        "trace_id": _string_or_none(first("trace_id")),
        "span_id": _string_or_none(first("span_id")),
        "boundary": _string_or_none(edge.get("boundary")),
    }


def _string_or_none(value: Any) -> str | None:
    return str(value) if value not in (None, "") else None


def _view_canonical_edge_kind(edge: dict[str, Any]) -> str:
    kind = str(edge.get("kind", ""))
    aliases = {"RETURN": "RETURNS", "FILTER": "FILTERS", "TRANSFORM": "TRANSFORMS"}
    return aliases.get(kind, kind)


def _view_effect_referenced(edge: dict[str, Any], effect_id: str) -> bool:
    return (
        edge.get("projection_effect_id") == effect_id
        or effect_id in edge.get("effect_ids", [])
        or effect_id in edge.get("carrier_effect_ids", [])
        or effect_id in edge.get("source_effect_ids", [])
        or effect_id in edge.get("source_carrier_effect_ids", [])
    )


def _view_effect_path_referenced(edge: dict[str, Any], effect_id: str) -> bool:
    """Use only projected attribution for path proofs, never source metadata."""
    return (
        edge.get("projection_effect_id") == effect_id
        or effect_id in (edge.get("effect_ids") or [])
        or effect_id in (edge.get("carrier_effect_ids") or [])
    )


def _simplified_path_issues(view: dict[str, Any], effect_id: str) -> list[str]:
    """Check that a projected complete path still has its causal boundaries."""
    nodes = {str(item.get("node_id")): item for item in view.get("nodes", []) if isinstance(item, dict)}
    edges = [item for item in view.get("edges", []) if isinstance(item, dict) and _view_effect_path_referenced(item, effect_id)]
    if not any(item.get("kind") == "vulnerability_anchor" for item in nodes.values() if effect_id in item.get("effect_ids", [])):
        return ["vulnerability anchor is absent from the effect-centered view"]
    effect_nodes = [item for item in nodes.values() if item.get("kind") == "effect_instance" and effect_id in item.get("effect_ids", [])]
    if not effect_nodes:
        return ["effect instance is absent from the effect-centered view"]
    if not any(item.get("kind") == "PRODUCES" and nodes.get(item.get("source"), {}).get("kind") == "vulnerability_anchor" and nodes.get(item.get("target"), {}).get("kind") == "effect_instance" for item in edges):
        return ["vulnerability anchor -> effect production edge is absent from the effect-centered view"]
    carrier_edges = [item for item in edges if item.get("kind") == "CARRIED_BY" and nodes.get(item.get("source"), {}).get("kind") == "effect_instance"]
    carriers = {item.get("target") for item in carrier_edges}
    if not carriers:
        return ["effect production -> carrier edge is absent from the effect-centered view"]
    result_nodes = {node_id for node_id, item in nodes.items() if item.get("kind") == "tool_result_field"}
    frontier = set(carriers)
    seen: set[str] = set()
    allowed = {
        "RETURNS", "SERIALIZE", "SERIALIZES", "DERIVES_VALUE", "ALIGNS_WITH",
        "STATE_WRITE", "STATE_READ", "WRITES_RESOURCE", "READS_RESOURCE",
        "PRESERVES", "TRANSFORMS",
    }
    while frontier:
        current = frontier.pop()
        if current in seen:
            continue
        seen.add(current)
        if current in result_nodes:
            break
        for edge in edges:
            if edge.get("source") == current and edge.get("kind") in allowed and edge.get("status") in {"PRESERVED", "TRANSFORMED"}:
                frontier.add(str(edge.get("target")))
    if not seen & result_nodes:
        return ["effect carrier -> Tool result edge is absent from the effect-centered view"]
    required_order = [
        "L0_RAW_MCP_RESULT->L1_NORMALIZED_TOOL_RESULT",
        "L1_NORMALIZED_TOOL_RESULT->L2_HOST_PROCESSED_TOOL_RESULT",
        "L2_HOST_PROCESSED_TOOL_RESULT->L3_SESSION_TOOL_RESULT",
        "L3_SESSION_TOOL_RESULT->L4_MODEL_VISIBLE_OBSERVATION",
    ]
    required = set(required_order)
    chains: dict[tuple[Any, str], dict[str, list[dict[str, Any]]]] = {}
    for edge in edges:
        boundary = edge.get("boundary")
        if boundary not in required or edge.get("side") != "vulnerable":
            continue
        dynamic = edge.get("dynamic") if isinstance(edge.get("dynamic"), dict) else {}
        call_key = str((edge.get("field_mapping") or {}).get("call_key") or dynamic.get("call_key") or "")
        repetition = edge.get("repetition")
        chains.setdefault((repetition, call_key), {}).setdefault(str(boundary), []).append(edge)
    complete_chain = False
    missing: set[str] = set()
    for chain, boundary_edges in chains.items():
        chain_missing = required - set(boundary_edges)
        if chain_missing:
            missing.update(chain_missing)
            continue

        def walk(index: int, previous_target: str | None) -> bool:
            if index == len(required_order):
                return True
            boundary = required_order[index]
            for candidate in boundary_edges.get(boundary, []):
                if previous_target is not None and candidate.get("source") != previous_target:
                    continue
                if candidate.get("status") not in {"PRESERVED", "TRANSFORMED"} or not candidate.get("effect_value_linked"):
                    continue
                if boundary == required_order[-1] and not (
                    candidate.get("kind") == "OBSERVE"
                    and candidate.get("exact_l4_observed")
                    and nodes.get(candidate.get("target"), {}).get("kind") == "exact_l4_content_block"
                ):
                    continue
                if walk(index + 1, str(candidate.get("target"))):
                    return True
            return False

        if walk(0, None):
            complete_chain = True
            break
        missing.update(required)
    if not complete_chain:
        return ["continuous effect path is broken"] + [f"missing or unresolved boundary: {item}" for item in sorted(missing or required)]
    return []


def validate_simplified_cross_layer_graph(view: dict[str, Any], *, source_graph: dict[str, Any] | None = None) -> list[str]:
    """Validate only the display projection; full graph validation remains authoritative."""
    errors: list[str] = []
    if view.get("schema_version") != VIEW_SCHEMA_VERSION:
        errors.append(f"schema_version must be {VIEW_SCHEMA_VERSION}")
    if view.get("view") != "effect-centered":
        errors.append("view must be effect-centered")
    declared = {str(item) for item in view.get("effect_ids", [])}
    node_ids = [item.get("node_id") for item in view.get("nodes", []) if isinstance(item, dict)]
    edge_ids = [item.get("edge_id") for item in view.get("edges", []) if isinstance(item, dict)]
    if len(node_ids) != len(set(node_ids)):
        errors.append("simplified view node IDs must be unique")
    if len(edge_ids) != len(set(edge_ids)):
        errors.append("simplified view edge IDs must be unique")
    node_by_id = {item.get("node_id"): item for item in view.get("nodes", []) if isinstance(item, dict)}
    resource_effects = {
        str(effect_id)
        for effect_node in view.get("nodes", [])
        if effect_node.get("kind") == "effect_instance" and effect_node.get("effect_kind") == "RESOURCE_EFFECT"
        for effect_id in effect_node.get("effect_ids", [])
    }
    for node in view.get("nodes", []):
        if node.get("kind") not in SIMPLIFIED_NODE_KINDS:
            errors.append(f"non-core node {node.get('node_id')} leaked into simplified nodes")
        if node.get("effect_ids") and not set(node.get("effect_ids", [])).issubset(declared):
            errors.append(f"simplified node {node.get('node_id')} references unknown effect")
        if node.get("kind") in {"resource_event", "resource_state", "readback_value"} and not set(node.get("effect_ids", [])).issubset(resource_effects):
            errors.append(f"resource node {node.get('node_id')} is not attributed to a Resource effect")
    for edge in view.get("edges", []):
        if edge.get("source") not in node_by_id or edge.get("target") not in node_by_id:
            errors.append(f"simplified edge {edge.get('edge_id')} references missing endpoint")
        if edge.get("kind") not in SIMPLIFIED_EDGE_KINDS:
            errors.append(f"non-core edge {edge.get('edge_id')} leaked into simplified edges")
        for key in _VIEW_EDGE_REQUIRED_FIELDS:
            if key not in edge:
                errors.append(f"simplified edge {edge.get('edge_id')} lacks {key}")
        if edge.get("kind") == "OBSERVE" and edge.get("boundary") == "L3_SESSION_TOOL_RESULT->L4_MODEL_VISIBLE_OBSERVATION" and (edge.get("projection_effect_id") or edge.get("effect_ids") or edge.get("carrier_effect_ids")) and not edge.get("exact_l4_observed"):
            errors.append(f"simplified L4 edge {edge.get('edge_id')} is not observed")
    if source_graph is not None:
        if view.get("effect_path_status") != source_graph.get("effect_path_status"):
            errors.append("effect_path_status changed by graph projection")
        if view.get("graph_validation") != source_graph.get("graph_validation"):
            errors.append("graph_validation changed by graph projection")
        for effect_id, path in source_graph.get("effect_path_status", {}).items():
            if isinstance(path, dict) and path.get("status") == "COMPLETE":
                errors.extend(f"{effect_id}: {reason}" for reason in _simplified_path_issues(view, str(effect_id)))
    serialized = json.dumps(view, ensure_ascii=False)
    if _contains_forbidden_graph_content(serialized):
        errors.append("simplified graph contains forbidden GT content")
    return sorted(set(errors))


def build_simplified_cross_layer_graph(graph: dict[str, Any]) -> dict[str, Any]:
    """Project a validated full graph into an effect-centered display view.

    This function is intentionally a one-way presentation projection. It never
    recomputes Stage 4, path status, prediction, or effect attribution.
    """
    source_nodes = [item for item in graph.get("nodes", []) if isinstance(item, dict)]
    source_edges = [item for item in graph.get("edges", []) if isinstance(item, dict)]
    declared_effects = {str(item) for item in graph.get("effect_ids", [])}
    effect_kinds = {
        str(effect_id): str(node.get("effect_kind"))
        for node in source_nodes
        if node.get("kind") == "effect_instance"
        for effect_id in node.get("effect_ids", [])
    }
    resource_effects = {effect_id for effect_id, kind in effect_kinds.items() if kind == "RESOURCE_EFFECT"}
    core_candidates: dict[str, list[dict[str, Any]]] = {kind: [] for kind in SIMPLIFIED_NODE_KINDS}
    view_nodes: list[dict[str, Any]] = []
    source_to_view: dict[str, list[dict[str, Any]]] = {}
    for source in source_nodes:
        kind = str(source.get("kind", ""))
        if kind not in SIMPLIFIED_NODE_KINDS:
            continue
        scopes = _view_effect_scope(source, declared_effects, resource_effects)
        if kind in {"resource_event", "resource_state", "readback_value"} and not scopes:
            continue
        if scopes and kind not in {"tool_call", "tool_handler", "agent_task"}:
            projected_scopes: list[str | None] = list(scopes)
        else:
            projected_scopes = [None]
        for effect_id in projected_scopes:
            projected = _view_copy(source)
            projected["node_id"] = _stable_id("view", graph.get("graph_id", ""), source.get("node_id"), effect_id or "shared")
            projected["source_node_id"] = source.get("node_id")
            if effect_id:
                projected["source_effect_ids"] = list(source.get("effect_ids", []))
                projected["effect_ids"] = [effect_id]
                projected["projection_effect_id"] = effect_id
                if isinstance(projected.get("carrier_effect_ids"), list):
                    projected["carrier_effect_ids"] = [item for item in projected["carrier_effect_ids"] if item == effect_id]
            view_nodes.append(projected)
            source_to_view.setdefault(str(source.get("node_id")), []).append(projected)
            core_candidates.setdefault(kind, []).append(projected)

    def candidates_for(source_id: str, effect_id: str | None) -> list[dict[str, Any]]:
        candidates = source_to_view.get(str(source_id), [])
        if effect_id:
            scoped = [item for item in candidates if item.get("projection_effect_id") == effect_id]
            if scoped:
                return scoped
        unscoped = [item for item in candidates if not item.get("projection_effect_id")]
        return unscoped or candidates

    def endpoint(source_id: str, *, effect_id: str | None, edge: dict[str, Any], is_source: bool) -> dict[str, Any] | None:
        original = next((item for item in source_nodes if str(item.get("node_id")) == str(source_id)), None)
        if original is None:
            return None
        candidates = candidates_for(source_id, effect_id)
        if len(candidates) == 1:
            return candidates[0]
        if len(candidates) > 1:
            return None
        replacement = _view_resource_replacement(original, edge=edge, effect_id=effect_id, core_candidates=core_candidates, is_source=is_source)
        if replacement is not None:
            return replacement
        if str(edge.get("kind")) in {"SERIALIZE", "SERIALIZES", "RETURN", "RETURNS"} and is_source:
            handlers = [item for item in core_candidates.get("tool_handler", []) if _view_node_matches(item, original, effect_id)]
            if len(handlers) == 1:
                return handlers[0]
        if str(edge.get("kind")) == "ALIGNS_WITH" and is_source:
            handlers = [item for item in core_candidates.get("tool_handler", []) if _view_node_matches(item, original, effect_id)]
            if len(handlers) == 1:
                return handlers[0]
        return None

    view_edges: list[dict[str, Any]] = []
    collapsed_edges: list[dict[str, Any]] = []
    for source_edge in source_edges:
        boundary = str(source_edge.get("boundary", ""))
        original_kind = str(source_edge.get("kind", ""))
        keep = original_kind in SIMPLIFIED_EDGE_KINDS or original_kind in {"RETURN", "FILTER", "TRANSFORM"} or boundary in _DISPLAY_BOUNDARIES
        if not keep:
            collapsed = _view_copy(source_edge)
            collapsed["collapsed_reason"] = "static_or_non-effect transport edge"
            collapsed_edges.append(collapsed)
            continue
        source_node = next((item for item in source_nodes if str(item.get("node_id")) == str(source_edge.get("source"))), {})
        target_node = next((item for item in source_nodes if str(item.get("node_id")) == str(source_edge.get("target"))), {})
        scopes = _view_edge_scope(source_edge, source_node, target_node, declared_effects)
        projected_scopes: list[str | None] = scopes or [None]
        projected_any = False
        for effect_id in projected_scopes:
            source_view = endpoint(str(source_edge.get("source")), effect_id=effect_id, edge=source_edge, is_source=True)
            target_view = endpoint(str(source_edge.get("target")), effect_id=effect_id, edge=source_edge, is_source=False)
            if source_view is None or target_view is None:
                continue
            projected = _view_copy(source_edge)
            projected["edge_id"] = _edge_id("view", graph.get("graph_id", ""), source_edge.get("edge_id"), effect_id or "shared", source_view.get("node_id"), target_view.get("node_id"))
            projected["source"] = source_view.get("node_id")
            projected["target"] = target_view.get("node_id")
            projected["source_edge_id"] = source_edge.get("edge_id")
            projected["source_effect_ids"] = list(source_edge.get("effect_ids", []))
            projected["source_carrier_effect_ids"] = list(source_edge.get("carrier_effect_ids", []))
            if effect_id:
                projected["projection_effect_id"] = effect_id
                projected["effect_ids"] = [item for item in source_edge.get("effect_ids", []) if str(item) == effect_id]
                projected["carrier_effect_ids"] = [item for item in source_edge.get("carrier_effect_ids", []) if str(item) == effect_id]
                projected.setdefault("field_mapping", {})["projection_effect_id"] = effect_id
            if boundary in _DISPLAY_BOUNDARIES:
                projected["kind"] = _view_boundary_kind(source_edge)
            else:
                projected["kind"] = _view_canonical_edge_kind(source_edge)
            projected.setdefault("effect_ids", [])
            projected.setdefault("carrier_effect_ids", [])
            projected.setdefault("plane", "EFFECT" if effect_id else source_edge.get("plane", "EXECUTION"))
            projected.setdefault("status", source_edge.get("status", "UNASSESSED"))
            projected.setdefault("effect_value_linked", bool(source_edge.get("effect_value_linked")))
            projected.setdefault("transport_observed", bool(source_edge.get("transport_observed")))
            projected.setdefault("effect_carrier_observed", bool(source_edge.get("effect_carrier_observed")))
            projected.setdefault("exact_l4_observed", bool(source_edge.get("exact_l4_observed")))
            projected.setdefault("evidence_refs", list(source_edge.get("evidence_refs", [])))
            projected.update(_view_edge_context(source_edge))
            projected["source_edge"] = _view_copy(source_edge)
            view_edges.append(projected)
            projected_any = True
        if not projected_any:
            collapsed = _view_copy(source_edge)
            collapsed["collapsed_reason"] = "endpoint is represented as collapsed metadata or has ambiguous effect scope"
            collapsed_edges.append(collapsed)

    view_node_ids = {str(item.get("node_id")) for item in view_nodes}
    collapsed_nodes: list[dict[str, Any]] = []
    for source in source_nodes:
        if source.get("kind") in SIMPLIFIED_NODE_KINDS:
            continue
        collapsed = _view_copy(source)
        scopes = _view_effect_scope(source, declared_effects, resource_effects)
        targets: list[str] = []
        for candidate in view_nodes:
            if source.get("side") not in {candidate.get("side"), "both"} and candidate.get("side") not in {source.get("side"), "both"}:
                continue
            if scopes and not set(scopes) & (set(candidate.get("effect_ids", [])) | ({candidate.get("projection_effect_id")} if candidate.get("projection_effect_id") else set())):
                continue
            if source.get("kind") == "model_request_message" and candidate.get("kind") != "exact_l4_content_block":
                continue
            if source.get("kind") == "resource" and candidate.get("kind") != "resource_event":
                continue
            targets.append(str(candidate.get("node_id")))
        collapsed["collapsed_into"] = sorted(set(targets))
        collapsed["collapsed_reason"] = "display projection retains source/path/evidence metadata outside the core view"
        collapsed_nodes.append(collapsed)

    source_status = graph.get("status", "UNASSESSED")
    view = {
        "schema_version": VIEW_SCHEMA_VERSION,
        "view": "effect-centered",
        "source_graph_id": graph.get("graph_id"),
        "source_graph_digest": graph.get("graph_digest"),
        "effect_ids": sorted(declared_effects),
        "component_origin": graph.get("component_origin"),
        "vulnerability_component": _view_copy(graph.get("vulnerability_component", {})),
        "nodes": sorted(view_nodes, key=lambda item: str(item.get("node_id"))),
        "edges": sorted(view_edges, key=lambda item: str(item.get("edge_id"))),
        "collapsed_nodes": sorted(collapsed_nodes, key=lambda item: str(item.get("node_id"))),
        "collapsed_edges": sorted(collapsed_edges, key=lambda item: str(item.get("edge_id"))),
        "effect_relations": _view_copy(graph.get("effect_relations", [])),
        "effect_observation": _view_copy(graph.get("effect_observation", {})),
        "stage4_effect_observation": _view_copy(graph.get("stage4_effect_observation", {})),
        "effect_path_status": _view_copy(graph.get("effect_path_status", {})),
        "unresolved_boundaries": _view_copy(graph.get("unresolved_boundaries", [])),
        "graph_validation": _view_copy(graph.get("graph_validation", {})),
        "status": source_status,
        "projection_metadata": {
            "full_graph_unchanged": True,
            "prediction_inputs_unchanged": True,
            "collapsed_node_kinds": sorted({str(item.get("kind")) for item in collapsed_nodes}),
            "collapsed_edge_kinds": sorted({str(item.get("kind")) for item in collapsed_edges}),
            "resource_effect_ids": sorted(resource_effects),
        },
    }
    projection_errors = validate_simplified_cross_layer_graph(view, source_graph=graph)
    if source_status == "COMPLETE" and projection_errors:
        view["status"] = "PARTIAL"
        view["unresolved_boundaries"] = sorted(set(view["unresolved_boundaries"]) | {"effect-centered projection cannot prove the full source COMPLETE path"})
    view["projection_validation"] = {"status": "OK" if not projection_errors else "ERROR", "errors": projection_errors}
    return view


build_graph = build_cross_layer_graph
validate_graph = validate_cross_layer_graph

__all__ = ["SCHEMA_VERSION", "VIEW_SCHEMA_VERSION", "build_cross_layer_graph", "build_simplified_cross_layer_graph", "build_graph", "validate_cross_layer_graph", "validate_simplified_cross_layer_graph", "validate_graph", "graph_summary"]
