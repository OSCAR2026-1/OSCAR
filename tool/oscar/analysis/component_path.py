"""Structured, label-free Tool-to-component path proofs for Stage 0.

The proof is deliberately stricter than a package-name search.  Python paths
are resolved from AST imports/functions/calls.  JavaScript and TypeScript use
the repository's balanced-token resolver from ``tool_discovery``.  A path is
usable only when its Tool handler, structured call chain, component call and
patch anchor are all present.
"""

from __future__ import annotations

import ast
import re
from collections import deque
from pathlib import Path
from typing import Any

try:
    from oscar.analysis.effect_modeling import _js_tokens
    from oscar.analysis.tool_discovery import _js_function_ranges, discover_javascript_tool_paths
except ImportError:  # pragma: no cover
    from oscar.analysis.effect_modeling import _js_tokens
    from oscar.analysis.tool_discovery import _js_function_ranges, discover_javascript_tool_paths


PYTHON_EXTENSIONS = {".py"}
JS_EXTENSIONS = {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"}
EXCLUDED_PARTS = {".git", ".venv", "venv", "node_modules", "dist", "build", "coverage", "test", "tests", "__tests__"}


def _norm_module(value: str) -> str:
    return value.lower().replace("-", "_").strip()


def _component_names(name: str) -> set[str]:
    normalized = _norm_module(name)
    values = {normalized, normalized.split("/")[-1]}
    if normalized.startswith("@") and "/" in normalized:
        values.add(normalized.split("/", 1)[1])
    return {value for value in values if value}


def _callee(node: ast.Call) -> str:
    parts: list[str] = []
    value: ast.AST = node.func
    while isinstance(value, ast.Attribute):
        parts.append(value.attr)
        value = value.value
    if isinstance(value, ast.Name):
        parts.append(value.id)
    return ".".join(reversed(parts))


def _module_file(root: Path, source_file: Path, module: str, level: int = 0) -> Path | None:
    if level:
        base = source_file.parent
        for _ in range(max(0, level - 1)):
            base = base.parent
        candidate = base / (module.replace(".", "/") if module else "")
    else:
        candidate = root / module.replace(".", "/")
    choices = [candidate.with_suffix(".py"), candidate / "__init__.py"]
    if candidate.suffix == ".py":
        choices.insert(0, candidate)
    for choice in choices:
        if choice.is_file() and choice.resolve().is_relative_to(root.resolve()):
            return choice.resolve()
    return None


def _patch_changed_lines(patch: str | None) -> dict[str, set[int]]:
    changed: dict[str, set[int]] = {}
    current: str | None = None
    new_line = 0
    old_line = 0
    for line in str(patch or "").splitlines():
        if line.startswith("--- "):
            continue
        if line.startswith("+++ "):
            current = line[4:].strip().removeprefix("b/")
            if current == "/dev/null":
                current = None
            continue
        if line.startswith("@@"):
            match = re.search(r"-(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))?", line)
            if match:
                old_line = int(match.group(1))
                new_line = int(match.group(3))
            continue
        if current is None:
            continue
        if line.startswith("+") and not line.startswith("+++"):
            changed.setdefault(current, set()).add(new_line)
            new_line += 1
        elif line.startswith("-") and not line.startswith("---"):
            changed.setdefault(current, set()).add(old_line)
            old_line += 1
        elif line.startswith(" "):
            old_line += 1
            new_line += 1
    return changed


def _python_anchor_index(root: Path, patch: str | None) -> dict[str, list[str]]:
    changed = _patch_changed_lines(patch)
    anchors: dict[str, list[str]] = {}
    for relative, lines in changed.items():
        path = (root / relative).resolve()
        if not path.is_file() or path.suffix.lower() not in PYTHON_EXTENSIONS:
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"), filename=str(path))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            start = int(getattr(node, "lineno", 0))
            end = int(getattr(node, "end_lineno", start))
            if any(start <= line <= end for line in lines):
                anchors.setdefault(node.name, []).append(f"{relative}:{start}")
    return anchors


def _js_anchor_index(root: Path, patch: str | None) -> dict[str, list[str]]:
    changed = _patch_changed_lines(patch)
    anchors: dict[str, list[str]] = {}
    for relative, lines in changed.items():
        path = (root / relative).resolve()
        if not path.is_file() or path.suffix.lower() not in JS_EXTENSIONS:
            continue
        tokens = _js_tokens(path.read_text(encoding="utf-8", errors="replace"))
        try:
            functions = _js_function_ranges(tokens, [])
        except (TypeError, ValueError):
            functions = []
        for item in functions:
            start = int(item.get("line", 0))
            end = max(start, max((tokens[index]["line"] for index in range(item.get("start", 0), min(item.get("end", 0), len(tokens)))), default=start))
            if any(start <= line <= end for line in lines):
                name = str(item.get("name", "" )).split(".")[-1]
                if name:
                    anchors.setdefault(name, []).append(f"{relative}:{start}")
    return anchors


def _python_path_proof(
    source_root: Path,
    entrypoint: str | None,
    explicit_tool: str | None,
    component_name: str,
    origin: str,
    patch: str | None,
    analysis_root: Path,
    analysis_patch: str | None,
) -> dict[str, Any]:
    root = source_root.resolve()
    component_modules = _component_names(component_name)
    files = sorted(path for path in root.rglob("*.py") if not any(part in EXCLUDED_PARTS for part in path.parts))
    modules: dict[str, dict[str, Any]] = {}
    parse_errors: list[str] = []
    for path in files:
        relative = path.relative_to(root).as_posix()
        try:
            tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"), filename=str(path))
        except SyntaxError as exc:
            parse_errors.append(f"{relative}:{exc.lineno}")
            continue
        external: dict[str, str] = {}
        local: dict[str, tuple[str, str]] = {}
        for statement in tree.body:
            if isinstance(statement, ast.Import):
                for item in statement.names:
                    module_root = _norm_module(item.name.split(".")[0])
                    alias = item.asname or item.name.split(".")[0]
                    if module_root in component_modules:
                        external[alias] = _norm_module(item.name)
                    else:
                        target = _module_file(root, path, item.name)
                        if target:
                            local[alias] = (target.relative_to(root).as_posix(), "__module__")
            elif isinstance(statement, ast.ImportFrom):
                module_root = _norm_module((statement.module or "").split(".")[0])
                if module_root in component_modules:
                    for item in statement.names:
                        if item.name != "*":
                            external[item.asname or item.name] = f"{_norm_module(statement.module or '')}.{item.name}"
                else:
                    target = _module_file(root, path, statement.module or "", statement.level)
                    if target:
                        target_relative = target.relative_to(root).as_posix()
                        for item in statement.names:
                            if item.name != "*":
                                local[item.asname or item.name] = (target_relative, item.name)
        functions: dict[str, dict[str, Any]] = {}
        all_function_names = [node.name for node in ast.walk(tree)
                              if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))]
        function_names = set(all_function_names)
        duplicate_names: set[str] = {name for name in all_function_names if all_function_names.count(name) > 1}
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            name = node.name
            if name in functions:
                duplicate_names.add(name)
                continue
            functions[name] = {
                "name": name,
                "line": int(getattr(node, "lineno", 0)),
                "end_line": int(getattr(node, "end_lineno", getattr(node, "lineno", 0))),
                "node": node,
                "calls": [],
                "external_calls": [],
            }
            for call in ast.walk(node):
                if not isinstance(call, ast.Call):
                    continue
                callee = _callee(call)
                if not callee:
                    continue
                root_name = callee.split(".", 1)[0]
                if root_name in external:
                    if root_name in function_names or root_name in duplicate_names:
                        continue
                    api = f"{external[root_name]}.{callee.split('.', 1)[1]}" if "." in callee else external[root_name]
                    functions[name]["external_calls"].append({"api": api, "line": int(getattr(call, "lineno", functions[name]["line"]))})
                elif root_name in local:
                    target_module, imported = local[root_name]
                    if "." in callee and imported == "__module__":
                        target_name = callee.split(".", 1)[1]
                    elif imported != "__module__":
                        target_name = imported
                    else:
                        target_name = root_name
                    functions[name]["calls"].append({"module": target_module, "function": target_name, "line": int(getattr(call, "lineno", functions[name]["line"]))})
                elif "." not in callee and root_name in functions and root_name not in duplicate_names:
                    functions[name]["calls"].append({"module": relative, "function": root_name, "line": int(getattr(call, "lineno", functions[name]["line"]))})
        registrations: list[dict[str, Any]] = []
        for details in functions.values():
            node = details["node"]
            for decorator in getattr(node, "decorator_list", []):
                target = decorator.func if isinstance(decorator, ast.Call) else decorator
                if isinstance(target, ast.Attribute) and target.attr == "tool":
                    tool = node.name
                    if isinstance(decorator, ast.Call):
                        for keyword in decorator.keywords:
                            if keyword.arg == "name" and isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str):
                                tool = keyword.value.value
                        if decorator.args and isinstance(decorator.args[0], ast.Constant) and isinstance(decorator.args[0].value, str):
                            tool = decorator.args[0].value
                    registrations.append({"tool": tool, "handler": node.name, "source_ref": f"{relative}:{details['line']}", "module": relative})
        for call in (node for node in ast.walk(tree) if isinstance(node, ast.Call)):
            if not isinstance(call.func, ast.Attribute) or call.func.attr not in {"add_tool", "tool"}:
                continue
            args = call.args
            handler = next((item.id for item in args if isinstance(item, ast.Name) and item.id in functions), None)
            if not handler:
                continue
            tool = handler
            if args and isinstance(args[0], ast.Constant) and isinstance(args[0].value, str):
                tool = args[0].value
            registrations.append({"tool": tool, "handler": handler, "source_ref": f"{relative}:{call.lineno}", "module": relative})
        modules[relative] = {"functions": functions, "registrations": registrations, "duplicates": duplicate_names}

    anchors = _python_anchor_index(analysis_root.resolve(), analysis_patch if origin == "MCP_FRAMEWORK" else patch)
    anchor_names = set(anchors)
    tools: list[dict[str, Any]] = []
    graph_nodes: list[dict[str, Any]] = []
    graph_edges: list[dict[str, Any]] = []
    for registration in modules.get(_find_relative(root, entrypoint), {}).get("registrations", []):
        if explicit_tool and registration["tool"] != explicit_tool:
            continue
        start = (registration["module"], registration["handler"])
        queue: deque[tuple[str, str, list[str], list[str]]] = deque([(start[0], start[1], [registration["handler"]], [])])
        seen: set[tuple[str, str]] = set()
        paths: list[dict[str, Any]] = []
        while queue:
            module, function, chain, refs = queue.popleft()
            key = (module, function)
            if key in seen:
                continue
            seen.add(key)
            details = modules.get(module, {}).get("functions", {}).get(function)
            if not details:
                continue
            node_id = f"python:{module}:{function}"
            graph_nodes.append({"node_id": node_id, "kind": "function", "module": module, "symbol": function, "source_ref": f"{module}:{details['line']}"})
            for call in details["calls"]:
                target_key = (call["module"], call["function"])
                if target_key in seen:
                    continue
                graph_edges.append({"from": node_id, "to": f"python:{target_key[0]}:{target_key[1]}", "kind": "CALL", "source_ref": f"{module}:{call['line']}"})
                queue.append((target_key[0], target_key[1], [*chain, target_key[1]], [*refs, f"{module}:{call['line']}"]))
            for external in details["external_calls"]:
                api_name = external["api"].split(".")[-1]
                matched = [ref for name, refs_for_name in anchors.items() if name == api_name for ref in refs_for_name]
                if origin == "MCP_SERVER_SELF":
                    matched = [ref for name, refs_for_name in anchors.items() if name == function for ref in refs_for_name] or matched
                path = {"call_chain": [*chain, external["api"]], "component_call": external["api"], "source_refs": [f"{module}:{external['line']}", *refs], "anchor_refs": sorted(set(matched))}
                paths.append(path)
            if origin == "MCP_SERVER_SELF" and function in anchor_names:
                paths.append({"call_chain": chain, "component_call": f"server:{function}", "source_refs": [f"{module}:{details['line']}", *refs], "anchor_refs": sorted(anchors.get(function, []))})
        tool_node = f"python:tool:{registration['tool']}"
        handler_node = f"python:{registration['module']}:{registration['handler']}"
        graph_nodes.append({"node_id": tool_node, "kind": "tool_registration", "tool": registration["tool"], "source_ref": registration["source_ref"]})
        graph_edges.append({"from": tool_node, "to": handler_node, "kind": "REGISTER", "tool": registration["tool"], "source_ref": registration["source_ref"]})
        for path in paths:
            if not path.get("anchor_refs"):
                continue
            component_node = f"python:component:{path['component_call']}"
            graph_nodes.append({"node_id": component_node, "kind": "component_api", "symbol": path["component_call"], "component_name": component_name, "source_refs": path["source_refs"]})
            graph_edges.append({"from": handler_node, "to": component_node, "kind": "COMPONENT_CALL", "tool": registration["tool"], "source_refs": path["source_refs"]})
            for anchor_ref in path["anchor_refs"]:
                anchor_node = f"python:anchor:{anchor_ref}"
                graph_nodes.append({"node_id": anchor_node, "kind": "patch_anchor", "anchor_ref": anchor_ref, "component_name": component_name})
                graph_edges.append({"from": component_node, "to": anchor_node, "kind": "PATCH_ANCHOR", "tool": registration["tool"], "anchor_ref": anchor_ref, "source_refs": path["source_refs"]})
        usable = [item for item in paths if item.get("anchor_refs")]
        tools.append({**registration, "component_paths": paths, "dependency_paths": paths, "reaches_component": bool(usable), "reaches_direct_dependency": False})
    selected = [item for item in tools if not explicit_tool or item.get("tool") == explicit_tool]
    resolved = len(selected) == 1 and bool(selected[0].get("reaches_component"))
    status = "RESOLVED" if resolved else ("PARTIAL" if tools else "UNRESOLVED")
    reason = None if resolved else ("Tool path reaches no patch-mapped component anchor" if tools else "no structured Tool registration was found")
    return {"schema_version": "vulveil-tool-discovery/v2", "status": status, "language": "python", "component_origin": origin,
            "component_name": component_name, "tools": tools, "graph": {"nodes": graph_nodes, "edges": graph_edges},
            "anchor_candidates": [{"name": name, "refs": refs} for name, refs in sorted(anchors.items())],
            "parse_errors": parse_errors, "reason": reason}


def _find_relative(root: Path, entrypoint: str | None) -> str:
    if entrypoint:
        candidate = Path(entrypoint)
        if candidate.is_absolute() and candidate.is_relative_to(root):
            return candidate.relative_to(root).as_posix()
        return candidate.as_posix().lstrip("./")
    candidates = sorted(path.relative_to(root).as_posix() for path in root.rglob("*.py") if path.is_file())
    return candidates[0] if candidates else ""


def _javascript_path_proof(source_root: Path, entrypoint: str | None, explicit_tool: str | None,
                           component_name: str, origin: str, patch: str | None,
                           analysis_root: Path, analysis_patch: str | None) -> dict[str, Any]:
    discovery = discover_javascript_tool_paths(source_root.resolve(), component_name)
    anchors = _js_anchor_index(analysis_root.resolve(), analysis_patch if origin == "MCP_FRAMEWORK" else patch)
    tools: list[dict[str, Any]] = []
    graph_nodes: list[dict[str, Any]] = []
    graph_edges: list[dict[str, Any]] = []
    for item in discovery.get("tools", []):
        paths = []
        for path in item.get("dependency_paths", []):
            api = str(path.get("dependency_call", ""))
            name = api.split(".")[-1]
            refs = [ref for anchor, values in anchors.items() if anchor == name for ref in values]
            paths.append({"call_chain": path.get("call_chain", []), "component_call": api,
                          "source_refs": path.get("source_refs", []), "anchor_refs": refs})
        usable = [path for path in paths if path.get("anchor_refs")]
        tool_node = f"javascript:tool:{item.get('tool')}"
        handler_node = f"javascript:handler:{item.get('handler')}"
        graph_nodes.extend([
            {"node_id": tool_node, "kind": "tool_registration", "tool": item.get("tool"), "source_ref": item.get("source_ref")},
            {"node_id": handler_node, "kind": "function", "symbol": item.get("handler"), "source_ref": item.get("source_ref")},
        ])
        graph_edges.append({"from": tool_node, "to": handler_node, "kind": "REGISTER", "tool": item.get("tool"), "source_ref": item.get("source_ref")})
        for path in usable:
            component_node = f"javascript:component:{path['component_call']}"
            graph_nodes.append({"node_id": component_node, "kind": "component_api", "symbol": path["component_call"], "component_name": component_name, "source_refs": path["source_refs"]})
            graph_edges.append({"from": handler_node, "to": component_node, "kind": "COMPONENT_CALL", "tool": item.get("tool"), "source_refs": path["source_refs"]})
            for anchor_ref in path["anchor_refs"]:
                anchor_node = f"javascript:anchor:{anchor_ref}"
                graph_nodes.append({"node_id": anchor_node, "kind": "patch_anchor", "anchor_ref": anchor_ref, "component_name": component_name})
                graph_edges.append({"from": component_node, "to": anchor_node, "kind": "PATCH_ANCHOR", "tool": item.get("tool"), "anchor_ref": anchor_ref, "source_refs": path["source_refs"]})
        tools.append({**item, "component_paths": paths, "reaches_component": bool(usable), "reaches_direct_dependency": bool(usable)})
    selected = [item for item in tools if not explicit_tool or item.get("tool") == explicit_tool]
    resolved = len(selected) == 1 and selected[0].get("reaches_component") is True
    return {"schema_version": "vulveil-tool-discovery/v2", "status": "RESOLVED" if resolved else ("PARTIAL" if tools else "UNRESOLVED"),
            "language": "javascript-typescript", "component_origin": origin, "component_name": component_name,
            "tools": tools, "graph": {"nodes": graph_nodes, "edges": graph_edges},
            "anchor_candidates": [{"name": name, "refs": refs} for name, refs in sorted(anchors.items())],
            "parse_errors": discovery.get("parse_errors", []),
            "reason": None if resolved else "Tool path is missing or does not map to a patch anchor"}


def discover_component_tool_paths(source_root: Path, entrypoint: str | None, explicit_tool: str | None,
                                  component_name: str, origin: str, patch: str | None = None,
                                  analysis_root: Path | None = None, analysis_patch: str | None = None) -> dict[str, Any]:
    """Build a structured Tool-to-component-to-anchor proof."""
    root = source_root.resolve()
    target_root = (analysis_root or root).resolve()
    suffix = Path(entrypoint or "").suffix.lower()
    if suffix in PYTHON_EXTENSIONS or (not suffix and any(root.rglob("*.py"))):
        return _python_path_proof(root, entrypoint, explicit_tool, component_name, origin, patch, target_root, analysis_patch)
    if suffix in JS_EXTENSIONS or (not suffix and any(root.rglob("*.js"))):
        return _javascript_path_proof(root, entrypoint, explicit_tool, component_name, origin, patch, target_root, analysis_patch)
    return {"schema_version": "vulveil-tool-discovery/v2", "status": "UNRESOLVED", "language": "unsupported",
            "component_origin": origin, "component_name": component_name, "tools": [], "graph": {"nodes": [], "edges": []},
            "anchor_candidates": [], "parse_errors": [], "reason": "unsupported source language"}


def validate_component_tool_path(discovery: Any, *, component_name: str, tool_name: str | None = None) -> list[str]:
    """Revalidate caller-provided discovery before readiness accepts it."""
    errors: list[str] = []
    if not isinstance(discovery, dict) or discovery.get("schema_version") != "vulveil-tool-discovery/v2":
        return ["structured component Tool path schema is missing"]
    if discovery.get("component_name") != component_name:
        errors.append("Tool path component identity does not match the case component")
    tools = discovery.get("tools")
    if not isinstance(tools, list):
        return ["structured component Tool path tools are missing"]
    selected = [item for item in tools if isinstance(item, dict) and (not tool_name or item.get("tool") == tool_name)]
    if len(selected) != 1:
        errors.append("Tool path must identify exactly one selected Tool")
    graph = discovery.get("graph", {})
    raw_nodes = graph.get("nodes", []) if isinstance(graph, dict) else []
    raw_edges = graph.get("edges", []) if isinstance(graph, dict) else []
    graph_nodes: dict[str, dict[str, Any]] = {}
    if not isinstance(raw_nodes, list):
        errors.append("Tool path graph nodes are missing")
    else:
        for node in raw_nodes:
            if not isinstance(node, dict) or not isinstance(node.get("node_id"), str):
                errors.append("Tool path graph contains an invalid node")
                continue
            node_id = node["node_id"]
            previous = graph_nodes.get(node_id)
            if previous is not None and previous != node:
                errors.append("Tool path graph contains conflicting duplicate nodes")
            graph_nodes[node_id] = node
    graph_edges = raw_edges if isinstance(raw_edges, list) else []
    for edge in graph_edges:
        if not isinstance(edge, dict):
            errors.append("Tool path graph contains an invalid edge")
            continue
        if edge.get("from") not in graph_nodes or edge.get("to") not in graph_nodes:
            errors.append("Tool path graph edge endpoint is not a declared node")
    anchor_candidates = discovery.get("anchor_candidates", [])
    known_anchor_refs = {
        str(ref)
        for item in anchor_candidates
        if isinstance(item, dict) and isinstance(item.get("refs"), list)
        for ref in item["refs"]
        if isinstance(ref, str) and ref
    } if isinstance(anchor_candidates, list) else set()
    if not isinstance(anchor_candidates, list):
        errors.append("Tool path anchor candidates are missing")
    for item in selected:
        paths = item.get("component_paths")
        if not item.get("handler") or not item.get("source_ref"):
            errors.append("Tool registration does not identify a handler and source reference")
        if item.get("reaches_component") is not True or not isinstance(paths, list):
            errors.append("Tool path does not reach a structured component path")
            continue
        usable = [path for path in paths if isinstance(path, dict) and path.get("anchor_refs") and path.get("source_refs") and path.get("call_chain")]
        if not usable:
            errors.append("Tool path reaches no patch anchor with source references")
        tool_id_prefix = ("python:" if discovery.get("language") == "python" else "javascript:") + "tool:"
        matching_edges = [edge for edge in graph_edges if isinstance(edge, dict) and edge.get("kind") == "REGISTER" and edge.get("tool") == item.get("tool")]
        tool_node_id = f"{tool_id_prefix}{item.get('tool')}"
        handler_node_id = (
            f"python:{item.get('source_ref', '').rsplit(':', 1)[0]}:{item.get('handler')}"
            if discovery.get("language") == "python"
            else f"javascript:handler:{item.get('handler')}"
        )
        registration_node = graph_nodes.get(tool_node_id)
        handler_node = graph_nodes.get(handler_node_id)
        if not registration_node or registration_node.get("kind") != "tool_registration" or registration_node.get("tool") != item.get("tool"):
            errors.append("Tool registration node does not match the selected Tool identity")
        if not handler_node or handler_node.get("kind") != "function" or handler_node.get("symbol") != item.get("handler"):
            errors.append("Tool handler node does not match the selected handler identity")
        matching_edges = [edge for edge in graph_edges if isinstance(edge, dict) and edge.get("kind") == "REGISTER" and edge.get("tool") == item.get("tool") and edge.get("from") == tool_node_id and edge.get("to") == handler_node_id]
        if not matching_edges:
            errors.append("Tool registration is not structurally linked to its handler")
        for path in usable:
            source_refs = {str(ref) for ref in path.get("source_refs", []) if isinstance(ref, str) and ref}
            component_call = path.get("component_call")
            if not isinstance(component_call, str) or not component_call:
                errors.append("component path has no component API identity")
                continue
            language_prefix = "python" if discovery.get("language") == "python" else "javascript"
            component_node_id = f"{language_prefix}:component:{component_call}"
            component_node = graph_nodes.get(component_node_id)
            if not component_node or component_node.get("kind") != "component_api" or component_node.get("component_name") != component_name:
                errors.append("component path component node does not match the component identity")
            elif not source_refs.issubset(set(component_node.get("source_refs", []))):
                errors.append("component path source references are not present on the component node")
            if not any(
                edge.get("kind") == "COMPONENT_CALL" and edge.get("tool") == item.get("tool")
                and edge.get("from") == handler_node_id and edge.get("to") == component_node_id
                and source_refs.issubset(set(edge.get("source_refs", [])))
                for edge in graph_edges if isinstance(edge, dict)
            ):
                errors.append("component path has no graph component-call edge")
            for anchor in path.get("anchor_refs", []):
                if not isinstance(anchor, str) or anchor not in known_anchor_refs:
                    errors.append("component path anchor is not declared by anchor_candidates")
                    continue
                anchor_node_id = f"{language_prefix}:anchor:{anchor}"
                anchor_node = graph_nodes.get(anchor_node_id)
                if not anchor_node or anchor_node.get("kind") != "patch_anchor" or anchor_node.get("component_name") != component_name or anchor_node.get("anchor_ref") != anchor:
                    errors.append("component path anchor node does not match the component anchor")
                if not any(
                    edge.get("kind") == "PATCH_ANCHOR" and edge.get("tool") == item.get("tool")
                    and edge.get("from") == component_node_id and edge.get("to") == anchor_node_id
                    and edge.get("anchor_ref") == anchor
                    and source_refs.issubset(set(edge.get("source_refs", [])))
                    for edge in graph_edges if isinstance(edge, dict)
                ):
                    errors.append("component path anchor is not represented by a graph edge")
    if not isinstance(graph, dict) or not isinstance(graph.get("nodes"), list) or not isinstance(graph.get("edges"), list) or not graph_nodes or not graph_edges:
        errors.append("Tool path graph is missing structured nodes or edges")
    return sorted(set(errors))


__all__ = ["discover_component_tool_paths", "validate_component_tool_path"]
