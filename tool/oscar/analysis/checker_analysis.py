"""Small, label-free checker and path-constraint extractors.

The analyzer reports structure that is present in source.  It never treats a
name, a category, or a string similarity as proof that a checker is safe.
Python uses the standard AST; JavaScript/TypeScript uses a deliberately
conservative token/line fallback until a full parser is available.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Any


_NORMALIZATION_NAMES = {
    "abspath", "realpath", "normpath", "resolve", "absolute", "normalize",
}
_CONTAINMENT_NAMES = {"commonpath", "relative_to", "is_relative_to"}
_TYPE_NAMES = {"isinstance", "issubclass", "type", "typeof"}
_SANITIZATION_NAMES = {
    "escape", "quote", "quote_plus", "html_escape", "sanitize", "sanitise",
    "allowlist", "denylist", "whitelist", "blacklist",
}
_URL_NAMES = {
    "urlparse", "urlsplit", "hostname", "netloc", "allow_redirects",
    "follow_redirects", "max_redirects", "redirect",
}
_COMMAND_NAMES = {"shell", "shlex", "popen", "spawn", "exec", "command", "argv"}
_REJECT_NAMES = {"raise", "throw", "reject", "deny", "blocked", "forbidden", "invalid"}
_BUILTIN_NAMES = {
    "and", "as", "assert", "async", "await", "else", "for", "from", "if",
    "import", "in", "is", "not", "or", "return", "try", "while", "with",
    "True", "False", "None", "len", "str", "int", "float", "bool", "list",
    "dict", "set", "tuple", "type", "isinstance",
}


def _name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _call_names(node: ast.AST) -> list[str]:
    return [_name(item.func) for item in ast.walk(node) if isinstance(item, ast.Call) and _name(item.func)]


def _symbols(node: ast.AST) -> list[str]:
    values = []
    for item in ast.walk(node):
        if isinstance(item, ast.Name) and isinstance(item.ctx, ast.Load) and item.id not in _BUILTIN_NAMES:
            values.append(item.id)
    return sorted(set(values))


def _source_ref(path: str, line: int | None) -> str:
    return f"{path}:{line or 1}"


def _contains_reject(nodes: list[ast.stmt]) -> bool:
    for node in nodes:
        if isinstance(node, (ast.Raise, ast.Return)):
            return True
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
            call = _name(node.value.func).lower()
            if any(token in call for token in _REJECT_NAMES):
                return True
        if isinstance(node, ast.If) and (_contains_reject(node.body) or _contains_reject(node.orelse)):
            return True
    return False


def _call_matching(calls: list[str], names: set[str]) -> list[str]:
    return [call for call in calls if call.rsplit(".", 1)[-1].lower() in names or call.lower() in names]


def _root_candidate(node: ast.AST, normalized: set[str]) -> str | None:
    all_names = _symbols(node)
    preferred = [item for item in all_names if any(token in item.lower() for token in ("root", "base", "allow", "dir"))]
    names = [item for item in all_names if item not in normalized]
    return (preferred or names)[-1] if (preferred or names) else None


def _normalization_map(tree: ast.AST) -> tuple[dict[str, dict[str, Any]], list[dict[str, Any]]]:
    normalized: dict[str, dict[str, Any]] = {}
    calls: list[dict[str, Any]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        callee = _name(node.func)
        short = callee.rsplit(".", 1)[-1].lower()
        if short not in _NORMALIZATION_NAMES:
            continue
        entry = {
            "callee": callee,
            "line": node.lineno,
            "source_ref": None,
            "input_symbols": _symbols(node),
        }
        calls.append(entry)
        parent = getattr(node, "_vulveil_parent", None)
        if isinstance(parent, ast.Assign):
            for target in parent.targets:
                if isinstance(target, ast.Name):
                    normalized[target.id] = entry
        elif isinstance(parent, ast.NamedExpr) and isinstance(parent.target, ast.Name):
            normalized[parent.target.id] = entry
    return normalized, calls


def _attach_parents(tree: ast.AST) -> None:
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            setattr(child, "_vulveil_parent", parent)


def _checker_kind_for_test(test: ast.AST) -> tuple[str | None, float]:
    calls = _call_names(test)
    lowered = [call.lower() for call in calls]
    if any(call.rsplit(".", 1)[-1].lower() in {"isinstance", "issubclass", "type"} for call in calls):
        return "type_check", 0.94
    if any(call.rsplit(".", 1)[-1].lower() in _CONTAINMENT_NAMES for call in calls):
        return "path_containment", 0.96
    if any(call.rsplit(".", 1)[-1].lower() in _NORMALIZATION_NAMES for call in calls):
        return "path_normalization", 0.9
    if any(call.rsplit(".", 1)[-1].lower() in _URL_NAMES for call in calls) or any(token in " ".join(lowered) for token in ("hostname", "netloc", "redirect")):
        return "url_redirect", 0.83
    if any(call.rsplit(".", 1)[-1].lower() in _SANITIZATION_NAMES for call in calls):
        return "sanitization", 0.86
    text = " ".join(lowered)
    if any(token in text for token in ("startswith", "endswith", "len", "index", "range")) or any(isinstance(item, ast.Compare) for item in ast.walk(test)):
        return "boundary_check", 0.78
    if any(token in text for token in _COMMAND_NAMES):
        return "command_argument", 0.8
    return None, 0.0


def _checker(
    *, path: str, function: str | None, line: int, expression: str,
    kind: str, symbols: list[str], blocking_action: str, confidence: float,
    extra_refs: list[str] | None = None,
) -> dict[str, Any]:
    ref = _source_ref(path, line)
    return {
        "checker_id": "checker-pending",
        "checker_kind": kind,
        "source_ref": ref,
        "function": function,
        "expression": expression,
        "input_symbols": symbols,
        "protected_resource": None,
        "blocking_action": blocking_action,
        "confidence": round(confidence, 2),
        "evidence_refs": sorted(set([ref, *(extra_refs or [])])),
    }


def _python_checkers(path: str, source: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    try:
        tree = ast.parse(source, filename=path)
    except (SyntaxError, ValueError, TypeError):
        return [], []
    _attach_parents(tree)
    normalized, normalization_calls = _normalization_map(tree)
    checkers: list[dict[str, Any]] = []
    constraints: list[dict[str, Any]] = []
    function_stack: list[str] = []

    class Visitor(ast.NodeVisitor):
        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            function_stack.append(node.name)
            self.generic_visit(node)
            function_stack.pop()

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            function_stack.append(node.name)
            self.generic_visit(node)
            function_stack.pop()

        def visit_If(self, node: ast.If) -> None:
            kind, confidence = _checker_kind_for_test(node.test)
            expression = ast.unparse(node.test)
            calls = _call_names(node.test)
            symbols = _symbols(node.test)
            if kind:
                item = _checker(
                    path=path, function=function_stack[-1] if function_stack else None,
                    line=node.lineno, expression=expression, kind=kind,
                    symbols=symbols, blocking_action="reject" if _contains_reject(node.body) else "branch",
                    confidence=confidence,
                )
                if kind == "path_containment":
                    item["protected_resource"] = _root_candidate(node.test, set(normalized))
                checkers.append(item)
                if kind == "path_containment":
                    used_normalization = [
                        name for name in symbols if name in normalized
                    ] or [
                        call for call in calls
                        if call.rsplit(".", 1)[-1].lower() in _NORMALIZATION_NAMES
                    ]
                    has_real_normalization = bool(used_normalization)
                    has_reject = _contains_reject(node.body) or _contains_reject(node.orelse)
                    # startswith/prefix checks intentionally never reach this
                    # branch: they are not real-path containment evidence.
                    if has_real_normalization and has_reject:
                        root = item.get("protected_resource")
                        normalized_inputs = []
                        for symbol, entry in normalized.items():
                            if symbol not in symbols:
                                continue
                            raw_inputs = [
                                item for item in entry.get("input_symbols", [])
                                if item.lower() not in {"os", "path", "posixpath", "pathlib"}
                                and item.lower() not in _NORMALIZATION_NAMES
                                and item != root
                            ]
                            normalized_inputs.extend(raw_inputs)
                        input_symbols = sorted(set(normalized_inputs or [symbol for symbol in symbols if symbol != root]))
                        constraints.append({
                            "constraint_kind": "root_containment",
                            "input": input_symbols[0] if input_symbols else None,
                            "normalization": sorted(set(
                                [
                                    call.rsplit(".", 1)[-1].lower() for call in calls
                                    if call.rsplit(".", 1)[-1].lower() in _NORMALIZATION_NAMES
                                ]
                                + [
                                    normalized[name]["callee"].rsplit(".", 1)[-1].lower()
                                    for name in used_normalization
                                    if name in normalized
                                ]
                            ) or {"resolve"}),
                            "root": root,
                            "relation": "within",
                            "failure_action": "reject",
                            "source_refs": sorted(set([item["source_ref"], *[
                                _source_ref(path, entry["line"]) for entry in normalization_calls
                                if entry["line"] <= node.lineno
                            ]])),
                            "evidence_refs": [item["source_ref"]],
                        })
            self.generic_visit(node)

        def visit_Call(self, node: ast.Call) -> None:
            callee = _name(node.func)
            short = callee.rsplit(".", 1)[-1].lower()
            kind = None
            confidence = 0.0
            if short in _NORMALIZATION_NAMES:
                kind, confidence = "path_normalization", 0.9
            elif short in _SANITIZATION_NAMES or any(token in callee.lower() for token in ("escape", "sanitize", "quote")):
                kind, confidence = "sanitization", 0.84
            elif short in {"get", "request", "fetch", "axios"} and any(
                keyword.arg in {"allow_redirects", "follow_redirects", "max_redirects"}
                and keyword.value is not None for keyword in node.keywords
            ):
                kind, confidence = "url_redirect", 0.86
            elif short in {"run", "call", "check_output", "popen", "spawn", "exec"}:
                for keyword in node.keywords:
                    if keyword.arg == "shell" and isinstance(keyword.value, ast.Constant) and keyword.value.value is False:
                        kind, confidence = "command_argument", 0.9
                        break
            if kind:
                checkers.append(_checker(
                    path=path, function=function_stack[-1] if function_stack else None,
                    line=node.lineno, expression=ast.unparse(node), kind=kind,
                    symbols=_symbols(node), blocking_action="constrain", confidence=confidence,
                ))
            self.generic_visit(node)

    Visitor().visit(tree)
    return checkers, constraints


def _javascript_checkers(path: str, source: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    checkers: list[dict[str, Any]] = []
    lines = source.splitlines() or [source]
    current_function: str | None = None
    for line_number, line in enumerate(lines, start=1):
        function_match = re.search(r"(?:function\s+|(?:const|let|var)\s+)([A-Za-z_$][\w$]*)", line)
        if function_match:
            current_function = function_match.group(1)
        lowered = line.lower()
        kind = None
        confidence = 0.0
        if "typeof" in lowered or "instanceof" in lowered:
            kind, confidence = "type_check", 0.7
        elif any(token in lowered for token in ("commonpath", "isrelativeto", ".relativeto(")):
            kind, confidence = "path_containment", 0.72
        elif any(token in lowered for token in ("realpath", "resolve(", "normalize(", "abspath")):
            kind, confidence = "path_normalization", 0.68
        elif any(token in lowered for token in ("escape(", "quote(", "sanitize", "allowlist", "denylist")):
            kind, confidence = "sanitization", 0.68
        elif any(token in lowered for token in ("allowredirects: false", "followredirects: false", "maxredirects")):
            kind, confidence = "url_redirect", 0.72
        elif any(token in lowered for token in ("shell: false", "spawn(", "execfile(")):
            kind, confidence = "command_argument", 0.68
        elif re.search(r"\b(if|switch)\b", lowered) and any(token in lowered for token in ("startswith", "endswith", "length", "index")):
            kind, confidence = "boundary_check", 0.62
        if kind:
            symbols = sorted(set(re.findall(r"[A-Za-z_$][\w$]*", line)))
            checkers.append(_checker(
                path=path, function=current_function, line=line_number, expression=line.strip(),
                kind=kind, symbols=symbols, blocking_action="reject" if any(token in lowered for token in ("throw", "return", "reject")) else "branch",
                confidence=confidence,
            ))
    return checkers, []


def analyze_checkers(sources: list[dict[str, Any]], *, side: str = "fixed") -> dict[str, Any]:
    """Extract checkers and only provable real-path constraints from sources."""
    raw_checkers: list[dict[str, Any]] = []
    path_constraints: list[dict[str, Any]] = []
    for item in sources:
        path = str(item.get("path", "inline.py"))
        content = str(item.get("content", ""))
        if Path(path).suffix.lower() in {".py", ".pyw"}:
            checkers, constraints = _python_checkers(path, content)
        elif Path(path).suffix.lower() in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}:
            checkers, constraints = _javascript_checkers(path, content)
        else:
            checkers, constraints = [], []
        raw_checkers.extend(checkers)
        path_constraints.extend(constraints)
    for index, checker in enumerate(raw_checkers, start=1):
        checker["checker_id"] = f"checker-{index}"
        checker["side"] = side
    for constraint in path_constraints:
        refs = constraint.get("evidence_refs", [])
        constraint["evidence_refs"] = sorted(set(refs))
    return {
        "checkers": raw_checkers,
        "path_constraints": path_constraints,
        "analysis_status": "SUPPORTED" if raw_checkers else "UNRESOLVED",
    }


__all__ = ["analyze_checkers"]
