"""Label-free MCP Tool inventory, input synthesis and dependency-path discovery."""

from __future__ import annotations

import ast
import copy
import json
from pathlib import Path
from typing import Any


try:
    from oscar.analysis.effect_modeling import _balanced_end, _js_callee, _js_tokens
except ImportError:  # pragma: no cover - direct script execution
    from oscar.analysis.effect_modeling import _balanced_end, _js_callee, _js_tokens


SCHEMA_VERSION = "vulveil-tool-discovery/v1"


def _dependency_names(name: str) -> set[str]:
    normalized = name.lower().replace("-", "_")
    names = {normalized, normalized.split("/")[-1]}
    if normalized.startswith("@") and "/" in normalized:
        names.add(normalized.split("/", 1)[1])
    return names


def _call_name(node: ast.Call) -> str:
    parts: list[str] = []
    value: ast.AST = node.func
    while isinstance(value, ast.Attribute):
        parts.append(value.attr)
        value = value.value
    if isinstance(value, ast.Name):
        parts.append(value.id)
    return ".".join(reversed(parts))


def _decorated_tool(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str | None:
    for decorator in node.decorator_list:
        call = decorator if isinstance(decorator, ast.Call) else None
        target = call.func if call else decorator
        if isinstance(target, ast.Attribute) and target.attr == "tool":
            if call:
                for keyword in call.keywords:
                    if keyword.arg == "name" and isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str):
                        return keyword.value.value
                if call.args and isinstance(call.args[0], ast.Constant) and isinstance(call.args[0].value, str):
                    return call.args[0].value
            return node.name
    return None


def _annotation_schema(annotation: ast.AST | None) -> dict[str, Any]:
    if annotation is None:
        return {}
    text = ast.unparse(annotation)
    base = text.split("[", 1)[0].split(".")[-1].lower()
    if base in {"str", "string"}:
        return {"type": "string"}
    if base in {"int", "integer"}:
        return {"type": "integer"}
    if base in {"float", "number"}:
        return {"type": "number"}
    if base in {"bool", "boolean"}:
        return {"type": "boolean"}
    if base in {"list", "tuple", "set", "sequence"}:
        return {"type": "array"}
    if base in {"dict", "mapping"}:
        return {"type": "object"}
    return {}


def _function_schema(node: ast.FunctionDef | ast.AsyncFunctionDef) -> dict[str, Any]:
    positional = [*node.args.posonlyargs, *node.args.args]
    defaults = [None] * (len(positional) - len(node.args.defaults)) + list(node.args.defaults)
    properties: dict[str, Any] = {}
    required: list[str] = []
    for argument, default in zip(positional, defaults):
        if argument.arg in {"self", "cls"}:
            continue
        schema = _annotation_schema(argument.annotation)
        if default is None:
            required.append(argument.arg)
        elif isinstance(default, ast.Constant):
            schema["default"] = default.value
        properties[argument.arg] = schema
    for argument, default in zip(node.args.kwonlyargs, node.args.kw_defaults):
        schema = _annotation_schema(argument.annotation)
        if default is None:
            required.append(argument.arg)
        elif isinstance(default, ast.Constant):
            schema["default"] = default.value
        properties[argument.arg] = schema
    return {"type": "object", "properties": properties, "required": required, "additionalProperties": False}


def discover_python_tool_paths(source_root: Path, dependency_name: str) -> dict[str, Any]:
    """Find conservative Python Tool-to-direct-dependency call paths with ASTs."""
    functions: dict[str, dict[str, Any]] = {}
    registrations: list[dict[str, Any]] = []
    parse_errors: list[str] = []
    dependency_names = _dependency_names(dependency_name)
    paths = sorted(path for path in source_root.rglob("*.py") if not any(part in {".git", ".venv", "venv", "node_modules"} for part in path.parts))
    trees: list[tuple[Path, ast.Module, set[str]]] = []
    for path in paths:
        try:
            tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"), filename=str(path))
        except SyntaxError as exc:
            parse_errors.append(f"{path.relative_to(source_root).as_posix()}:{exc.lineno}")
            continue
        aliases: set[str] = set()
        for node in tree.body:
            if isinstance(node, ast.Import):
                for item in node.names:
                    if item.name.lower().replace("-", "_").split(".")[0] in dependency_names:
                        aliases.add(item.asname or item.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom) and (node.module or "").lower().replace("-", "_").split(".")[0] in dependency_names:
                aliases.update(item.asname or item.name for item in node.names)
        trees.append((path, tree, aliases))

    for path, tree, aliases in trees:
        relative = path.relative_to(source_root).as_posix()
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            calls = [_call_name(call) for call in ast.walk(node) if isinstance(call, ast.Call)]
            functions.setdefault(node.name, {"calls": set(), "dependency_calls": set(), "source_refs": []})
            functions[node.name]["source_refs"].append(f"{relative}:{node.lineno}")
            functions[node.name]["calls"].update(name.split(".")[0] for name in calls if name)
            functions[node.name]["dependency_calls"].update(name for name in calls if name.split(".")[0] in aliases)
            tool_name = _decorated_tool(node)
            if tool_name:
                registrations.append({"tool": tool_name, "handler": node.name, "source_ref": f"{relative}:{node.lineno}", "input_schema": _function_schema(node)})
        for call in (node for node in ast.walk(tree) if isinstance(node, ast.Call)):
            if isinstance(call.func, ast.Attribute) and call.func.attr == "add_tool" and call.args and isinstance(call.args[0], ast.Name):
                handler = call.args[0].id
                tool_name = handler
                for keyword in call.keywords:
                    if keyword.arg == "name" and isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str):
                        tool_name = keyword.value.value
                registrations.append({"tool": tool_name, "handler": handler, "source_ref": f"{relative}:{call.lineno}", "input_schema": {}})

    tools: list[dict[str, Any]] = []
    for registration in registrations:
        queue: list[tuple[str, list[str]]] = [(registration["handler"], [registration["handler"]])]
        seen: set[str] = set()
        discovered: list[dict[str, Any]] = []
        while queue:
            function, chain = queue.pop(0)
            if function in seen:
                continue
            seen.add(function)
            details = functions.get(function, {})
            for dependency_call in sorted(details.get("dependency_calls", [])):
                discovered.append({"call_chain": [*chain, dependency_call], "dependency_call": dependency_call, "source_refs": details.get("source_refs", [])})
            for called in sorted(details.get("calls", [])):
                if called in functions and called not in seen:
                    queue.append((called, [*chain, called]))
        tools.append({**registration, "dependency_paths": discovered, "reaches_direct_dependency": bool(discovered)})
    return {
        "schema_version": SCHEMA_VERSION,
        "language": "python",
        "dependency_name": dependency_name,
        "status": "DISCOVERED" if tools else "UNRESOLVED",
        "tools": tools,
        "parse_errors": parse_errors,
    }


JS_EXTENSIONS = (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts")
JS_REGISTRATION_CALLS = {"tool", "registerTool", "registerToolIfEnabled"}
JS_CONTROL_WORDS = {"if", "for", "while", "switch", "catch", "function", "return", "typeof", "new", "async"}


def _js_string(token: dict[str, Any]) -> str | None:
    if token.get("kind") != "string":
        return None
    raw = str(token.get("value", ""))
    if raw.startswith("`"):
        return raw[1:-1] if "${" not in raw else None
    try:
        value = ast.literal_eval(raw)
    except (SyntaxError, ValueError):
        return None
    return value if isinstance(value, str) else None


def _js_dependency_matches(module: str, dependency_name: str) -> bool:
    module = module.lower().replace("-", "_")
    dependency = dependency_name.lower().replace("-", "_")
    return module == dependency or module.split("/")[-1] == dependency.split("/")[-1]


def _resolve_js_module(source_root: Path, source_file: Path, module: str) -> Path | None:
    if not module.startswith("."):
        return None
    candidate = (source_file.parent / module).resolve()
    choices = [candidate]
    if candidate.suffix:
        stem = candidate.with_suffix("")
        choices.extend(stem.with_suffix(extension) for extension in JS_EXTENSIONS)
    else:
        choices.extend(candidate.with_suffix(extension) for extension in JS_EXTENSIONS)
        choices.extend(candidate / f"index{extension}" for extension in JS_EXTENSIONS)
    root = source_root.resolve()
    for choice in choices:
        if choice.is_file() and choice.is_relative_to(root):
            return choice
    return None


def _js_imports(source_root: Path, path: Path, tokens: list[dict[str, Any]], dependency_name: str) -> tuple[set[str], dict[str, tuple[str, str]], dict[str, str]]:
    dependency_aliases: set[str] = set()
    named_imports: dict[str, tuple[str, str]] = {}
    namespace_imports: dict[str, str] = {}
    relative = path.relative_to(source_root).as_posix()
    index = 0
    while index < len(tokens):
        if tokens[index]["value"] == "import":
            end = index + 1
            while end < len(tokens) and tokens[end]["value"] != ";" and tokens[end]["line"] <= tokens[index]["line"] + 8:
                end += 1
            statement = tokens[index + 1:end]
            from_index = next((offset for offset, token in enumerate(statement) if token["value"] == "from"), None)
            if from_index is not None and from_index + 1 < len(statement):
                module = _js_string(statement[from_index + 1])
                bindings = statement[:from_index]
                if module:
                    target = _resolve_js_module(source_root, path, module)
                    if _js_dependency_matches(module, dependency_name):
                        for offset, token in enumerate(bindings):
                            if token["kind"] != "word" or token["value"] in {"as", "type"}:
                                continue
                            alias = token["value"]
                            if offset + 1 < len(bindings) and bindings[offset + 1]["value"] == "as" and offset + 2 < len(bindings):
                                alias = bindings[offset + 2]["value"]
                            dependency_aliases.add(alias)
                    elif target:
                        target_relative = target.relative_to(source_root).as_posix()
                        if bindings and bindings[0]["value"] == "*":
                            as_index = next((offset for offset, token in enumerate(bindings) if token["value"] == "as"), None)
                            if as_index is not None and as_index + 1 < len(bindings):
                                namespace_imports[bindings[as_index + 1]["value"]] = target_relative
                        elif bindings and bindings[0]["value"] == "{":
                            cursor = 1
                            while cursor < len(bindings) and bindings[cursor]["value"] != "}":
                                if bindings[cursor]["kind"] == "word":
                                    original = bindings[cursor]["value"]
                                    alias = original
                                    if cursor + 2 < len(bindings) and bindings[cursor + 1]["value"] == "as":
                                        alias = bindings[cursor + 2]["value"]
                                        cursor += 2
                                    named_imports[alias] = (target_relative, original)
                                cursor += 1
                        else:
                            default = next((token["value"] for token in bindings if token["kind"] == "word" and token["value"] != "type"), None)
                            if default:
                                named_imports[default] = (target_relative, "default")
            index = end
            continue
        if (tokens[index]["value"] == "require" and index + 2 < len(tokens)
                and tokens[index + 1]["value"] == "(" and _js_string(tokens[index + 2])):
            module = _js_string(tokens[index + 2]) or ""
            if _js_dependency_matches(module, dependency_name):
                equals = next((cursor for cursor in range(max(0, index - 5), index) if tokens[cursor]["value"] == "="), None)
                if equals is not None and equals > 0 and tokens[equals - 1]["kind"] == "word":
                    dependency_aliases.add(tokens[equals - 1]["value"])
        index += 1
    return dependency_aliases, named_imports, namespace_imports


def _js_class_ranges(tokens: list[dict[str, Any]]) -> list[dict[str, Any]]:
    classes: list[dict[str, Any]] = []
    for index, token in enumerate(tokens):
        if token["value"] != "class" or index + 1 >= len(tokens) or tokens[index + 1]["kind"] != "word":
            continue
        body_start = next((cursor for cursor in range(index + 2, min(len(tokens), index + 20)) if tokens[cursor]["value"] == "{"), None)
        body_end = _balanced_end(tokens, body_start, "{") if body_start is not None else None
        if body_start is not None and body_end is not None:
            classes.append({"name": tokens[index + 1]["value"], "start": body_start + 1, "end": body_end,
                            "line": token["line"]})
    return classes


def _js_function_ranges(tokens: list[dict[str, Any]], classes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    ranges: list[dict[str, Any]] = []
    for index, token in enumerate(tokens):
        if token["value"] == "function":
            name_index = index + 1
            name = tokens[name_index]["value"] if name_index < len(tokens) and tokens[name_index]["kind"] == "word" else None
            open_paren = next((cursor for cursor in range(name_index, min(len(tokens), name_index + 8)) if tokens[cursor]["value"] == "("), None)
            close_paren = _balanced_end(tokens, open_paren) if open_paren is not None else None
            body_start = close_paren + 1 if close_paren is not None and close_paren + 1 < len(tokens) and tokens[close_paren + 1]["value"] == "{" else None
            body_end = _balanced_end(tokens, body_start, "{") if body_start is not None else None
            if name and body_start is not None and body_end is not None:
                ranges.append({"name": name, "start": body_start + 1, "end": body_end, "line": token["line"]})
        if token["value"] == "=>":
            equals = next((cursor for cursor in range(index - 1, max(-1, index - 30), -1) if tokens[cursor]["value"] == "="), None)
            name = tokens[equals - 1]["value"] if equals is not None and equals > 0 and tokens[equals - 1]["kind"] == "word" else None
            if name and index + 1 < len(tokens) and tokens[index + 1]["value"] == "{":
                body_end = _balanced_end(tokens, index + 1, "{")
                if body_end is not None:
                    ranges.append({"name": name, "start": index + 2, "end": body_end, "line": tokens[equals - 1]["line"]})
    for class_info in classes:
        depth = 0
        index = class_info["start"]
        while index < class_info["end"]:
            value = tokens[index]["value"]
            if value == "{":
                depth += 1
            elif value == "}":
                depth = max(0, depth - 1)
            if depth == 0 and tokens[index]["kind"] == "word" and value not in {"private", "public", "protected", "static", "async", "get", "set"}:
                open_paren = index + 1 if index + 1 < class_info["end"] and tokens[index + 1]["value"] == "(" else None
                if open_paren is not None:
                    close_paren = _balanced_end(tokens, open_paren)
                    body_start = next((cursor for cursor in range((close_paren or open_paren) + 1,
                                                                  min(class_info["end"], (close_paren or open_paren) + 16))
                                       if tokens[cursor]["value"] == "{"), None)
                    body_end = _balanced_end(tokens, body_start, "{") if body_start is not None else None
                    if body_start is not None and body_end is not None and body_end <= class_info["end"]:
                        ranges.append({"name": f"{class_info['name']}.{value}", "start": body_start + 1,
                                       "end": body_end, "line": tokens[index]["line"], "class": class_info["name"]})
                        index = body_end
            index += 1
    unique: dict[tuple[str, int, int], dict[str, Any]] = {}
    for item in ranges:
        unique[(item["name"], item["start"], item["end"])] = item
    return list(unique.values())


def _js_object_bindings(tokens: list[dict[str, Any]], module: str, functions: dict[str, dict[str, Any]],
                        named_imports: dict[str, tuple[str, str]]) -> dict[str, tuple[str, str]]:
    bindings: dict[str, tuple[str, str]] = {}
    for index in range(len(tokens) - 7):
        if not (tokens[index]["value"] == "this" and tokens[index + 1]["value"] == "."
                and tokens[index + 2]["kind"] == "word" and tokens[index + 3]["value"] == "="
                and tokens[index + 4]["value"] == "new" and tokens[index + 5]["kind"] == "word"
                and tokens[index + 6]["value"] == "("):
            continue
        receiver = f"this.{tokens[index + 2]['value']}"
        class_name = tokens[index + 5]["value"]
        if class_name in named_imports:
            target_module, imported_name = named_imports[class_name]
            bindings[receiver] = (target_module, imported_name)
        elif any(name.startswith(class_name + ".") for name in functions):
            bindings[receiver] = (module, class_name)
    return bindings


def _js_calls(tokens: list[dict[str, Any]], start: int, end: int, dependency_aliases: set[str]) -> tuple[set[str], set[str]]:
    calls: set[str] = set()
    dependency_calls: set[str] = set()
    for index in range(max(1, start), min(end, len(tokens))):
        if tokens[index]["value"] != "(" or tokens[index - 1]["kind"] != "word":
            continue
        if index > 1 and tokens[index - 2]["value"] == "function":
            continue
        callee, _ = _js_callee(tokens, index - 1)
        if callee.split(".")[-1] in JS_CONTROL_WORDS:
            continue
        calls.add(callee)
        if callee.split(".")[0] in dependency_aliases:
            dependency_calls.add(callee)
    return calls, dependency_calls


def discover_javascript_tool_paths(source_root: Path, dependency_name: str) -> dict[str, Any]:
    """Find conservative JS/TS Tool paths using balanced tokens and module imports."""
    source_root = source_root.resolve()
    paths = sorted(path for path in source_root.rglob("*") if path.suffix.lower() in JS_EXTENSIONS
                   and not any(part in {".git", "node_modules", "dist", "build", "coverage", "test", "tests", "__tests__"} for part in path.parts))
    modules: dict[str, dict[str, Any]] = {}
    parse_errors: list[str] = []
    for path in paths:
        relative = path.relative_to(source_root).as_posix()
        tokens = _js_tokens(path.read_text(encoding="utf-8", errors="replace"))
        stack: list[str] = []
        valid = True
        for token in tokens:
            value = token["value"]
            if value in "([{":
                stack.append(value)
            elif value in ")]}" and (not stack or {")": "(", "]": "[", "}": "{"}[value] != stack.pop()):
                valid = False
                break
        if not valid or stack:
            parse_errors.append(f"{relative}:unbalanced delimiters")
            continue
        dependency_aliases, named_imports, namespace_imports = _js_imports(source_root, path, tokens, dependency_name)
        functions: dict[str, dict[str, Any]] = {}
        classes = _js_class_ranges(tokens)
        for item in _js_function_ranges(tokens, classes):
            calls, dependency_calls = _js_calls(tokens, item["start"], item["end"], dependency_aliases)
            functions[item["name"]] = {**item, "calls": calls, "dependency_calls": dependency_calls}
        registrations: list[dict[str, Any]] = []
        for index in range(1, len(tokens)):
            if tokens[index]["value"] != "(" or tokens[index - 1]["kind"] != "word":
                continue
            callee, _ = _js_callee(tokens, index - 1)
            if callee.split(".")[-1] not in JS_REGISTRATION_CALLS:
                continue
            close = _balanced_end(tokens, index)
            if close is None or index + 1 >= close:
                continue
            tool_name = _js_string(tokens[index + 1])
            if not tool_name:
                continue
            arrows: list[int] = []
            paren_depth = brace_depth = bracket_depth = 0
            for cursor in range(index + 1, close):
                value = tokens[cursor]["value"]
                if value == "(":
                    paren_depth += 1
                elif value == ")":
                    paren_depth = max(0, paren_depth - 1)
                elif value == "{":
                    brace_depth += 1
                elif value == "}":
                    brace_depth = max(0, brace_depth - 1)
                elif value == "[":
                    bracket_depth += 1
                elif value == "]":
                    bracket_depth = max(0, bracket_depth - 1)
                elif value == "=>" and brace_depth == 0 and bracket_depth == 0 and paren_depth == 0:
                    arrows.append(cursor)
            handler: str | None = None
            if arrows:
                arrow = arrows[-1]
                synthetic = f"__tool_{tool_name}_{tokens[index]['line']}"
                if arrow + 1 < close and tokens[arrow + 1]["value"] == "{":
                    body_end = _balanced_end(tokens, arrow + 1, "{")
                    if body_end is not None and body_end <= close:
                        calls, dependency_calls = _js_calls(tokens, arrow + 2, body_end, dependency_aliases)
                        owner_class = next((item["name"] for item in classes if item["start"] <= index <= item["end"]), None)
                        synthetic_name = f"{owner_class}.{synthetic}" if owner_class else synthetic
                        functions[synthetic_name] = {"name": synthetic_name, "start": arrow + 2, "end": body_end,
                                                "line": tokens[index]["line"], "calls": calls,
                                                "dependency_calls": dependency_calls}
                        handler = synthetic_name
                else:
                    expression_end = next((cursor for cursor in range(arrow + 1, close) if tokens[cursor]["value"] == ","), close)
                    calls, dependency_calls = _js_calls(tokens, arrow + 1, expression_end, dependency_aliases)
                    owner_class = next((item["name"] for item in classes if item["start"] <= index <= item["end"]), None)
                    synthetic_name = f"{owner_class}.{synthetic}" if owner_class else synthetic
                    functions[synthetic_name] = {"name": synthetic_name, "start": arrow + 1, "end": expression_end,
                                            "line": tokens[index]["line"], "calls": calls,
                                            "dependency_calls": dependency_calls}
                    handler = synthetic_name
            if handler is None:
                candidates = [tokens[cursor]["value"] for cursor in range(close - 1, index, -1)
                              if tokens[cursor]["kind"] == "word" and tokens[cursor]["value"] not in {"async"}]
                handler = candidates[0] if candidates else None
            if handler:
                registrations.append({"tool": tool_name, "handler": handler,
                                      "source_ref": f"{relative}:{tokens[index]['line']}", "input_schema": {}})
        object_bindings = _js_object_bindings(tokens, relative, functions, named_imports)
        modules[relative] = {"functions": functions, "dependency_aliases": dependency_aliases,
                             "named_imports": named_imports, "namespace_imports": namespace_imports,
                             "object_bindings": object_bindings, "registrations": registrations}

    def resolve_call(module: str, function: str, callee: str) -> tuple[str, str] | None:
        parts = callee.split(".")
        current = modules[module]
        if len(parts) == 1 and parts[0] in current["functions"]:
            return module, parts[0]
        if len(parts) == 2 and parts[0] == "this":
            owner_class = function.split(".", 1)[0] if "." in function else None
            method = f"{owner_class}.{parts[1]}" if owner_class else parts[1]
            if method in current["functions"]:
                return module, method
        if len(parts) >= 3 and ".".join(parts[:2]) in current["object_bindings"]:
            target_module, target_class = current["object_bindings"][".".join(parts[:2])]
            method = f"{target_class}.{parts[2]}"
            if target_module in modules and method in modules[target_module]["functions"]:
                return target_module, method
        if len(parts) == 1 and parts[0] in current["named_imports"]:
            target_module, target_name = current["named_imports"][parts[0]]
            if target_name == "default":
                return None
            if target_module in modules and target_name in modules[target_module]["functions"]:
                return target_module, target_name
        if len(parts) == 2 and parts[0] in current["namespace_imports"]:
            target_module = current["namespace_imports"][parts[0]]
            if target_module in modules and parts[1] in modules[target_module]["functions"]:
                return target_module, parts[1]
        return None

    tools: list[dict[str, Any]] = []
    for module, details in modules.items():
        for registration in details["registrations"]:
            queue: list[tuple[str, str, list[str]]] = [(module, registration["handler"], [registration["handler"]])]
            seen: set[tuple[str, str]] = set()
            discovered: list[dict[str, Any]] = []
            while queue:
                current_module, function, chain = queue.pop(0)
                key = (current_module, function)
                if key in seen or current_module not in modules or function not in modules[current_module]["functions"]:
                    continue
                seen.add(key)
                function_details = modules[current_module]["functions"][function]
                for dependency_call in sorted(function_details["dependency_calls"]):
                    discovered.append({"call_chain": [*chain, dependency_call], "dependency_call": dependency_call,
                                       "source_refs": [f"{current_module}:{function_details['line']}"]})
                for call in sorted(function_details["calls"]):
                    target = resolve_call(current_module, function, call)
                    if target and target not in seen:
                        queue.append((target[0], target[1], [*chain, target[1]]))
            tools.append({**registration, "dependency_paths": discovered,
                          "reaches_direct_dependency": bool(discovered)})
    return {"schema_version": SCHEMA_VERSION, "language": "javascript-typescript",
            "dependency_name": dependency_name, "status": "DISCOVERED" if tools else "UNRESOLVED",
            "tools": tools, "parse_errors": parse_errors}


def _resolve_ref(schema: dict[str, Any], root: dict[str, Any]) -> dict[str, Any]:
    reference = schema.get("$ref")
    if not isinstance(reference, str) or not reference.startswith("#/"):
        return schema
    value: Any = root
    for part in reference[2:].split("/"):
        if not isinstance(value, dict) or part not in value:
            raise ValueError(f"unresolved schema reference: {reference}")
        value = value[part]
    if not isinstance(value, dict):
        raise ValueError(f"schema reference is not an object: {reference}")
    return value


def _schema_value(schema: dict[str, Any], root: dict[str, Any], depth: int, refs: set[str]) -> Any:
    if depth > 12:
        raise ValueError("schema nesting exceeds limit")
    if "$ref" in schema:
        reference = str(schema["$ref"])
        if reference in refs:
            raise ValueError(f"recursive schema reference: {reference}")
        return _schema_value(_resolve_ref(schema, root), root, depth + 1, refs | {reference})
    if "const" in schema:
        return copy.deepcopy(schema["const"])
    if isinstance(schema.get("enum"), list) and schema["enum"]:
        return copy.deepcopy(schema["enum"][0])
    if "default" in schema:
        return copy.deepcopy(schema["default"])
    if isinstance(schema.get("examples"), list) and schema["examples"]:
        return copy.deepcopy(schema["examples"][0])
    for keyword in ("oneOf", "anyOf"):
        options = schema.get(keyword)
        if isinstance(options, list) and options and isinstance(options[0], dict):
            return _schema_value(options[0], root, depth + 1, refs)
    schema_type = schema.get("type")
    if isinstance(schema_type, list):
        schema_type = next((item for item in schema_type if item != "null"), "null")
    if schema_type == "object" or isinstance(schema.get("properties"), dict):
        properties = schema.get("properties", {})
        required = schema.get("required", [])
        return {key: _schema_value(properties[key], root, depth + 1, refs) for key in required if key in properties and isinstance(properties[key], dict)}
    if schema_type == "array":
        item_schema = schema.get("items", {})
        count = max(0, int(schema.get("minItems", 0)))
        return [_schema_value(item_schema, root, depth + 1, refs) for _ in range(count)] if isinstance(item_schema, dict) else []
    if schema_type == "integer":
        return int(schema.get("minimum", 0))
    if schema_type == "number":
        return float(schema.get("minimum", 0))
    if schema_type == "boolean":
        return False
    if schema_type == "null":
        return None
    if schema_type == "string" or not schema_type:
        minimum = max(1, int(schema.get("minLength", 1)))
        return ("vulveil-placeholder" + "x" * minimum)[:minimum]
    raise ValueError(f"unsupported schema type: {schema_type}")


def synthesize_tool_input(schema: dict[str, Any]) -> dict[str, Any]:
    """Generate one deterministic schema-shaped baseline input, never an exploit input."""
    try:
        value = _schema_value(schema, schema, 0, set())
    except (TypeError, ValueError) as exc:
        return {"status": "UNRESOLVED", "input": None, "reason": str(exc), "requires_semantic_review": True}
    if not isinstance(value, dict):
        return {"status": "UNRESOLVED", "input": None, "reason": "Tool input schema root is not an object", "requires_semantic_review": True}
    return {
        "status": "GENERATED",
        "input": value,
        "reason": None,
        "requires_semantic_review": True,
        "scope": "schema-shaped baseline only; not a vulnerability trigger",
    }


def discover_runtime_tools(*, command: list[str], cwd: Path, env: dict[str, str], transport: str = "stdio",
                           endpoint: str | None = None, headers: dict[str, str] | None = None,
                           timeout: float = 30.0, startup_timeout: float = 20.0) -> dict[str, Any]:
    """Read a managed server's authoritative tools/list without invoking a Tool."""
    from oscar.runtime.host_core import client_context

    with client_context(transport=transport, command=command, cwd=cwd, env=env, timeout=timeout,
                        endpoint=endpoint, headers=headers, startup_timeout=startup_timeout) as client:
        initialize = client.request("initialize", {"protocolVersion": client.protocol_version, "capabilities": {},
                                                    "clientInfo": {"name": "vulveil-tool-discovery", "version": "1"}})
        client.notify("notifications/initialized")
        response = client.request("tools/list", {})
    raw_tools = response.get("tools", []) if isinstance(response, dict) else []
    tools: list[dict[str, Any]] = []
    for tool in raw_tools:
        if not isinstance(tool, dict) or not isinstance(tool.get("name"), str):
            continue
        schema = tool.get("inputSchema", tool.get("input_schema", {}))
        generated = synthesize_tool_input(schema if isinstance(schema, dict) else {})
        tools.append({"name": tool["name"], "description": tool.get("description"), "input_schema": schema,
                      "baseline_input": generated})
    return {"schema_version": SCHEMA_VERSION, "status": "DISCOVERED" if tools else "UNRESOLVED",
            "transport": transport, "initialize": initialize, "tools": tools}
