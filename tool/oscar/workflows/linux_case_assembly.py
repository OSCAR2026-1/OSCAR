"""Fail-closed Linux stdio case assembly; GT files are never consulted."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import tomllib
from pathlib import Path
from typing import Any

try:
    from oscar.runtime.blind_runtime import _read_evidence, validate_blind_case
    from oscar.runtime.environment import build_frozen_environment_manifest, compare_environment_manifests
    from oscar.runtime.prepared_host_runner import run_prepared_case
    from oscar.workflows.dependency_evidence import verify_dependency_pair
    from oscar.contracts.component_contract import component_from_spec, is_legacy_direct_runtime
except ImportError:
    from oscar.runtime.blind_runtime import _read_evidence, validate_blind_case
    from oscar.runtime.environment import build_frozen_environment_manifest, compare_environment_manifests
    from oscar.runtime.prepared_host_runner import run_prepared_case
    from oscar.workflows.dependency_evidence import verify_dependency_pair
    from oscar.contracts.component_contract import component_from_spec, is_legacy_direct_runtime

EXCLUDED = {".git", ".venv", "venv", "node_modules", "__pycache__", ".pytest_cache"}
SUFFIXES = {".py", ".pyi", ".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".json", ".toml", ".txt", ".lock"}
SENSITIVE_NAMES = {".env", ".npmrc", ".pypirc", ".netrc", "id_rsa", "id_ed25519", "credentials", "credentials.json", "secrets.json", "host_record.json", "blind_evidence.jsonl"}
GT_FRAGMENTS = {"03_gt", "gt_linux", "recorder", "ground_truth", "active_agent_gt"}
IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}\Z")


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _inventory(source: Path) -> dict[str, str]:
    if not source.is_dir() or source.is_symlink():
        raise ValueError("source must be an ordinary existing directory")
    inventory: dict[str, str] = {}
    for directory, dirs, files in os.walk(source, followlinks=False):
        for name in [*dirs, *files]:
            item = Path(directory) / name
            if item.is_symlink():
                raise ValueError(f"source symlink requires review: {item}")
            lowered = name.lower()
            if name not in EXCLUDED and (lowered in SENSITIVE_NAMES or any(part in lowered for part in GT_FRAGMENTS)):
                raise ValueError(f"sensitive or GT-like source path requires review: {item}")
        dirs[:] = [name for name in dirs if name not in EXCLUDED]
        for name in files:
            item = Path(directory) / name
            if item.suffix.lower() not in SUFFIXES or not item.is_file():
                raise ValueError(f"non-source file requires review: {item}")
            if item.suffix.lower() in {".py", ".pyi", ".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".json", ".toml", ".txt"}:
                text = item.read_text(encoding="utf-8", errors="replace").lower()
                if any(marker in text for marker in ("ground_truth_label", "patched_trigger_blocked", "active_agent_gt_pairs")):
                    raise ValueError(f"GT-derived content requires review: {item}")
            inventory[item.relative_to(source).as_posix()] = _digest(item)
    if not inventory:
        raise ValueError("source contains no allowed files")
    return inventory


def _run(command: list[str], timeout: int = 900) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace",
                          timeout=timeout, check=False, shell=False)


def _inspect(image: str) -> str:
    result = _run(["docker", "image", "inspect", image, "--format", "{{.Id}}"], timeout=30)
    if result.returncode or not IMAGE_ID.fullmatch(result.stdout.strip()):
        raise ValueError(f"image unavailable or invalid: {image}")
    return result.stdout.strip()


def verify_container_images(spec: dict[str, Any]) -> None:
    expected = spec.get("environment", {}).get("container_image_ids", {})
    for side in ("vulnerable", "patched"):
        image = expected.get(side)
        command = spec.get("server_runner", {}).get(side, {}).get("command", [])
        if not isinstance(image, str) or not IMAGE_ID.fullmatch(image) or image not in command or _inspect(image) != image:
            raise ValueError(f"INVALID_ENVIRONMENT_PARITY: {side} image ID drift")


def verify_assembled_inputs(spec: dict[str, Any], case_root: Path) -> None:
    environment = spec.get("environment", {})
    expected_sources = environment.get("source_inventory_sha256", {})
    expected_dockerfiles = environment.get("dockerfile_sha256", {})
    for side, source_key in (("vulnerable", "vulnerable"), ("patched", "fixed")):
        source_ref = spec.get("source", {}).get(source_key, {}).get("root")
        docker_ref = environment.get("dockerfiles", {}).get(side)
        if not isinstance(source_ref, str) or Path(source_ref).is_absolute() or ".." in Path(source_ref).parts:
            raise ValueError(f"INVALID_ENVIRONMENT_PARITY: invalid {side} source path")
        if not isinstance(docker_ref, str) or Path(docker_ref).is_absolute() or ".." in Path(docker_ref).parts:
            raise ValueError(f"INVALID_ENVIRONMENT_PARITY: invalid {side} Dockerfile path")
        source = (case_root / source_ref).resolve()
        dockerfile = (case_root / docker_ref).resolve()
        if not source.is_relative_to(case_root.resolve()) or not dockerfile.is_relative_to(case_root.resolve()):
            raise ValueError(f"INVALID_ENVIRONMENT_PARITY: {side} assembly input escapes case root")
        actual_source = hashlib.sha256(json.dumps(_inventory(source), sort_keys=True).encode()).hexdigest()
        if actual_source != expected_sources.get(side) or not dockerfile.is_file() or _digest(dockerfile) != expected_dockerfiles.get(side):
            raise ValueError(f"INVALID_ENVIRONMENT_PARITY: {side} assembly input drift")
    source_spec = spec.get("source", {})
    component, _, _ = component_from_spec(spec)
    origin = component.get("origin") if component else "DIRECT_RUNTIME_DEPENDENCY"
    source_roots = {
        "vulnerable": (case_root / source_spec.get("vulnerable", {}).get("root")).resolve(),
        "patched": (case_root / source_spec.get("fixed", {}).get("root")).resolve(),
    } if isinstance(source_spec, dict) else {}
    if len(source_roots) == 2:
        assembled_patch = spec.get("patch")
        if _patch_text(assembled_patch).strip():
            changed_server_paths = _verify_patch_explains_pair(source_roots["vulnerable"], source_roots["patched"], assembled_patch, "assembled Server patch")
        else:
            old_inventory = _inventory(source_roots["vulnerable"])
            new_inventory = _inventory(source_roots["patched"])
            changed_server_paths = {name for name in set(old_inventory) | set(new_inventory)
                                    if old_inventory.get(name) != new_inventory.get(name)}
            if changed_server_paths:
                raise ValueError("INVALID_ENVIRONMENT_PARITY: Server patch is missing for runnable source differences")
        if origin != "MCP_SERVER_SELF":
            manifest_names = {
                "requirements.txt", "requirements-dev.txt", "pyproject.toml", "poetry.lock", "uv.lock",
                "pipfile", "pipfile.lock", "package.json", "package-lock.json", "npm-shrinkwrap.json",
                "yarn.lock", "pnpm-lock.yaml",
            }
            if any(Path(path).name.lower() not in manifest_names for path in changed_server_paths):
                raise ValueError("INVALID_ENVIRONMENT_PARITY: runnable Server patch covers non-manifest source")
            dependency_name = str(component.get("name", ""))
            dependency_vulnerable = str(component.get("vulnerable_version", component.get("vulnerable_commit", "")))
            dependency_fixed = str(component.get("fixed_version", component.get("fixed_commit", "")))
            ecosystem = str(environment.get("package_manager", "")).lower()
            _verify_target_manifest_changes(
                source_roots["vulnerable"], source_roots["patched"], changed_server_paths,
                dependency_name, dependency_vulnerable, dependency_fixed, ecosystem,
            )
    source_role = source_spec.get("role") if isinstance(source_spec, dict) else None
    analysis_required = origin == "MCP_FRAMEWORK" or (origin == "DIRECT_RUNTIME_DEPENDENCY" and (not is_legacy_direct_runtime(spec) or source_role == "server_runtime"))
    if analysis_required:
        analysis = spec.get("analysis_source")
        expected_analysis = environment.get("analysis_source_inventory_sha256", {})
        if not isinstance(analysis, dict) or not isinstance(expected_analysis, dict):
            label = "framework" if origin == "MCP_FRAMEWORK" else "dependency"
            raise ValueError(f"INVALID_ENVIRONMENT_PARITY: {label} analysis source inventory is missing")
        for side, source_key in (("vulnerable", "vulnerable"), ("patched", "fixed")):
            selected = analysis.get(source_key)
            analysis_ref = selected.get("root") if isinstance(selected, dict) else None
            if not isinstance(analysis_ref, str) or Path(analysis_ref).is_absolute() or ".." in Path(analysis_ref).parts:
                label = "framework" if origin == "MCP_FRAMEWORK" else "dependency"
                raise ValueError(f"INVALID_ENVIRONMENT_PARITY: invalid {side} {label} analysis source path")
            analysis_root = (case_root / analysis_ref).resolve()
            if not analysis_root.is_relative_to(case_root.resolve()):
                label = "framework" if origin == "MCP_FRAMEWORK" else "dependency"
                raise ValueError(f"INVALID_ENVIRONMENT_PARITY: {side} {label} analysis source escapes case root")
            actual = hashlib.sha256(json.dumps(_inventory(analysis_root), sort_keys=True).encode()).hexdigest()
            if actual != expected_analysis.get(side):
                label = "framework" if origin == "MCP_FRAMEWORK" else "dependency"
                raise ValueError(f"INVALID_ENVIRONMENT_PARITY: {side} {label} analysis source drift")
        _verify_patch_explains_pair(
            (case_root / analysis["vulnerable"]["root"]).resolve(),
            (case_root / analysis["fixed"]["root"]).resolve(),
            spec.get("analysis_patch"),
            "assembled component analysis patch",
        )


def _dockerfile(ecosystem: str, base_image: str, command: list[str]) -> str:
    install = ("RUN python3 -m venv /opt/venv && /opt/venv/bin/pip install --no-cache-dir -r requirements.txt\n"
               "ENV PATH=/opt/venv/bin:$PATH\n" if ecosystem == "pypi" else "RUN npm ci --omit=dev --ignore-scripts\n")
    return (f"FROM {base_image}\nWORKDIR /case\nCOPY source/ /case/\n{install}"
            "USER 10001:10001\n" + f"CMD {json.dumps(command, ensure_ascii=True)}\n")


def _requirements_ok(path: Path) -> bool:
    if not path.is_file():
        return False
    lines = [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip() and not line.lstrip().startswith("#")]
    return bool(lines) and all(re.fullmatch(r"[A-Za-z0-9_.-]+(?:\[[A-Za-z0-9_,.-]+\])?==[A-Za-z0-9_.+!-]+", line) for line in lines)


def _manifest_dependencies(path: Path, ecosystem: str) -> dict[str, str]:
    """Read only production direct-dependency declarations from known manifests."""
    if not path.is_file():
        raise ValueError(f"target manifest is missing: {path.name}")
    if path.name == "package.json":
        document = json.loads(path.read_text(encoding="utf-8"))
        values: dict[str, Any] = {}
        for key in ("dependencies", "optionalDependencies"):
            section = document.get(key, {})
            if not isinstance(section, dict) or any(not isinstance(name, str) or not isinstance(value, str) for name, value in section.items()):
                raise ValueError(f"{path.name} {key} is malformed")
            values.update(section)
        return {name.lower(): value for name, value in values.items()}
    if path.name in {"requirements.txt", "requirements-dev.txt"}:
        values: dict[str, str] = {}
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            match = re.fullmatch(r"([A-Za-z0-9_.-]+)(?:\[[A-Za-z0-9_,.-]+\])?\s*(.+)", line)
            if not match:
                raise ValueError(f"unsupported dependency declaration in {path.name}")
            values[re.sub(r"[-_.]+", "-", match.group(1)).lower()] = match.group(2).strip()
        return values
    if path.name == "pyproject.toml":
        document = tomllib.loads(path.read_text(encoding="utf-8"))
        declared = document.get("project", {}).get("dependencies", [])
        if not isinstance(declared, list):
            raise ValueError("pyproject.toml project.dependencies is malformed")
        values: dict[str, str] = {}
        for item in declared:
            if not isinstance(item, str):
                raise ValueError("pyproject.toml has a non-string dependency")
            match = re.fullmatch(r"([A-Za-z0-9_.-]+)(?:\[[A-Za-z0-9_,.-]+\])?\s*(.*)", item.split(";", 1)[0].strip())
            if not match:
                raise ValueError("unsupported pyproject.toml dependency declaration")
            values[re.sub(r"[-_.]+", "-", match.group(1)).lower()] = match.group(2).strip()
        return values
    raise ValueError(f"cannot semantically verify changed manifest: {path.name}")


def _lockfile_target_state(path: Path, target: str, ecosystem: str) -> tuple[dict[str, str], str | None]:
    """Return non-target root declarations and the exact target resolution."""
    if path.name == "package-lock.json":
        document = json.loads(path.read_text(encoding="utf-8"))
        packages = document.get("packages", {})
        root = packages.get("") if isinstance(packages, dict) else None
        if not isinstance(root, dict) or not isinstance(root.get("dependencies"), dict):
            raise ValueError("package-lock.json root dependencies are missing")
        root_deps = {str(name).lower(): str(value) for name, value in root["dependencies"].items()}
        target_node = packages.get(f"node_modules/{target}") if isinstance(packages, dict) else None
        resolved = target_node.get("version") if isinstance(target_node, dict) else None
        if not isinstance(resolved, str):
            raise ValueError("package-lock.json target resolution is missing")
        return ({name: value for name, value in root_deps.items() if name != target}, resolved)
    if path.name in {"uv.lock", "poetry.lock"}:
        if path.name == "poetry.lock":
            raise ValueError("poetry.lock cannot be semantically verified for target-only changes")
        document = tomllib.loads(path.read_text(encoding="utf-8"))
        packages = document.get("package", [])
        if not isinstance(packages, list):
            raise ValueError("uv.lock package table is malformed")
        versions: dict[str, str] = {}
        for item in packages:
            if not isinstance(item, dict) or not isinstance(item.get("name"), str) or not isinstance(item.get("version"), str):
                raise ValueError("uv.lock package entry is malformed")
            versions[item["name"].lower()] = item["version"]
        if target not in versions:
            raise ValueError("uv.lock target resolution is missing")
        return ({name: value for name, value in versions.items() if name != target}, versions[target])
    raise ValueError(f"cannot semantically verify changed lockfile: {path.name}")


def _verify_target_manifest_changes(
    old_root: Path,
    new_root: Path,
    changed_paths: set[str],
    component_name: str,
    vulnerable: str,
    fixed: str,
    ecosystem: str,
) -> None:
    """Allow only a target dependency declaration/resolution change on Server."""
    target = component_name.lower() if ecosystem == "npm" else re.sub(r"[-_.]+", "-", component_name).lower()
    primary_names = {"package.json", "requirements.txt", "pyproject.toml"}
    lock_names = {"package-lock.json", "uv.lock", "poetry.lock"}
    for relative in sorted(changed_paths):
        filename = Path(relative).name.lower()
        old_path = old_root / relative
        new_path = new_root / relative
        if filename in primary_names:
            old_deps = _manifest_dependencies(old_path, ecosystem)
            new_deps = _manifest_dependencies(new_path, ecosystem)
            if target not in old_deps or target not in new_deps:
                raise ValueError(f"Server manifest change does not retain target component: {relative}")
            if {name: value for name, value in old_deps.items() if name != target} != {name: value for name, value in new_deps.items() if name != target}:
                raise ValueError(f"Server manifest contains patch-external dependency changes: {relative}")
            continue
        if filename in lock_names:
            old_deps, old_resolved = _lockfile_target_state(old_path, target, ecosystem)
            new_deps, new_resolved = _lockfile_target_state(new_path, target, ecosystem)
            if old_deps != new_deps:
                raise ValueError(f"Server lockfile contains patch-external dependency changes: {relative}")
            if old_resolved != vulnerable or new_resolved != fixed:
                raise ValueError(f"Server lockfile target resolution is not the requested vulnerable/fixed pair: {relative}")
            continue
        raise ValueError(f"Server dependency/config difference is not a verified manifest or lockfile: {relative}")


def _patch_text(patch: Any) -> str:
    return patch if isinstance(patch, str) else patch.get("unified_diff", "") if isinstance(patch, dict) else ""


def _diff_path(raw: str, prefix: str | None = None) -> str | None:
    value = raw.strip().split("\t", 1)[0]
    if value == "/dev/null":
        return None
    if prefix and value.startswith(prefix + "/"):
        value = value[len(prefix) + 1:]
    value = value.removeprefix("a/").removeprefix("b/")
    path = Path(value)
    if not value or path.is_absolute() or ".." in path.parts:
        return None
    return path.as_posix()


def _parse_unified_diff(patch: Any) -> list[dict[str, Any]]:
    """Parse file headers and hunks without trusting path names alone."""
    text = _patch_text(patch)
    if not text.strip():
        return []
    files: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    hunk: dict[str, Any] | None = None
    for line in text.splitlines(keepends=True):
        if line.startswith("diff --git "):
            if current is not None:
                files.append(current)
            current = {"old": None, "new": None, "rename_from": None, "rename_to": None, "hunks": []}
            hunk = None
        elif line.startswith("rename from "):
            if current is None:
                current = {"old": None, "new": None, "rename_from": None, "rename_to": None, "hunks": []}
            current["rename_from"] = _diff_path(line[len("rename from "):])
        elif line.startswith("rename to "):
            if current is None:
                current = {"old": None, "new": None, "rename_from": None, "rename_to": None, "hunks": []}
            current["rename_to"] = _diff_path(line[len("rename to "):])
        elif line.startswith("--- "):
            if current is None:
                current = {"old": None, "new": None, "rename_from": None, "rename_to": None, "hunks": []}
            current["old"] = _diff_path(line[4:], "a")
            hunk = None
        elif line.startswith("+++ "):
            if current is None:
                current = {"old": None, "new": None, "rename_from": None, "rename_to": None, "hunks": []}
            current["new"] = _diff_path(line[4:], "b")
            hunk = None
        elif line.startswith("@@ ") or line.startswith("@@@ "):
            if current is None:
                continue
            match = re.match(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@", line)
            if not match:
                raise ValueError("unified diff contains an invalid hunk header")
            hunk = {"old_start": int(match.group(1)), "old_count": int(match.group(2) or "1"),
                    "new_start": int(match.group(3)), "new_count": int(match.group(4) or "1"), "lines": []}
            current["hunks"].append(hunk)
        elif hunk is not None and line.startswith((" ", "+", "-")):
            hunk["lines"].append(line)
        elif line.startswith("\\ No newline at end of file"):
            continue
    if current is not None:
        files.append(current)
    for item in files:
        if item["old"] is None:
            item["old"] = item.get("rename_from")
        if item["new"] is None:
            item["new"] = item.get("rename_to")
        if item["old"] is None and item["new"] is None:
            raise ValueError("unified diff file record has no path")
    return files


def _patch_paths(patch: Any) -> set[str]:
    paths: set[str] = set()
    for item in _parse_unified_diff(patch):
        paths.update(path for path in (item.get("old"), item.get("new")) if path)
    return paths


def _mapped_patch_path(raw: str | None, root: Path, prefixes: tuple[str, ...]) -> str | None:
    if raw is None:
        return None
    value = str(raw)
    path = Path(value)
    if path.is_absolute():
        try:
            return path.resolve().relative_to(root.resolve()).as_posix()
        except ValueError:
            pass
    for prefix in prefixes:
        if value.startswith(prefix + "/"):
            value = value[len(prefix) + 1:]
            break
    return _diff_path(value)


def _read_patch_lines(path: Path | None) -> list[str]:
    if path is None:
        return []
    if not path.is_file() or path.is_symlink():
        raise ValueError(f"patch references a missing source file: {path}")
    try:
        return path.read_text(encoding="utf-8").splitlines(keepends=True)
    except (OSError, UnicodeDecodeError) as exc:
        raise ValueError(f"patch source is not readable text: {path}") from exc


def _apply_patch_file(old_lines: list[str], item: dict[str, Any], label: str) -> list[str]:
    hunks = item.get("hunks", [])
    if not hunks:
        if item.get("old") != item.get("new"):
            return old_lines
        return old_lines
    output: list[str] = []
    cursor = 0
    for hunk in hunks:
        old_start = int(hunk["old_start"])
        old_count = int(hunk["old_count"])
        target = 0 if old_count == 0 and old_start == 0 else max(0, old_start - 1)
        if target < cursor or target > len(old_lines):
            raise ValueError(f"{label} hunk starts outside vulnerable source")
        output.extend(old_lines[cursor:target])
        cursor = target
        consumed = 0
        for raw in hunk.get("lines", []):
            prefix = raw[:1]
            payload = raw[1:]
            if prefix in {" ", "-"}:
                if cursor + consumed >= len(old_lines) or old_lines[cursor + consumed] != payload:
                    raise ValueError(f"{label} patch context/deletion does not match vulnerable source")
                if prefix == " ":
                    output.append(old_lines[cursor + consumed])
                consumed += 1
            elif prefix == "+":
                output.append(payload)
            else:
                raise ValueError(f"{label} contains an unsupported hunk line")
        if consumed != old_count:
            raise ValueError(f"{label} hunk old-line count is inconsistent")
        cursor += consumed
    output.extend(old_lines[cursor:])
    return output


def _verify_patch_explains_pair(old_root: Path, new_root: Path, patch: Any, label: str) -> set[str]:
    """Require exact source/content parity under a unified patch."""
    files = _parse_unified_diff(patch)
    if not files:
        raise ValueError(f"{label} is missing a unified diff")
    old_inventory = _inventory(old_root)
    new_inventory = _inventory(new_root)
    actual_changed = {
        name for name in set(old_inventory) | set(new_inventory)
        if old_inventory.get(name) != new_inventory.get(name)
    }
    covered: set[str] = set()
    for index, item in enumerate(files):
        old_name = _mapped_patch_path(item.get("old"), old_root, ("a",))
        new_name = _mapped_patch_path(item.get("new"), new_root, ("b",))
        if item.get("old") is not None and old_name is None:
            raise ValueError(f"{label} contains an invalid vulnerable path")
        if item.get("new") is not None and new_name is None:
            raise ValueError(f"{label} contains an invalid fixed path")
        old_path = old_root / old_name if old_name else None
        new_path = new_root / new_name if new_name else None
        old_lines = _read_patch_lines(old_path)
        expected_new = _apply_patch_file(old_lines, item, f"{label} file {index + 1}")
        actual_new = _read_patch_lines(new_path)
        if expected_new != actual_new:
            raise ValueError(f"{label} content does not match vulnerable/fixed source")
        if old_name:
            covered.add(old_name)
        if new_name:
            covered.add(new_name)
        if not item.get("hunks") and old_name and new_name and old_inventory.get(old_name) != new_inventory.get(new_name):
            raise ValueError(f"{label} rename record changes content without hunks")
    if actual_changed != covered:
        missing = sorted(actual_changed - covered)
        extra = sorted(covered - actual_changed)
        details = []
        if missing:
            details.append("uncovered=" + ",".join(missing))
        if extra:
            details.append("unnecessary=" + ",".join(extra))
        raise ValueError(f"{label} does not explain the complete source pair (" + "; ".join(details) + ")")
    return actual_changed


def _python_inventory(image: str) -> dict[str, str]:
    command = ["docker", "run", "--rm", "--network", "none", "--entrypoint", "/opt/venv/bin/python",
               image, "-m", "pip", "freeze", "--all"]
    result = _run(command, timeout=120)
    if result.returncode:
        raise ValueError("installed Python dependency inventory cannot be read")
    inventory: dict[str, str] = {}
    for line in result.stdout.splitlines():
        match = re.fullmatch(r"([A-Za-z0-9_.-]+)==([A-Za-z0-9_.+!-]+)", line.strip())
        if not match:
            raise ValueError(f"non-immutable installed Python dependency: {line.strip()}")
        inventory[re.sub(r"[-_.]+", "-", match.group(1)).lower()] = match.group(2)
    if not inventory:
        raise ValueError("installed Python dependency inventory is empty")
    return inventory


def _npm_inventory(image: str) -> dict[str, str]:
    result = _run(["docker", "run", "--rm", "--network", "none", "--entrypoint", "npm",
                   image, "ls", "--all", "--json", "--omit=dev"], timeout=120)
    if result.returncode:
        raise ValueError("installed npm dependency tree cannot be read")
    tree = json.loads(result.stdout)
    inventory: dict[str, str] = {}

    def walk(node: dict[str, Any], parent: str) -> None:
        dependencies = node.get("dependencies", {})
        if not isinstance(dependencies, dict):
            raise ValueError("installed npm tree is malformed")
        for name, child in dependencies.items():
            if not isinstance(child, dict) or not isinstance(child.get("version"), str):
                raise ValueError(f"unresolved npm dependency: {name}")
            key = f"{parent}/{name}" if parent else name
            inventory[key] = child["version"]
            walk(child, key)

    walk(tree, "")
    if not inventory:
        raise ValueError("installed npm dependency inventory is empty")
    return inventory


def assemble_linux_case(case_path: Path, *, base_image: str, external_boundary: dict[str, Any],
                        build: bool = False, build_network: str = "none") -> dict[str, Any]:
    case_path = case_path.resolve()
    root = case_path.parent
    spec = json.loads(case_path.read_text(encoding="utf-8"))
    errors = validate_blind_case(spec)
    if errors:
        raise ValueError("invalid blind case: " + "; ".join(errors))
    if spec.get("status") != "prepared" or case_path.name != "blind_case.json":
        raise ValueError("expected prepared blind_case.json")
    if not re.fullmatch(r"[A-Za-z0-9._/:-]+@sha256:[a-f0-9]{64}", base_image):
        raise ValueError("base image must be pinned by digest")
    if build_network not in {"none", "default"}:
        raise ValueError("build network must be none or explicitly opted-in default")
    boundary = external_boundary
    if (not isinstance(boundary, dict) or not boundary.get("kind")
            or not re.fullmatch(r"[a-f0-9]{64}", str(boundary.get("initial_state_sha256", "")))
            or boundary.get("network_mode", "none") != "none" or boundary.get("host_mounts", []) != [] or boundary.get("ports", []) != []):
        raise ValueError("controlled offline boundary requires kind and SHA-256, without mounts, ports or network")
    ecosystem = str(spec["environment"].get("package_manager", "")).lower()
    if ecosystem not in {"npm", "pypi"}:
        raise ValueError("unsupported container ecosystem")
    roots = {side: (root / spec["source"]["vulnerable" if side == "vulnerable" else "fixed"]["root"]).resolve()
             for side in ("vulnerable", "patched")}
    inventories = {}
    for side, source in roots.items():
        if source == root or root.is_relative_to(source) or any(part.lower() in GT_FRAGMENTS for part in source.parts):
            raise ValueError(f"source root overlaps case or GT directory: {source}")
        inventories[side] = _inventory(source)
        if ecosystem == "pypi" and not _requirements_ok(source / "requirements.txt"):
            raise ValueError("Python build requires exact production requirements.txt pins")
        if ecosystem == "npm" and not (source / "package-lock.json").is_file():
            raise ValueError("npm build requires package-lock.json")
        command = spec["server_runner"][side]["command"]
        if (not isinstance(command, list) or not command or command[0] not in {"node", "python3", "node_modules/.bin/tsx"}
                or any(not isinstance(item, str) or not item or Path(item).is_absolute() or ".." in Path(item).parts for item in command)):
            raise ValueError("server command must use supported container-local argv")
        if command[0] == "node_modules/.bin/tsx":
            manifest = json.loads((source / "package.json").read_text(encoding="utf-8"))
            if "tsx" not in manifest.get("dependencies", {}):
                raise ValueError("tsx must be a production dependency")
    component, component_errors, _ = component_from_spec(spec)
    if component is None or component_errors:
        raise ValueError("invalid vulnerability component: " + "; ".join(component_errors))
    origin = component.get("origin")
    dependency_name = str(component.get("name", ""))
    dependency_vulnerable = str(component.get("vulnerable_version", component.get("vulnerable_commit", "")))
    dependency_fixed = str(component.get("fixed_version", component.get("fixed_commit", "")))
    if origin == "DIRECT_RUNTIME_DEPENDENCY":
        evidence = verify_dependency_pair(
            roots["vulnerable"], roots["patched"], dependency_name,
            dependency_vulnerable, dependency_fixed, ecosystem,
        )
        if evidence["status"] != "VERIFIED":
            raise ValueError("direct-runtime dependency revalidation failed: " + "; ".join(evidence["reasons"]))
    server_patch = spec.get("patch")
    if _patch_text(server_patch).strip():
        changed_server_paths = _verify_patch_explains_pair(roots["vulnerable"], roots["patched"], server_patch, "Server patch")
    else:
        changed_server_paths = {name for name in set(inventories["vulnerable"]) | set(inventories["patched"])
                                if inventories["vulnerable"].get(name) != inventories["patched"].get(name)}
        if changed_server_paths:
            raise ValueError("Server patch is missing for runnable source differences")
    if origin != "MCP_SERVER_SELF":
        manifest_names = {
            "requirements.txt", "requirements-dev.txt", "pyproject.toml", "poetry.lock", "uv.lock",
            "pipfile", "pipfile.lock", "package.json", "package-lock.json", "npm-shrinkwrap.json",
            "yarn.lock", "pnpm-lock.yaml",
        }
        non_manifest = sorted(path for path in changed_server_paths if Path(path).name.lower() not in manifest_names)
        if non_manifest:
            raise ValueError("runnable Server source or unrelated assets differ outside target manifest/lockfile: " + ", ".join(non_manifest))
        _verify_target_manifest_changes(
            roots["vulnerable"], roots["patched"], changed_server_paths,
            dependency_name, dependency_vulnerable, dependency_fixed, ecosystem,
        )
    analysis_roots: dict[str, Path] = {}
    analysis_inventories: dict[str, dict[str, str]] = {}
    source_role = spec.get("source", {}).get("role") if isinstance(spec.get("source"), dict) else None
    analysis_spec = spec.get("analysis_source")
    analysis_required = origin == "MCP_FRAMEWORK" or (origin == "DIRECT_RUNTIME_DEPENDENCY" and (not is_legacy_direct_runtime(spec) or source_role == "server_runtime"))
    if analysis_required:
        if not isinstance(analysis_spec, dict) or analysis_spec.get("status") not in {None, "VERIFIED"}:
            label = "framework" if origin == "MCP_FRAMEWORK" else "dependency"
            raise ValueError(f"{label} analysis source pair is unresolved")
        for side, source_key in (("vulnerable", "vulnerable"), ("patched", "fixed")):
            selected = analysis_spec.get(source_key)
            analysis_ref = selected.get("root") if isinstance(selected, dict) else None
            if not isinstance(analysis_ref, str) or Path(analysis_ref).is_absolute():
                label = "framework" if origin == "MCP_FRAMEWORK" else "dependency"
                raise ValueError(f"{label} analysis source pair is missing")
            analysis_root = (root / analysis_ref).resolve()
            if (analysis_root == root or root.is_relative_to(analysis_root)
                    or any(part.lower() in GT_FRAGMENTS for part in analysis_root.parts)):
                label = "framework" if origin == "MCP_FRAMEWORK" else "dependency"
                raise ValueError(f"{label} analysis source overlaps case or GT directory: {analysis_root}")
            if not analysis_root.is_dir() or analysis_root.is_symlink():
                label = "framework" if origin == "MCP_FRAMEWORK" else "dependency"
                raise ValueError(f"{label} analysis source root is unavailable: {side}")
            analysis_roots[side] = analysis_root
            analysis_inventories[side] = _inventory(analysis_root)
        if not isinstance(spec.get("analysis_patch"), dict) or not spec["analysis_patch"].get("unified_diff"):
            label = "framework" if origin == "MCP_FRAMEWORK" else "dependency"
            raise ValueError(f"{label} repair patch is unresolved")
        _verify_patch_explains_pair(
            analysis_roots["vulnerable"], analysis_roots["patched"], spec.get("analysis_patch"),
            ("framework" if origin == "MCP_FRAMEWORK" else "dependency") + " analysis patch",
        )
    context = root / "container"
    if context.exists() or (root / "baseline_environment_manifest.json").exists() or (root / "assembly_smoke").exists():
        raise ValueError("assembly output already exists; review before rebuilding")
    context.mkdir()
    plan: dict[str, Any] = {"schema_version": "vulveil-linux-container-plan/v1", "status": "PREPARED_AWAITING_CONTAINER_BUILD",
                            "base_image": base_image, "build_network_mode": build_network, "network_mode": "none", "host_mounts": [], "ports": [], "sides": {}}
    assembled = copy.deepcopy(spec)
    assembled["source"] = {"vulnerable": {"root": "container/vulnerable/source"},
                           "fixed": {"root": "container/patched/source"},
                           "role": spec["source"].get("role"),
                           "source_commit": spec["source"].get("source_commit")}
    assembled["external_boundary"] = boundary
    assembled["environment"].update({"os_policy": "Linux-container", "base_image": base_image,
        "build_network_mode": build_network,
        "container_security": {"network_mode": "none", "cap_drop": ["ALL"], "no_new_privileges": True,
                               "read_only_rootfs": True, "host_mounts": [], "ports": []},
        "source_inventory_sha256": {side: hashlib.sha256(json.dumps(items, sort_keys=True).encode()).hexdigest()
                                    for side, items in inventories.items()}})
    if analysis_roots:
        assembled["analysis_source"] = {
            "vulnerable": {"root": "container/analysis/vulnerable/source"},
            "fixed": {"root": "container/analysis/patched/source"},
            "role": "dependency_analysis", "status": "VERIFIED",
        }
        assembled["environment"]["analysis_source_inventory_sha256"] = {
            side: hashlib.sha256(json.dumps(items, sort_keys=True).encode()).hexdigest()
            for side, items in analysis_inventories.items()
        }
    for side in ("vulnerable", "patched"):
        side_context = context / side
        copied = side_context / "source"
        shutil.copytree(roots[side], copied, ignore=shutil.ignore_patterns(*EXCLUDED))
        if _inventory(copied) != inventories[side]:
            raise ValueError("source changed during assembly")
        if analysis_roots:
            analysis_copied = context / "analysis" / side / "source"
            shutil.copytree(analysis_roots[side], analysis_copied, ignore=shutil.ignore_patterns(*EXCLUDED))
            if _inventory(analysis_copied) != analysis_inventories[side]:
                raise ValueError("dependency analysis source changed during assembly")
        dockerfile = side_context / "Dockerfile"
        dockerfile.write_text(_dockerfile(ecosystem, base_image, spec["server_runner"][side]["command"]), encoding="utf-8")
        tag = f"vulveil-{re.sub(r'[^a-z0-9_.-]+', '-', spec['case_id'].lower()).strip('-')[:48]}-{side}:local"
        build_command = ["docker", "build", "--pull=false", "--network", build_network, "--file", str(dockerfile), "--tag", tag, str(side_context)]
        plan["sides"][side] = {"dockerfile": str(dockerfile.relative_to(root)), "dockerfile_sha256": _digest(dockerfile),
                                "image_tag": tag, "build_command": build_command, "source_inventory": inventories[side]}
    assembled["environment"]["dockerfiles"] = {side: plan["sides"][side]["dockerfile"] for side in plan["sides"]}
    assembled["environment"]["dockerfile_sha256"] = {side: plan["sides"][side]["dockerfile_sha256"] for side in plan["sides"]}
    if not build:
        (root / "container_plan.json").write_text(json.dumps(plan, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        return plan
    try:
        plan["base_image_id"] = _inspect(base_image)
        assembled["environment"]["base_image_id"] = plan["base_image_id"]
        image_ids = {}
        for side in ("vulnerable", "patched"):
            result = _run(plan["sides"][side]["build_command"])
            if result.returncode:
                raise ValueError(f"{side} image build failed: {(result.stderr or result.stdout)[-1200:]}")
            image_ids[side] = _inspect(plan["sides"][side]["image_tag"])
            plan["sides"][side]["image_id"] = image_ids[side]
            command = ["docker", "run", "--rm", "-i", "--network", "none", "--cap-drop=ALL",
                       "--security-opt", "no-new-privileges", "--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
                       "--pids-limit", "256", "--user", "10001:10001", "--env", "HOME=/tmp", "--env", "XDG_CACHE_HOME=/tmp",
                       image_ids[side], *spec["server_runner"][side]["command"]]
            assembled["server_runner"][side].update({"command": command, "cwd": "."})
        if ecosystem == "pypi":
            installed = {side: _python_inventory(image_ids[side]) for side in ("vulnerable", "patched")}
            target = re.sub(r"[-_.]+", "-", dependency_name).lower()
            check_target = origin in {"DIRECT_RUNTIME_DEPENDENCY", "MCP_FRAMEWORK"}
            if check_target:
                for side, expected in (("vulnerable", dependency_vulnerable), ("patched", dependency_fixed)):
                    if installed[side].get(target) != expected:
                        raise ValueError(f"{side} image contains the wrong target dependency version")
            if ({name: version for name, version in installed["vulnerable"].items() if not check_target or (name != target and not name.startswith(target + "/"))}
                    != {name: version for name, version in installed["patched"].items() if not check_target or (name != target and not name.startswith(target + "/"))}):
                raise ValueError("installed non-target Python dependencies differ across images")
            for side in installed:
                plan["sides"][side]["installed_inventory"] = installed[side]
        else:
            installed = {side: _npm_inventory(image_ids[side]) for side in ("vulnerable", "patched")}
            target = dependency_name
            check_target = origin in {"DIRECT_RUNTIME_DEPENDENCY", "MCP_FRAMEWORK"}
            if check_target:
                for side, expected in (("vulnerable", dependency_vulnerable), ("patched", dependency_fixed)):
                    if installed[side].get(target) != expected:
                        raise ValueError(f"{side} image contains the wrong target npm dependency version")
            for side in installed:
                plan["sides"][side]["installed_inventory"] = installed[side]
            if ({name: version for name, version in installed["vulnerable"].items() if not check_target or name != target}
                    != {name: version for name, version in installed["patched"].items() if not check_target or name != target}):
                raise ValueError("installed non-target npm dependencies differ across images")
        assembled["environment"].update({"container_image_ids": image_ids, "baseline_manifest": "baseline_environment_manifest.json"})
        verify_container_images(assembled)
        assembled["status"] = "ready"
        if validate_blind_case(assembled):
            raise ValueError("assembled case violates blind contract")
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=root, prefix="assembled-smoke-", suffix=".json", delete=False) as stream:
            json.dump(assembled, stream, ensure_ascii=False)
            smoke_case = Path(stream.name)
        try:
            for side in ("vulnerable", "patched"):
                result = run_prepared_case(smoke_case, side, root / "assembly_smoke" / side)
                evidence = _read_evidence(Path(result["evidence"]))
                if not evidence["valid"] or not any(row.get("actual_next_model_request") is True for row in evidence["rows"]):
                    raise ValueError(f"{side} smoke lacks exact L0-L4 evidence")
        finally:
            smoke_case.unlink(missing_ok=True)
        assembled["environment"]["host_smoke"] = "paired-L0-L4-passed"
        assembled["case_hash"] = hashlib.sha256(json.dumps({k: v for k, v in assembled.items() if k != "case_hash"}, sort_keys=True).encode()).hexdigest()
        assembled["_blind_case_base_dir"] = str(root)
        baseline = build_frozen_environment_manifest(assembled, root / "baseline", producer="linux-case-assembly")
        if compare_environment_manifests(baseline, build_frozen_environment_manifest(assembled, root / "check"))["status"] != "MATCHED":
            raise ValueError("frozen parity failed")
        assembled.pop("_blind_case_base_dir")
        (root / "baseline_environment_manifest.json").write_text(json.dumps(baseline, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        case_path.write_text(json.dumps(assembled, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        plan["status"] = "READY"
    except (OSError, ValueError, subprocess.TimeoutExpired, RuntimeError) as exc:
        plan["status"] = "ASSEMBLY_FAILED"
        plan["reason"] = f"{type(exc).__name__}: {exc}"
    (root / "container_plan.json").write_text(json.dumps(plan, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return plan


def main() -> int:
    parser = argparse.ArgumentParser(description="Assemble label-free case into Linux containers")
    parser.add_argument("--case", type=Path, required=True)
    parser.add_argument("--base-image", required=True)
    parser.add_argument("--external-boundary", required=True)
    parser.add_argument("--build", action="store_true")
    parser.add_argument("--build-network", choices=("none", "default"), default="none")
    args = parser.parse_args()
    result = assemble_linux_case(args.case, base_image=args.base_image,
                                 external_boundary=json.loads(args.external_boundary),
                                 build=args.build, build_network=args.build_network)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["status"] == "READY" else 2


if __name__ == "__main__":
    raise SystemExit(main())
