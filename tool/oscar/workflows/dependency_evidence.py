"""Offline, label-free direct-runtime dependency verification for Stage 0.

Only formats whose root package and resolved version can be identified
unambiguously are accepted. Unknown lockfile formats fail closed.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import tomllib
from pathlib import Path
from typing import Any


def _name(value: str, ecosystem: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower() if ecosystem == "pypi" else value.lower()


def _fingerprint(path: Path) -> dict[str, str]:
    return {"file": path.name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}


def _python_requirement(value: str) -> tuple[str, str] | None:
    match = re.fullmatch(r"\s*([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?\s*(.*)", value.split(";", 1)[0])
    if not match or "@" in match.group(2):
        return None
    return _name(match.group(1), "pypi"), match.group(2).replace(" ", "")


def _server_files(root: Path) -> dict[str, str]:
    excluded_dirs = {".git", ".venv", "venv", "node_modules", "__pycache__", ".pytest_cache"}
    metadata = {"package.json", "package-lock.json", "pyproject.toml", "requirements.txt", "uv.lock"}
    result: dict[str, str] = {}
    for directory, directories, files in os.walk(root, followlinks=False):
        directories[:] = [name for name in directories if name not in excluded_dirs and not (Path(directory) / name).is_symlink()]
        for name in files:
            path = Path(directory) / name
            if path.is_symlink() or name in metadata:
                continue
            result[path.relative_to(root).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def _load_side(root: Path, target: str, ecosystem: str) -> tuple[dict[str, Any], list[str]]:
    errors: list[str] = []
    declarations: list[tuple[Path, dict[str, str]]] = []
    locked: list[tuple[Path, str]] = []
    installed: list[tuple[Path, str]] = []
    try:
        if ecosystem == "npm":
            manifest = root / "package.json"
            if not manifest.is_file():
                return {}, ["package.json is missing from the MCP module root"]
            doc = json.loads(manifest.read_text(encoding="utf-8"))
            if _name(str(doc.get("name", "")), ecosystem) == target:
                errors.append("target dependency is the MCP server package itself")
            deps = doc.get("dependencies", {})
            if not isinstance(deps, dict) or any(not isinstance(v, str) for v in deps.values()):
                return {}, ["package.json dependencies are malformed"]
            declarations.append((manifest, {_name(k, ecosystem): v for k, v in deps.items()}))
            lock = root / "package-lock.json"
            if lock.is_file():
                data = json.loads(lock.read_text(encoding="utf-8"))
                packages = data.get("packages", {})
                root_deps = packages.get("", {}).get("dependencies", {})
                if not isinstance(root_deps, dict) or {_name(k, ecosystem): v for k, v in root_deps.items()} != declarations[0][1]:
                    errors.append("package-lock root dependencies differ from package.json")
                entry = packages.get(f"node_modules/{target}", {})
                if isinstance(entry, dict) and isinstance(entry.get("version"), str):
                    locked.append((lock, entry["version"]))
                else:
                    errors.append("package-lock has no resolved target package")
            installed_path = root / "node_modules" / target / "package.json"
            if installed_path.is_file():
                installed_doc = json.loads(installed_path.read_text(encoding="utf-8"))
                if _name(str(installed_doc.get("name", "")), ecosystem) != target:
                    errors.append("installed npm package name does not match the target")
                elif isinstance(installed_doc.get("version"), str):
                    installed.append((installed_path, installed_doc["version"]))
        else:
            manifest = root / "pyproject.toml"
            requirements = root / "requirements.txt"
            if manifest.is_file():
                doc = tomllib.loads(manifest.read_text(encoding="utf-8"))
                if _name(str(doc.get("project", {}).get("name", "")), ecosystem) == target:
                    errors.append("target dependency is the MCP server package itself")
                values = doc.get("project", {}).get("dependencies", [])
                if not isinstance(values, list):
                    errors.append("pyproject project.dependencies are malformed")
                else:
                    parsed = [_python_requirement(v) if isinstance(v, str) else None for v in values]
                    if any(v is None for v in parsed) or len({v[0] for v in parsed if v}) != len(parsed):
                        errors.append("unsupported Python dependency declaration")
                    else:
                        declarations.append((manifest, dict(parsed)))
            if requirements.is_file():
                values = [v.strip() for v in requirements.read_text(encoding="utf-8").splitlines() if v.strip() and not v.lstrip().startswith("#")]
                parsed = [_python_requirement(v) for v in values]
                if any(v is None for v in parsed) or len({v[0] for v in parsed if v}) != len(parsed):
                    errors.append("unsupported requirements.txt entry or include")
                else:
                    declarations.append((requirements, dict(parsed)))
                    for name, constraint in parsed:
                        if name == target and re.fullmatch(r"==[A-Za-z0-9_.+!-]+", constraint):
                            locked.append((requirements, constraint[2:]))
            if not declarations:
                errors.append("no supported production Python dependency manifest")
            lock = root / "uv.lock"
            if lock.is_file():
                data = tomllib.loads(lock.read_text(encoding="utf-8"))
                versions = {str(v.get("version")) for v in data.get("package", []) if _name(str(v.get("name", "")), ecosystem) == target and v.get("version")}
                if len(versions) == 1:
                    locked.append((lock, next(iter(versions))))
                elif versions:
                    errors.append("uv.lock resolves multiple target versions")
            metadata_paths = [
                *root.glob(".venv/lib/python*/site-packages/*.dist-info/METADATA"),
                *root.glob("venv/lib/python*/site-packages/*.dist-info/METADATA"),
                *root.glob("site-packages/*.dist-info/METADATA"),
            ]
            for metadata in metadata_paths:
                fields: dict[str, str] = {}
                for line in metadata.read_text(encoding="utf-8", errors="replace").splitlines():
                    if ": " in line:
                        key, value = line.split(": ", 1)
                        if key in {"Name", "Version"}:
                            fields[key] = value
                if _name(fields.get("Name", ""), ecosystem) == target and fields.get("Version"):
                    installed.append((metadata, fields["Version"]))
    except (OSError, ValueError, TypeError, AttributeError, KeyError) as exc:
        errors.append(f"dependency metadata cannot be parsed: {type(exc).__name__}")
    if not declarations:
        errors.append("no supported production dependency declaration")
    elif any(target not in deps for _, deps in declarations):
        errors.append("target is not a direct production dependency in every manifest")
    elif any({name for name in deps if name != target} != {name for name in declarations[0][1] if name != target} for _, deps in declarations):
        errors.append("production manifests disagree on non-target direct dependencies")
    if len({v for _, v in locked}) > 1:
        errors.append("target versions disagree between lockfiles")
    if len({v for _, v in installed}) > 1:
        errors.append("installed target versions disagree")
    if not locked:
        errors.append("no supported immutable resolved target version")
    return {
        "declarations": [{**_fingerprint(path), "target_constraint": deps.get(target)} for path, deps in declarations],
        "direct_dependencies": declarations[0][1] if declarations else {},
        "locked": [{**_fingerprint(path), "version": value} for path, value in locked],
        "installed": [{**_fingerprint(path), "version": value} for path, value in installed],
        "resolved_version": locked[0][1] if locked else None,
    }, errors


def verify_dependency_pair(vulnerable_root: Path | None, fixed_root: Path | None,
                           package: str, vulnerable_version: str, fixed_version: str,
                           ecosystem: str) -> dict[str, Any]:
    """Verify independent declarations, resolved versions and pair parity."""
    ecosystem = ecosystem.lower()
    if ecosystem not in {"npm", "pypi"}:
        return {"status": "UNRESOLVED", "reasons": [f"unsupported ecosystem: {ecosystem}"], "sides": {}}
    target = _name(package, ecosystem)
    sides: dict[str, Any] = {}
    reasons: list[str] = []
    for side, root, expected in (("vulnerable", vulnerable_root, vulnerable_version), ("fixed", fixed_root, fixed_version)):
        if root is None or not root.is_dir():
            reasons.append(f"{side} source root is missing")
            continue
        evidence, errors = _load_side(root, target, ecosystem)
        sides[side] = evidence
        reasons.extend(f"{side}: {error}" for error in errors)
        if evidence.get("resolved_version") and evidence["resolved_version"] != expected:
            reasons.append(f"{side}: resolved target version differs from requested version")
        for item in evidence.get("installed", []):
            if item["version"] != expected:
                reasons.append(f"{side}: installed target version differs from requested version")
    if len(sides) == 2:
        v, f = (sides[name]["direct_dependencies"] for name in ("vulnerable", "fixed"))
        if {k: value for k, value in v.items() if k != target} != {k: value for k, value in f.items() if k != target}:
            reasons.append("non-target direct production dependencies differ between sides")
        if vulnerable_version == fixed_version:
            reasons.append("vulnerable and fixed target versions are identical")
        try:
            if _server_files(vulnerable_root) != _server_files(fixed_root):
                reasons.append("MCP server source or non-dependency assets differ between sides")
        except OSError:
            reasons.append("MCP server source parity cannot be verified")
    return {"status": "VERIFIED" if not reasons else "UNRESOLVED", "ecosystem": ecosystem,
            "target": target, "sides": sides, "reasons": sorted(set(reasons)),
            "installed_check": "VERIFIED" if len(sides) == 2 and all(sides[s]["installed"] for s in sides) else "NOT_AVAILABLE"}
