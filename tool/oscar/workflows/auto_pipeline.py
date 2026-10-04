"""Blind case resolver and automation entry point.

The resolver intentionally does not inspect active GT, canonical GT packages,
GT labels, or GT evidence. Registered cases must be blind case contracts.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Iterator

from oscar.paths import CONFIG_ROOT, TOOL_ROOT

try:
    from oscar.runtime.blind_runtime import run_blind_case
    from oscar.workflows.stage0_onboarding import discover_candidate
    from oscar.workflows.stage2_readiness import assess_case
except ImportError:  # pragma: no cover - direct script execution
    from oscar.runtime.blind_runtime import run_blind_case
    from oscar.workflows.stage0_onboarding import discover_candidate
    from oscar.workflows.stage2_readiness import assess_case


def normalize(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")


def package_matches(package: str, repository: str) -> bool:
    package_key = normalize(package)
    repo_key = normalize(repository)
    repo_tail = normalize(repository.rsplit("/", 1)[-1])
    candidates = {repo_key, repo_tail}
    if repo_tail.startswith("mcp-"):
        candidates.add(repo_tail[4:])
    if repo_tail.endswith("-mcp-server"):
        candidates.add(repo_tail[:-11])
    return package_key in candidates or any(
        package_key in candidate or candidate in package_key for candidate in candidates
    )


def jsonl_rows(path: Path) -> Iterator[dict[str, Any]]:
    if not path.exists():
        return
    with path.open(encoding="utf-8") as stream:
        for line in stream:
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(value, dict):
                yield value


def _registry_rows(root: Path) -> list[dict[str, Any]]:
    candidates = [
        CONFIG_ROOT / "blind_registry.json" if root.resolve() == TOOL_ROOT.parent.resolve() else root / "01_oscar" / "config" / "blind_registry.json",
        root / "01_oscar" / "blind_registry.json",
        root / "vulveil" / "blind_registry.json",
        root / "blind_registry.json",
    ]
    path = next((candidate for candidate in candidates if candidate.exists()), None)
    if path is None:
        return []
    value = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(value, dict):
        value = value.get("cases", [])
    if not isinstance(value, list):
        return []
    rows: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        case_file = item.get("case_file")
        if isinstance(case_file, str):
            base = TOOL_ROOT if path == CONFIG_ROOT / "blind_registry.json" else path.parent
            referenced = (base / case_file).resolve()
            if not referenced.exists():
                continue
            loaded = json.loads(referenced.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                loaded = dict(loaded)
                loaded["_blind_case_base_dir"] = str(referenced.parent)
                loaded["_readiness"] = assess_case(loaded, str(referenced))
                rows.append(loaded)
        else:
            loaded = dict(item)
            loaded["_blind_case_base_dir"] = str(path.parent)
            loaded["_readiness"] = assess_case(loaded, "registry:inline")
            rows.append(loaded)
    return rows


def resolve_case(
    root: Path, advisory: str, package: str, vulnerable_version: str, fixed_version: str
) -> dict[str, Any]:
    for spec in _registry_rows(root):
        identity = spec.get("identity", {})
        server = spec.get("server", {})
        repository = server.get("repository", identity.get("server", ""))
        if str(identity.get("advisory", identity.get("vulnerability", ""))).lower() != advisory.lower():
            continue
        if not package_matches(package, str(identity.get("package", package))) and not package_matches(package, str(repository)):
            continue
        if identity.get("vulnerable_version") != vulnerable_version or identity.get("fixed_version") != fixed_version:
            continue
        readiness = spec.get("_readiness", {})
        if readiness.get("status") != "READY":
            continue
        return {
            "status": "BLIND_MATCH",
            "case": spec,
            "reason": "registered blind case contract matched the four-field identity",
        }

    candidate = discover_candidate(root, advisory, package, vulnerable_version, fixed_version)
    if candidate.get("status") == "CANDIDATE_MATCH":
        return {
            "status": "PREPARATION_REQUIRED",
            "reason": "candidate metadata matched, but no READY blind case is registered",
            "onboarding_requirement": {
                "command": "prepare-case",
                "required_inputs": [
                    "repository", "vulnerable_source_root", "fixed_source_root",
                    "vulnerable_dependency_source_root", "fixed_dependency_source_root",
                    "dependency_patch", "tool_input", "agent_task",
                ],
                "candidate_id": candidate.get("candidate", {}).get("candidate_id"),
            },
            "candidate": {key: candidate.get("candidate", {}).get(key) for key in ("repository", "source_commit", "fixed_version_or_commit", "dependency_name", "resolved_version")},
        }
    if candidate.get("status") == "UNRESOLVED_DIRECT_DEPENDENCY":
        if candidate.get("candidate_count") == 0:
            return {"status": "NOT_FOUND", "reason": "no registered blind case or direct-runtime candidate matched", "onboarding_requirement": {"command": "prepare-case"}}
        return candidate
    return {"status": "UNRESOLVED_DIRECT_DEPENDENCY", "reason": "no registered blind case or direct-runtime candidate matched", "onboarding_requirement": {"command": "prepare-case"}}


def auto_run(
    root: Path,
    advisory: str,
    package: str,
    vulnerable_version: str,
    fixed_version: str,
    output: Path,
) -> dict[str, Any]:
    resolution = resolve_case(root, advisory, package, vulnerable_version, fixed_version)
    output.mkdir(parents=True, exist_ok=True)
    (output / "resolution.json").write_text(
        json.dumps(resolution, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    result: dict[str, Any] = {
        "schema_version": "vulveil-auto-run/v2",
        "input": {
            "advisory": advisory,
            "package": package,
            "vulnerable_version": vulnerable_version,
            "fixed_version": fixed_version,
        },
        "resolution": {key: value for key, value in resolution.items() if key != "case"},
    }
    if resolution["status"] == "BLIND_MATCH":
        case = resolution["case"]
        base_dir = Path(str(case.get("_blind_case_base_dir", root)))
        prediction = run_blind_case(case, output, base_dir=base_dir)
        result["prediction_file"] = str((output / "prediction.json").resolve())
        result["status"] = "PREDICTION_GENERATED"
        result["run_status"] = prediction["run_status"]
    else:
        result["status"] = resolution["status"]
        result["onboarding_requirement"] = resolution.get("onboarding_requirement", {"command": "prepare-case"})
    (output / "auto_run.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return result
