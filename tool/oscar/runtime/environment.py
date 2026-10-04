"""Frozen environment manifests and parity checks for OSCAR runs."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any


def stable_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def sha256_file(path: Path) -> str | None:
    if not path.exists() or not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def command_version(command: list[str]) -> str | None:
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=5,
            check=False,
            shell=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    output = (completed.stdout or completed.stderr).strip()
    return output.splitlines()[0] if output else None


def normalized_command(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value]


def _runner_manifest(spec: dict[str, Any]) -> dict[str, Any]:
    runner = spec.get("runner", {})
    result: dict[str, Any] = {}
    for side in ("vulnerable", "patched"):
        side_spec = runner.get(side, {}) if isinstance(runner, dict) else {}
        result[side] = {
            "command": normalized_command(side_spec.get("command")),
            "cwd": str(side_spec.get("cwd", "")),
            "environment": copy.deepcopy(side_spec.get("env", {})),
            "environment_keys": sorted(str(key) for key in side_spec.get("env", {})),
            "tool_calls": copy.deepcopy(side_spec.get("tool_calls", [])),
            "evidence_file": str(side_spec.get("evidence_file", "blind_evidence.jsonl")),
        }
    return result


def _runtime_manifest(spec: dict[str, Any]) -> dict[str, Any]:
    environment = spec.get("environment", {})
    if not isinstance(environment, dict):
        environment = {}
    lockfile = environment.get("lockfile")
    base_dir = Path(str(spec.get("_blind_case_base_dir", "."))).resolve()
    lockfile_path = (base_dir / str(lockfile)).resolve() if lockfile and not Path(str(lockfile)).is_absolute() else Path(str(lockfile)).resolve() if lockfile else None
    node_path = shutil.which("node")
    package_manager = str(environment.get("package_manager", ""))
    package_manager_command = (
        [package_manager, "--version"] if package_manager and shutil.which(package_manager) else []
    )
    return {
        "os": platform.platform(),
        "system": platform.system(),
        "machine": platform.machine(),
        "python": sys.version.split()[0],
        "node": command_version([node_path, "--version"]) if node_path else None,
        "package_manager": package_manager,
        "package_manager_version": command_version(package_manager_command) if package_manager_command else None,
        "lockfile": str(lockfile_path) if lockfile_path else None,
        "lockfile_sha256": sha256_file(lockfile_path) if lockfile_path else None,
        "declared": copy.deepcopy(environment),
    }


def _manifest_core(spec: dict[str, Any]) -> dict[str, Any]:
    identity = spec.get("identity", {})
    server = spec.get("server", {})
    runner = spec.get("runner", {})
    return {
        "schema_version": "vulveil-frozen-environment/v1",
        "case_identity": copy.deepcopy(identity),
        "server": copy.deepcopy(server),
        "dependencies": copy.deepcopy(spec.get("dependencies", {})),
        "source": copy.deepcopy(spec.get("source", spec.get("sources", {}))),
        "patch": copy.deepcopy(spec.get("patch", spec.get("patch_diff", {}))),
        "vulnerability_component": copy.deepcopy(spec.get("vulnerability_component", {})),
        "analysis_source": copy.deepcopy(spec.get("analysis_source", {})),
        "analysis_patch": copy.deepcopy(spec.get("analysis_patch", {})),
        "direct_runtime_dependency": copy.deepcopy(spec.get("direct_runtime_dependency", {})),
        "counterfactuals": copy.deepcopy(spec.get("counterfactuals", [])),
        "tool": copy.deepcopy(spec.get("tool", {})),
        "tool_input": copy.deepcopy(spec.get("tool_input", {})),
        "agent_task": spec.get("agent_task", ""),
        "host_profile": copy.deepcopy(spec.get("host_profile", {})),
        "host_runner": copy.deepcopy(spec.get("host_runner", {})),
        "deepseek_harness_contract": copy.deepcopy(spec.get("deepseek_harness_contract", {})),
        "server_runner": copy.deepcopy(spec.get("server_runner", {})),
        "runtime": _runtime_manifest(spec),
        "external_boundary": copy.deepcopy(spec.get("external_boundary", {})),
        "random_seed": spec.get("random_seed"),
        "repetitions": runner.get("repetitions", spec.get("repetitions", 1)),
        "dynamic_budget": runner.get("dynamic_budget", spec.get("dynamic_budget", 1)),
        "counterfactual_execution": {
            "input_mode": runner.get("counterfactual_input_mode"),
            "budget": runner.get("counterfactual_budget", 0),
            "repetitions": runner.get("counterfactual_repetitions", 1),
        },
        "runner": _runner_manifest(spec),
    }


def build_frozen_environment_manifest(
    spec: dict[str, Any], output_root: Path, *, producer: str = "OSCAR"
) -> dict[str, Any]:
    """Build a digestable manifest without including run-specific output paths."""
    core = _manifest_core(spec)
    return {
        **core,
        "manifest_sha256": sha256_text(stable_json(core)),
        "provenance": {
            "producer": producer,
            "run_id": str(spec.get("run_id", "")),
            "output_root": str(output_root.resolve()),
        },
    }


def write_frozen_environment_manifest(
    spec: dict[str, Any], output_root: Path, *, producer: str = "OSCAR"
) -> dict[str, Any]:
    manifest = build_frozen_environment_manifest(spec, output_root, producer=producer)
    output_root.mkdir(parents=True, exist_ok=True)
    (output_root / "environment_manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return manifest


_ALLOWED_DIFFERENCE_KEYS = {
    "manifest_sha256",
    "provenance",
    "producer",
    "run_id",
    "output_root",
}


def _parity_view(value: Any, key: str | None = None) -> Any:
    if isinstance(value, dict):
        return {
            name: _parity_view(item, name)
            for name, item in value.items()
            if name not in _ALLOWED_DIFFERENCE_KEYS
        }
    if isinstance(value, list):
        return [_parity_view(item, key) for item in value]
    return value


def _diff_paths(left: Any, right: Any, prefix: str = "") -> list[str]:
    if type(left) is not type(right):
        return [prefix or "$" ]
    if isinstance(left, dict):
        paths: list[str] = []
        for key in sorted(set(left) | set(right)):
            child = f"{prefix}.{key}" if prefix else key
            if key not in left or key not in right:
                paths.append(child)
            else:
                paths.extend(_diff_paths(left[key], right[key], child))
        return paths
    if isinstance(left, list):
        paths: list[str] = []
        for index in range(max(len(left), len(right))):
            child = f"{prefix}[{index}]"
            if index >= len(left) or index >= len(right):
                paths.append(child)
            else:
                paths.extend(_diff_paths(left[index], right[index], child))
        return paths
    return [] if left == right else [prefix or "$"]


def compare_environment_manifests(
    gt_manifest: dict[str, Any], vulveil_manifest: dict[str, Any]
) -> dict[str, Any]:
    gt_view = _parity_view(gt_manifest)
    vulveil_view = _parity_view(vulveil_manifest)
    differences = _diff_paths(gt_view, vulveil_view)
    expected_gt_digest = sha256_text(stable_json(gt_view))
    expected_vulveil_digest = sha256_text(stable_json(vulveil_view))
    if gt_manifest.get("manifest_sha256") and gt_manifest.get("manifest_sha256") != expected_gt_digest:
        differences.append("manifest_sha256:gt_invalid")
    if vulveil_manifest.get("manifest_sha256") and vulveil_manifest.get("manifest_sha256") != expected_vulveil_digest:
        differences.append("manifest_sha256:vulveil_invalid")
    return {
        "status": "MATCHED" if not differences else "INVALID_ENVIRONMENT_PARITY",
        "gt_manifest_sha256": gt_manifest.get("manifest_sha256"),
        "vulveil_manifest_sha256": vulveil_manifest.get("manifest_sha256"),
        "differences": differences,
    }
