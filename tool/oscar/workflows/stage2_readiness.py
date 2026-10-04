"""Audit label-free cases for autonomous Stage 2 execution readiness."""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from oscar.paths import CONFIG_ROOT, RESEARCH_ROOT, TOOL_ROOT

try:
    from oscar.contracts.component_contract import component_for_localization, component_origin, is_legacy_direct_runtime, validate_vulnerability_component
    from oscar.analysis.component_path import validate_component_tool_path
except ImportError:  # pragma: no cover - direct script execution
    from oscar.contracts.component_contract import component_for_localization, component_origin, is_legacy_direct_runtime, validate_vulnerability_component
    from oscar.analysis.component_path import validate_component_tool_path


WINDOWS_ABSOLUTE = re.compile(r"^[A-Za-z]:[\\/]")
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}


def _has_source_pair(spec: dict[str, Any]) -> bool:
    source = spec.get("source", spec.get("sources", spec.get("source_roots", spec.get("source_root"))))
    if isinstance(source, dict):
        return bool(source.get("vulnerable")) and bool(source.get("fixed", source.get("patched")))
    return bool(spec.get("vulnerable_source")) and bool(spec.get("fixed_source"))


def _requires_analysis_material(spec: dict[str, Any]) -> bool:
    source = spec.get("source")
    origin = component_origin(spec)
    if origin == "MCP_SERVER_SELF":
        return False
    if origin == "MCP_FRAMEWORK":
        return True
    if origin == "DIRECT_RUNTIME_DEPENDENCY":
        if is_legacy_direct_runtime(spec):
            return (
                isinstance(source, dict) and source.get("role") == "server_runtime"
            ) or "analysis_source" in spec or "analysis_patch" in spec
        return True
    return "analysis_source" in spec or "analysis_patch" in spec


def _analysis_material_label(origin: str | None) -> str:
    return "framework" if origin == "MCP_FRAMEWORK" else "dependency"


def _analysis_patch_reason(origin: str | None) -> str:
    return "framework source/patch is missing" if origin == "MCP_FRAMEWORK" else "dependency upstream repair patch is missing"


def _has_analysis_source_pair(spec: dict[str, Any]) -> bool:
    analysis = spec.get("analysis_source")
    if not isinstance(analysis, dict):
        return False
    if analysis.get("status") not in {None, "VERIFIED"}:
        return False
    return bool(analysis.get("vulnerable")) and bool(analysis.get("fixed", analysis.get("patched")))


def _has_patch(spec: dict[str, Any]) -> bool:
    patch = spec.get("patch", spec.get("patch_diff"))
    if isinstance(patch, str):
        return bool(patch.strip())
    if not isinstance(patch, dict):
        return False
    if any(bool(patch.get(key)) for key in ("unified_diff", "diff", "content", "text", "path")):
        return True
    return bool(
        patch.get("git_repo", patch.get("repository"))
        and patch.get("vulnerable_revision", patch.get("base_revision"))
        and patch.get("fixed_revision", patch.get("revision"))
    )


def _has_analysis_patch(spec: dict[str, Any]) -> bool:
    if "analysis_patch" not in spec:
        return False
    patch = spec.get("analysis_patch")
    if isinstance(patch, str):
        return bool(patch.strip())
    if not isinstance(patch, dict) or patch.get("status") not in {None, "VERIFIED"}:
        return False
    if any(bool(patch.get(key)) for key in ("unified_diff", "diff", "content", "text", "path")):
        return True
    return bool(
        patch.get("git_repo", patch.get("repository"))
        and patch.get("vulnerable_revision", patch.get("base_revision"))
        and patch.get("fixed_revision", patch.get("revision"))
    )


def _runner_readiness(spec: dict[str, Any]) -> tuple[bool, list[str]]:
    reasons: list[str] = []
    runner = spec.get("runner", {})
    for side in ("vulnerable", "patched"):
        side_spec = runner.get(side, {}) if isinstance(runner, dict) else {}
        command = side_spec.get("command", [])
        cwd = str(side_spec.get("cwd", ""))
        if not isinstance(command, list) or not command:
            reasons.append(f"runner.{side}.command is missing")
            continue
        if any(WINDOWS_ABSOLUTE.match(str(item)) for item in command) or WINDOWS_ABSOLUTE.match(cwd):
            reasons.append(f"runner.{side} still contains a Windows absolute path")
    return not reasons, reasons


def _transport_host_readiness(spec: dict[str, Any]) -> tuple[bool, list[str]]:
    tool = spec.get("tool", {}) if isinstance(spec.get("tool"), dict) else {}
    configuration = tool.get("configuration", {}) if isinstance(tool.get("configuration"), dict) else {}
    transport = configuration.get("transport", "stdio")
    if transport not in {"stdio", "streamable-http", "sse"}:
        return False, [f"unsupported Tool transport: {transport}"]
    if transport == "stdio":
        return True, []

    reasons: list[str] = []
    server_runner = spec.get("server_runner")
    if not isinstance(server_runner, dict):
        return False, [f"{transport} requires paired managed server_runner adapters"]
    for side in ("vulnerable", "patched"):
        adapter = server_runner.get(side)
        if not isinstance(adapter, dict):
            reasons.append(f"server_runner.{side} is missing")
            continue
        if adapter.get("transport") != transport:
            reasons.append(f"server_runner.{side}.transport does not match Tool transport")
        command = adapter.get("command")
        if not isinstance(command, list) or not command or not all(isinstance(item, str) and item for item in command):
            reasons.append(f"server_runner.{side}.command is not a managed argv list")
        endpoint = adapter.get("endpoint")
        parsed = urlsplit(str(endpoint or ""))
        try:
            port = parsed.port
        except ValueError:
            port = None
        if parsed.scheme != "http" or parsed.hostname not in LOOPBACK_HOSTS or port is None:
            reasons.append(f"server_runner.{side}.endpoint is not a fixed loopback HTTP URL")
        headers = adapter.get("headers", {})
        if not isinstance(headers, dict) or not all(isinstance(key, str) and isinstance(value, str) for key, value in headers.items()):
            reasons.append(f"server_runner.{side}.headers is not a string map")
        elif any(key.lower() in {"authorization", "cookie", "proxy-authorization"} for key in headers):
            reasons.append(f"server_runner.{side}.headers embeds credentials")
    return not reasons, reasons


def _container_readiness(spec: dict[str, Any]) -> tuple[bool, list[str]]:
    environment = spec.get("environment", {})
    image_ids = environment.get("container_image_ids") if isinstance(environment, dict) else None
    if image_ids:
        if spec.get("status") != "ready":
            return False, ["assembled container case is not marked ready"]
        if environment.get("host_smoke") != "paired-L0-L4-passed":
            return False, ["paired shared Host L0-L4 smoke is missing"]
        if not shutil.which("docker"):
            return False, ["paired container images cannot be inspected because Docker is unavailable"]
        reasons: list[str] = []
        for side in ("vulnerable", "patched"):
            image_id = image_ids.get(side) if isinstance(image_ids, dict) else None
            command = spec.get("server_runner", {}).get(side, {}).get("command", [])
            if not isinstance(image_id, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
                reasons.append(f"{side} immutable image ID is missing")
                continue
            if image_id not in command:
                reasons.append(f"{side} server runner does not use its declared image ID")
                continue
            inspected = subprocess.run(["docker", "image", "inspect", image_id, "--format", "{{.Id}}"],
                                       capture_output=True, text=True, encoding="utf-8", errors="replace",
                                       timeout=15, check=False)
            if inspected.returncode or inspected.stdout.strip() != image_id:
                reasons.append(f"{side} immutable image ID is unavailable or drifted")
        return not reasons, reasons
    image = environment.get("container_image") if isinstance(environment, dict) else None
    declared_digest = environment.get("container_image_digest") if isinstance(environment, dict) else None
    if not image:
        return True, []
    if not shutil.which("docker"):
        return False, ["declared container image cannot be inspected because Docker is unavailable"]
    try:
        inspected = subprocess.run(
            ["docker", "image", "inspect", str(image), "--format", "{{.Id}}"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, [f"declared container image inspection failed: {type(exc).__name__}"]
    if inspected.returncode != 0 or not inspected.stdout.strip():
        return False, ["declared container image is unavailable"]
    actual_digest = inspected.stdout.strip()
    if declared_digest and str(declared_digest) != actual_digest:
        return False, [f"container image digest mismatch: declared {declared_digest}, actual {actual_digest}"]
    return True, []


def assess_case(spec: dict[str, Any], source: str) -> dict[str, Any]:
    reasons: list[str] = []
    component_reasons = validate_vulnerability_component(spec)
    reasons.extend(component_reasons)
    origin = component_origin(spec) or "DIRECT_RUNTIME_DEPENDENCY"
    if spec.get("status") == "prepared":
        reasons.append("prepared case still requires Linux container assembly and Host smoke")
    if not _has_source_pair(spec):
        reasons.append("vulnerable/fixed source pair is missing")
    if not _has_patch(spec):
        reasons.append("unified patch is missing")
    analysis_source_ready = _has_analysis_source_pair(spec)
    analysis_patch_ready = _has_analysis_patch(spec)
    analysis_label = _analysis_material_label(origin)
    if _requires_analysis_material(spec) and not analysis_source_ready:
        reasons.append(f"independent {analysis_label} source pair is missing")
    if _requires_analysis_material(spec) and not analysis_patch_ready:
        reasons.append(_analysis_patch_reason(origin))
    runner_ready, runner_reasons = _runner_readiness(spec)
    reasons.extend(runner_reasons)
    transport_ready, transport_reasons = _transport_host_readiness(spec)
    reasons.extend(transport_reasons)
    container_ready, container_reasons = _container_readiness(spec)
    reasons.extend(container_reasons)
    runner = spec.get("runner", {})
    if runner.get("counterfactual_input_mode") != "env-json/v1":
        reasons.append("runner does not attest env-json counterfactual input overrides")
    identity = spec.get("identity", {})
    tool = spec.get("tool", {}) if isinstance(spec.get("tool"), dict) else {}
    server = spec.get("server", {}) if isinstance(spec.get("server"), dict) else {}
    onboarding = spec.get("onboarding", {}) if isinstance(spec.get("onboarding"), dict) else {}
    path_discovery = onboarding.get("tool_path_discovery") if isinstance(onboarding.get("tool_path_discovery"), dict) else None
    selected_tool = tool.get("name") or server.get("tool")
    component = component_for_localization(spec)
    path_errors: list[str] = []
    path_ready = bool(selected_tool)
    if origin != "DIRECT_RUNTIME_DEPENDENCY" and path_discovery is None:
        path_ready = False
    if path_discovery is not None:
        if origin != "DIRECT_RUNTIME_DEPENDENCY":
            path_errors = validate_component_tool_path(
                path_discovery,
                component_name=str(component.get("name", "")),
                tool_name=selected_tool,
            )
            path_ready = path_ready and path_discovery.get("status") == "RESOLVED" and not path_errors
        path_key = "reaches_component" if origin != "DIRECT_RUNTIME_DEPENDENCY" else "reaches_direct_dependency"
        path_ready = sum(
            item.get("tool") == selected_tool and item.get(path_key) is True
            for item in path_discovery.get("tools", []) if isinstance(item, dict)
        ) == 1 and path_ready
    contract = runner.get("evidence_contract", {}) if isinstance(runner, dict) else {}
    if not isinstance(contract, dict):
        contract = {}
    required_levels = contract.get("required_levels", [])
    if not required_levels and isinstance(runner, dict) and any(
        isinstance(runner.get(side), dict) and runner.get(side, {}).get("evidence_file") for side in ("vulnerable", "patched")
    ):
        # Compatibility for pre-Stage-0 blind contracts; the runner's evidence
        # file still has to satisfy all levels at execution time.
        required_levels = [
            "L0_RAW_MCP_RESULT", "L1_NORMALIZED_TOOL_RESULT", "L2_HOST_PROCESSED_TOOL_RESULT",
            "L3_SESSION_TOOL_RESULT", "L4_MODEL_VISIBLE_OBSERVATION",
        ]
        contract = dict(contract)
        contract.setdefault("record_file", runner.get("vulnerable", {}).get("evidence_file"))
    expected_levels = {
        "L0_RAW_MCP_RESULT", "L1_NORMALIZED_TOOL_RESULT", "L2_HOST_PROCESSED_TOOL_RESULT",
        "L3_SESSION_TOOL_RESULT", "L4_MODEL_VISIBLE_OBSERVATION",
    }
    checks = {
        "vulnerability_component": {
            "status": "PASS" if not component_reasons else "FAIL",
            "evidence": spec.get("vulnerability_component", spec.get("direct_runtime_dependency", {})),
            "unresolved_reason": "; ".join(component_reasons) or None,
            "suggested_machine_action": "repair component relation and version fields" if component_reasons else None,
            "requires_human_review": bool(component_reasons),
        },
        "source_pair": {
            "status": "PASS" if _has_source_pair(spec) else "UNRESOLVED",
            "evidence": spec.get("source", spec.get("sources", {})),
            "unresolved_reason": None if _has_source_pair(spec) else "vulnerable/fixed source pair is missing",
            "suggested_machine_action": None if _has_source_pair(spec) else "provide local source roots or cached source archives",
            "requires_human_review": not _has_source_pair(spec),
        },
        "patch": {
            "status": "PASS" if _has_patch(spec) else "UNRESOLVED",
            "evidence": spec.get("patch", spec.get("patch_diff")),
            "unresolved_reason": None if _has_patch(spec) else "unified patch is missing",
            "suggested_machine_action": None if _has_patch(spec) else "generate a local Git diff for the vulnerable/fixed pair",
            "requires_human_review": not _has_patch(spec),
        },
        "analysis_source": {
            "status": "PASS" if analysis_source_ready else ("UNRESOLVED" if _requires_analysis_material(spec) else "NOT_REQUIRED"),
            "evidence": spec.get("analysis_source"),
            "unresolved_reason": None if analysis_source_ready or not _requires_analysis_material(spec) else f"independent {analysis_label} source pair is missing",
            "suggested_machine_action": None if analysis_source_ready or not _requires_analysis_material(spec) else f"provide vulnerable/fixed {analysis_label} source roots and their inventories",
            "requires_human_review": _requires_analysis_material(spec) and not analysis_source_ready,
        },
        "analysis_patch": {
            "status": "PASS" if analysis_patch_ready else ("UNRESOLVED" if _requires_analysis_material(spec) else "NOT_REQUIRED"),
            "evidence": spec.get("analysis_patch"),
            "unresolved_reason": None if analysis_patch_ready or not _requires_analysis_material(spec) else _analysis_patch_reason(origin),
            "suggested_machine_action": None if analysis_patch_ready or not _requires_analysis_material(spec) else f"provide the vulnerable/fixed {analysis_label} repair diff or local revision pair",
            "requires_human_review": _requires_analysis_material(spec) and not analysis_patch_ready,
        },
        "tool_to_component_path": {
            "status": "PASS" if path_ready else "UNRESOLVED",
            "evidence": {"component_origin": origin, "server_tool": server.get("tool"), "tool_name": tool.get("name"), "tool_path_discovery": path_discovery, "effect_modeling": spec.get("effect_modeling")},
            "unresolved_reason": None if path_ready else "; ".join(path_errors) or ("Tool registration or unique framework call path is not identified" if origin == "MCP_FRAMEWORK" else "Tool registration or unique component call path is not identified"),
            "suggested_machine_action": None if path_ready else "run structured Tool path discovery and select one component-reaching Tool",
            "requires_human_review": not path_ready,
        },
        "vulnerable_fixed_runner": {
            "status": "PASS" if runner_ready else "UNRESOLVED",
            "evidence": {"vulnerable": runner.get("vulnerable", {}), "patched": runner.get("patched", {})},
            "unresolved_reason": "; ".join(runner_reasons) or None,
            "suggested_machine_action": "rebind Linux executable, cwd and package root" if runner_reasons else None,
            "requires_human_review": bool(runner_reasons),
        },
        "docker_image_digest": {
            "status": "PASS" if container_ready else "INVALID",
            "evidence": spec.get("environment", {}),
            "unresolved_reason": "; ".join(container_reasons) or None,
            "suggested_machine_action": "build or pin the declared image digest" if container_reasons else None,
            "requires_human_review": bool(container_reasons),
        },
        "shared_host_compatibility": {
            "status": "PASS" if isinstance(spec.get("host_profile"), dict) and spec.get("host_profile", {}).get("id") and transport_ready else "UNRESOLVED",
            "evidence": {"host_profile": spec.get("host_profile", {}), "transport": tool.get("configuration", {}).get("transport", "stdio"), "server_runner": spec.get("server_runner")},
            "unresolved_reason": "; ".join(transport_reasons) if transport_reasons else (None if isinstance(spec.get("host_profile"), dict) and spec.get("host_profile", {}).get("id") else "shared Host profile is missing"),
            "suggested_machine_action": "bind paired loopback managed-server adapters" if transport_reasons else (None if isinstance(spec.get("host_profile"), dict) and spec.get("host_profile", {}).get("id") else "bind the shared-research-host profile"),
            "requires_human_review": not bool(isinstance(spec.get("host_profile"), dict) and spec.get("host_profile", {}).get("id") and transport_ready),
        },
        "l0_l4_evidence_contract": {
            "status": "PASS" if expected_levels.issubset(set(required_levels)) and contract.get("record_file") else "UNRESOLVED",
            "evidence": contract,
            "unresolved_reason": None if expected_levels.issubset(set(required_levels)) and contract.get("record_file") else "L0-L4 evidence contract is incomplete",
            "suggested_machine_action": None if expected_levels.issubset(set(required_levels)) and contract.get("record_file") else "declare all L0-L4 levels and blind_evidence.jsonl",
            "requires_human_review": not bool(expected_levels.issubset(set(required_levels)) and contract.get("record_file")),
        },
        "counterfactual_input_attestation": {
            "status": "PASS" if runner.get("counterfactual_input_mode") == "env-json/v1" else "UNRESOLVED",
            "evidence": {"mode": runner.get("counterfactual_input_mode"), "tool_input_digest": runner.get("tool_input_digest")},
            "unresolved_reason": None if runner.get("counterfactual_input_mode") == "env-json/v1" else "counterfactual input attestation is missing",
            "suggested_machine_action": None if runner.get("counterfactual_input_mode") == "env-json/v1" else "enable env-json/v1 and sign each replay with tool_input_digest",
            "requires_human_review": runner.get("counterfactual_input_mode") != "env-json/v1",
        },
        "no_gt_leakage": {
            "status": "PASS" if not any(key in json.dumps(spec).lower() for key in ("ground_truth_label", "active_agent_gt_pairs", "patched_trigger_blocked")) else "INVALID",
            "evidence": "blind case metadata scan",
            "unresolved_reason": None if not any(key in json.dumps(spec).lower() for key in ("ground_truth_label", "active_agent_gt_pairs", "patched_trigger_blocked")) else "GT-derived field or path is present",
            "suggested_machine_action": None,
            "requires_human_review": False,
        },
    }
    # Keep the old check names readable for existing readiness consumers while
    # making the component check and routing check canonical for new cases.
    checks["direct_runtime_dependency"] = dict(checks["vulnerability_component"])
    checks["tool_to_dependency_path"] = dict(checks["tool_to_component_path"])
    for name, check in checks.items():
        if check["status"] not in {"PASS", "SUPPORTED", "NOT_REQUIRED"}:
            reason = check.get("unresolved_reason") or f"{name} is not ready"
            if reason not in reasons:
                reasons.append(reason)
    return {
        "case_id": str(spec.get("case_id", identity.get("advisory", source))),
        "source": source,
        "status": "READY" if not reasons else "UNASSESSED_INPUTS",
        "source_pair_ready": _has_source_pair(spec),
        "patch_ready": _has_patch(spec),
        "analysis_source_ready": analysis_source_ready if _requires_analysis_material(spec) else None,
        "analysis_patch_ready": analysis_patch_ready if _requires_analysis_material(spec) else None,
        "component_origin": origin,
        "vulnerability_component_ready": not component_reasons,
        "direct_runtime_dependency_ready": not component_reasons if origin == "DIRECT_RUNTIME_DEPENDENCY" else None,
        "runner_ready": runner_ready and transport_ready and container_ready,
        "container_ready": container_ready,
        "counterfactual_runner_ready": runner.get("counterfactual_input_mode") == "env-json/v1",
        "reasons": reasons,
        "checks": checks,
    }


def _load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def build_readiness_report(root: Path) -> dict[str, Any]:
    cases: list[dict[str, Any]] = []
    registry_path = CONFIG_ROOT / "blind_registry.json"
    if registry_path.exists():
        registry = _load_json(registry_path)
        for item in registry.get("cases", []):
            if not isinstance(item, dict):
                continue
            case_file = item.get("case_file")
            if isinstance(case_file, str):
                path = (TOOL_ROOT / case_file).resolve()
                cases.append(assess_case(_load_json(path), str(path.relative_to(root))))
            else:
                cases.append(assess_case(item, f"{TOOL_ROOT.name}/config/blind_registry.json:inline"))
    blueprint_root = root / "02_vulveil_cases" / "cases"
    for path in sorted(blueprint_root.glob("*/blind_case.json")):
        cases.append(assess_case(_load_json(path), str(path.relative_to(root))))
    ready = sum(item["status"] == "READY" for item in cases)
    return {
        "schema_version": "vulveil-stage2-readiness/v1",
        "scope": "label-free blind case inputs only",
        "case_count": len(cases),
        "ready_count": ready,
        "unassessed_input_count": len(cases) - ready,
        "cases": cases,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=RESEARCH_ROOT)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = build_readiness_report(args.root.resolve())
    serialized = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(serialized, encoding="utf-8")
    else:
        print(serialized, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
