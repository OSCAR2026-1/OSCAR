"""Blind OSCAR runtime.

This module consumes only a blind case contract and runner evidence. It never
loads GT files or GT annotations. GT comparison belongs to ``evaluate.py``.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import time
import copy
import hashlib
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from oscar.paths import RESEARCH_ROOT

try:
    from oscar.runtime.environment import compare_environment_manifests, write_frozen_environment_manifest
    from oscar.analysis.effect_modeling import build_effect_model, generate_counterfactual_inputs, inspect_l4_effect
    from oscar.analysis.cross_layer_graph import build_cross_layer_graph, build_simplified_cross_layer_graph, graph_summary
    from oscar.runtime.failure_diagnostics import diagnose_prediction
    from oscar.analysis.impact_assessment import assess_concrete_impact
    from oscar.contracts.prediction_contract import assert_prediction_contract
    from oscar.analysis.localization import build_localization
    from oscar.contracts.component_contract import validate_vulnerability_component
except ImportError:  # pragma: no cover - direct script execution
    from oscar.runtime.environment import compare_environment_manifests, write_frozen_environment_manifest
    from oscar.analysis.effect_modeling import build_effect_model, generate_counterfactual_inputs, inspect_l4_effect
    from oscar.analysis.cross_layer_graph import build_cross_layer_graph, build_simplified_cross_layer_graph, graph_summary
    from oscar.runtime.failure_diagnostics import diagnose_prediction
    from oscar.analysis.impact_assessment import assess_concrete_impact
    from oscar.contracts.prediction_contract import assert_prediction_contract
    from oscar.analysis.localization import build_localization
    from oscar.contracts.component_contract import validate_vulnerability_component


EVIDENCE_LEVELS = (
    "L0_RAW_MCP_RESULT",
    "L1_NORMALIZED_TOOL_RESULT",
    "L2_HOST_PROCESSED_TOOL_RESULT",
    "L3_SESSION_TOOL_RESULT",
    "L4_MODEL_VISIBLE_OBSERVATION",
)

_FORBIDDEN_KEYS = {
    "ground_truth_label",
    "ground_truth",
    "gt",
    "gt_id",
    "active_gt_id",
    "vulnerable_label",
    "patched_trigger_blocked",
    "annotation_status",
    "annotation",
    "gt_annotation",
    "included_in_gt",
    "active_agent_gt_id",
    "source_gt_id",
    "gt_label_schema",
    "impact_label",
    "expected_subtype",
}
_FORBIDDEN_VALUES = {"POSITIVE", "NEGATIVE", "UNASSESSED"}
_RUNTIME_VALIDATION_FIELDS = {
    "validation_conclusion",
    "runtime_validation_status",
    "attestation_status",
}
_RUNTIME_EFFECT_FIELDS = {
    "classification_status",
    "provenance_status",
    "effect_realization.status",
    "propagation.tool_result",
    "propagation.host",
    "propagation.session",
    "propagation.agent_observation",
    "propagation.max_reached_level",
    "realization_status",
    "patch_attribution",
    "impact_status",
    "effect_status",
}
_RUNTIME_VALIDATION_VALUES = {
    "CHECKER_SPECIFIC_VALIDATED",
    "PAIRED_EFFECT_DIFFERENCE_ONLY",
    "UNASSESSED",
}
_FORBIDDEN_PATH_PARTS = {
    "active_agent_gt_pairs.json",
    "ground_truth",
    "gt_pilot",
    "dsh_remaining",
    "dsh_controls",
    "patched_trigger_blocked",
    "recorder",
    "hidden_gt",
}


class BlindCaseError(ValueError):
    """Raised when a case violates the blind runtime contract."""


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _adapt_legacy_v1_case(spec: dict[str, Any]) -> dict[str, Any]:
    """Normalize the historical public v1 contract without adding labels."""
    if spec.get("schema_version") != "vulveil-blind-case/v1":
        return spec
    adapted = copy.deepcopy(spec)
    identity = adapted.setdefault("identity", {})
    component = adapted.get("component", {})
    identity.setdefault("package", component.get("name"))
    identity.setdefault("vulnerable_version", component.get("vulnerable_version"))
    identity.setdefault("fixed_version", component.get("fixed_version"))
    repository = identity.get("repository", "")
    adapted.setdefault("server", {
        "repository": repository,
        "module": repository.rstrip("/").rsplit("/", 1)[-1],
        "commit": identity.get("repository_commit", ""),
    })
    tool = adapted.get("tool")
    if isinstance(tool, dict) and "configuration" not in tool:
        tool["configuration"] = {"transport": tool.get("transport", "stdio")}
    if isinstance(tool, dict) and not tool.get("name"):
        tool["name"] = "host-defined-tool-sequence"
    profile = adapted.get("host_profile")
    if isinstance(profile, dict):
        profile.setdefault("model", profile.get("id", "shared-research-host/v1"))
    runner = adapted.get("runner")
    if isinstance(runner, dict):
        for side in ("vulnerable", "patched"):
            side_spec = runner.get(side)
            if isinstance(side_spec, dict) and side_spec.get("evidence_file") == "host_record.json":
                side_spec["evidence_file"] = "evidence.jsonl"
    return adapted


def _adapt_public_case(spec: dict[str, Any]) -> dict[str, Any]:
    return _adapt_legacy_v1_case(_adapt_v3_case(spec))


def _adapt_v3_case(spec: dict[str, Any]) -> dict[str, Any]:
    """Adapt the public v3 contract to the legacy internal runtime shape.

    The adapter is intentionally one-way and in-memory: v3 remains the only
    persisted blind contract, while existing Stage 1-4 code receives the
    normalized fields it already understands.
    """
    if spec.get("schema_version") != "vulveil-blind-case/v3":
        return spec
    public = spec.get("public_vulnerability", {})
    source = spec.get("source", {})
    analysis_source = spec.get("analysis_source", {})
    analysis_patch = spec.get("analysis_patch", {})
    frozen_input = spec.get("frozen_input", {})
    task = spec.get("agent_task", {})
    profile = spec.get("host_profile", {})
    environment = spec.get("environment", {})
    runner = spec.get("runner", {})
    advisory = str(public.get("advisory_id", ""))
    package = str(public.get("component_name", ""))
    vulnerable_version = str(public.get("vulnerable_version", ""))
    fixed_version = str(public.get("fixed_version", ""))
    repository = str(public.get("repository_url", ""))
    source_commit = str(public.get("source_commit", ""))
    source_evidence = [{
        "ref": source_commit,
        "advisory_id": advisory,
        "component": {"name": package, "purl": public.get("component_purl"), "repository": repository},
        "version": vulnerable_version,
    }]
    patch_evidence = [{
        "ref": public.get("patch_url"),
        "advisory_id": advisory,
        "component": {"name": package, "purl": public.get("component_purl"), "repository": repository},
        "vulnerable_version": vulnerable_version,
        "fixed_version": fixed_version,
    }]
    component: dict[str, Any] = {
        "origin": public.get("component_origin"),
        "name": package,
        "purl": public.get("component_purl"),
        "repository": repository,
        "vulnerable_version": vulnerable_version,
        "fixed_version": fixed_version,
        "vulnerable_commit": source_commit,
        "relation_status": "AFFECTED_EXACT_COMPONENT",
        "source_evidence": source_evidence,
        "patch_evidence": patch_evidence,
    }
    if public.get("component_origin") == "DIRECT_RUNTIME_DEPENDENCY":
        component.update({"dependency_depth": 1, "dependency_scope": "runtime"})

    def adapt_side(side: str) -> dict[str, Any]:
        value = runner.get(side, {})
        return {
            "command": value.get("command", []),
            "cwd": "",
            "env": value.get("environment", {}),
            "evidence_file": "evidence.jsonl",
        }

    return {
        "schema_version": "vulveil-localization/v1",
        "case_id": spec.get("case_id"),
        "identity": {
            "advisory": advisory,
            "package": package,
            "vulnerable_version": vulnerable_version,
            "fixed_version": fixed_version,
        },
        "advisory_semantics": copy.deepcopy(public.get("advisory_semantics")),
        "server": {"repository": repository, "module": package, "commit": source_commit},
        "vulnerability_component": component,
        "source": {
            "role": "server_runtime",
            "vulnerable": {"root": source.get("vulnerable_root"), "tree_sha256": source.get("vulnerable_tree_sha256")},
            "fixed": {"root": source.get("fixed_root"), "tree_sha256": source.get("fixed_tree_sha256")},
        },
        "analysis_source": analysis_source,
        "analysis_patch": analysis_patch,
        "tool": {"name": spec.get("tool", {}).get("name"), "configuration": {"transport": spec.get("tool", {}).get("transport", "stdio")}},
        "agent_task": task.get("text", "") if isinstance(task, dict) else "",
        "tool_input": frozen_input.get("arguments", {}) if isinstance(frozen_input, dict) else {},
        "tool_sequence": spec.get("tool_sequence", []),
        "host_profile": {"id": profile.get("opaque_id"), "model": "shared-research-host/v3", "profile_sha256": profile.get("profile_sha256")},
        "environment": {
            "image": environment.get("image"),
            "image_id": environment.get("image_id"),
            "network": environment.get("network"),
            "user": environment.get("user"),
            "read_only": environment.get("read_only"),
            "cap_drop": environment.get("cap_drop", []),
            "security_options": environment.get("security_options", []),
        },
        "external_boundary": spec.get("external_boundary", {}),
        "runner": {
            "repetitions": runner.get("repetitions", 3),
            "timeout_seconds": runner.get("timeout_seconds", 60),
            "vulnerable": adapt_side("vulnerable"),
            "patched": adapt_side("fixed"),
        },
    }


def _scan_blind_value(
    value: Any,
    path: str = "$",
    errors: list[str] | None = None,
    *,
    allow_runtime_status: bool = False,
) -> list[str]:
    errors = errors if errors is not None else []
    if isinstance(value, dict):
        for key, item in value.items():
            key_text = str(key)
            key_lower = key_text.lower()
            if key_lower in _FORBIDDEN_KEYS:
                errors.append(f"{path}.{key_text}: GT field is forbidden")
            if key_lower == "recorder" or "recorder" in key_lower:
                errors.append(f"{path}.{key_text}: recorder contract is not allowed in blind runtime")
            _scan_blind_value(item, f"{path}.{key_text}", errors, allow_runtime_status=allow_runtime_status)
        return errors
    if isinstance(value, list):
        for index, item in enumerate(value):
            _scan_blind_value(item, f"{path}[{index}]", errors, allow_runtime_status=allow_runtime_status)
        return errors
    if isinstance(value, str):
        upper = value.upper()
        normalized_path = path.lower()
        runtime_field = any(normalized_path.endswith(f".{field}") for field in _RUNTIME_VALIDATION_FIELDS)
        runtime_effect_field = any(normalized_path.endswith(f".{field}") for field in _RUNTIME_EFFECT_FIELDS)
        runtime_metadata = allow_runtime_status and (
            (upper == "UNASSESSED" and normalized_path.endswith((".status", ".run_status")))
            or (upper.startswith("UNASSESSED") and normalized_path.endswith((".maximum_effect_boundary", ".first_nonpropagation_transition")))
            or (runtime_effect_field and upper in {"UNASSESSED", "NOT_ASSESSED", "NOT_REACHED", "REACHED", "DROPPED", "TRANSFORMED", "REALIZED", "NOT_REALIZED", "SUPPORTED", "PARTIAL", "UNRESOLVED"})
            or (runtime_field and upper in _RUNTIME_VALIDATION_VALUES)
        )
        label_match = re.search(
            r"(?<![A-Za-z0-9_])(POSITIVE|NEGATIVE|UNASSESSED)(?![A-Za-z0-9_])", value, re.IGNORECASE
        )
        forbidden_label = bool(label_match)
        if (upper in _FORBIDDEN_VALUES and not runtime_metadata) or (forbidden_label and not runtime_metadata):
            errors.append(f"{path}: GT label value is forbidden")
        normalized = value.replace("\\", "/").lower()
        for part in _FORBIDDEN_PATH_PARTS:
            if part in normalized:
                errors.append(f"{path}: forbidden GT/evidence path fragment {part}")
        if "ground_truth_label" in normalized or "patched_trigger_blocked" in normalized:
            errors.append(f"{path}: forbidden GT field name")
        if re.search(r"(?<![A-Za-z])GT-\d+(?![A-Za-z0-9])", value, re.IGNORECASE):
            errors.append(f"{path}: GT case identifier is forbidden")
    return errors


def validate_blind_case(spec: dict[str, Any]) -> list[str]:
    spec = _adapt_public_case(spec)
    errors = _scan_blind_value(spec)
    if spec.get("schema_version") not in {"vulveil-blind-case/v1", "vulveil-localization/v1"}:
        errors.append("schema_version must be vulveil-blind-case/v1")
    identity = spec.get("identity", {})
    for field in ("advisory", "package", "vulnerable_version", "fixed_version"):
        if not identity.get(field):
            errors.append(f"identity.{field} is required")
    # Historical v1 cases without a component remain runnable as UNASSESSED;
    # once either contract field is present, malformed input is rejected.
    errors.extend(validate_vulnerability_component(spec, require_present=False))
    server = spec.get("server", {})
    for field in ("repository", "module"):
        if not server.get(field):
            errors.append(f"server.{field} is required")
    tool = spec.get("tool", {})
    if not isinstance(tool, dict) or not tool.get("name"):
        errors.append("tool.name is required")
    if not isinstance(spec.get("agent_task"), str) or not spec.get("agent_task"):
        errors.append("agent_task must be a non-empty string")
    if not isinstance(spec.get("tool_input"), dict):
        errors.append("tool_input must be an object")
    transport = tool.get("configuration", {}).get("transport", "stdio") if isinstance(tool, dict) else "stdio"
    if transport not in {"stdio", "streamable-http", "sse"}:
        errors.append("tool.configuration.transport must be stdio, streamable-http or sse")
    server_runner = spec.get("server_runner")
    if server_runner is not None:
        if not isinstance(server_runner, dict):
            errors.append("server_runner must be an object")
        else:
            for side in ("vulnerable", "patched"):
                adapter = server_runner.get(side, {})
                adapter_transport = adapter.get("transport", transport) if isinstance(adapter, dict) else None
                if adapter_transport != transport:
                    errors.append(f"server_runner.{side}.transport must match Tool transport")
                command = adapter.get("command") if isinstance(adapter, dict) else None
                if not isinstance(command, list) or not command or not all(isinstance(item, str) and item for item in command):
                    errors.append(f"server_runner.{side}.command must be a non-empty argv list")
                endpoint = adapter.get("endpoint") if isinstance(adapter, dict) else None
                if transport in {"streamable-http", "sse"}:
                    parsed = urlsplit(str(endpoint or ""))
                    if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost", "::1"} or parsed.port is None:
                        errors.append(f"server_runner.{side}.endpoint must be an explicit loopback http URL with port")
                    headers = adapter.get("headers", {})
                    if not isinstance(headers, dict) or not all(isinstance(key, str) and isinstance(value, str) for key, value in headers.items()):
                        errors.append(f"server_runner.{side}.headers must be a string map")
                    elif any(key.lower() in {"authorization", "cookie", "proxy-authorization"} for key in headers):
                        errors.append(f"server_runner.{side}.headers must not embed credentials")
                elif endpoint is not None:
                    errors.append(f"server_runner.{side}.endpoint is not allowed for stdio")
    if not isinstance(spec.get("host_profile"), dict) or not spec["host_profile"].get("model"):
        errors.append("host_profile.model is required")
    environment = spec.get("environment", spec.get("environment_manifest"))
    if not isinstance(environment, dict):
        errors.append("environment must be an object")
    runner = spec.get("runner", {})
    repetitions = runner.get("repetitions", spec.get("repetitions", 1))
    budget = runner.get("dynamic_budget", spec.get("dynamic_budget", repetitions))
    if not isinstance(repetitions, int) or repetitions < 1:
        errors.append("runner.repetitions must be a positive integer")
    if not isinstance(budget, int) or budget < 1:
        errors.append("runner.dynamic_budget must be a positive integer")
    counterfactual_mode = runner.get("counterfactual_input_mode")
    if counterfactual_mode not in {None, "env-json/v1"}:
        errors.append("runner.counterfactual_input_mode must be env-json/v1 when present")
    counterfactual_budget = runner.get("counterfactual_budget", 3)
    counterfactual_repetitions = runner.get("counterfactual_repetitions", 1)
    if counterfactual_mode and (not isinstance(counterfactual_repetitions, int) or counterfactual_repetitions < 1):
        errors.append("runner.counterfactual_repetitions must be a positive integer")
    required_counterfactual_budget = 3 * counterfactual_repetitions if isinstance(counterfactual_repetitions, int) else 3
    if counterfactual_mode and (not isinstance(counterfactual_budget, int) or counterfactual_budget < required_counterfactual_budget):
        errors.append("runner.counterfactual_budget must cover every generated intervention repetition")
    for side in ("vulnerable", "patched"):
        side_spec = runner.get(side, {})
        command = side_spec.get("command")
        if not isinstance(command, list) or not command or not all(isinstance(item, str) for item in command):
            errors.append(f"runner.{side}.command must be a non-empty argv list")
        elif _has_workspace_root_bind_mount(command, RESEARCH_ROOT):
            errors.append(f"runner.{side}.command must not bind-mount the OSCAR workspace root")
        evidence_file = str(side_spec.get("evidence_file", "blind_evidence.jsonl"))
        if not evidence_file or "recorder" in evidence_file.lower():
            errors.append(f"runner.{side}.evidence_file must not be a recorder path")
    oracle = spec.get("oracle", {})
    if not isinstance(oracle, dict):
        errors.append("oracle must be an object")
    else:
        # These fields remain readable for old case files, but Stage 2 never
        # uses them as a decision predicate. Source/patch/trace input is
        # intentionally validated by the effect modeler instead.
        for key in ("vulnerability_anchor", "vulnerability_specific_effect", "l4_signal_token"):
            if key in oracle and not isinstance(oracle[key], (str, type(None))):
                errors.append(f"oracle.{key} must be a string or null")
    return sorted(set(errors))


def _safe_environment() -> dict[str, str]:
    blocked_fragments = (
        "ground_truth",
        "active_agent_gt",
        "patched_triggered",
        "patched_trigger_blocked",
        "unassessed",
    )
    return {
        key: value
        for key, value in os.environ.items()
        if not any(fragment in key.lower() for fragment in blocked_fragments)
    }


def _write_text(path: Path, value: Any) -> None:
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    path.write_text(str(value or ""), encoding="utf-8")


def _replace_run_placeholders(value: Any, run_root: Path, spec: dict[str, Any]) -> Any:
    workspace_root = RESEARCH_ROOT
    case_dir = Path(str(spec.get("_blind_case_base_dir", ""))) if spec.get("_blind_case_base_dir") else None
    replacements = {
        "__VULVEIL_OUTPUT_DIR__": str(run_root),
        "__VULVEIL_FRESH_OUTPUT_DIR__": str(run_root),
        "__VULVEIL_RUNNER_FILE__": str(Path(__file__).with_name("prepared_host_runner.py")),
        "__VULVEIL_CASE_FILE__": str(case_dir / "blind_case.json") if case_dir else "__VULVEIL_CASE_FILE__",
        "__VULVEIL_CASE_DIR__": str(case_dir) if case_dir else "__VULVEIL_CASE_DIR__",
        "__VULVEIL_WORKSPACE__": str(workspace_root),
        "__VULVEIL_CASE_ID__": str(spec.get("case_id", spec["identity"]["advisory"])),
        "__VULVEIL_CASE_SIDE__": str(spec.get("_runtime_side", "")),
        "__VULVEIL_REPETITION__": str(spec.get("_runtime_repetition", "")),
    }
    if case_dir is not None and case_dir.parent.name == "cases":
        replacements["__OSCAR_CASESET_ROOT__"] = str(case_dir.parent.parent)
    if isinstance(value, str):
        for placeholder, replacement in replacements.items():
            value = value.replace(placeholder, replacement)
        return value
    if isinstance(value, list):
        return [_replace_run_placeholders(item, run_root, spec) for item in value]
    if isinstance(value, dict):
        return {key: _replace_run_placeholders(item, run_root, spec) for key, item in value.items()}
    return value


def _mount_sources(command: list[str]) -> list[str]:
    sources: list[str] = []
    index = 0
    while index < len(command):
        token = command[index]
        mount_spec = None
        if token in {"-v", "--volume"} and index + 1 < len(command):
            mount_spec = command[index + 1]
            index += 1
        elif token.startswith("--volume="):
            mount_spec = token.split("=", 1)[1]
        elif token == "--mount" and index + 1 < len(command):
            mount_spec = command[index + 1]
            index += 1
            options = dict(
                item.split("=", 1)
                for item in mount_spec.split(",")
                if "=" in item
            )
            mount_spec = options.get("source", options.get("src", ""))
        elif token.startswith("--mount="):
            options = dict(
                item.split("=", 1)
                for item in token.split("=", 1)[1].split(",")
                if "=" in item
            )
            mount_spec = options.get("source", options.get("src", ""))
        if mount_spec:
            source = mount_spec.split(":", 1)[0]
            if source:
                sources.append(source)
        index += 1
    return sources


def _has_workspace_root_bind_mount(command: list[str], workspace_root: Path | None) -> bool:
    for source in _mount_sources(command):
        if source == "__VULVEIL_WORKSPACE__":
            return True
        if workspace_root is not None:
            try:
                if Path(source).resolve() == workspace_root.resolve():
                    return True
            except OSError:
                continue
    return False


def _text_from_value(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    return "" if value is None else str(value)


def _read_evidence(path: Path, signal: str | None = None) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    parse_errors = 0
    if path.exists():
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                parse_errors += 1
                continue
            if isinstance(value, dict):
                rows.append(value)
    levels = [str(row.get("level")) for row in rows if row.get("level")]
    missing_levels = [level for level in EVIDENCE_LEVELS if level not in levels]
    serialized = "\n".join(json.dumps(row, ensure_ascii=False, sort_keys=True) for row in rows)
    contract_errors = _scan_blind_value(rows, "$.evidence")
    forbidden_evidence = sorted(value for value in _FORBIDDEN_VALUES if value in serialized)
    l4_text = "\n".join(
        _text_from_value(row.get("text", row.get("observation", row.get("content", ""))))
        for row in rows
        if row.get("level") == "L4_MODEL_VISIBLE_OBSERVATION"
    )
    effect_text = "\n".join(
        _text_from_value(row.get("text", row.get("effect", row.get("content", ""))))
        for row in rows
        if row.get("level") in EVIDENCE_LEVELS[:4]
    )
    return {
        "path": str(path),
        "exists": path.exists(),
        "record_count": len(rows),
        "levels": sorted(set(levels)),
        "missing_levels": missing_levels,
        "parse_errors": parse_errors,
        "forbidden_evidence_values": forbidden_evidence,
        "blind_contract_errors": contract_errors,
        "l4_signal_present": bool(signal and signal in l4_text),
        "effect_signal_present": bool(signal and signal in effect_text),
        "anchor_reached": any(
            row.get("vulnerability_anchor_reached") is True
            or row.get("anchor_reached") is True
            for row in rows
        ),
        "valid": bool(path.exists()) and not missing_levels and parse_errors == 0 and not contract_errors,
        "rows": rows,
    }


def _tool_input_digest(value: Any) -> str:
    serialized = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def _run_side(
    spec: dict[str, Any],
    output_root: Path,
    side: str,
    repetition: int,
    *,
    tool_input_override: dict[str, Any] | None = None,
    counterfactual_role: str | None = None,
) -> dict[str, Any]:
    runner = spec["runner"][side]
    run_root = (
        output_root / "counterfactuals" / str(counterfactual_role) / side / str(repetition)
        if counterfactual_role
        else output_root / side / str(repetition)
    )
    run_root.mkdir(parents=True, exist_ok=True)
    # The formal image runs as uid 10001. Make only this run-local output mount
    # writable; the runner mount is a single read-only label-free file.
    os.chmod(run_root, 0o777)
    runtime_spec = dict(spec)
    runtime_spec["_runtime_side"] = side
    runtime_spec["_runtime_repetition"] = repetition
    env = _safe_environment()
    env.update({str(key): str(value) for key, value in _replace_run_placeholders(runner.get("env", {}), run_root, runtime_spec).items()})
    env.update(
        {
            "VULVEIL_CASE_ID": str(spec.get("case_id", spec["identity"]["advisory"])),
            "VULVEIL_CASE_SIDE": side,
            "VULVEIL_REPETITION": str(repetition),
            "VULVEIL_DYNAMIC_BUDGET": str(spec["runner"].get("dynamic_budget", 1)),
            "VULVEIL_OUTPUT_DIR": str(run_root),
        }
    )
    effective_input = tool_input_override if tool_input_override is not None else spec.get("tool_input", {})
    effective_input_digest = _tool_input_digest(effective_input)
    if tool_input_override is not None:
        env.update({
            "VULVEIL_TOOL_INPUT_JSON": json.dumps(tool_input_override, ensure_ascii=False, sort_keys=True),
            "VULVEIL_TOOL_INPUT_SHA256": effective_input_digest,
            "VULVEIL_COUNTERFACTUAL_ROLE": str(counterfactual_role or ""),
        })
    started = time.time()
    timeout = float(spec["runner"].get("timeout_seconds", 120))
    command = _replace_run_placeholders(runner["command"], run_root, runtime_spec)
    workspace_root = RESEARCH_ROOT
    if _has_workspace_root_bind_mount(command, workspace_root):
        raise BlindCaseError("runner command must not bind-mount the OSCAR workspace root")
    result: dict[str, Any] = {
        "side": side,
        "repetition": repetition,
        "command": [str(item) for item in runner["command"]],
        "cwd": str(runner.get("cwd", "")),
        "started_at": started,
        "tool_input_digest": effective_input_digest,
        "counterfactual_role": counterfactual_role,
    }
    output_contract_errors: list[str] = []
    try:
        completed = subprocess.run(
            command,
            cwd=_replace_run_placeholders(runner.get("cwd", ""), run_root, runtime_spec) or None,
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
            shell=False,
        )
        result.update({"exit_code": completed.returncode, "timed_out": False})
        _write_text(run_root / "stdout.txt", completed.stdout)
        _write_text(run_root / "stderr.txt", completed.stderr)
        output_contract_errors.extend(_scan_blind_value(completed.stdout, "$.stdout"))
        output_contract_errors.extend(_scan_blind_value(completed.stderr, "$.stderr"))
    except subprocess.TimeoutExpired as exc:
        result.update({"exit_code": None, "timed_out": True})
        _write_text(run_root / "stdout.txt", exc.stdout)
        _write_text(run_root / "stderr.txt", exc.stderr)
    result["finished_at"] = time.time()
    result["output_contract_errors"] = sorted(set(output_contract_errors))
    evidence_reference = Path(
        _replace_run_placeholders(str(runner.get("evidence_file", "blind_evidence.jsonl")), run_root, runtime_spec)
    )
    evidence_path = evidence_reference if evidence_reference.is_absolute() else run_root / evidence_reference
    try:
        evidence_path.resolve().relative_to(run_root.resolve())
    except ValueError:
        result["evidence"] = {
            "path": str(evidence_path),
            "exists": False,
            "record_count": 0,
            "levels": [],
            "missing_levels": list(EVIDENCE_LEVELS),
            "parse_errors": 0,
            "forbidden_evidence_values": [],
            "blind_contract_errors": [],
            "l4_signal_present": False,
            "effect_signal_present": False,
            "anchor_reached": False,
            "valid": False,
        }
        result["valid"] = False
        result["output_dir"] = str(run_root)
        return result
    result["evidence"] = _read_evidence(evidence_path)
    attested_digests = {
        str(row.get("tool_input_digest"))
        for row in result["evidence"].get("rows", [])
        if row.get("tool_input_digest")
    }
    result["tool_input_attested"] = (
        tool_input_override is None
        or attested_digests == {effective_input_digest}
    )
    result["valid"] = (
        not result["timed_out"]
        and result["exit_code"] == 0
        and result["evidence"]["valid"]
        and not result["output_contract_errors"]
        and result["tool_input_attested"]
    )
    result["output_dir"] = str(run_root)
    return result


def _side_summary(results: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "run_count": len(results),
        "valid_run_count": sum(item["valid"] for item in results),
        "l4_signal_per_run": [item["evidence"]["l4_signal_present"] for item in results],
        "effect_signal_per_run": [item["evidence"]["effect_signal_present"] for item in results],
        "anchor_reached_per_run": [item["evidence"]["anchor_reached"] for item in results],
        "runs": results,
    }


def _public_side_summary(summary: dict[str, Any]) -> dict[str, Any]:
    """Keep evidence content while removing run-local paths and timing data."""
    public = copy.deepcopy(summary)
    for run in public.get("runs", []):
        for key in ("command", "cwd", "started_at", "finished_at", "output_dir"):
            run.pop(key, None)
        evidence = run.get("evidence", {})
        evidence.pop("path", None)
    return public


def _execute_counterfactual_matrix(
    spec: dict[str, Any],
    output_root: Path,
    vulnerable_results: list[dict[str, Any]],
    patched_results: list[dict[str, Any]],
    effect_model: dict[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    trigger_fields = sorted({
        str(field)
        for effect in effect_model.get("effects", [])
        for field in effect.get("condition", {}).get("input_fields", [])
    })
    variants = generate_counterfactual_inputs(spec.get("tool_input", {}), trigger_fields)
    cases: list[dict[str, Any]] = [
        {
            "name": "vulnerable-trigger-input",
            "role": "trigger",
            "tool_input": spec.get("tool_input", {}),
            "input_digest": _tool_input_digest(spec.get("tool_input", {})),
            "input_attested": True,
            "trace": [row for run in vulnerable_results for row in run["evidence"].get("rows", [])],
        },
        {
            "name": "fixed-version-same-input",
            "role": "fixed",
            "tool_input": spec.get("tool_input", {}),
            "input_digest": _tool_input_digest(spec.get("tool_input", {})),
            "input_attested": True,
            "trace": [row for run in patched_results for row in run["evidence"].get("rows", [])],
        },
    ]
    summaries: list[dict[str, Any]] = []
    repetitions = int(spec["runner"].get("counterfactual_repetitions", 1))
    remaining_budget = int(spec["runner"].get("counterfactual_budget", 3))
    for variant in variants:
        if variant["role"] == "trigger":
            continue
        variant_runs: list[dict[str, Any]] = []
        for repetition in range(1, repetitions + 1):
            if remaining_budget <= 0:
                break
            remaining_budget -= 1
            variant_runs.append(
                _run_side(
                    spec,
                    output_root,
                    "vulnerable",
                    repetition,
                    tool_input_override=variant["tool_input"],
                    counterfactual_role=variant["role"],
                )
            )
        input_attested = bool(variant_runs) and all(run.get("tool_input_attested") and run.get("valid") for run in variant_runs)
        cases.append({
            "name": variant["kind"],
            "role": variant["role"],
            "tool_input": variant["tool_input"],
            "input_digest": _tool_input_digest(variant["tool_input"]),
            "input_attested": input_attested,
            "trace": [row for run in variant_runs for row in run["evidence"].get("rows", [])],
        })
        summaries.append({
            "role": variant["role"],
            "kind": variant["kind"],
            "input_digest": _tool_input_digest(variant["tool_input"]),
            "input_attested": input_attested,
            "runs": [_public_side_summary({"runs": [run]})["runs"][0] for run in variant_runs],
        })
    return cases, {
        "status": "EXECUTED" if len(summaries) == 3 and all(item["input_attested"] for item in summaries) else "INCOMPLETE",
        "input_mode": "env-json/v1",
        "runs": summaries,
    }


def _graph_gate(cross_layer_graph: dict[str, Any]) -> tuple[str | None, str | None, str]:
    """Return the prediction gate decision without inspecting any GT data."""
    graph_status = cross_layer_graph.get("status")
    graph_validation = cross_layer_graph.get("graph_validation")
    validation_status = graph_validation.get("status") if isinstance(graph_validation, dict) else None
    if validation_status != "OK":
        return "INVALID", "cross_layer_graph_validation_failed", "cross-layer graph validation is not OK"
    if graph_status == "INVALID":
        return "INVALID", "cross_layer_graph_invalid", "cross-layer graph is INVALID"
    if graph_status == "UNASSESSED":
        return "UNASSESSED", "cross_layer_graph_incomplete", "cross-layer graph boundary evidence is incomplete"
    if graph_status == "PARTIAL":
        return None, None, ""
    if graph_status != "COMPLETE":
        return "INVALID", "cross_layer_graph_status_invalid", "cross-layer graph status is not COMPLETE"
    return None, None, ""


def _stage4_level_rank(level: str | None) -> int:
    return {"P0": 0, "P1": 1, "P2-E": 2, "P2-R": 3, "P2-T": 4, "P2-H": 5, "P3-W": 6}.get(str(level), -1)


def _decoded_values(value: Any) -> list[Any]:
    values = [value]
    if isinstance(value, dict):
        for item in value.values():
            values.extend(_decoded_values(item))
    elif isinstance(value, list):
        for item in value:
            values.extend(_decoded_values(item))
    elif isinstance(value, str) and value.lstrip().startswith(("{", "[")):
        try:
            decoded = json.loads(value)
        except json.JSONDecodeError:
            decoded = None
        if isinstance(decoded, (dict, list)):
            values.extend(_decoded_values(decoded))
    return values


def _named_strings(value: Any) -> list[tuple[str, str]]:
    result: list[tuple[str, str]] = []
    for decoded in _decoded_values(value):
        if not isinstance(decoded, dict):
            continue
        for key, item in decoded.items():
            if isinstance(item, str) and len(item) >= 4:
                result.append(("".join(char.lower() for char in str(key) if char.isalnum()), item))
    return result


def _boundary_features(rows: list[dict[str, Any]], tool_input: dict[str, Any]) -> dict[str, bool]:
    payloads = [row.get("content") for row in rows if row.get("level") == "L0_RAW_MCP_RESULT"]
    serialized = "\n".join(json.dumps(payload, ensure_ascii=False, sort_keys=True) for payload in payloads)
    lowered = serialized.lower()
    input_fields = [
        ("".join(char.lower() for char in str(key) if char.isalnum()), value)
        for key, value in tool_input.items()
        if isinstance(value, str) and len(value) >= 4
    ]
    output_fields = [item for payload in payloads for item in _named_strings(payload)]
    echoed = any(
        input_value == output_value
        and (output_name == input_name or output_name.endswith(input_name))
        for input_name, input_value in input_fields
        for output_name, output_value in output_fields
    )
    transformed = any(
        isinstance(value, dict)
        and value.get("redirected") is True
        and isinstance(value.get("finalUrl"), str)
        for payload in payloads
        for value in _decoded_values(payload)
    )
    return {
        "tool_result_failure": any(
            isinstance(payload, dict) and payload.get("isError") is True
            for payload in payloads
        ) or (
            "failed" in lowered
            and ("fatal" in lowered or "exit code" in lowered or "could not" in lowered)
        ),
        "input_echo_without_transition": echoed and not transformed,
    }


def _impact_stage4_run(
    effect_model: dict[str, Any],
    run: dict[str, Any],
    tool_input: dict[str, Any],
) -> dict[str, Any]:
    rows = run.get("evidence", {}).get("rows", [])
    result = inspect_l4_effect(effect_model, rows)
    return {
        **result,
        "repetition": run.get("repetition"),
        "valid": run.get("valid") is True,
        "timed_out": run.get("timed_out") is True,
        "tool_input_digest": run.get("tool_input_digest"),
        "anchor_reached": run.get("evidence", {}).get("anchor_reached") is True,
        "boundary_features": _boundary_features(rows, tool_input),
        "trace_levels": sorted({
            str(row.get("level")) for row in run.get("evidence", {}).get("rows", [])
            if isinstance(row, dict) and row.get("level")
        }),
    }


def _impact_pairing_context(manifest: dict[str, Any]) -> dict[str, Any]:
    def digest(value: Any) -> str:
        raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    return {
        "parity_verified": True,
        "frozen_input_digest": digest(manifest.get("tool_input", {})),
        "agent_task_digest": digest(manifest.get("agent_task", "")),
        "host_session_digest": digest({
            "host_profile": manifest.get("host_profile", {}),
            "host_runner": manifest.get("host_runner", {}),
            "deepseek_harness_contract": manifest.get("deepseek_harness_contract", {}),
        }),
        "external_boundary_digest": digest(manifest.get("external_boundary", {})),
        "environment_manifest_digest": str(manifest.get("manifest_sha256", "")),
    }


def _prediction(
    spec: dict[str, Any],
    manifest: dict[str, Any],
    vulnerable: dict[str, Any],
    patched: dict[str, Any],
    localization: dict[str, Any],
    effect_model: dict[str, Any],
    cross_layer_graph: dict[str, Any],
    counterfactual_execution: dict[str, Any] | None = None,
) -> dict[str, Any]:
    v_runs = vulnerable["runs"]
    p_runs = patched["runs"]
    all_valid = (
        vulnerable["run_count"] > 0
        and patched["run_count"] > 0
        and vulnerable["valid_run_count"] == vulnerable["run_count"]
        and patched["valid_run_count"] == patched["run_count"]
        and vulnerable["run_count"] == patched["run_count"]
    )
    stage4_runs: list[dict[str, Any]] = []
    graph_complete = cross_layer_graph.get("status") == "COMPLETE"
    graph_partial = cross_layer_graph.get("status") == "PARTIAL"
    stage4: dict[str, Any] = {"status": "UNASSESSED", "reason": "paired execution did not reach Stage 4", "runs": []}
    if any(item["timed_out"] for item in [*v_runs, *p_runs]):
        run_status = "BLOCKED"
        invalid_reason = "runner_timeout"
    elif not all_valid:
        run_status = "INVALID"
        invalid_reason = "runner_or_evidence_contract_failed"
    elif localization.get("status") != "LOCALIZED":
        run_status = "UNASSESSED"
        invalid_reason = "localization_unassessed"
        level = None
        reachable = None
        v_l4_presence = []
        v_effect_presence = []
        v_anchor_presence = []
        stage4 = {"status": "UNASSESSED", "reason": "Stage 1 localization is not localized", "runs": []}
    elif effect_model.get("status") != "GENERATED":
        run_status = "UNASSESSED"
        invalid_reason = "effect_model_unassessed"
        level = None
        reachable = None
        v_l4_presence = []
        v_effect_presence = []
        v_anchor_presence = []
        stage4 = {"status": "UNASSESSED", "reason": "effect model is not generated", "runs": []}
    else:
        graph_run_status, graph_reason, graph_message = _graph_gate(cross_layer_graph)
        if graph_run_status is not None:
            run_status = graph_run_status
            invalid_reason = graph_reason
            level = None
            reachable = None
            stage4 = {"status": "UNASSESSED", "reason": graph_message, "runs": []}
        else:
            stage4_runs = [_impact_stage4_run(effect_model, item, spec.get("tool_input", {})) for item in v_runs]
            v_l4_presence = [item.get("status") == "REACHED" for item in stage4_runs]
            v_effect_presence = [any(effect.get("production_status") == "PRODUCED" for effect in item.get("effects", [])) for item in stage4_runs]
            v_tool_presence = [any(effect.get("reached_tool_result") is True for effect in item.get("effects", [])) for item in stage4_runs]
            v_host_presence = [any(effect.get("reached_host_session") is True for effect in item.get("effects", [])) for item in stage4_runs]
            v_resource_presence = [any(effect.get("external_resource_affected") is True for effect in item.get("effects", [])) for item in stage4_runs]
            v_anchor_presence = [item["evidence"]["anchor_reached"] for item in v_runs]
            v_l4 = all(v_l4_presence)
            v_effect = all(v_effect_presence)
            v_tool = all(v_tool_presence)
            v_host = all(v_host_presence)
            v_resource = all(v_resource_presence)
            v_anchor = all(v_anchor_presence)
            unstable_reason = None
            if any(v_l4_presence) and not v_l4:
                unstable_reason = "vulnerable_l4_signal_varied_across_repetitions"
            elif any(v_effect_presence) and not v_effect:
                unstable_reason = "vulnerable_effect_signal_varied_across_repetitions"
            elif any(v_anchor_presence) and not v_anchor:
                unstable_reason = "vulnerable_anchor_reachability_varied_across_repetitions"
            stage4_unassessed = any(item.get("status") == "UNASSESSED" for item in stage4_runs)
            graph_effects = cross_layer_graph.get("effect_observation", {})
            graph_exact_l4 = any(
                item.get("by_side", {}).get("vulnerable", {}).get("exact_l4_observed") is True
                for item in graph_effects.values()
            )
            reached_effect_ids = sorted({
                effect_id
                for item in stage4_runs
                for effect_id in item.get("reached_effect_ids", [])
            })
            not_reached_effect_ids = sorted({
                effect_id
                for item in stage4_runs
                for effect_id in item.get("not_reached_effect_ids", [])
            })
            unassessed_effect_ids = sorted({
                effect_id
                for item in stage4_runs
                for effect_id in item.get("unassessed_effect_ids", [])
            })
            if v_l4 and not graph_exact_l4 and graph_complete:
                unstable_reason = "stage4_graph_exact_l4_mismatch"
            stage4 = {
                "status": "UNASSESSED" if stage4_unassessed else "REACHED" if v_l4 else "NOT_REACHED",
                "graph_exact_l4_observed": graph_exact_l4,
                "reachability_levels": {
                    "P0": True,
                    "P1": v_anchor,
                    "P2-E": v_effect,
                    "P2-R": v_resource,
                    "P2-T": v_tool,
                    "P2-H": v_host,
                    "P3-W": v_l4,
                },
                "per_run_highest_witnessed_level": [item.get("highest_witnessed_level", "P0") for item in stage4_runs],
                "reached_effect_ids": reached_effect_ids,
                "not_reached_effect_ids": not_reached_effect_ids,
                "unassessed_effect_ids": unassessed_effect_ids,
                "runs": stage4_runs,
            }
            per_effect_summary: dict[str, dict[str, Any]] = {}
            for effect_id in sorted({str(effect.get("effect_id")) for item in stage4_runs for effect in item.get("effects", []) if effect.get("effect_id")}):
                observations = [effect for item in stage4_runs for effect in item.get("effects", []) if str(effect.get("effect_id")) == effect_id]
                per_effect_summary[effect_id] = {
                    "effect_kind": observations[0].get("effect_kind") if observations else None,
                    "production_statuses": sorted({str(effect.get("production_status")) for effect in observations}),
                    "highest_witnessed_level": max((effect.get("highest_witnessed_level", "P0") for effect in observations), key=_stage4_level_rank, default="P0"),
                    "external_resource_affected_all_runs": bool(observations) and len(observations) == len(stage4_runs) and all(effect.get("external_resource_affected") is True for effect in observations),
                    "reached_tool_result_all_runs": bool(observations) and len(observations) == len(stage4_runs) and all(effect.get("reached_tool_result") is True for effect in observations),
                    "reached_host_session_all_runs": bool(observations) and len(observations) == len(stage4_runs) and all(effect.get("reached_host_session") is True for effect in observations),
                    "reached_exact_l4_all_runs": bool(observations) and len(observations) == len(stage4_runs) and all(effect.get("reached_exact_l4") is True for effect in observations),
                    "stop_layers": sorted({str(effect.get("stop_layer")) for effect in observations}),
                    "termination_reasons": sorted({str(effect.get("termination_reason")) for effect in observations if effect.get("termination_reason")}),
                    "evidence_refs": sorted({str(ref) for effect in observations for ref in effect.get("evidence_refs", []) if ref}),
                }
            stage4["per_effect"] = per_effect_summary
            if stage4_unassessed:
                run_status = "UNASSESSED"
                invalid_reason = "actual_next_model_request_unassessed"
                level = None
                reachable = None
            elif unstable_reason:
                run_status = "INVALID"
                invalid_reason = unstable_reason
                level = None
                reachable = None
            elif v_l4:
                level = "P3-W_WITNESSED_AGENT_REACHABLE"
                reachable: bool | None = True
            elif v_host:
                level = "P2-H_HOST_SESSION_REACHED"
                reachable = False
            elif v_tool:
                level = "P2-T_TOOL_RESULT_REACHED"
                reachable = False
            elif v_resource:
                level = "P2-R_EXTERNAL_RESOURCE_AFFECTED"
                reachable = False
            elif v_effect:
                level = "P2-E_EFFECT_PRODUCED"
                reachable = False
            elif v_anchor:
                level = "P1_CODE_REACHABLE"
                reachable = False
            else:
                level = "P0_PRESENT"
                reachable = False
            if not stage4_unassessed and unstable_reason is None:
                run_status = "VALID"
                invalid_reason = None
                if graph_partial:
                    # Stage 4 can establish a concrete server/tool effect even
                    # when the graph cannot attest the complete Agent path.
                    # Keep the compatibility reachability fields conservative.
                    level = None
                    reachable = None
    if run_status != "VALID":
        level = None
        reachable = None
    fixed_stage4_runs = [_impact_stage4_run(effect_model, item, spec.get("tool_input", {})) for item in p_runs]
    impact = assess_concrete_impact(
        effect_model,
        stage4_runs,
        vulnerable_anchor_reached=[bool(item.get("evidence", {}).get("anchor_reached")) for item in v_runs],
        fixed_runs=fixed_stage4_runs,
        paired_execution_valid=all_valid and run_status == "VALID",
        cross_layer_path_validated=(
        graph_complete
            and isinstance(cross_layer_graph.get("graph_validation"), dict)
            and cross_layer_graph["graph_validation"].get("status") == "OK"
        ),
        pairing_context=_impact_pairing_context(manifest),
    )
    if run_status != "VALID":
        level = None
        reachable = None
        impact["predicted_impact"] = None
        impact["impact_status"] = "UNASSESSED"
        impact["agent_visible"] = None
        impact["maximum_effect_boundary"] = "UNASSESSED"
        impact["effect_realized"] = None
        impact["impact_effect_ids"] = []
        impact["per_effect"] = {}
    elif graph_partial:
        # A partial graph cannot support an Agent-observation claim.  Preserve
        # the effect boundary and impact result, but do not expose an L4
        # observation as a reachability prediction.
        impact["agent_visible"] = False
        for item in impact.get("per_effect", {}).values():
            if isinstance(item, dict):
                item["agent_visible"] = False
    identity = dict(spec["identity"])
    identity["case_id"] = spec.get("case_id", identity.get("advisory"))
    graph_validation = cross_layer_graph.get("graph_validation")
    if not isinstance(graph_validation, dict):
        graph_validation = {}
    prediction = {
        "schema_version": "vulveil-prediction/v2",
        "case_identity": identity,
        "component_origin": spec.get("vulnerability_component", {}).get("origin") if isinstance(spec.get("vulnerability_component"), dict) else "DIRECT_RUNTIME_DEPENDENCY",
        "run_status": run_status,
        "invalid_reason": invalid_reason,
        "predicted_reachability": reachable,
        "witnessed_level": level,
        "localization": {
            "schema_version": localization.get("schema_version"),
            "status": localization.get("status"),
            "reasons": localization.get("reasons", []),
            "localization_digest": localization.get("localization_digest"),
            "file": "localization.json",
        },
        "effect_model": effect_model,
        "anchor_candidates": localization.get("anchor_candidates", []),
        "cross_layer_graph": {
            "schema_version": cross_layer_graph.get("schema_version"),
            "graph_id": cross_layer_graph.get("graph_id"),
            "graph_digest": cross_layer_graph.get("graph_digest"),
            "status": cross_layer_graph.get("status"),
            "file": "cross_layer_graph.json",
            "validation_file": "graph_validation.json",
            "summary": graph_summary(cross_layer_graph),
        },
        "graph_validation": {
            "status": graph_validation.get("status"),
            "errors": graph_validation.get("errors", []),
        },
        "vulnerable_fixed_evidence": {
            "vulnerable": _public_side_summary(vulnerable),
            "patched": _public_side_summary(patched),
        },
        "runtime_provenance": {
            "runner_contract": "vulveil-blind-runner/v1",
            "stage_1": "patch-mapped-localization/v1",
            "stage_2": "patch-guided-differential-effect-modeling/v3",
            "stage_4": "structured-effect-boundary-inspection/v1",
            "stage_3": "cross-layer-graph-construction/v3",
            "repetitions": spec["runner"].get("repetitions", 1),
            "dynamic_budget": spec["runner"].get("dynamic_budget", 1),
        },
        "counterfactual_execution": counterfactual_execution or {"status": "NOT_SUPPORTED_BY_RUNNER", "runs": []},
        "environment_manifest_digest": manifest["manifest_sha256"],
        "environment_manifest": "environment_manifest.json",
    }
    prediction.update(impact)
    prediction["stage4_analysis"] = stage4
    return prediction


def assert_prediction_blind(prediction: dict[str, Any]) -> None:
    errors = _scan_blind_value(prediction, allow_runtime_status=True)
    if errors:
        raise BlindCaseError("prediction contains forbidden GT content: " + "; ".join(errors))


def run_blind_case(spec: dict[str, Any], output_root: Path, *, base_dir: Path | None = None) -> dict[str, Any]:
    spec = _adapt_public_case(spec)
    errors = validate_blind_case(spec)
    if errors:
        raise BlindCaseError("invalid blind case: " + "; ".join(errors))
    if spec.get("status") == "prepared":
        raise BlindCaseError("prepared case requires verified paired container images before blind execution")
    output_root = output_root.resolve()
    if base_dir is None and spec.get("_blind_case_base_dir"):
        base_dir = Path(str(spec["_blind_case_base_dir"])).resolve()
    if base_dir is not None:
        spec = {**spec, "_blind_case_base_dir": str(base_dir.resolve())}
    if spec.get("environment", {}).get("container_image_ids"):
        if spec.get("status") != "ready" or base_dir is None:
            raise BlindCaseError("INVALID_ENVIRONMENT_PARITY: assembled case root or readiness is missing")
        try:
            from oscar.workflows.linux_case_assembly import verify_assembled_inputs, verify_container_images
        except ImportError:
            from oscar.workflows.linux_case_assembly import verify_assembled_inputs, verify_container_images
        verify_container_images(spec)
        verify_assembled_inputs(spec, base_dir)
    if any("__VULVEIL_CASE_FILE__" in str(item) for side in ("vulnerable", "patched") for item in spec["runner"][side]["command"]):
        if base_dir is None or not (base_dir / "blind_case.json").is_file():
            raise BlindCaseError("prepared Host runner requires its existing blind_case.json base_dir")
    manifest = write_frozen_environment_manifest(spec, output_root)
    baseline_ref = spec.get("environment", {}).get("baseline_manifest")
    if baseline_ref:
        if not base_dir or Path(str(baseline_ref)).is_absolute() or ".." in Path(str(baseline_ref)).parts:
            raise BlindCaseError("INVALID_ENVIRONMENT_PARITY: baseline path must stay in case directory")
        baseline_path = (base_dir / str(baseline_ref)).resolve() if base_dir else Path(str(baseline_ref)).resolve()
        if not baseline_path.is_relative_to(base_dir.resolve()):
            raise BlindCaseError("INVALID_ENVIRONMENT_PARITY: baseline path escapes case directory")
        if not baseline_path.is_file():
            raise BlindCaseError("INVALID_ENVIRONMENT_PARITY: baseline manifest is missing")
        parity = compare_environment_manifests(load_json(baseline_path), manifest)
        if parity["status"] != "MATCHED":
            raise BlindCaseError("INVALID_ENVIRONMENT_PARITY: " + ", ".join(parity["differences"]))
    repetitions = int(spec["runner"].get("repetitions", 1))
    vulnerable_results = [
        _run_side(spec, output_root, "vulnerable", repetition)
        for repetition in range(1, repetitions + 1)
    ]
    patched_results = [
        _run_side(spec, output_root, "patched", repetition)
        for repetition in range(1, repetitions + 1)
    ]
    vulnerable = _side_summary(vulnerable_results)
    patched = _side_summary(patched_results)
    traces = {
        "vulnerable": [row for run in vulnerable_results for row in run["evidence"].get("rows", [])],
        "fixed": [row for run in patched_results for row in run["evidence"].get("rows", [])],
    }
    localization = build_localization(spec, base_dir=base_dir)
    effect_model = build_effect_model(spec, traces, base_dir=base_dir, localization=localization)
    counterfactual_execution: dict[str, Any] | None = None
    if effect_model.get("status") == "GENERATED" and spec["runner"].get("counterfactual_input_mode") == "env-json/v1":
        cases, counterfactual_execution = _execute_counterfactual_matrix(
            spec, output_root, vulnerable_results, patched_results, effect_model
        )
        modeled_spec = copy.deepcopy(spec)
        modeled_spec["counterfactuals"] = cases
        modeled_spec["counterfactual_policy"] = "required"
        effect_model = build_effect_model(modeled_spec, traces, base_dir=base_dir, localization=localization)
        counterfactual_execution["model_status"] = effect_model.get("status")
    cross_layer_graph = build_cross_layer_graph(
        spec,
        effect_model,
        traces,
        vulnerable_results=vulnerable_results,
        fixed_results=patched_results,
        base_dir=base_dir,
        localization=localization,
    )
    cross_layer_graph_view = build_simplified_cross_layer_graph(cross_layer_graph)
    (output_root / "localization.json").write_text(
        json.dumps(localization, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (output_root / "effect_model.json").write_text(
        json.dumps(effect_model, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (output_root / "cross_layer_graph.json").write_text(
        json.dumps(cross_layer_graph, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (output_root / "cross_layer_graph_view.json").write_text(
        json.dumps(cross_layer_graph_view, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (output_root / "graph_validation.json").write_text(
        json.dumps(cross_layer_graph.get("graph_validation", {}), ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    prediction = _prediction(spec, manifest, vulnerable, patched, localization, effect_model, cross_layer_graph, counterfactual_execution)
    assert_prediction_blind(prediction)
    assert_prediction_contract(prediction)
    (output_root / "prediction.json").write_text(
        json.dumps(prediction, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (output_root / "diagnostic.json").write_text(
        json.dumps(diagnose_prediction(prediction), ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return prediction
