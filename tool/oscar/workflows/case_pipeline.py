"""Reusable case planning and execution primitives for OSCAR."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import time
from pathlib import Path
from typing import Any


VULNERABILITY_CATEGORIES = {
    "SENSITIVE_INFORMATION_DISCLOSURE",
    "COMMAND_OR_QUERY_INJECTION",
    "SSRF_WITH_RESPONSE_OR_METADATA",
    "PATH_TRAVERSAL_OR_ARBITRARY_FILE_IO",
    "AUTHENTICATION_OR_AUTHORIZATION_BYPASS",
}
EVIDENCE_LEVELS = (
    "L0_RAW_MCP_RESULT",
    "L1_NORMALIZED_TOOL_RESULT",
    "L2_HOST_PROCESSED_TOOL_RESULT",
    "L3_SESSION_TOOL_RESULT",
    "L4_MODEL_VISIBLE_OBSERVATION",
)


def stable_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def case_hash(spec: dict[str, Any]) -> str:
    return hashlib.sha256(stable_json(spec).encode("utf-8")).hexdigest()


def load_case(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def validate_case(spec: dict[str, Any], require_runner: bool = False) -> list[str]:
    errors: list[str] = []
    if spec.get("schema_version") != "vulveil-case/v1":
        errors.append("schema_version must be vulveil-case/v1")
    identity = spec.get("identity", {})
    for field in ("advisory", "package", "vulnerable_version", "fixed_version"):
        if not identity.get(field):
            errors.append(f"identity.{field} is required")
    # The historical field is sampling metadata only.  It is optional and is
    # never a Stage 2 eligibility or effect-kind gate.
    server = spec.get("server", {})
    for field in ("repository", "module", "tool"):
        if not server.get(field):
            errors.append(f"server.{field} is required")
    if not isinstance(spec.get("agent_task"), str) or not spec.get("agent_task"):
        errors.append("agent_task must be a non-empty string")
    if not isinstance(spec.get("tool_input"), dict):
        errors.append("tool_input must be an object")
    host = spec.get("host_profile", {})
    for field in ("id", "model"):
        if not host.get(field):
            errors.append(f"host_profile.{field} is required")
    runner = spec.get("runner", {})
    repetitions = runner.get("repetitions", 1)
    if not isinstance(repetitions, int) or repetitions < 1:
        errors.append("runner.repetitions must be a positive integer")
    for side in ("vulnerable", "patched"):
        command = runner.get(side, {}).get("command")
        if require_runner and (not isinstance(command, list) or not command or not all(isinstance(item, str) for item in command)):
            errors.append(f"runner.{side}.command must be a non-empty argv list")
        if command is not None and (not isinstance(command, list) or not command or not all(isinstance(item, str) for item in command)):
            errors.append(f"runner.{side}.command must be a non-empty argv list")
    timeout = runner.get("timeout_seconds", 120)
    if not isinstance(timeout, (int, float)) or timeout <= 0:
        errors.append("runner.timeout_seconds must be positive")
    contract = runner.get("evidence_contract", {})
    required_levels = contract.get("required_levels", list(EVIDENCE_LEVELS))
    if not isinstance(required_levels, list) or not required_levels or any(level not in EVIDENCE_LEVELS for level in required_levels):
        errors.append("runner.evidence_contract.required_levels must contain valid evidence levels")
    if not isinstance(contract.get("record_file", "recorder.jsonl"), str):
        errors.append("runner.evidence_contract.record_file must be a string")
    oracle = spec.get("oracle", {})
    assertion = oracle.get("l4_signal_assertion", "not_applicable")
    if assertion not in {"present", "absent", "not_applicable"}:
        errors.append("oracle.l4_signal_assertion must be present, absent, or not_applicable")
    if assertion == "present" and not oracle.get("l4_signal_token"):
        errors.append("oracle.l4_signal_token is required when assertion is present")
    return errors


def validate_recorder_file(path: Path, required_levels: list[str]) -> dict[str, Any]:
    records: list[dict[str, Any]] = []
    parse_errors = 0
    if path.exists():
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                parse_errors += 1
                continue
            if isinstance(value, dict):
                records.append(value)
    levels = sorted({record.get("level") for record in records if record.get("level")})
    missing = [level for level in required_levels if level not in levels]
    return {
        "path": str(path),
        "exists": path.exists(),
        "record_count": len(records),
        "levels": levels,
        "missing_levels": missing,
        "parse_errors": parse_errors,
        "valid": path.exists() and not missing and parse_errors == 0,
    }


def make_case_blueprint(
    advisory: str,
    package: str,
    vulnerable_version: str,
    fixed_version: str,
    experiment_type: str,
    repository: str,
    module: str,
    tool: str,
) -> dict[str, Any]:
    return {
        "schema_version": "vulveil-case/v1",
        "status": "blueprint",
        "identity": {
            "advisory": advisory,
            "package": package,
            "vulnerable_version": vulnerable_version,
            "fixed_version": fixed_version,
        },
        "experiment_type": experiment_type,
        "server": {"repository": repository, "module": module, "tool": tool},
        "agent_task": "TODO: freeze the Agent task before execution",
        "tool_input": {},
        "host_profile": {"id": "deterministic", "model": "cli-mock", "temperature": 0},
        "runner": {
            "repetitions": 3,
            "timeout_seconds": 120,
            "evidence_contract": {"required_levels": list(EVIDENCE_LEVELS), "record_file": "recorder.jsonl"},
            "vulnerable": {"command": [], "cwd": "", "env": {}},
            "patched": {"command": [], "cwd": "", "env": {}},
        },
        "effect_modeling": {
            "schema_version": "vulveil-effect-model/v3",
            "requires_source_patch_trace": True,
            "adapter_policy": "python-ast-or-javascript-structured-tokens",
        },
    }


def build_plan(spec: dict[str, Any], output_root: Path) -> dict[str, Any]:
    errors = validate_case(spec, require_runner=True)
    if errors:
        raise ValueError("invalid case: " + "; ".join(errors))
    runner = spec["runner"]
    return {
        "schema_version": "vulveil-execution-plan/v1",
        "status": "planned",
        "case_hash": case_hash(spec),
        "case_id": spec.get("case_id", spec["identity"]["advisory"]),
        "identity": spec["identity"],
        "experiment_type": spec["experiment_type"],
        "host_profile": spec["host_profile"],
        "agent_task": spec["agent_task"],
        "tool_input": spec["tool_input"],
        "repetitions": runner["repetitions"],
        "sides": {
            side: {
                "command": runner[side]["command"],
                "cwd": runner[side].get("cwd", ""),
                "output_root": str(output_root / side),
                "env_keys": sorted(runner[side].get("env", {}).keys()),
            }
            for side in ("vulnerable", "patched")
        },
        "evidence_contract": runner["evidence_contract"],
        "canonical_gt_overwritten": False,
    }


def run_case(spec: dict[str, Any], output_root: Path) -> dict[str, Any]:
    plan = build_plan(spec, output_root)
    runner = spec["runner"]
    output_root.mkdir(parents=True, exist_ok=True)
    (output_root / "plan.json").write_text(json.dumps(plan, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    results: list[dict[str, Any]] = []
    for side in ("vulnerable", "patched"):
        side_spec = runner[side]
        side_root = output_root / side
        side_root.mkdir(parents=True, exist_ok=True)
        for repetition in range(1, runner["repetitions"] + 1):
            run_root = side_root / str(repetition)
            run_root.mkdir(parents=True, exist_ok=True)
            env = os.environ.copy()
            env.update({str(key): str(value) for key, value in side_spec.get("env", {}).items()})
            env.update({
                "VULVEIL_CASE_ID": str(plan["case_id"]),
                "VULVEIL_CASE_SIDE": side,
                "VULVEIL_REPETITION": str(repetition),
                "VULVEIL_OUTPUT_DIR": str(run_root),
            })
            started = time.time()
            try:
                completed = subprocess.run(
                    side_spec["command"],
                    cwd=side_spec.get("cwd") or None,
                    env=env,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=runner["timeout_seconds"],
                    check=False,
                    shell=False,
                )
                result = {
                    "side": side,
                    "repetition": repetition,
                    "exit_code": completed.returncode,
                    "timed_out": False,
                    "started_at": started,
                    "finished_at": time.time(),
                }
                (run_root / "stdout.txt").write_text(completed.stdout, encoding="utf-8")
                (run_root / "stderr.txt").write_text(completed.stderr, encoding="utf-8")
            except subprocess.TimeoutExpired as exc:
                result = {
                    "side": side,
                    "repetition": repetition,
                    "exit_code": None,
                    "timed_out": True,
                    "started_at": started,
                    "finished_at": time.time(),
                }
                (run_root / "stdout.txt").write_text(str(exc.stdout or ""), encoding="utf-8")
                (run_root / "stderr.txt").write_text(str(exc.stderr or ""), encoding="utf-8")
            contract = runner.get("evidence_contract", {})
            recorder = run_root / contract.get("record_file", "recorder.jsonl")
            result["evidence"] = validate_recorder_file(recorder, contract.get("required_levels", list(EVIDENCE_LEVELS)))
            (run_root / "run_result.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            results.append(result)
    summary = {
        "schema_version": "vulveil-execution-run/v1",
        "status": "completed",
        "case_hash": plan["case_hash"],
        "case_id": plan["case_id"],
        "results": results,
        "invalid_run_count": sum(item["timed_out"] or item["exit_code"] != 0 or not item["evidence"]["valid"] for item in results),
        "canonical_gt_overwritten": False,
    }
    (output_root / "run_summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return summary
