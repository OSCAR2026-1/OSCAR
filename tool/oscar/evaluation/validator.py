"""GT/evidence validation harness.

This module is intentionally separate from the blind OSCAR runtime. It is
the only place in the package that understands active GT labels and exclusion
metadata.
"""

from __future__ import annotations

import argparse
import json
import re
from itertools import product
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import unquote

try:
    from oscar.contracts.component_contract import component_origin
except ImportError:  # pragma: no cover
    from oscar.contracts.component_contract import component_origin


ACTIVE_EXPERIMENT_TYPES = {
    "SENSITIVE_INFORMATION_DISCLOSURE",
    "COMMAND_OR_QUERY_INJECTION",
    "SSRF_WITH_RESPONSE_OR_METADATA",
    "PATH_TRAVERSAL_OR_ARBITRARY_FILE_IO",
    "AUTHENTICATION_OR_AUTHORIZATION_BYPASS",
}

DIRECT_RUNTIME_RELATION_STATUSES = {
    "affected_exact_direct_runtime",
    "affected_commit_direct_runtime",
}


def _active_direct_component_contract(case: dict[str, Any]) -> dict[str, Any] | None:
    """Normalize a GT-domain direct component without applying blind scans."""
    component = case.get("vulnerability_component")
    legacy = case.get("direct_runtime_dependency")
    if not isinstance(component, dict) and not isinstance(legacy, dict):
        return None

    def value(raw: dict[str, Any], *keys: str) -> Any:
        for key in keys:
            if raw.get(key) is not None:
                return raw[key]
        return None

    def normalize(raw: dict[str, Any]) -> dict[str, Any]:
        relation = value(raw, "relation_status")
        relation = {
            "affected_exact_direct_runtime": "AFFECTED_EXACT_COMPONENT",
            "affected_commit_direct_runtime": "AFFECTED_COMMIT_COMPONENT",
        }.get(relation, relation)
        return {
            "origin": value(raw, "origin") or "DIRECT_RUNTIME_DEPENDENCY",
            "name": value(raw, "name", "dependency_name"),
            "purl": value(raw, "purl", "dependency_purl"),
            "repository": value(raw, "repository"),
            "vulnerable_version": value(raw, "vulnerable_version"),
            "fixed_version": value(raw, "fixed_version", "fixed_version_or_commit"),
            "vulnerable_commit": value(raw, "vulnerable_commit"),
            "fixed_commit": value(raw, "fixed_commit"),
            "dependency_depth": value(raw, "dependency_depth"),
            "dependency_scope": value(raw, "dependency_scope"),
            "relation_status": relation,
        }

    normalized_component = normalize(component) if isinstance(component, dict) else None
    normalized_legacy = normalize(legacy) if isinstance(legacy, dict) else None
    if normalized_component and normalized_legacy and normalized_component != normalized_legacy:
        return {"_conflict": True}
    return normalized_component or normalized_legacy


def active_direct_component_valid(case: dict[str, Any]) -> bool:
    """Validate the independent GT record contract, not blind evidence paths."""
    component = _active_direct_component_contract(case)
    if not component or component.get("_conflict"):
        return False
    if component.get("origin") != "DIRECT_RUNTIME_DEPENDENCY":
        return False
    if not component.get("name") or not (component.get("purl") or component.get("repository")):
        return False
    vulnerable = component.get("vulnerable_version") or component.get("vulnerable_commit")
    fixed = component.get("fixed_version") or component.get("fixed_commit")
    return bool(
        vulnerable
        and fixed
        and vulnerable != fixed
        and component.get("dependency_depth") == 1
        and component.get("dependency_scope") == "runtime"
        and component.get("relation_status") in {
            "AFFECTED_EXACT_COMPONENT",
            "AFFECTED_COMMIT_COMPONENT",
        }
    )


def direct_runtime_dependency_valid(case: dict[str, Any]) -> bool:
    """Compatibility predicate; depth/scope are enforced only for direct origin."""
    origin = component_origin(case)
    return origin != "DIRECT_RUNTIME_DEPENDENCY" or active_direct_component_valid(case)


def active_non_direct_component_valid(case: dict[str, Any]) -> bool:
    """Validate active GT component identity without applying Stage 0 advisory rules."""
    origin = component_origin(case)
    component = case.get("vulnerability_component")
    if origin not in {"MCP_SERVER_SELF", "MCP_FRAMEWORK"} or not isinstance(component, dict):
        return False
    has_identity = bool(component.get("name")) and bool(component.get("purl") or component.get("repository"))
    has_version_boundary = (
        bool(component.get("vulnerable_version"))
        and bool(component.get("fixed_version"))
        and component.get("vulnerable_version") != component.get("fixed_version")
    )
    has_commit_boundary = (
        bool(component.get("vulnerable_commit"))
        and bool(component.get("fixed_commit"))
        and component.get("vulnerable_commit") != component.get("fixed_commit")
    )
    return (
        has_identity
        and (has_version_boundary or has_commit_boundary)
        and bool(component.get("relation_status"))
        and bool(component.get("source_evidence"))
        and bool(component.get("patch_evidence"))
        and not isinstance(case.get("direct_runtime_dependency"), dict)
    )


def vulnerability_component_valid(case: dict[str, Any]) -> bool:
    if component_origin(case) in {"MCP_SERVER_SELF", "MCP_FRAMEWORK"}:
        return active_non_direct_component_valid(case)
    return active_direct_component_valid(case)


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


class EvidencePathResolutionError(ValueError):
    """Raised when one manifest path resolves to more than one evidence tree."""


def resolve_evidence_path(root: Path, evidence_root: Path, value: str) -> Path:
    path = Path(value)
    if path.is_absolute() or ".." in path.parts or "\\" in value:
        raise EvidencePathResolutionError(
            f"evidence path must be relative and POSIX-only: {value}"
        )

    direct = (root / path).resolve()
    try:
        direct.relative_to(root.resolve())
    except ValueError as exc:
        raise EvidencePathResolutionError(f"evidence path escapes research root: {value}") from exc
    return direct


def expand_reference(value: str) -> list[str]:
    """Expand the small brace form used by active evidence globs."""
    matches = list(re.finditer(r"\{([^{}]+)\}", value))
    if not matches:
        return [value]
    choices = [match.group(1).split(",") for match in matches]
    expanded = []
    for replacement in product(*choices):
        result = value
        for match, item in reversed(list(zip(matches, replacement))):
            result = result[: match.start()] + item + result[match.end() :]
        expanded.append(result)
    return expanded


def event_rows(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not path.exists():
        return rows
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if value.get("type") == "session_event" and isinstance(value.get("event"), dict):
            rows.append(value["event"])
    return rows


def l4_texts(path: Path) -> list[str]:
    texts: list[str] = []
    for event in event_rows(path):
        if event.get("type") != "assistant/message":
            continue
        content = event.get("data", {}).get("message", {}).get("content", [])
        for block in content:
            if block.get("type") == "text":
                texts.append(str(block.get("text", "")))
    return texts


def evidence_run_paths(path: Path) -> list[Path]:
    if path.name == "host_record.json":
        return [path]
    if path.name != "session_events.jsonl" or not path.parent.name.isdigit():
        return [path]
    side_dir = path.parent.parent
    paths = sorted(side_dir.glob("*/session_events.jsonl"))
    return paths or [path]


def evidence_side(paths: Iterable[str], root: Path, evidence_root: Path) -> dict[str, Any]:
    expanded: list[Path] = []
    resolution_errors: list[dict[str, str]] = []
    for value in paths:
        for reference in expand_reference(value):
            try:
                resolved = resolve_evidence_path(root, evidence_root, reference)
            except EvidencePathResolutionError as exc:
                resolution_errors.append({"path": reference, "error": str(exc)})
                continue
            expanded.extend(evidence_run_paths(resolved))
    unique = list(dict.fromkeys(expanded))
    run_details = []
    for path in unique:
        if path.name == "host_record.json" and path.exists():
            record = load_json(path)
            session = record.get("session", {})
            tool_calls = session.get("tool_calls", [])
            if not tool_calls and session.get("tool_call"):
                tool_calls = [session["tool_call"]]
            tool_results = session.get("tool_results", [])
            if not tool_results and session.get("tool_result"):
                tool_results = [session["tool_result"]]
            request = record.get("model", {}).get("next_request")
            messages = request.get("messages", []) if isinstance(request, dict) else []
            tool_content = [
                message.get("content", [])
                for message in messages
                if isinstance(message, dict) and message.get("role") == "tool"
            ]
            run_details.append(
                {
                    "path": str(path),
                    "exists": True,
                    "event_count": len(tool_calls) + len(tool_results) or (1 if record.get("valid") is True else 0),
                    "tool_calls": len(tool_calls) or len(tool_results) or (1 if record.get("valid") is True else 0),
                    "tool_results": len(tool_results),
                    "l4_text": json.dumps(tool_content[-1:] if tool_content else [], ensure_ascii=False, sort_keys=True),
                    "record_valid": (
                        (
                            record.get("quality", {}).get("invalid_run") is False
                            and all(value == "observed" for value in record.get("evidence_levels", {}).values())
                        )
                        if isinstance(record.get("quality"), dict) and isinstance(record.get("evidence_levels"), dict)
                        else record.get("valid") is True and record.get("l4_attested") is True
                    ),
                }
            )
            continue
        events = event_rows(path)
        run_details.append(
            {
                "path": str(path),
                "exists": path.exists(),
                "event_count": len(events),
                "tool_calls": sum(event.get("type") == "tool/call" for event in events),
                "tool_results": sum(event.get("type") == "tool/result" for event in events),
                "l4_text": "\n".join(l4_texts(path)),
                "record_valid": True,
            }
        )
    return {
        "run_count": len(run_details),
        "valid_run_count": sum(
            detail["exists"]
            and detail["record_valid"]
            and detail["event_count"] > 0
            and detail["tool_calls"] >= 1
            and (detail["tool_results"] == 0 or detail["tool_calls"] == detail["tool_results"])
            for detail in run_details
        ),
        "runs": run_details,
        "resolution_errors": resolution_errors,
    }


def active_case_evidence(
    case: dict[str, Any], root: Path, evidence_root: Path
) -> tuple[dict[str, Any], dict[str, Any]]:
    def side_of(value: str) -> str | None:
        normalized = value.replace("\\", "/").lower()
        if "/vulnerable/" in normalized or "_vulnerable/" in normalized:
            return "vulnerable"
        if "/patched/" in normalized or "_patched/" in normalized or "/fixed/" in normalized or "_fixed/" in normalized:
            return "patched"
        return None

    references = case.get("evidence_files", [])
    if not references and case.get("evidence_glob"):
        references = expand_reference(case["evidence_glob"])
    vulnerable_refs = [
        value
        for value in references
        if side_of(value) == "vulnerable"
        and value.replace("\\", "/").endswith(("session_events.jsonl", "host_record.json"))
    ]
    patched_refs = [
        value
        for value in references
        if side_of(value) == "patched"
        and value.replace("\\", "/").endswith(("session_events.jsonl", "host_record.json"))
    ]
    vulnerable = evidence_side(vulnerable_refs, root, evidence_root)
    patched = evidence_side(patched_refs, root, evidence_root)
    signal = case.get("l4_signal_token")
    structured_vulnerable = case.get("l4_signal_vulnerable")
    structured_patched = case.get("l4_signal_patched")
    vulnerable_l4 = "\n".join(run["l4_text"] for run in vulnerable["runs"])
    patched_l4 = "\n".join(run["l4_text"] for run in patched["runs"])
    if signal is None and isinstance(structured_vulnerable, list) and isinstance(structured_patched, list):
        # Recent Linux annotations preserve a per-run signal decision instead
        # of copying a sensitive marker into the manifest.  This branch is
        # confined to the independent GT validator; blind runtime never reads
        # these fields.
        vulnerable_presence = [value is True for value in structured_vulnerable]
        patched_presence = [value is True for value in structured_patched]
        signal_source = "structured_per_run_annotation"
    else:
        vulnerable_presence = [bool(signal and signal in unquote(run["l4_text"])) for run in vulnerable["runs"]]
        patched_presence = [bool(signal and signal in unquote(run["l4_text"])) for run in patched["runs"]]
        signal_source = "l4_signal_token"
    signal_check = {
        "token": signal,
        "source": signal_source,
        "vulnerable_present": bool(signal and signal in unquote(vulnerable_l4)),
        "patched_present": bool(signal and signal in unquote(patched_l4)),
        "vulnerable_per_run": vulnerable_presence,
        "patched_per_run": patched_presence,
        "vulnerable_all_runs_present": bool(vulnerable_presence) and all(vulnerable_presence),
        "patched_all_runs_absent": not any(patched_presence),
    }
    declared_counts = case.get("repetition_counts", {})
    repetition_counts_match = (
        not declared_counts
        or (
            declared_counts.get("vulnerable") == vulnerable["run_count"]
            and declared_counts.get("patched") == patched["run_count"]
        )
    )
    evidence = {
        "vulnerable": vulnerable,
        "patched": patched,
        "signal": signal_check,
        "repetition_counts_match": repetition_counts_match,
        "paired_valid": (
            vulnerable["run_count"] > 0
            and patched["run_count"] > 0
            and vulnerable["valid_run_count"] == vulnerable["run_count"]
            and patched["valid_run_count"] == patched["run_count"]
            and repetition_counts_match
        ),
    }
    return evidence, {"vulnerable_l4": vulnerable_l4, "patched_l4": patched_l4}


def analyze_active_case(
    case: dict[str, Any], root: Path, evidence_root: Path
) -> dict[str, Any]:
    evidence, _ = active_case_evidence(case, root, evidence_root)
    label = case.get("ground_truth_label")
    trigger = case.get("vulnerable_trigger_status")
    signal = evidence["signal"]
    signal_assertion = case.get(
        "l4_signal_assertion",
        "present" if label == "POSITIVE" else "absent",
    )
    semantic_checks = {
        "binary_label": label in {"POSITIVE", "NEGATIVE"},
        "experiment_type_allowed": case.get("experiment_type") in ACTIVE_EXPERIMENT_TYPES,
        "vulnerability_component_contract": vulnerability_component_valid(case),
        "direct_runtime_dependency_scope": direct_runtime_dependency_valid(case),
        "included_and_annotated": case.get("included_in_gt") is True
        and case.get("annotation_status") == "ANNOTATED",
        "paired_valid": evidence["paired_valid"],
        "positive_signal_reached": label != "POSITIVE"
        or (
            signal_assertion == "present"
            and signal["vulnerable_all_runs_present"]
            and signal["patched_all_runs_absent"]
        ),
        "negative_signal_absent_or_not_applicable": label != "NEGATIVE"
        or (
            signal_assertion in {"absent", "not_applicable"}
            and not signal["vulnerable_present"]
        ),
        "control_attribution_guard": not (
            trigger in {"NOT_TRIGGERED", "UNREACHABLE"}
            and case.get("patch_attribution") == "SUPPORTED"
        ),
    }
    valid = all(semantic_checks.values())
    if label == "POSITIVE" and valid:
        level = "P3-W"
    elif trigger == "TRIGGERED" and case.get("tool_result_status") == "REACHED" and valid:
        level = "P2"
    elif valid:
        level = "P1"
    else:
        level = "UNASSESSED"
    return {
        "active_agent_gt_id": case.get("active_agent_gt_id"),
        "source_gt_id": case.get("source_gt_id"),
        "case_id": case.get("case_id"),
        "experiment_type": case.get("experiment_type"),
        "ground_truth_label": label,
        "vulnerable_trigger_status": trigger,
        "agent_observation_status": case.get("agent_observation_status"),
        "patch_attribution": case.get("patch_attribution"),
        "evidence_mode": case.get("evidence_mode"),
        "witnessed_level": level,
        "semantic_valid": valid,
        "semantic_checks": semantic_checks,
        "evidence": evidence,
        "formal_statistics_included": case.get("formal_statistics_included", False),
        "component_origin": component_origin(case) or "DIRECT_RUNTIME_DEPENDENCY",
    }


def analyze_active(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    gt = load_json(Path(args.gt).resolve())
    evidence_root = (
        Path(args.evidence_root).resolve()
        if args.evidence_root
        else root / "03_gt" / "canonical" / "v1" / "cases"
    )
    cases = gt.get("active_cases", [])
    analyses = [analyze_active_case(case, root, evidence_root) for case in cases]
    excluded_leaked = "excluded_cases" in gt or "excluded_count" in gt
    counts_match = (
        gt.get("positive_count") == sum(item.get("ground_truth_label") == "POSITIVE" for item in cases)
        and gt.get("negative_count") == sum(item.get("ground_truth_label") == "NEGATIVE" for item in cases)
        and gt.get("record_count", len(cases)) == len(cases)
    )
    all_ok = bool(cases) and all(item["semantic_valid"] for item in analyses) and not excluded_leaked and counts_match
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    for item in analyses:
        (output / f"graph_{item['active_agent_gt_id']}.json").write_text(
            json.dumps(item["evidence"], ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
    (output / "analysis.jsonl").write_text(
        "".join(json.dumps(item, ensure_ascii=False, sort_keys=True) + "\n" for item in analyses),
        encoding="utf-8",
    )
    summary = {
        "tool": "OSCAR GT/evidence validator",
        "version": "0.3.0",
        "schema_version": "vulveil-gt-validation/v2",
        "case_count": len(analyses),
        "all_validation_checks_passed": all_ok,
        "positive_count": sum(item["ground_truth_label"] == "POSITIVE" for item in analyses),
        "negative_count": sum(item["ground_truth_label"] == "NEGATIVE" for item in analyses),
        "formal_gt_count": len(cases),
        "excluded_records_in_gt": 0,
        "counts_match_gt_manifest": counts_match,
        "cases": [
            {
                "active_agent_gt_id": item["active_agent_gt_id"],
                "source_gt_id": item["source_gt_id"],
                "ground_truth_label": item["ground_truth_label"],
                "experiment_type": item["experiment_type"],
                "witnessed_level": item["witnessed_level"],
                "semantic_valid": item["semantic_valid"],
                "semantic_checks": item["semantic_checks"],
            }
            for item in analyses
        ],
    }
    (output / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if all_ok else 1


def validate_summary(path: Path) -> dict[str, Any]:
    summary = load_json(path)
    ok = (
        summary.get("schema_version") == "vulveil-gt-validation/v2"
        and bool(summary.get("all_validation_checks_passed"))
        and summary.get("case_count", 0) > 0
        and summary.get("excluded_records_in_gt") == 0
        and summary.get("counts_match_gt_manifest") is True
    )
    return {
        "status": "OK" if ok else "ERROR",
        "case_count": summary.get("case_count"),
        "all_validation_checks_passed": summary.get("all_validation_checks_passed"),
    }


def validate_command(args: argparse.Namespace) -> int:
    result = validate_summary(Path(args.input).resolve())
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["status"] == "OK" else 1
