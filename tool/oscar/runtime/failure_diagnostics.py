"""Structured, label-free diagnostics for blind OSCAR executions."""

from __future__ import annotations

from typing import Any


SCHEMA_VERSION = "vulveil-run-diagnostic/v1"


def _root_cause(reasons: list[str], *, fallback: str = "UNRESOLVED") -> str:
    """Classify missing blind inputs without consulting GT or guessing a label."""
    text = " ".join(reasons).lower()
    if any(token in text for token in ("l4", "model-visible", "model visible", "actual next", "observation boundary")):
        return "OBSERVATION_BOUNDARY"
    if any(token in text for token in ("tool binding", "tool registration", "tool-to-dependency", "dependency path", "carrier", "sink")):
        return "TOOL_BINDING"
    if "tool result provenance" in text:
        return "TOOL_BINDING"
    if any(token in text for token in ("evidence", "trace", "l0", "l1", "l2", "l3", "provenance")):
        return "EVIDENCE_CONTRACT"
    if any(token in text for token in ("patch", "hunk", "repair diff", "upstream repair")):
        return "PATCH_MATERIAL"
    if any(token in text for token in ("source", "dependency analysis", "direct-runtime", "dependency scope")):
        return "SOURCE_MATERIAL"
    if any(token in text for token in ("container", "docker", "image", "environment", "parity")):
        return "CONTAINER_ENVIRONMENT"
    return fallback


def _origin(prediction: dict[str, Any]) -> str:
    localization = prediction.get("localization", {})
    if isinstance(localization, dict) and localization.get("component_origin"):
        return str(localization["component_origin"])
    return str(prediction.get("component_origin") or "DIRECT_RUNTIME_DEPENDENCY")


def _source_action(origin: str) -> str:
    if origin == "MCP_FRAMEWORK":
        return "supply matching vulnerable/fixed framework source roots and framework identity evidence"
    if origin == "MCP_SERVER_SELF":
        return "supply matching vulnerable/fixed MCP Server source roots and the Server security patch"
    return "supply matching runnable Server source roots, dependency analysis source and direct-runtime evidence"


def _patch_action(origin: str) -> str:
    if origin == "MCP_FRAMEWORK":
        return "supply the framework/SDK repair patch mapped to the component source pair"
    if origin == "MCP_SERVER_SELF":
        return "supply the MCP Server security patch mapped to the Server source pair"
    return "supply the dependency upstream repair patch mapped to the component source pair"


def diagnose_prediction(prediction: dict[str, Any]) -> dict[str, Any]:
    status = str(prediction.get("run_status", "INVALID"))
    reason = str(prediction.get("invalid_reason") or "")
    category = "COMPLETED"
    action = None
    details: list[str] = []
    root_cause = "NONE" if status == "VALID" else "UNRESOLVED"
    retryable = False

    if status == "BLOCKED" or "runner_timeout" in reason:
        category = "RUNNER_TIMEOUT"
        action = "inspect managed server startup, Tool latency and the frozen timeout budget"
        root_cause = "CONTAINER_ENVIRONMENT"
        retryable = True
    elif "ENVIRONMENT_PARITY" in reason.upper() or ("environment" in reason.lower() and "mismatch" in reason.lower()):
        category = "ENVIRONMENT_PARITY"
        action = "rebuild or restore the pinned image, source inventory and baseline manifest"
        root_cause = "CONTAINER_ENVIRONMENT"
        retryable = True
    elif status == "INVALID" and reason == "runner_or_evidence_contract_failed":
        runs = prediction.get("vulnerable_fixed_evidence", {})
        exceptions: list[str] = []
        contract_errors: list[str] = []
        for side in ("vulnerable", "patched"):
            for run in runs.get(side, {}).get("runs", []):
                if run.get("exception"):
                    exceptions.append(str(run["exception"]))
                contract_errors.extend(str(item) for item in run.get("output_contract_errors", []))
        joined = " ".join(exceptions).lower()
        if any(token in joined for token in ("mcp", "jsonrpc", "session", "transport", "server")):
            category = "TRANSPORT_OR_SERVER"
            action = "inspect the managed server command, endpoint, session and JSON-RPC transcript"
            root_cause = "CONTAINER_ENVIRONMENT"
            retryable = True
        else:
            category = "EVIDENCE_CONTRACT"
            action = "repair the runner so every repetition emits attested L0-L4 evidence"
            root_cause = "EVIDENCE_CONTRACT"
        details.extend(exceptions)
        details.extend(contract_errors)
    elif reason in {
        "cross_layer_graph_validation_failed",
        "cross_layer_graph_invalid",
        "cross_layer_graph_status_invalid",
    }:
        graph = prediction.get("cross_layer_graph", {})
        summary = graph.get("summary", {}) if isinstance(graph, dict) else {}
        validation = prediction.get("graph_validation", {})
        details.extend(str(item) for item in summary.get("unresolved_boundaries", []))
        if isinstance(validation, dict):
            details.extend(str(item) for item in validation.get("errors", []))
        category = "CROSS_LAYER_GRAPH_INVALID"
        action = "repair unresolved cross-layer boundaries and produce an OK graph validation"
        root_cause = "TOOL_BINDING"
    elif reason == "cross_layer_graph_incomplete":
        graph = prediction.get("cross_layer_graph", {})
        summary = graph.get("summary", {}) if isinstance(graph, dict) else {}
        details.extend(str(item) for item in summary.get("unresolved_boundaries", []))
        category = "CROSS_LAYER_GRAPH_INCOMPLETE"
        action = "complete and attest the cross-layer Tool, dependency and observation boundaries"
        root_cause = "TOOL_BINDING"
    elif status == "INVALID":
        category = "UNSTABLE_REPETITIONS"
        action = "compare per-repetition carrier, anchor and exact L4 evidence"
        root_cause = "EVIDENCE_CONTRACT"
    elif status == "UNASSESSED" and reason == "localization_unassessed":
        localization = prediction.get("localization", {})
        details.extend(str(item) for item in localization.get("reasons", localization.get("unresolved_reasons", [])))
        origin = _origin(prediction)
        root_cause = _root_cause(details, fallback="LOCALIZATION")
        category = {
            "SOURCE_MATERIAL": "SOURCE_MATERIAL_UNRESOLVED",
            "PATCH_MATERIAL": "PATCH_MATERIAL_UNRESOLVED",
            "TOOL_BINDING": "TOOL_BINDING_UNRESOLVED",
            "CONTAINER_ENVIRONMENT": "CONTAINER_ENVIRONMENT_UNRESOLVED",
            "EVIDENCE_CONTRACT": "EVIDENCE_CONTRACT_UNRESOLVED",
            "OBSERVATION_BOUNDARY": "OBSERVATION_BOUNDARY_UNRESOLVED",
        }.get(root_cause, "LOCALIZATION_UNRESOLVED")
        action = {
            "SOURCE_MATERIAL": _source_action(origin),
            "PATCH_MATERIAL": _patch_action(origin),
            "TOOL_BINDING": "select one registered Tool with a unique structured path to the target component",
            "CONTAINER_ENVIRONMENT": "restore the pinned Linux image, runner and frozen environment manifest",
            "EVIDENCE_CONTRACT": "repair the runner so paired L0-L3 evidence and Tool-result provenance are attested",
            "OBSERVATION_BOUNDARY": "capture an attested next model request containing the exact role=tool message",
        }.get(root_cause, "supply a matching source pair, patch and structured Tool binding")
    elif status == "UNASSESSED" and reason == "effect_model_unassessed":
        model = prediction.get("effect_model", {})
        details.extend(str(item) for item in model.get("reasons", model.get("modeling_reasons", [])))
        origin = _origin(prediction)
        counterfactual = prediction.get("counterfactual_execution", {})
        if counterfactual.get("status") == "INCOMPLETE":
            category = "COUNTERFACTUAL_INCOMPLETE"
            action = "repair input override attestation or increase the declared counterfactual budget"
            root_cause = "EVIDENCE_CONTRACT"
        else:
            root_cause = _root_cause(details, fallback="EFFECT_MODEL")
            category = {
                "SOURCE_MATERIAL": "SOURCE_MATERIAL_UNRESOLVED",
                "PATCH_MATERIAL": "PATCH_MATERIAL_UNRESOLVED",
                "TOOL_BINDING": "TOOL_BINDING_UNRESOLVED",
                "CONTAINER_ENVIRONMENT": "CONTAINER_ENVIRONMENT_UNRESOLVED",
                "EVIDENCE_CONTRACT": "EVIDENCE_CONTRACT_UNRESOLVED",
                "OBSERVATION_BOUNDARY": "OBSERVATION_BOUNDARY_UNRESOLVED",
            }.get(root_cause, "EFFECT_MODEL_UNRESOLVED")
            action = {
                "SOURCE_MATERIAL": _source_action(origin),
                "PATCH_MATERIAL": _patch_action(origin),
                "TOOL_BINDING": "inspect Tool registration, sink and effect-carrier provenance across the component path",
                "CONTAINER_ENVIRONMENT": "restore the pinned Linux image, runner and frozen environment manifest",
                "EVIDENCE_CONTRACT": "repair paired L0-L3 evidence, input attestations and fixed-side blocking",
                "OBSERVATION_BOUNDARY": "capture an attested next model request with exact role=tool content",
            }.get(root_cause, "inspect paired traces, Tool-result provenance and fixed-side blocking")
    elif status == "UNASSESSED":
        category = "OBSERVATION_BOUNDARY_UNRESOLVED"
        action = "capture an attested actual next model request with exact role=tool content"
        root_cause = "OBSERVATION_BOUNDARY"

    return {
        "schema_version": SCHEMA_VERSION,
        "case_id": prediction.get("case_identity", {}).get("case_id"),
        "run_status": status,
        "category": category,
        "reason": reason or None,
        "details": list(dict.fromkeys(details)),
        "root_cause": root_cause,
        "suggested_machine_action": action,
        "requires_human_review": status != "VALID",
        "retryable_environment_failure": retryable,
        "gt_used": False,
    }


def aggregate_diagnostics(diagnostics: list[dict[str, Any]]) -> dict[str, Any]:
    categories: dict[str, int] = {}
    for diagnostic in diagnostics:
        category = str(diagnostic.get("category", "UNKNOWN"))
        categories[category] = categories.get(category, 0) + 1
    return {
        "schema_version": "vulveil-diagnostic-summary/v1",
        "case_count": len(diagnostics),
        "category_counts": dict(sorted(categories.items())),
        "requires_human_review_count": sum(item.get("requires_human_review") is True for item in diagnostics),
        "retryable_environment_failure_count": sum(item.get("retryable_environment_failure") is True for item in diagnostics),
        "diagnostics": diagnostics,
        "gt_used": False,
    }
