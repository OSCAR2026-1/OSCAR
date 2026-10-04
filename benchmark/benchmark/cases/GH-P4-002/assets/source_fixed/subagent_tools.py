"""Subagent packet, persistence, and auto-run helpers."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from mcp.types import TextContent

from . import workflow_tools


_SUBAGENT_ROLE_GUIDANCE: dict[str, dict[str, Any]] = {
    "searcher": {
        "goal": "Find the smallest set of files, symbols, routes, and components relevant to the task.",
        "focus": [
            "Use architecture and retrieval artifacts first.",
            "Prefer exact file/symbol/route identification over broad prose.",
            "Return concise ranked candidates with reasons.",
        ],
        "output_contract": {
            "kind": "search_result",
            "required_fields": ["top_candidates", "queries_used", "notes"],
        },
    },
    "trace": {
        "goal": "Trace the relevant request, data, and control flow through the codebase.",
        "focus": [
            "Explain how controllers, services, repositories, and models connect.",
            "Call out unknowns and missing links explicitly.",
            "Keep the trace grounded in retrieved files only.",
        ],
        "output_contract": {
            "kind": "logic_trace",
            "required_fields": ["entrypoints", "flow_steps", "dependencies", "gaps"],
        },
    },
    "fix_plan": {
        "goal": "Produce a minimal change plan for implementing or fixing the task.",
        "focus": [
            "Prefer the smallest correct patch.",
            "List concrete files and expected edits.",
            "Identify validation steps and risks.",
        ],
        "output_contract": {
            "kind": "fix_plan",
            "required_fields": ["files", "changes", "verification", "risks"],
        },
    },
    "verifier": {
        "goal": "Define the smallest proof that the proposed change works.",
        "focus": [
            "Prefer narrow tests and command scopes.",
            "Tie each verification step to a specific behavior.",
            "Note any environment or fixture gaps.",
        ],
        "output_contract": {
            "kind": "verification_plan",
            "required_fields": ["checks", "commands", "expected_outcomes"],
        },
    },
    "reviewer": {
        "goal": "Review the proposed or applied changes for correctness, regressions, and missing coverage.",
        "focus": [
            "Find concrete defects first.",
            "Call out behavior regressions and missing tests.",
            "Keep summaries short after findings.",
        ],
        "output_contract": {
            "kind": "review_findings",
            "required_fields": ["findings", "residual_risks"],
        },
    },
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _subagent_guidance(role: str) -> dict[str, Any]:
    normalized = (role or "").strip().lower()
    default = {
        "goal": "Handle the assigned focused subtask using the provided packet only.",
        "focus": [
            "Stay narrow and do not broaden scope.",
            "Ground conclusions in the provided artifacts.",
            "Return structured output.",
        ],
        "output_contract": {
            "kind": "subagent_result",
            "required_fields": ["notes"],
        },
    }
    return {"role": normalized or "subagent", **default, **_SUBAGENT_ROLE_GUIDANCE.get(normalized, {})}


def _subagent_artifact_name(role: str, name: str) -> str:
    normalized = (role or "subagent").strip().lower().replace(" ", "_")
    return f"subagents/{normalized}/{name}"


def _summarize_saved_results(results: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for role, entry in sorted(results.items()):
        out.append(
            {
                "role": role,
                "saved_at": entry.get("saved_at"),
                "summary": entry.get("summary"),
                "artifact_path": entry.get("artifact_path"),
                "kind": (entry.get("result") or {}).get("kind") if isinstance(entry.get("result"), dict) else None,
            }
        )
    return out


def _build_subagent_packet(
    server: Any,
    workspace: Any,
    workflow: dict[str, Any],
    *,
    role: str,
    query: str = "",
    bundle: dict[str, Any] | None = None,
    architecture_map: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Construct a focused packet for one subagent role."""
    guidance = _subagent_guidance(role)
    active_bundle = bundle or workflow.get("context_bundle") or {}
    active_architecture = architecture_map
    if active_architecture is None:
        active_architecture = _load_json(
            Path(workflow_tools.workspace_artifact_paths(server, workspace)["architecture_map"])
        )
    saved_results = ((workflow.get("artifacts") or {}).get("subagent_results") or {}) if workflow else {}
    return {
        "schema_version": 1,
        "prepared_at": _utc_now(),
        "role": role,
        "guidance": guidance,
        "task": {
            "objective": workflow.get("objective"),
            "query": query or active_bundle.get("query") or workflow.get("objective"),
            "workflow_type": workflow.get("workflow_type"),
        },
        "workspace": {
            "name": workspace.name,
            "repo_count": len(workspace.repos),
            "artifacts": workflow_tools.workspace_artifact_paths(server, workspace),
        },
        "workflow": {
            "workflow_id": workflow.get("workflow_id"),
            "stage": workflow.get("stage"),
            "status": workflow.get("status"),
            "metadata": workflow.get("metadata") or {},
            "artifacts": {
                "linear_ticket_path": (workflow.get("artifacts") or {}).get("linear_ticket_path"),
                "ticket_analysis_path": (workflow.get("artifacts") or {}).get("ticket_analysis_path"),
                "developer_handoff_path": (workflow.get("artifacts") or {}).get("developer_handoff_path"),
            },
        },
        "ticket": (workflow.get("artifacts") or {}).get("linear_ticket"),
        "context": {
            "context_source": active_bundle.get("context_source"),
            "workspace_digest": active_bundle.get("workspace_digest"),
            "architecture_overview": active_bundle.get("architecture_overview") or [],
            "repo_overview": active_bundle.get("repo_overview") or [],
            "repo_summaries": active_bundle.get("repo_summaries") or [],
            "retrieval_hits": active_bundle.get("retrieval_hits") or [],
            "logic_hits": active_bundle.get("logic_hits") or [],
            "locate_hits": active_bundle.get("locate_hits") or [],
            "build_commands": active_bundle.get("build_commands") or [],
        },
        "architecture": {
            "repo_names": list((active_architecture.get("repos") or {}).keys()),
            "repos": active_architecture.get("repos") or {},
        },
        "prior_subagent_results": _summarize_saved_results(saved_results),
    }


async def prepare_subagent_packet(server: Any, args: dict) -> Any:
    """Build and persist a focused subagent packet from workflow context."""
    role = ((args or {}).get("role") or "").strip().lower()
    if not role:
        return [TextContent(type="text", text="Error: role is required")]

    workspace, workflow, error = workflow_tools.resolve_workflow_context(server, args, require_workflow=True)
    if error:
        return [TextContent(type="text", text=f"Error: {error}")]

    query = ((args or {}).get("query") or "").strip()
    context_chars = int((args or {}).get("context_chars", 4000) or 4000)
    limit = int((args or {}).get("limit", 8) or 8)
    include_build_commands = bool((args or {}).get("include_build_commands", True))
    force_refresh = bool((args or {}).get("force_refresh", False))

    bundle = workflow.get("context_bundle") or {}
    if force_refresh or not bundle:
        payload, workflow = workflow_tools._prepare_context_bundle_payload(
            server,
            workspace,
            workflow=workflow,
            query=query or (workflow.get("objective") or ""),
            context_chars=context_chars,
            limit=limit,
            include_build_commands=include_build_commands,
        )
        bundle = payload.get("context_bundle") or {}
    packet = _build_subagent_packet(
        server,
        workspace,
        workflow,
        role=role,
        query=query,
        bundle=bundle,
    )

    artifact_name = _subagent_artifact_name(role, "packet.json")
    artifact_path = server.workflow_manager.write_json_artifact(
        workspace.name,
        workflow["workflow_id"],
        artifact_name,
        packet,
    )
    packet_artifacts = dict((workflow.get("artifacts") or {}).get("subagent_packets") or {})
    packet_artifacts[role] = artifact_path
    workflow = server.workflow_manager.update_session(
        workspace.name,
        workflow["workflow_id"],
        artifacts={"subagent_packets": packet_artifacts},
        event_type="subagent_packet_prepared",
        event_payload={"role": role, "query": packet["task"]["query"]},
    )

    return workflow_tools.json_response(
        {
            "workflow": {
                "workflow_id": workflow["workflow_id"],
                "status": workflow["status"],
                "stage": workflow["stage"],
                "updated_at": workflow["updated_at"],
            },
            "subagent_packet": packet,
            "artifact_path": artifact_path,
        }
    )


async def run_subagent(server: Any, args: dict) -> Any:
    """Run a focused server-side subagent over a prepared packet."""
    role = ((args or {}).get("role") or "").strip().lower()
    if not role:
        return [TextContent(type="text", text="Error: role is required")]

    packet_payload = await prepare_subagent_packet(server, args)
    if isinstance(packet_payload, list):
        return packet_payload

    packet = packet_payload["subagent_packet"]
    result = _execute_subagent_role(role, packet)
    result.setdefault("role", role)
    result.setdefault("packet_role", packet["role"])
    persisted = False
    saved_result = None
    if bool((args or {}).get("persist_result", True)):
        stored = await store_subagent_result(
            server,
            {
                "workflow_id": packet["workflow"]["workflow_id"],
                "workspace_name": packet["workspace"]["name"],
                "role": role,
                "summary": result.get("summary"),
                "result": result,
            },
        )
        if isinstance(stored, list):
            return stored
        persisted = True
        saved_result = stored.get("saved_result")

    return workflow_tools.json_response(
        {
            "workflow": packet_payload.get("workflow"),
            "subagent_packet": {
                "role": packet["role"],
                "artifact_path": packet_payload.get("artifact_path"),
                "task": packet["task"],
            },
            "subagent_result": result,
            "persisted": persisted,
            "saved_result": saved_result,
        }
    )


async def store_subagent_result(server: Any, args: dict) -> Any:
    """Persist a subagent result into workflow artifacts for later merge."""
    role = ((args or {}).get("role") or "").strip().lower()
    if not role:
        return [TextContent(type="text", text="Error: role is required")]

    workspace, workflow, error = workflow_tools.resolve_workflow_context(server, args, require_workflow=True)
    if error:
        return [TextContent(type="text", text=f"Error: {error}")]

    result = (args or {}).get("result")
    if result is None:
        return [TextContent(type="text", text="Error: result is required")]

    summary = ((args or {}).get("summary") or "").strip()
    status = ((args or {}).get("status") or "completed").strip() or "completed"
    payload = {
        "schema_version": 1,
        "saved_at": _utc_now(),
        "role": role,
        "status": status,
        "summary": summary or None,
        "result": result,
    }
    artifact_name = _subagent_artifact_name(role, "result.json")
    artifact_path = server.workflow_manager.write_json_artifact(
        workspace.name,
        workflow["workflow_id"],
        artifact_name,
        payload,
    )
    result_artifacts = dict((workflow.get("artifacts") or {}).get("subagent_results") or {})
    result_artifacts[role] = {
        "saved_at": payload["saved_at"],
        "summary": payload["summary"],
        "status": status,
        "artifact_path": artifact_path,
        "result": result,
    }
    workflow = server.workflow_manager.update_session(
        workspace.name,
        workflow["workflow_id"],
        artifacts={"subagent_results": result_artifacts},
        event_type="subagent_result_saved",
        event_payload={"role": role, "status": status},
    )
    return workflow_tools.json_response(
        {
            "workflow": {
                "workflow_id": workflow["workflow_id"],
                "status": workflow["status"],
                "stage": workflow["stage"],
                "updated_at": workflow["updated_at"],
            },
            "saved_result": result_artifacts[role],
        }
    )


async def merge_subagent_results(server: Any, args: dict) -> Any:
    """Return a structured view of all persisted subagent results for a workflow."""
    workspace, workflow, error = workflow_tools.resolve_workflow_context(server, args, require_workflow=True)
    if error:
        return [TextContent(type="text", text=f"Error: {error}")]

    artifacts = workflow.get("artifacts") or {}
    subagent_packets = artifacts.get("subagent_packets") or {}
    subagent_results = artifacts.get("subagent_results") or {}
    summary = {
        "workflow_id": workflow.get("workflow_id"),
        "workflow_stage": workflow.get("stage"),
        "packet_roles": sorted(subagent_packets.keys()),
        "result_roles": sorted(subagent_results.keys()),
        "results": _summarize_saved_results(subagent_results),
    }
    return workflow_tools.json_response({"workflow": summary, "subagent_results": subagent_results})


def auto_run_subagent_roles(
    server: Any,
    workspace: Any,
    workflow: dict[str, Any],
    roles: list[str],
    *,
    query: str = "",
    bundle: dict[str, Any] | None = None,
    reason: str = "",
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Run deterministic subagent roles and persist packet/result artifacts."""
    normalized_roles: list[str] = []
    for role in roles:
        normalized = (role or "").strip().lower()
        if normalized and normalized not in normalized_roles:
            normalized_roles.append(normalized)
    if not normalized_roles:
        return workflow, []

    architecture_map = _load_json(Path(workflow_tools.workspace_artifact_paths(server, workspace)["architecture_map"]))
    packet_artifacts = dict((workflow.get("artifacts") or {}).get("subagent_packets") or {})
    result_artifacts = dict((workflow.get("artifacts") or {}).get("subagent_results") or {})
    auto_results: list[dict[str, Any]] = []

    for role in normalized_roles:
        packet = _build_subagent_packet(
            server,
            workspace,
            workflow,
            role=role,
            query=query,
            bundle=bundle,
            architecture_map=architecture_map,
        )
        packet_path = server.workflow_manager.write_json_artifact(
            workspace.name,
            workflow["workflow_id"],
            _subagent_artifact_name(role, "packet.json"),
            packet,
        )
        packet_artifacts[role] = packet_path

        result = _execute_subagent_role(role, packet)
        result.setdefault("packet_role", packet["role"])
        saved_at = _utc_now()
        result_payload = {
            "schema_version": 1,
            "saved_at": saved_at,
            "role": role,
            "status": "completed",
            "summary": result.get("summary"),
            "result": result,
        }
        result_path = server.workflow_manager.write_json_artifact(
            workspace.name,
            workflow["workflow_id"],
            _subagent_artifact_name(role, "result.json"),
            result_payload,
        )
        result_artifacts[role] = {
            "saved_at": saved_at,
            "summary": result.get("summary"),
            "status": "completed",
            "artifact_path": result_path,
            "result": result,
        }
        auto_results.append(
            {
                "role": role,
                "packet_path": packet_path,
                "result_path": result_path,
                "summary": result.get("summary"),
                "kind": result.get("kind"),
            }
        )

    updated_workflow = server.workflow_manager.update_session(
        workspace.name,
        workflow["workflow_id"],
        artifacts={
            "subagent_packets": packet_artifacts,
            "subagent_results": result_artifacts,
        },
        event_type="subagents_auto_ran",
        event_payload={"roles": normalized_roles, "reason": reason or "workflow_milestone"},
    )
    return updated_workflow, auto_results


def _execute_subagent_role(role: str, packet: dict[str, Any]) -> dict[str, Any]:
    normalized = role.strip().lower()
    handlers = {
        "searcher": _run_searcher,
        "trace": _run_trace,
        "fix_plan": _run_fix_plan,
        "verifier": _run_verifier,
        "reviewer": _run_reviewer,
    }
    handler = handlers.get(normalized, _run_generic)
    result = handler(packet)
    if not isinstance(result, dict):
        result = {"kind": "subagent_result", "notes": "Subagent handler returned a non-dict result."}
    result.setdefault("role", normalized)
    return result


def _run_searcher(packet: dict[str, Any]) -> dict[str, Any]:
    locate_hits = packet["context"].get("locate_hits") or []
    retrieval_hits = packet["context"].get("retrieval_hits") or []
    logic_hits = packet["context"].get("logic_hits") or []
    top_candidates: list[dict[str, Any]] = []
    seen: set[str] = set()
    for source_name, items in (
        ("locate", locate_hits),
        ("logic", logic_hits),
        ("retrieval", retrieval_hits),
    ):
        for item in items:
            path = item.get("path")
            repo = item.get("repo")
            key = f"{repo}:{path}"
            if not path or key in seen:
                continue
            seen.add(key)
            top_candidates.append(
                {
                    "repo": repo,
                    "path": path,
                    "reason": f"{source_name} hit",
                    "line": item.get("line") or item.get("start_line"),
                    "score": item.get("score"),
                }
            )
            if len(top_candidates) >= 10:
                break
        if len(top_candidates) >= 10:
            break
    return {
        "kind": "search_result",
        "summary": f"Ranked {len(top_candidates)} candidate files from locate, logic, and retrieval hits.",
        "top_candidates": top_candidates,
        "queries_used": [packet["task"].get("query")],
        "notes": "Focus on the top candidates first before broad repo search.",
    }


def _run_trace(packet: dict[str, Any]) -> dict[str, Any]:
    architecture = packet.get("architecture", {}).get("repos") or {}
    flow_steps: list[dict[str, Any]] = []
    dependencies: list[dict[str, Any]] = []
    entrypoints: list[dict[str, Any]] = []
    for repo_name, repo_data in list(architecture.items())[:3]:
        roles = repo_data.get("roles") or {}
        for controller in (roles.get("controller") or [])[:3]:
            entrypoints.append({"repo": repo_name, "path": controller.get("path"), "summary": controller.get("summary")})
        for route in (repo_data.get("route_map") or [])[:5]:
            flow_steps.append(
                {
                    "repo": repo_name,
                    "route": route.get("route"),
                    "path": route.get("path"),
                    "handler_symbols": route.get("handler_symbols") or [],
                }
            )
        for component in (repo_data.get("components") or [])[:8]:
            if component.get("roles"):
                dependencies.append(
                    {
                        "repo": repo_name,
                        "path": component.get("path"),
                        "roles": component.get("roles"),
                        "symbols": component.get("symbols") or [],
                    }
                )
    return {
        "kind": "logic_trace",
        "summary": f"Captured {len(entrypoints)} entrypoints and {len(flow_steps)} flow steps from the saved architecture map.",
        "entrypoints": entrypoints,
        "flow_steps": flow_steps,
        "dependencies": dependencies[:12],
        "gaps": [] if flow_steps else ["No route or controller flow was found in the saved architecture map."],
    }


def _run_fix_plan(packet: dict[str, Any]) -> dict[str, Any]:
    locate_hits = packet["context"].get("locate_hits") or []
    logic_hits = packet["context"].get("logic_hits") or []
    build_commands = packet["context"].get("build_commands") or []
    files = []
    seen: set[str] = set()
    for item in locate_hits + logic_hits:
        key = f"{item.get('repo')}:{item.get('path')}"
        if not item.get("path") or key in seen:
            continue
        seen.add(key)
        files.append({"repo": item.get("repo"), "path": item.get("path")})
        if len(files) >= 6:
            break
    changes = [
        {
            "file": file_entry["path"],
            "intent": "Inspect and apply the minimum change required for the task.",
        }
        for file_entry in files
    ]
    verification = []
    for repo_entry in build_commands[:3]:
        verification.append(
            {
                "repo": repo_entry.get("repo"),
                "commands": repo_entry.get("commands") or [],
            }
        )
    risks = []
    if not files:
        risks.append("No concrete files were identified; refine the query or run the searcher role first.")
    if not verification:
        risks.append("No build/test commands were present in the context bundle.")
    return {
        "kind": "fix_plan",
        "summary": f"Prepared a minimal fix plan covering {len(files)} likely files.",
        "files": files,
        "changes": changes,
        "verification": verification,
        "risks": risks,
    }


def _run_verifier(packet: dict[str, Any]) -> dict[str, Any]:
    build_commands = packet["context"].get("build_commands") or []
    checks = []
    commands = []
    for repo_entry in build_commands[:4]:
        repo = repo_entry.get("repo")
        repo_commands = repo_entry.get("commands") or []
        if repo_commands:
            checks.append({"repo": repo, "behavior": "Run the narrowest configured verification command."})
            commands.append({"repo": repo, "commands": repo_commands[:2]})
    expected = [
        "Targeted verification command exits successfully.",
        "No unexpected regressions appear in touched routes, services, or models.",
    ]
    if not commands:
        expected.append("No commands were available; manual verification may be required.")
    return {
        "kind": "verification_plan",
        "summary": f"Prepared {len(commands)} repo-level verification steps from cached build commands.",
        "checks": checks,
        "commands": commands,
        "expected_outcomes": expected,
    }


def _run_reviewer(packet: dict[str, Any]) -> dict[str, Any]:
    workflow_artifacts = packet.get("workflow", {}).get("artifacts") or {}
    findings = []
    if not workflow_artifacts.get("developer_handoff_path"):
        findings.append("No developer handoff artifact is present yet.")
    if not packet["context"].get("logic_hits"):
        findings.append("No logic hits were included; review coverage may be weak.")
    return {
        "kind": "review_findings",
        "summary": "Initial review based on saved workflow artifacts and context coverage.",
        "findings": findings,
        "residual_risks": [] if not findings else ["Review depth is limited until a diff or change artifact exists."],
    }


def _run_generic(packet: dict[str, Any]) -> dict[str, Any]:
    return {
        "kind": "subagent_result",
        "summary": "No specialized handler exists for this role yet.",
        "notes": f"Prepared packet for role '{packet['role']}' is ready for external execution.",
    }
