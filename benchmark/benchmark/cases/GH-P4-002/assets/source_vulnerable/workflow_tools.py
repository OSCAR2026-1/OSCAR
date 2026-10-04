"""Workflow-oriented helper functions for the multi-repo MCP server."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any, Optional

from mcp.types import TextContent

from .retrieval_tools import build_context_packet
from .workspace_ai import ensure_workspace_ai_files, locate_in_workspace_index


def json_response(payload: Any) -> Any:
    """Return structured tool content directly."""
    return payload


def bool_arg(args: dict, key: str, default: bool = False) -> bool:
    """Treat omitted/null boolean args as their semantic default."""
    value = (args or {}).get(key)
    if value is None:
        return default
    return bool(value)


def workspace_artifact_paths(server: Any, workspace: Any) -> dict[str, str]:
    """Return stable paths for workflow-relevant workspace artifacts."""
    workspace_root = server._workspace_root(workspace) or (server.workspace_manager.workspaces_dir / workspace.name)
    return {
        "workspace_root": str(workspace_root),
        "context": str(workspace_root / "context.md"),
        "workspace_context": str(workspace_root / "WORKSPACE_CONTEXT.md"),
        "architecture_map": str(workspace_root / ".mcp" / "architecture_map.json"),
        "repo_index": str(workspace_root / ".mcp" / "repo_index.json"),
        "digests": str(workspace_root / ".mcp" / "digests.json"),
        "retrieval_chunks": str(workspace_root / ".mcp" / "retrieval" / "chunks.json"),
        "logic_chunks": str(workspace_root / ".mcp" / "retrieval" / "logic_chunks.json"),
        "workspace_digest": str(workspace_root / ".mcp" / "summaries" / "workspace_digest.md"),
        "build_commands": str(server._workspace_build_commands_path(workspace.name)),
        "workflow_dir": str(workspace_root / ".mcp" / "workflows"),
    }


def workspace_summary(server: Any, workspace: Any) -> dict[str, Any]:
    """Return a structured workspace summary for workflow-oriented tools."""
    return {
        "name": workspace.name,
        "active": bool(getattr(workspace, "active", False)),
        "created_at": workspace.created_at,
        "workspace_root": str(server.workspace_manager.storage_path),
        "workspaces_dir": str(server.workspace_manager.workspaces_dir),
        "repo_count": len(workspace.repos),
        "artifacts": workspace_artifact_paths(server, workspace),
        "repos": [
            {
                "name": repo.name,
                "url": server._sanitize_url(repo.url),
                "path": repo.local_path,
                "branch": repo.branch,
                "last_updated": repo.last_updated,
                "exists": os.path.exists(repo.local_path),
            }
            for repo in workspace.repos
        ],
    }


def read_build_command_data(server: Any, workspace: Any) -> Optional[dict]:
    """Read build_command.json for a workspace, creating it first if needed."""
    path = server._ensure_build_command_file(workspace)
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def summarize_index_for_bundle(
    index: Optional[dict],
    *,
    repo_names: Optional[list[str]] = None,
    limit: int = 6,
) -> list[dict[str, Any]]:
    """Reduce repo_index.json into a small per-repo overview."""
    out: list[dict[str, Any]] = []
    repos = (index or {}).get("repos") or {}
    repo_filter = set(repo_names or [])
    for repo_name, repo_data in repos.items():
        if repo_filter and repo_name not in repo_filter:
            continue
        out.append(
            {
                "repo": repo_name,
                "primary_language": repo_data.get("primary_language"),
                "entrypoints": (repo_data.get("entrypoints") or [])[:5],
                "key_files": (repo_data.get("key_files") or [])[:5],
                "top_level_dirs": (repo_data.get("top_level_dirs") or [])[:6],
                "how_to_run": (repo_data.get("how_to_run") or [])[:3],
            }
        )
        if len(out) >= limit:
            break
    return out


def select_verification_commands(commands: list[str], mode: str) -> list[str]:
    """Pick the smallest useful verification command set from available commands."""
    if not commands:
        return []

    def score(command: str) -> tuple[int, int]:
        lower = command.lower()
        priority = 0
        specificity = 0
        if "test" in lower:
            priority = 5
        elif "check" in lower or "verify" in lower:
            priority = 4
        elif "lint" in lower:
            priority = 3
        elif "build" in lower:
            priority = 2
        elif "install" in lower or "package" in lower:
            priority = 1
        if lower.startswith(("python -m ", "poetry run ", "uv run ")):
            specificity = 2
        elif lower.startswith(("./gradlew ", "npm run ", "pnpm ", "yarn ")):
            specificity = 1
        return (priority, specificity, -len(command))

    ranked = sorted(commands, key=score, reverse=True)
    if mode == "full":
        picked: list[str] = []
        for command in ranked:
            if command not in picked:
                picked.append(command)
            if len(picked) == 3:
                break
        return picked
    return [ranked[0]]


def resolve_workflow_context(
    server: Any,
    args: dict,
    *,
    require_workflow: bool = False,
) -> tuple[Optional[Any], Optional[dict[str, Any]], Optional[str]]:
    """Resolve workspace and optional workflow session from tool arguments."""
    workflow = None
    workflow_id = (args or {}).get("workflow_id")
    workspace_name = (args or {}).get("workspace_name")

    if workflow_id:
        workflow = server.workflow_manager.find_session(workflow_id, workspace_name)
        if not workflow:
            return None, None, f"Workflow '{workflow_id}' not found"
        workspace_name = workflow.get("workspace_name")
    elif require_workflow:
        return None, None, "workflow_id is required"

    workspace, error = server._get_workspace_or_active(workspace_name)
    if error:
        return None, workflow, error

    return workspace, workflow, None


async def ensure_workspace(server: Any, args: dict) -> Any:
    """Ensure there is an active workspace ready for workflow execution."""
    workspace_name = (args or {}).get("workspace_name") or (args or {}).get("name")
    repos = (args or {}).get("repos") or []
    objective = ((args or {}).get("objective") or "").strip()

    if workspace_name:
        existing_workspace = server.workspace_manager.get_workspace(workspace_name)
        if existing_workspace:
            server.workspace_manager.set_active_workspace(workspace_name)
            existing_workspace = server.workspace_manager.get_workspace(workspace_name)
            generated = {}
            if existing_workspace.repos:
                server._ensure_build_command_file(existing_workspace)
                generated = server._ensure_workspace_ai_artifacts(existing_workspace)
            payload = {
                "action": "activated_existing",
                "workspace": workspace_summary(server, existing_workspace),
                "generated": generated,
            }
            if objective:
                payload["workflow_bootstrap"] = await _start_bootstrap_workflow(server, existing_workspace.name, args)
            return json_response(payload)

    if not workspace_name and not repos:
        active_workspace = server.workspace_manager.get_active_workspace()
        if active_workspace:
            generated = {}
            if active_workspace.repos:
                server._ensure_build_command_file(active_workspace)
                generated = server._ensure_workspace_ai_artifacts(active_workspace)
            payload = {
                "action": "reused_active",
                "workspace": workspace_summary(server, active_workspace),
                "generated": generated,
            }
            if objective:
                payload["workflow_bootstrap"] = await _start_bootstrap_workflow(server, active_workspace.name, args)
            return json_response(payload)

    if not repos:
        return [TextContent(type="text", text="Error: Workspace does not exist and no repositories were provided")]

    setup_result = await server._setup_workspace(
        {
            "repos": repos,
            "name": workspace_name,
            "workspace_root": (args or {}).get("workspace_root"),
            "storage_path": (args or {}).get("storage_path"),
            "base_dir": (args or {}).get("base_dir"),
            "async_mode": bool_arg(args, "async_mode", True),
            "max_concurrent": int((args or {}).get("max_concurrent", 3) or 3),
            "skip_preflight": bool((args or {}).get("skip_preflight", False)),
            "objective": objective,
            "workflow_type": (args or {}).get("workflow_type"),
            "metadata": (args or {}).get("metadata"),
            "issue_id": (args or {}).get("issue_id"),
            "query": (args or {}).get("query"),
            "auto_continue": (args or {}).get("auto_continue"),
            "stop_after": (args or {}).get("stop_after"),
            "context_chars": (args or {}).get("context_chars"),
            "limit": (args or {}).get("limit"),
            "include_build_commands": (args or {}).get("include_build_commands"),
        }
    )
    created_workspace = None
    if workspace_name:
        created_workspace = server.workspace_manager.get_workspace(workspace_name)
    if not created_workspace:
        created_workspace = server.workspace_manager.get_active_workspace()

    details = ""
    if isinstance(setup_result, list) and setup_result:
        details = getattr(setup_result[0], "text", "") or ""

    return json_response(
        {
            "action": "created_via_setup_workspace",
            "workspace": workspace_summary(server, created_workspace) if created_workspace else None,
            "details": details,
        }
    )


async def _start_bootstrap_workflow(server: Any, workspace_name: str, args: dict) -> Any:
    """Start a workflow from ensure_workspace once the workspace is ready."""
    workflow_args = {
        "workspace_name": workspace_name,
        "objective": ((args or {}).get("objective") or "").strip(),
        "workflow_type": (args or {}).get("workflow_type") or "general",
        "metadata": (args or {}).get("metadata") or {},
        "issue_id": (args or {}).get("issue_id"),
        "query": (args or {}).get("query"),
        "auto_continue": bool_arg(args, "auto_continue", True),
        "stop_after": (args or {}).get("stop_after"),
        "context_chars": int((args or {}).get("context_chars", 4000) or 4000),
        "limit": int((args or {}).get("limit", 8) or 8),
        "include_build_commands": bool_arg(args, "include_build_commands", True),
    }
    payload = await start_workflow(server, workflow_args)
    if isinstance(payload, list):
        return {"error": payload[0].text if payload else "Workflow bootstrap failed"}
    return payload


async def get_active_workspace(server: Any, args: dict) -> Any:
    """Return structured details for the active workspace."""
    workspace = server.workspace_manager.get_active_workspace()
    if not workspace:
        return [TextContent(type="text", text="Error: No active workspace")]
    return json_response({"workspace": workspace_summary(server, workspace)})


async def set_workspace_root(server: Any, args: dict) -> Any:
    """Set and optionally persist the workspace root outside the repo."""
    workspace_root = ((args or {}).get("workspace_root") or "").strip()
    if not workspace_root:
        return [TextContent(type="text", text="Error: workspace_root is required")]

    persist = bool((args or {}).get("persist", True))
    error = server._set_storage_path(workspace_root)
    if error:
        return [TextContent(type="text", text=f"Error: {error}")]

    persisted_to = None
    if persist:
        persist_error = server._persist_user_workspace_root(server.config["workspace_root"])
        if persist_error:
            return [TextContent(type="text", text=f"Error: {persist_error}")]
        persisted_to = str(server._user_config_path())

    return json_response(
        {
            "workspace_root": server.config["workspace_root"],
            "workspaces_dir": str(server.workspace_manager.workspaces_dir),
            "persisted": persist,
            "persisted_to": persisted_to,
        }
    )


async def start_workflow(server: Any, args: dict) -> Any:
    """Create a persisted workflow session bound to a workspace."""
    objective = ((args or {}).get("objective") or "").strip()
    if not objective:
        return [TextContent(type="text", text="Error: objective is required")]

    workspace, error = server._get_workspace_or_active((args or {}).get("workspace_name"))
    if error:
        return [TextContent(type="text", text=f"Error: {error}")]

    server._ensure_build_command_file(workspace)
    generated = server._ensure_workspace_ai_artifacts(workspace) if workspace.repos else {}

    metadata = (args or {}).get("metadata")
    if not isinstance(metadata, dict):
        metadata = {}
    workflow_type = ((args or {}).get("workflow_type") or "general").strip() or "general"
    issue_id = (
        (args or {}).get("issue_id")
        or metadata.get("issue_id")
        or metadata.get("linear_ticket")
        or metadata.get("ticket_id")
    )
    if issue_id:
        metadata.setdefault("issue_id", issue_id)
    session = server.workflow_manager.create_session(
        workspace.name,
        objective,
        workflow_type=workflow_type,
        metadata=metadata,
    )
    session = server.workflow_manager.update_session(
        workspace.name,
        session["workflow_id"],
        fields={"stage": "workspace_ready"},
        artifacts={**workspace_artifact_paths(server, workspace), "generated": generated},
        event_type="workspace_bound",
        event_payload={"repo_count": len(workspace.repos)},
    )
    payload: dict[str, Any] = {
        "workflow": session,
        "workspace": workspace_summary(server, workspace),
    }

    query = ((args or {}).get("query") or _bootstrap_query(objective, workflow_type, metadata, issue_id)).strip()
    auto_continue = (args or {}).get("auto_continue")
    if auto_continue is None:
        auto_continue = True
    stop_after = str((args or {}).get("stop_after") or ("ticket_context" if issue_id else "context")).strip().lower()

    if auto_continue:
        context_payload, session = _prepare_context_bundle_payload(
            server,
            workspace,
            workflow=session,
            query=query,
            context_chars=int((args or {}).get("context_chars", 4000) or 4000),
            limit=int((args or {}).get("limit", 8) or 8),
            include_build_commands=bool_arg(args, "include_build_commands", True),
        )
        payload["bootstrap"] = {
            "auto_continued": True,
            "query": query or None,
            "stopped_at": session.get("stage"),
            "context_ready": True,
        }
        payload["context_bundle"] = context_payload["context_bundle"]
        payload["workflow"] = {
            "workflow_id": session["workflow_id"],
            "status": session["status"],
            "stage": session["stage"],
            "updated_at": session["updated_at"],
        }
        if context_payload.get("auto_subagents"):
            payload["auto_subagents"] = context_payload["auto_subagents"]

        should_analyze_ticket = bool(issue_id) and stop_after not in {"workspace_ready", "context", "context_prepared"}
        if should_analyze_ticket:
            from . import analysis_tools

            ticket_args = {
                "issue_id": issue_id,
                "workflow_id": session["workflow_id"],
                "workspace_name": workspace.name,
            }
            repo_names = metadata.get("repo_names") or metadata.get("repos")
            if isinstance(repo_names, list) and repo_names:
                ticket_args["repo_names"] = repo_names
            analysis_payload = await analysis_tools.analyze_ticket_in_workspace(
                server,
                workspace,
                ticket_args,
                workflow=session,
            )
            if isinstance(analysis_payload, list):
                message = analysis_payload[0].text if analysis_payload else "Ticket analysis failed."
                session = server.workflow_manager.update_session(
                    workspace.name,
                    session["workflow_id"],
                    event_type="auto_continue_stopped",
                    event_payload={"reason": message},
                )
                payload.setdefault("bootstrap", {})["ticket_analysis_error"] = message
                payload["workflow"] = {
                    "workflow_id": session["workflow_id"],
                    "status": session["status"],
                    "stage": session["stage"],
                    "updated_at": session["updated_at"],
                }
            else:
                latest_session = server.workflow_manager.get_session(workspace.name, session["workflow_id"]) or session
                payload["ticket_analysis"] = analysis_payload
                payload["workflow"] = {
                    "workflow_id": latest_session["workflow_id"],
                    "status": latest_session["status"],
                    "stage": latest_session["stage"],
                    "updated_at": latest_session["updated_at"],
                }
                payload.setdefault("bootstrap", {})["ticket_context_ready"] = True
                payload["bootstrap"]["stopped_at"] = latest_session.get("stage")
                if analysis_payload.get("auto_subagents"):
                    payload.setdefault("auto_subagents", [])
                    payload["auto_subagents"].extend(analysis_payload["auto_subagents"])

    return json_response(payload)


async def get_workflow_status(server: Any, args: dict) -> Any:
    """Return the persisted state for a workflow session."""
    workflow_id = (args or {}).get("workflow_id")
    if not workflow_id:
        return [TextContent(type="text", text="Error: workflow_id is required")]

    session = server.workflow_manager.find_session(workflow_id, (args or {}).get("workspace_name"))
    if not session:
        return [TextContent(type="text", text=f"Error: Workflow '{workflow_id}' not found")]

    workspace = server.workspace_manager.get_workspace(session["workspace_name"])
    payload = {"workflow": session}
    if workspace:
        payload["workspace"] = workspace_summary(server, workspace)
    return json_response(payload)


async def prepare_context_bundle(server: Any, args: dict) -> Any:
    """Prepare a compact context bundle from workspace artifacts."""
    workspace, workflow, error = resolve_workflow_context(server, args)
    if error:
        return [TextContent(type="text", text=f"Error: {error}")]

    payload, _ = _prepare_context_bundle_payload(
        server,
        workspace,
        workflow=workflow,
        query=((args or {}).get("query") or "").strip(),
        context_chars=int((args or {}).get("context_chars", 4000) or 4000),
        limit=int((args or {}).get("limit", 8) or 8),
        include_build_commands=bool_arg(args, "include_build_commands", True),
    )
    return json_response(payload)


def _prepare_context_bundle_payload(
    server: Any,
    workspace: Any,
    *,
    workflow: Optional[dict[str, Any]],
    query: str,
    context_chars: int,
    limit: int,
    include_build_commands: bool,
) -> tuple[dict[str, Any], Optional[dict[str, Any]]]:
    context_chars = max(500, min(20000, int(context_chars or 4000)))
    limit = max(1, min(25, int(limit or 8)))
    query = (query or "").strip()
    if not query and workflow:
        metadata = workflow.get("metadata") or {}
        issue_id = (
            metadata.get("issue_id")
            or metadata.get("linear_ticket")
            or metadata.get("ticket_id")
        )
        query = _bootstrap_query(
            workflow.get("objective") or "",
            workflow.get("workflow_type") or "general",
            metadata,
            issue_id,
        ).strip()

    server._ensure_build_command_file(workspace)
    if workspace.repos:
        server._ensure_workspace_ai_artifacts(workspace)

    workspace_index = server._read_workspace_index(workspace) or {}
    locate_hits = []
    if query:
        locate_hits = locate_in_workspace_index(workspace_index, query, limit=limit).get("results", [])

    build_summary = []
    if include_build_commands:
        build_data = read_build_command_data(server, workspace) or {}
        order = build_data.get("order") or []
        repos_data = build_data.get("repos") or {}
        for repo_name in order:
            repo_entry = repos_data.get(repo_name) or {}
            build_summary.append(
                {
                    "repo": repo_name,
                    "source": repo_entry.get("source"),
                    "commands": (repo_entry.get("commands") or [])[:3],
                }
            )

    artifact_paths = workspace_artifact_paths(server, workspace)
    context_packet = build_context_packet(
        Path(artifact_paths["workspace_root"]),
        workspace_index,
        query,
        locate_hits=locate_hits,
        digest_chars=min(context_chars, 2000),
        repo_summary_limit=min(3, limit),
        chunk_limit=min(6, max(2, limit)),
    )
    selected_repo_names = [item.get("repo") for item in (context_packet.get("repo_summaries") or []) if item.get("repo")]

    bundle = {
        "workspace": {
            "name": workspace.name,
            "repo_count": len(workspace.repos),
        },
        "artifacts": artifact_paths,
        "query": query or None,
        "context_source": context_packet.get("mode"),
        "context_excerpt": (context_packet.get("workspace_digest") or {}).get("excerpt", "")[:context_chars],
        "context_truncated": bool((context_packet.get("workspace_digest") or {}).get("truncated")),
        "workspace_digest": context_packet.get("workspace_digest"),
        "architecture_overview": context_packet.get("architecture_overview") or [],
        "repo_overview": summarize_index_for_bundle(
            workspace_index,
            repo_names=selected_repo_names,
            limit=max(1, len(selected_repo_names) or min(3, limit)),
        ),
        "repo_summaries": context_packet.get("repo_summaries") or [],
        "retrieval_hits": context_packet.get("retrieval_hits") or [],
        "logic_hits": context_packet.get("logic_hits") or [],
        "locate_hits": locate_hits,
        "build_commands": build_summary,
    }

    payload: dict[str, Any] = {"context_bundle": bundle}
    updated_workflow = workflow
    if workflow:
        updated_workflow = server.workflow_manager.update_session(
            workspace.name,
            workflow["workflow_id"],
            fields={"stage": "context_prepared"},
            artifacts=artifact_paths,
            context_bundle=bundle,
            event_type="context_bundle_prepared",
            event_payload={
                "query": query,
                "locate_hits": len(locate_hits),
                "retrieval_hits": len(context_packet.get("retrieval_hits") or []),
                "logic_hits": len(context_packet.get("logic_hits") or []),
            },
        )
        from . import subagent_tools

        auto_query = query or workflow.get("objective") or ""
        updated_workflow, auto_results = subagent_tools.auto_run_subagent_roles(
            server,
            workspace,
            updated_workflow,
            ["searcher"],
            query=auto_query,
            bundle=bundle,
            reason="context_prepared",
        )
        payload["auto_subagents"] = auto_results
        payload["workflow"] = {
            "workflow_id": updated_workflow["workflow_id"],
            "status": updated_workflow["status"],
            "stage": updated_workflow["stage"],
            "updated_at": updated_workflow["updated_at"],
        }
    return payload, updated_workflow


def _bootstrap_query(
    objective: str,
    workflow_type: str,
    metadata: dict[str, Any],
    issue_id: Optional[str],
) -> str:
    parts: list[str] = []
    if issue_id:
        parts.append(str(issue_id))
    for key in ("title", "summary", "component", "area"):
        value = metadata.get(key)
        if isinstance(value, str) and value.strip():
            parts.append(value.strip())
    repo_names = metadata.get("repo_names") or metadata.get("repos")
    if isinstance(repo_names, list):
        parts.extend(str(item) for item in repo_names[:4] if item)
    if objective.strip():
        parts.append(objective.strip())
    if workflow_type.lower() in {"linear_ticket", "ticket", "issue"} and not parts:
        parts.append("ticket analysis")
    return " ".join(part for part in parts if part).strip()


async def locate_candidates(server: Any, args: dict) -> Any:
    """Locate candidate files for a workflow query using the workspace index."""
    query = ((args or {}).get("query") or "").strip()
    if not query:
        return [TextContent(type="text", text="Error: query is required")]

    workspace, workflow, error = resolve_workflow_context(server, args)
    if error:
        return [TextContent(type="text", text=f"Error: {error}")]

    limit = int((args or {}).get("limit", 8) or 8)
    limit = max(1, min(25, limit))

    if workspace.repos:
        server._ensure_workspace_ai_artifacts(workspace)
    workspace_index = server._read_workspace_index(workspace)
    if not workspace_index:
        return [TextContent(type="text", text="Error: workspace index is not available")]

    locate_result = locate_in_workspace_index(workspace_index, query, limit=limit)
    candidates = locate_result.get("results", [])

    payload: dict[str, Any] = {
        "query": query,
        "workspace": workspace.name,
        "result_count": len(candidates),
        "results": candidates,
    }
    if workflow:
        workflow = server.workflow_manager.update_session(
            workspace.name,
            workflow["workflow_id"],
            fields={"stage": "candidates_located"},
            candidate_files=candidates,
            event_type="candidates_located",
            event_payload={"query": query, "result_count": len(candidates)},
        )
        payload["workflow"] = {
            "workflow_id": workflow["workflow_id"],
            "status": workflow["status"],
            "stage": workflow["stage"],
            "updated_at": workflow["updated_at"],
        }

    return json_response(payload)


async def build_verification_plan(server: Any, args: dict) -> Any:
    """Build a deterministic verification plan from workspace artifacts."""
    workspace, workflow, error = resolve_workflow_context(server, args)
    if error:
        return [TextContent(type="text", text=f"Error: {error}")]

    mode = ((args or {}).get("mode") or "minimal").strip().lower()
    if mode not in {"minimal", "full"}:
        mode = "minimal"

    repo_names = (args or {}).get("repo_names")
    target_repos = workspace.repos
    if repo_names:
        target_repos = []
        for repo_name in repo_names:
            repo_info, repo_error = server._find_repo_in_workspace(workspace, repo_name)
            if repo_error:
                return [TextContent(type="text", text=f"Error: {repo_error}")]
            target_repos.append(repo_info)

    build_data = read_build_command_data(server, workspace) or {}
    build_repos = build_data.get("repos") or {}
    workspace_index = server._read_workspace_index(workspace) or {}
    indexed_repos = workspace_index.get("repos") or {}

    plan_repos = []
    missing_repos = []
    for repo in target_repos:
        repo_entry = build_repos.get(repo.name) or {}
        commands = list(repo_entry.get("commands") or [])
        source = "build_command.json" if commands else None
        if not commands:
            commands = list((indexed_repos.get(repo.name) or {}).get("how_to_run") or [])
            if commands:
                source = "repo_index"

        selected_commands = select_verification_commands(commands, mode)
        if not selected_commands:
            missing_repos.append(repo.name)

        plan_repos.append(
            {
                "repo": repo.name,
                "path": repo.local_path,
                "source": source or "missing",
                "selected_commands": selected_commands,
                "available_commands": commands[:5] if mode == "full" else commands[:3],
            }
        )

    plan = {
        "workspace": workspace.name,
        "mode": mode,
        "repos": plan_repos,
        "missing_repos": missing_repos,
        "recommended_order": [entry["repo"] for entry in plan_repos if entry["selected_commands"]],
    }

    payload: dict[str, Any] = {"verification_plan": plan}
    if workflow:
        workflow = server.workflow_manager.update_session(
            workspace.name,
            workflow["workflow_id"],
            fields={"stage": "verification_planned"},
            verification_plan=plan,
            event_type="verification_planned",
            event_payload={"mode": mode, "repo_count": len(plan_repos)},
        )
        from . import subagent_tools

        verifier_query = " ".join(
            filter(
                None,
                [
                    workflow.get("objective"),
                    "verification",
                    " ".join(plan.get("recommended_order") or []),
                ],
            )
        ).strip()
        workflow, auto_results = subagent_tools.auto_run_subagent_roles(
            server,
            workspace,
            workflow,
            ["verifier"],
            query=verifier_query,
            reason="verification_planned",
        )
        payload["workflow"] = {
            "workflow_id": workflow["workflow_id"],
            "status": workflow["status"],
            "stage": workflow["stage"],
            "updated_at": workflow["updated_at"],
        }
        payload["auto_subagents"] = auto_results

    return json_response(payload)


async def workspace_locate(server: Any, args: dict) -> Any:
    """Locate likely files and symbols within a workspace using repo_index.json."""
    workspace_name = (args or {}).get("workspace_name")
    query = ((args or {}).get("query") or "").strip()
    limit = int((args or {}).get("limit", 8) or 8)
    limit = max(1, min(25, limit))

    if not query:
        return [TextContent(type="text", text="Error: query is required")]

    workspace, error = server._get_workspace_or_active(workspace_name)
    if error:
        return [TextContent(type="text", text=f"Error: {error}")]

    if workspace.repos:
        server._ensure_workspace_ai_artifacts(workspace)

    workspace_index = server._read_workspace_index(workspace)
    if not workspace_index:
        return [TextContent(type="text", text="Error: workspace index is not available")]

    locate_result = locate_in_workspace_index(workspace_index, query, limit=limit)
    return json_response(
        {
            "workspace": workspace.name,
            "query": query,
            "limit": limit,
            "result_count": len(locate_result.get("results") or []),
            "results": locate_result.get("results") or [],
            "index_path": workspace_artifact_paths(server, workspace)["repo_index"],
        }
    )


async def refresh_workspace_context(server: Any, args: dict) -> Any:
    """Refresh workspace AI artifacts using incremental or full mode."""
    workspace_name = (args or {}).get("workspace_name")
    generate_code_workspace_file = bool((args or {}).get("generate_code_workspace_file", False))
    mode = ((args or {}).get("mode") or "delta").strip().lower()
    if mode not in {"delta", "full"}:
        mode = "delta"

    workspace, error = server._get_workspace_or_active(workspace_name)
    if error:
        return [TextContent(type="text", text=f"Error: {error}")]

    try:
        generated = ensure_workspace_ai_files(
            workspace,
            generate_code_workspace_file=generate_code_workspace_file,
            mode=mode,
        )
    except Exception as exc:
        return [TextContent(type="text", text=f"Error refreshing workspace context: {str(exc)}")]

    return json_response(
        {
            "workspace": workspace_summary(server, workspace),
            "generated": generated,
            "refresh": generated.get("refresh") or {"mode": mode},
        }
    )


async def get_workspace_info(server: Any, args: dict) -> Any:
    """Return a structured workspace snapshot with git and artifact metadata."""
    workspace, error = server._get_workspace_or_active((args or {}).get("workspace_name"))
    if error:
        return [TextContent(type="text", text=f"Error: {error}")]

    summary = workspace_summary(server, workspace)
    artifacts_present = {
        name: os.path.exists(path)
        for name, path in summary.get("artifacts", {}).items()
    }

    repos: list[dict[str, Any]] = []
    for repo in workspace.repos:
        repo_payload = {
            "name": repo.name,
            "url": server._sanitize_url(repo.url),
            "path": repo.local_path,
            "branch": repo.branch,
            "last_updated": repo.last_updated,
            "exists": os.path.exists(repo.local_path),
        }
        if repo_payload["exists"]:
            repo_info = server.git_manager.get_repo_info(repo.local_path)
            if "error" in repo_info:
                repo_payload["git"] = {"error": repo_info["error"]}
            else:
                repo_payload["git"] = {
                    "branch": repo_info.get("branch"),
                    "remote_url": server._sanitize_url(repo_info.get("remote_url")),
                    "last_commit_date": repo_info.get("last_commit_date"),
                    "is_dirty": repo_info.get("is_dirty"),
                    "untracked_files": repo_info.get("untracked_files"),
                }
        repos.append(repo_payload)

    summary["repos"] = repos
    return json_response(
        {
            "workspace": summary,
            "artifacts_present": artifacts_present,
        }
    )


async def verify_repos(server: Any, args: dict) -> Any:
    """Run configured verification commands and return structured execution results."""
    workspace, workflow, error = resolve_workflow_context(server, args)
    if error:
        return [TextContent(type="text", text=f"Error: {error}")]

    repo_names = (args or {}).get("repo_names")
    timeout = int((args or {}).get("timeout", 600) or 600)
    timeout = max(1, timeout)
    mode = ((args or {}).get("mode") or "minimal").strip().lower()
    if mode not in {"minimal", "full"}:
        mode = "minimal"

    build_data = read_build_command_data(server, workspace)
    if not build_data:
        return [TextContent(type="text", text="Error: build_command.json is not available")]

    repo_entries = build_data.get("repos") or {}
    workspace_index = server._read_workspace_index(workspace) or {}
    indexed_repos = workspace_index.get("repos") or {}
    order = list(build_data.get("order") or [repo.name for repo in workspace.repos])
    if repo_names:
        requested = {name for name in repo_names}
        order = [name for name in order if name in requested]

    missing_repos: list[str] = []
    results: list[dict[str, Any]] = []

    for repo_name in order:
        repo_entry = repo_entries.get(repo_name) or {}
        repo_info, repo_error = server._find_repo_in_workspace(workspace, repo_name)
        repo_path = repo_entry.get("path") or (repo_info.local_path if repo_info else None)
        commands = [command for command in (repo_entry.get("commands") or []) if isinstance(command, str) and command.strip()]
        source = repo_entry.get("source")
        if not commands:
            indexed_commands = [
                command
                for command in ((indexed_repos.get(repo_name) or {}).get("how_to_run") or [])
                if isinstance(command, str) and command.strip()
            ]
            if indexed_commands:
                commands = select_verification_commands(indexed_commands, mode)
                source = "repo_index"
        repo_result = {
            "repo": repo_name,
            "path": repo_path,
            "source": source,
            "commands": [],
            "success": False,
            "skipped": False,
        }

        if not commands:
            missing_repos.append(repo_name)
            repo_result["skipped"] = True
            repo_result["error"] = "missing_commands"
            results.append(repo_result)
            continue

        if repo_error and not repo_path:
            repo_result["skipped"] = True
            repo_result["error"] = repo_error
            results.append(repo_result)
            continue

        if not repo_path or not os.path.exists(repo_path):
            repo_result["skipped"] = True
            repo_result["error"] = f"repository_not_found: {repo_path}"
            results.append(repo_result)
            continue

        repo_success = True
        for command in commands:
            command_result = {
                "command": command,
                "success": False,
                "timed_out": False,
                "exit_code": None,
                "stdout_excerpt": "",
                "stderr_excerpt": "",
            }
            try:
                result = await server._run_subprocess(
                    command,
                    cwd=repo_path,
                    timeout=timeout,
                    shell=True,
                )
                command_result["exit_code"] = result.returncode
                command_result["success"] = result.returncode == 0
                command_result["stdout_excerpt"] = ((result.stdout or "").strip())[:1000]
                command_result["stderr_excerpt"] = ((result.stderr or "").strip())[:1000]
            except subprocess.TimeoutExpired:
                repo_success = False
                command_result["timed_out"] = True
                command_result["stderr_excerpt"] = f"Timed out after {timeout} seconds"
            except Exception as exc:
                repo_success = False
                command_result["stderr_excerpt"] = str(exc)
            else:
                if not command_result["success"]:
                    repo_success = False

            repo_result["commands"].append(command_result)

        repo_result["success"] = repo_success
        results.append(repo_result)

    completed = [item for item in results if not item["skipped"]]
    successful = [item for item in completed if item["success"]]
    failed = [item for item in completed if not item["success"]]
    skipped = [item for item in results if item["skipped"]]

    status = "completed"
    if missing_repos:
        status = "missing_commands"
    elif failed:
        status = "completed_with_errors"

    payload: dict[str, Any] = {
        "status": status,
        "workspace": workspace.name,
        "build_command_path": str(server._workspace_build_commands_path(workspace.name)),
        "timeout_seconds": timeout,
        "mode": mode,
        "requested_repos": list(repo_names or []),
        "missing_repos": missing_repos,
        "summary": {
            "repo_count": len(order),
            "completed": len(completed),
            "successful": len(successful),
            "failed": len(failed),
            "skipped": len(skipped),
        },
        "results": results,
    }
    if workflow:
        from . import subagent_tools

        verifier_query = " ".join(filter(None, [workflow.get("objective"), "verification execution"])).strip()
        workflow, auto_results = subagent_tools.auto_run_subagent_roles(
            server,
            workspace,
            workflow,
            ["verifier"],
            query=verifier_query,
            reason="verify_repos",
        )
        payload["workflow"] = {
            "workflow_id": workflow["workflow_id"],
            "status": workflow["status"],
            "stage": workflow["stage"],
            "updated_at": workflow["updated_at"],
        }
        payload["auto_subagents"] = auto_results

    return json_response(payload)
