"""Ticket-analysis helper functions for the multi-repo MCP server."""

from __future__ import annotations

import asyncio
from datetime import datetime
from typing import Any, Optional

from mcp.types import TextContent

from .linear_client import (
    LinearAuthError,
    LinearNotFoundError,
    LinearRequestError,
    LinearValidationError,
)
from .retrieval_tools import build_context_packet
from .workspace_ai import locate_in_workspace_index
from .workflow_tools import json_response, resolve_workflow_context


async def analyze_ticket_in_workspace(
    server: Any,
    workspace: Any,
    args: dict,
    workflow: Optional[dict[str, Any]] = None,
) -> Any:
    """Fetch Linear ticket, ground it in workspace context, and provide analysis."""
    if not server.linear_client:
        return [TextContent(type="text", text="Error: Linear API is not configured. Set linear_api_key.")]
    if not server.code_reviewer:
        return [TextContent(type="text", text="Error: Code review/analysis is not enabled. Configure OpenAI key.")]

    issue_id = args.get("issue_id")
    repo_names = args.get("repo_names")
    file_pattern = args.get("file_pattern")
    max_matches = args.get("max_matches", 50)

    if not issue_id:
        return [TextContent(type="text", text="Error: issue_id is required")]

    try:
        ticket = await asyncio.to_thread(server.linear_client.get_issue, issue_id)
    except LinearValidationError as e:
        if workflow:
            server.workflow_manager.update_session(
                workspace.name,
                workflow["workflow_id"],
                event_type="ticket_fetch_failed",
                event_payload={"issue_id": issue_id, "error": str(e), "kind": "validation"},
            )
        return [TextContent(type="text", text=f"Error: {str(e)}")]
    except LinearNotFoundError as e:
        if workflow:
            server.workflow_manager.update_session(
                workspace.name,
                workflow["workflow_id"],
                event_type="ticket_fetch_failed",
                event_payload={"issue_id": issue_id, "error": str(e), "kind": "not_found"},
            )
        return [TextContent(type="text", text=f"Error: {str(e)}")]
    except LinearAuthError as e:
        if workflow:
            server.workflow_manager.update_session(
                workspace.name,
                workflow["workflow_id"],
                event_type="ticket_fetch_failed",
                event_payload={"issue_id": issue_id, "error": str(e), "kind": "auth"},
            )
        return [TextContent(type="text", text=f"Error fetching Linear ticket: {str(e)}")]
    except LinearRequestError as e:
        if workflow:
            server.workflow_manager.update_session(
                workspace.name,
                workflow["workflow_id"],
                event_type="ticket_fetch_failed",
                event_payload={"issue_id": issue_id, "error": str(e), "kind": "request"},
            )
        return [TextContent(type="text", text=f"Error fetching Linear ticket: {str(e)}")]
    except Exception as e:
        return [TextContent(type="text", text=f"Error fetching Linear ticket: {str(e)}")]

    ticket_artifact_path = None
    if workflow:
        ticket_artifact_path = server.workflow_manager.write_json_artifact(
            workspace.name,
            workflow["workflow_id"],
            "linear_ticket.json",
            ticket,
        )
        workflow = server.workflow_manager.update_session(
            workspace.name,
            workflow["workflow_id"],
            artifacts={"linear_ticket": ticket, "linear_ticket_path": ticket_artifact_path},
            event_type="ticket_fetched",
            event_payload={"issue_id": ticket.get("identifier") or issue_id},
        )

    target_repos = workspace.repos
    if repo_names:
        filtered = []
        for name in repo_names:
            repo_info, error = server._find_repo_in_workspace(workspace, name)
            if error:
                return [TextContent(type="text", text=f"Error: {error}")]
            filtered.append(repo_info)
        target_repos = filtered

    repos = [{"name": repo.name, "path": repo.local_path} for repo in target_repos]

    search_text = f"{ticket.get('title', '')} {ticket.get('description', '')}"
    keywords = server._extract_keywords(search_text, limit=6)
    matches = []
    for kw in keywords:
        try:
            kw_matches = server.searcher.search_all_repos(
                repos, kw, file_pattern=file_pattern, context_lines=3, max_matches=max_matches
            )
        except ValueError as e:
            return [TextContent(type="text", text=f"Error: {str(e)}")]
        for match in kw_matches:
            matches.append(
                {
                    "repo": match.repo_name,
                    "file": match.file_path,
                    "line": match.line_number,
                    "snippet": match.line_content,
                }
            )
        if len(matches) >= max_matches:
            matches = matches[:max_matches]
            break

    if workspace.repos:
        server._ensure_workspace_ai_artifacts(workspace)

    workspace_index = server._read_workspace_index(workspace)
    locate_hits: list[dict[str, Any]] = []
    if workspace_index:
        try:
            locate_query = " ".join(filter(None, [ticket.get("identifier", ""), ticket.get("title", "")])).strip()
            locate_payload = locate_in_workspace_index(workspace_index, locate_query or search_text, limit=8)
            locate_hits = locate_payload.get("results", [])
        except Exception:
            locate_hits = []

    workspace_root = server._workspace_root(workspace) or (server.workspace_manager.workspaces_dir / workspace.name)
    context_packet = build_context_packet(
        workspace_root,
        workspace_index or {},
        " ".join(filter(None, [ticket.get("identifier", ""), ticket.get("title", ""), ticket.get("description", "")])),
        repo_names=[repo["name"] for repo in repos],
        locate_hits=locate_hits,
    )
    analysis_matches = _select_analysis_matches(matches, keywords, limit=min(12, max_matches))

    analysis = server.code_reviewer.analyze_ticket(
        ticket=ticket,
        repo_names=[repo["name"] for repo in repos],
        matches=analysis_matches,
        workspace_rules=server.config.get("workspace_rules"),
        workspace_context=context_packet,
        workspace_locate_hits=locate_hits,
    )

    if not analysis.get("success"):
        if workflow:
            server.workflow_manager.update_session(
                workspace.name,
                workflow["workflow_id"],
                event_type="ticket_analysis_failed",
                event_payload={
                    "issue_id": issue_id,
                    "error": analysis.get("error"),
                },
            )
        return [TextContent(type="text", text=f"Error during analysis: {analysis.get('error')}")]

    analysis_text = analysis.get("analysis", "No analysis returned.")
    repo_match_counts: dict[str, int] = {}
    file_match_keys: set[str] = set()
    for match in matches:
        repo_name = match.get("repo") or "unknown"
        repo_match_counts[repo_name] = repo_match_counts.get(repo_name, 0) + 1
        file_match_keys.add(f"{repo_name}:{match.get('file')}")

    summary_parts = [
        f"Linear Ticket: {ticket.get('identifier')} - {ticket.get('title')}",
        f"Workspace: {workspace.name}",
        f"Repos searched: {len(repos)}",
        f"Keyword matches: {len(matches)}",
    ]
    if locate_hits:
        summary_parts.append(f"Workspace locate hits: {len(locate_hits)}")
    summary = " | ".join(summary_parts)

    payload: dict[str, Any] = {
        "ticket": ticket,
        "workspace": {
            "name": workspace.name,
            "repo_count": len(workspace.repos),
            "repo_names": [repo.name for repo in workspace.repos],
        },
        "analysis": {
            "text": analysis_text,
            "keywords": keywords,
            "search_summary": {
                "repo_names": [repo["name"] for repo in repos],
                "repo_count": len(repos),
                "match_count": len(matches),
                "matched_file_count": len(file_match_keys),
                "match_counts_by_repo": repo_match_counts,
                "max_matches": max_matches,
                "analysis_match_count": len(analysis_matches),
                "file_pattern": file_pattern,
            },
            "matches": matches,
            "locate_hits": locate_hits,
            "workspace_context": {
                "included": True,
                "mode": context_packet.get("mode"),
                "workspace_digest_chars": len((context_packet.get("workspace_digest") or {}).get("excerpt", "")),
                "repo_summary_count": len(context_packet.get("repo_summaries") or []),
                "retrieval_hit_count": len(context_packet.get("retrieval_hits") or []),
                "logic_hit_count": len(context_packet.get("logic_hits") or []),
            },
            "context_packet": context_packet,
        },
        "summary": summary,
    }

    if workflow:
        artifact = {
            "issue_id": issue_id,
            "ticket_identifier": ticket.get("identifier"),
            "ticket_title": ticket.get("title"),
            "ticket_url": ticket.get("url"),
            "repo_names": [repo["name"] for repo in repos],
            "keywords": keywords,
            "match_count": len(matches),
            "matched_file_count": len(file_match_keys),
                "match_counts_by_repo": repo_match_counts,
                "matches": matches,
                "locate_hit_count": len(locate_hits),
                "locate_hits": locate_hits,
                "analysis_match_count": len(analysis_matches),
                "context_packet": context_packet,
                "analysis": analysis_text,
                "summary": summary,
                "updated_at": datetime.utcnow().isoformat(),
        }
        analysis_artifact_path = server.workflow_manager.write_json_artifact(
            workspace.name,
            workflow["workflow_id"],
            "ticket_analysis.json",
            artifact,
        )
        handoff_artifact_path = server.workflow_manager.write_text_artifact(
            workspace.name,
            workflow["workflow_id"],
            "developer_handoff.md",
            _render_developer_handoff(
                ticket=ticket,
                keywords=keywords,
                locate_hits=locate_hits,
                analysis_text=analysis_text,
            ),
        )
        workflow = server.workflow_manager.update_session(
            workspace.name,
            workflow["workflow_id"],
            fields={"stage": "ticket_analyzed"},
            artifacts={
                "linear_ticket": ticket,
                "linear_ticket_path": ticket_artifact_path,
                "ticket_analysis": artifact,
                "ticket_analysis_path": analysis_artifact_path,
                "developer_handoff_path": handoff_artifact_path,
            },
            event_type="ticket_analyzed",
            event_payload={
                "issue_id": issue_id,
                "match_count": len(matches),
                "locate_hit_count": len(locate_hits),
            },
        )
        payload["workflow"] = {
            "workflow_id": workflow["workflow_id"],
            "status": workflow["status"],
            "stage": workflow["stage"],
            "updated_at": workflow["updated_at"],
        }
        payload["artifacts"] = {
            "linear_ticket": ticket_artifact_path,
            "ticket_analysis": analysis_artifact_path,
            "developer_handoff": handoff_artifact_path,
        }
        from . import subagent_tools

        auto_query = " ".join(
            filter(
                None,
                [
                    ticket.get("identifier"),
                    ticket.get("title"),
                    "trace fix plan",
                ],
            )
        ).strip()
        workflow, auto_results = subagent_tools.auto_run_subagent_roles(
            server,
            workspace,
            workflow,
            ["trace", "fix_plan"],
            query=auto_query,
            reason="ticket_analyzed",
        )
        payload["workflow"] = {
            "workflow_id": workflow["workflow_id"],
            "status": workflow["status"],
            "stage": workflow["stage"],
            "updated_at": workflow["updated_at"],
        }
        payload["auto_subagents"] = auto_results

    return json_response(payload)


async def analyze_ticket(server: Any, args: dict) -> Any:
    """Fetch Linear ticket, search repos, and provide analysis."""
    workspace, workflow, error = resolve_workflow_context(server, args)
    if error:
        return [TextContent(type="text", text=f"Error: {error}. Use ensure_workspace first.")]
    return await analyze_ticket_in_workspace(server, workspace, args, workflow=workflow)


def _select_analysis_matches(matches: list[dict[str, Any]], keywords: list[str], limit: int) -> list[dict[str, Any]]:
    """Pass only the most useful search matches into the LLM prompt."""
    if not matches:
        return []

    lowered_keywords = [keyword.lower() for keyword in keywords if keyword]
    scored: list[tuple[float, dict[str, Any]]] = []
    for index, match in enumerate(matches):
        snippet = str(match.get("snippet") or "").lower()
        path = str(match.get("file") or "").lower()
        score = 1.0 / (index + 1)
        score += sum(1.0 for keyword in lowered_keywords if keyword in snippet)
        score += sum(1.5 for keyword in lowered_keywords if keyword in path)
        scored.append((score, match))

    scored.sort(key=lambda item: item[0], reverse=True)
    selected: list[dict[str, Any]] = []
    seen_files: set[str] = set()
    for _, match in scored:
        file_key = f"{match.get('repo')}:{match.get('file')}"
        if file_key in seen_files:
            continue
        seen_files.add(file_key)
        selected.append(match)
        if len(selected) >= limit:
            break
    return selected


def _render_developer_handoff(
    *,
    ticket: dict[str, Any],
    keywords: list[str],
    locate_hits: list[dict[str, Any]],
    analysis_text: str,
) -> str:
    lines = [
        f"# Developer Handoff: {ticket.get('identifier') or '<issue>'}",
        "",
        f"Title: {ticket.get('title') or ''}",
        f"State: {ticket.get('state') or 'unknown'}",
        f"URL: {ticket.get('url') or ''}",
        "",
        "## Search Keywords",
        ", ".join(keywords) if keywords else "None",
        "",
        "## Likely Starting Points",
    ]
    if locate_hits:
        for hit in locate_hits[:8]:
            location = f"{hit.get('repo')}:{hit.get('path')}"
            if hit.get("line"):
                location += f":{hit.get('line')}"
            lines.append(f"- {location}")
    else:
        lines.append("- No locate hits captured.")
    lines.extend(
        [
            "",
            "## Analysis",
            analysis_text.strip() or "No analysis text returned.",
            "",
            "## Next Step",
            "Implement the required code changes, refresh workspace context, and request developer review on the applied diff.",
        ]
    )
    return "\n".join(lines)
