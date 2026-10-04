"""Resource and prompt helpers for the multi-repo MCP server."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

from mcp.server.lowlevel.helper_types import ReadResourceContents
from mcp.types import GetPromptResult, Prompt, PromptArgument, PromptMessage, Resource, ResourceTemplate, TextContent


_TEXT_MIME_BY_SUFFIX = {
    ".md": "text/markdown",
    ".json": "application/json",
    ".txt": "text/plain",
    ".rules": "text/plain",
}


def make_workspace_uri(workspace_name: str, relative_path: str) -> str:
    rel = relative_path.replace("\\", "/").lstrip("/")
    return f"workspace://{workspace_name}/{rel}"


def list_resources(server: Any) -> list[Resource]:
    """List stable workspace resources for all known workspaces."""
    resources: list[Resource] = []
    for workspace in server.workspace_manager.list_workspaces():
        workspace_root = server._workspace_root(workspace) or (server.workspace_manager.workspaces_dir / workspace.name)
        known_files = [
            ("context.md", "Workspace context", "text/markdown"),
            ("WORKSPACE_CONTEXT.md", "Workspace context (canonical)", "text/markdown"),
            ("build_command.json", "Build commands", "application/json"),
            (".mcp/architecture_map.json", "Workspace architecture map", "application/json"),
            (".mcp/repo_index.json", "Workspace repo index", "application/json"),
            (".mcp/digests.json", "Workspace digests", "application/json"),
            (".mcp/retrieval/chunks.json", "Workspace retrieval chunks", "application/json"),
            (".mcp/retrieval/logic_chunks.json", "Workspace logic chunks", "application/json"),
            (".mcp/summaries/workspace_digest.md", "Workspace digest", "text/markdown"),
        ]
        for relative_path, description, mime_type in known_files:
            path = workspace_root / relative_path
            if path.exists():
                resources.append(
                    Resource(
                        name=f"{workspace.name}:{relative_path}",
                        uri=make_workspace_uri(workspace.name, relative_path),
                        description=description,
                        mimeType=mime_type,
                        size=path.stat().st_size if path.exists() else None,
                    )
                )

        summaries_root = workspace_root / ".mcp" / "summaries" / "repos"
        if summaries_root.exists():
            for summary_path in summaries_root.rglob("repo_summary.md"):
                relative_path = summary_path.relative_to(workspace_root).as_posix()
                resources.append(
                    Resource(
                        name=f"{workspace.name}:{relative_path}",
                        uri=make_workspace_uri(workspace.name, relative_path),
                        description="Repository summary",
                        mimeType="text/markdown",
                        size=summary_path.stat().st_size,
                    )
                )

        workflow_root = workspace_root / ".mcp" / "workflows"
        if workflow_root.exists():
            for workflow_path in workflow_root.glob("*.json"):
                relative_path = workflow_path.relative_to(workspace_root).as_posix()
                resources.append(
                    Resource(
                        name=f"{workspace.name}:{relative_path}",
                        uri=make_workspace_uri(workspace.name, relative_path),
                        description="Workflow session",
                        mimeType="application/json",
                        size=workflow_path.stat().st_size,
                    )
                )

        workflow_artifact_root = workspace_root / ".mcp" / "workflow_artifacts"
        if workflow_artifact_root.exists():
            for artifact_path in workflow_artifact_root.rglob("*"):
                if not artifact_path.is_file():
                    continue
                relative_path = artifact_path.relative_to(workspace_root).as_posix()
                resources.append(
                    Resource(
                        name=f"{workspace.name}:{relative_path}",
                        uri=make_workspace_uri(workspace.name, relative_path),
                        description="Workflow artifact",
                        mimeType=_TEXT_MIME_BY_SUFFIX.get(artifact_path.suffix.lower(), "text/plain"),
                        size=artifact_path.stat().st_size,
                    )
                )

    return resources


def list_resource_templates(server: Any) -> list[ResourceTemplate]:
    """List parameterized workspace resource templates."""
    return [
        ResourceTemplate(
            name="architecture-map",
            uriTemplate="workspace://{workspace}/.mcp/architecture_map.json",
            description="Generalized workspace architecture map with controller/service/view/model mappings",
            mimeType="application/json",
        ),
        ResourceTemplate(
            name="workflow-session",
            uriTemplate="workspace://{workspace}/.mcp/workflows/{workflow_id}.json",
            description="Persisted workflow session JSON",
            mimeType="application/json",
        ),
        ResourceTemplate(
            name="repo-summary",
            uriTemplate="workspace://{workspace}/.mcp/summaries/repos/{repo}/repo_summary.md",
            description="Repository summary markdown",
            mimeType="text/markdown",
        ),
        ResourceTemplate(
            name="workflow-artifact",
            uriTemplate="workspace://{workspace}/.mcp/workflow_artifacts/{workflow_id}/{artifact_name}",
            description="Persisted workflow artifact such as saved ticket, analysis, diff, or review request",
            mimeType="text/plain",
        ),
    ]


def read_resource(server: Any, uri: Any) -> list[ReadResourceContents]:
    """Read a workspace resource from a workspace:// URI."""
    workspace_name, relative_path = _parse_workspace_uri(str(uri))
    workspace_root = server.workspace_manager.workspaces_dir / workspace_name
    if not workspace_root.exists():
        raise ValueError(f"Workspace '{workspace_name}' not found")

    full_path = (workspace_root / relative_path).resolve()
    try:
        full_path.relative_to(workspace_root.resolve())
    except ValueError as exc:
        raise ValueError(f"Invalid resource path: {relative_path}") from exc

    if not full_path.exists() or not full_path.is_file():
        raise ValueError(f"Resource not found: {uri}")

    suffix = full_path.suffix.lower()
    mime_type = _TEXT_MIME_BY_SUFFIX.get(suffix, "text/plain")
    if suffix == ".json":
        text = full_path.read_text(encoding="utf-8")
    else:
        text = full_path.read_text(encoding="utf-8", errors="ignore")

    return [ReadResourceContents(content=text, mime_type=mime_type)]


def list_prompts() -> list[Prompt]:
    """Expose small workflow prompts to guide MCP clients."""
    return [
        Prompt(
            name="bootstrap_workspace",
            description="Guide a client through the generic workspace-first workflow.",
            arguments=[
                PromptArgument(name="objective", description="What the user is trying to accomplish", required=True),
                PromptArgument(name="workspace_name", description="Workspace to use or create", required=False),
            ],
        ),
        Prompt(
            name="analyze_ticket",
            description="Guide a client through ticket analysis using the generic workflow path.",
            arguments=[
                PromptArgument(name="issue_id", description="Linear issue identifier", required=True),
                PromptArgument(name="workflow_id", description="Existing workflow session", required=False),
            ],
        ),
        Prompt(
            name="prepare_subagent",
            description="Guide a client through the phase 1 subagent flow using prepared packets and persisted results.",
            arguments=[
                PromptArgument(name="role", description="Subagent role such as searcher, trace, fix_plan, verifier, or reviewer", required=True),
                PromptArgument(name="workflow_id", description="Workflow session identifier", required=True),
            ],
        ),
    ]


def get_prompt(name: str, arguments: Optional[dict[str, str]]) -> GetPromptResult:
    """Return prompt text for small workflow templates."""
    arguments = arguments or {}
    if name == "bootstrap_workspace":
        objective = arguments.get("objective", "<objective>")
        workspace_name = arguments.get("workspace_name", "<workspace>")
        text = "\n".join(
            [
                f"Use the workspace-first flow for '{objective}'.",
                "0. If needed, call set_workspace_root before creating a workspace.",
                f"1. ensure_workspace with workspace_name '{workspace_name}' if needed.",
                "2. start_workflow with the user objective and let it continue automatically through context preparation.",
                "3. The workflow will auto-run the searcher subagent after context is prepared.",
                "4. If a ticket exists, let the workflow continue through ticket analysis; trace and fix_plan will auto-run there.",
                "5. Read architecture_map and workflow artifacts before broad searches.",
                "6. use locate_candidates or workspace_locate before broad searches.",
                "7. build_verification_plan before running repo verification; verifier will auto-run.",
            ]
        )
    elif name == "analyze_ticket":
        issue_id = arguments.get("issue_id", "<issue-id>")
        workflow_id = arguments.get("workflow_id", "<workflow-id>")
        text = "\n".join(
            [
                f"Analyze Linear ticket '{issue_id}' using the generic workflow path.",
                f"Prefer analyze_ticket with workflow_id '{workflow_id}' if a workflow already exists.",
                "Read context resources before broad searching.",
                "Persist findings back into the workflow session.",
            ]
        )
    elif name == "prepare_subagent":
        role = arguments.get("role", "<role>")
        workflow_id = arguments.get("workflow_id", "<workflow-id>")
        text = "\n".join(
            [
                f"Prepare a focused '{role}' subagent for workflow '{workflow_id}'.",
                "1. Call prepare_subagent_packet with the role and workflow_id.",
                "2. Or call run_subagent to let the MCP execute that focused advisory role server-side.",
                "3. The MCP already auto-runs searcher/trace/fix_plan/verifier/reviewer at workflow milestones.",
                "4. Give the subagent only that packet, not the full workspace context.",
                "5. Persist its structured output with store_subagent_result if it ran outside the MCP.",
                "6. Use merge_subagent_results before leader-side implementation or review.",
            ]
        )
    else:
        raise ValueError(f"Unknown prompt: {name}")

    return GetPromptResult(
        description=f"Prompt template: {name}",
        messages=[
            PromptMessage(
                role="user",
                content=TextContent(type="text", text=text),
            )
        ],
    )


def _parse_workspace_uri(uri: str) -> tuple[str, str]:
    parsed = urlparse(uri)
    if parsed.scheme != "workspace":
        raise ValueError(f"Unsupported resource URI: {uri}")
    workspace_name = parsed.netloc
    relative_path = parsed.path.lstrip("/")
    if not workspace_name or not relative_path:
        raise ValueError(f"Invalid workspace resource URI: {uri}")
    return workspace_name, relative_path
