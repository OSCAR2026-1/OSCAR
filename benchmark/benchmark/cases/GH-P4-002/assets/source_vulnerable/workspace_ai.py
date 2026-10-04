
"""Workspace AI artifacts: .clinerules, workspace context, and repo index.

These files are generated inside each created workspace after repositories are cloned,
so Cline (or any coding agent) can quickly orient itself and locate relevant code with fewer searches.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .workspace_manager import Workspace


_TEXT_EXTS = {
    ".py", ".js", ".ts", ".tsx", ".jsx", ".java", ".kt", ".go", ".rs", ".cs",
    ".php", ".rb", ".swift", ".scala", ".c", ".cc", ".cpp", ".h", ".hpp",
    ".md", ".txt", ".yml", ".yaml", ".json", ".toml", ".ini", ".gradle",
    ".xml", ".sql", ".sh", ".bash", ".zsh",
}

# Limit how much we scan so setup stays fast
_MAX_FILES_PER_REPO = 2500
_MAX_BYTES_PER_FILE = 512 * 1024  # 512 KB
_MAX_SYMBOLS_PER_REPO = 400
_MAX_RETRIEVAL_FILES_PER_REPO = 36
_MAX_RETRIEVAL_CHUNKS_PER_REPO = 72
_MAX_RETRIEVAL_CHUNKS_PER_FILE = 3
_RETRIEVAL_CHUNK_LINE_COUNT = 36
_RETRIEVAL_CHUNK_CHAR_LIMIT = 700
_MAX_LOGIC_FILES_PER_REPO = 260
_MAX_LOGIC_CHUNKS_PER_REPO = 240
_MAX_LOGIC_CHUNKS_PER_FILE = 4
_LOGIC_CHUNK_LINE_LIMIT = 80
_LOGIC_CHUNK_CHAR_LIMIT = 1600
_REPO_INDEX_VERSION = 2
_DIGEST_SCHEMA_VERSION = 2
_RETRIEVAL_SCHEMA_VERSION = 2
_LOGIC_CHUNK_SCHEMA_VERSION = 2
_ARCHITECTURE_SCHEMA_VERSION = 1


def ensure_workspace_ai_files(
    workspace: Workspace,
    *,
    generate_code_workspace_file: bool = False,
    mode: str = "delta",
) -> Dict[str, Any]:
    """
    Generate/refresh workspace AI artifacts.

    Returns dict with paths of generated files.
    """
    ws_dir = Path(workspace.repos[0].local_path).parent if workspace.repos else None
    # WorkspaceManager stores repos under: <workspaces_dir>/<name>/<repo_name>
    # So workspace root is parent of repo folders.
    # We infer root from any repo path; if none, fallback to workspaces/<name>
    if ws_dir is None:
        raise ValueError("Workspace has no repositories; cannot infer workspace root.")
    workspace_root = ws_dir  # repo folders live directly under workspace root
    # but some implementations may use <workspace>/repos/<repo>; handle that too
    if (workspace_root / "repos").exists():
        workspace_root = workspace_root

    mcp_dir = workspace_root / ".mcp"
    mcp_dir.mkdir(parents=True, exist_ok=True)
    summaries_dir = mcp_dir / "summaries"
    summaries_dir.mkdir(parents=True, exist_ok=True)

    clinerules_path = workspace_root / ".clinerules"
    ctx_path_upper = workspace_root / "WORKSPACE_CONTEXT.md"
    ctx_path_lower = workspace_root / "workspace_context.md"
    # Some agents prefer a generic name; keep an alias for convenience.
    ctx_path_generic = workspace_root / "context.md"
    index_path = mcp_dir / "repo_index.json"
    digests_path = mcp_dir / "digests.json"
    workspace_digest_path = summaries_dir / "workspace_digest.md"
    retrieval_chunks_path = mcp_dir / "retrieval" / "chunks.json"
    logic_chunks_path = mcp_dir / "retrieval" / "logic_chunks.json"
    architecture_map_path = mcp_dir / "architecture_map.json"

    previous_index = _load_json(index_path)
    previous_digests = _load_json(digests_path)
    previous_retrieval = _load_json(retrieval_chunks_path)
    previous_logic_chunks = _load_json(logic_chunks_path)

    # Build repo index first (used to author context)
    index, digest_data, refresh_stats = build_repo_index(
        workspace_root,
        workspace,
        previous_index=previous_index,
        previous_digests=previous_digests,
        mode=mode,
    )

    _write_json(index_path, index)
    _write_json(digests_path, digest_data)

    retrieval_data = build_retrieval_metadata(
        workspace,
        index,
        digest_data,
        previous_retrieval=previous_retrieval,
        mode=mode,
    )
    _write_json(retrieval_chunks_path, retrieval_data)
    logic_chunk_data = build_logic_chunk_metadata(
        workspace,
        index,
        digest_data,
        previous_logic_chunks=previous_logic_chunks,
        mode=mode,
    )
    _write_json(logic_chunks_path, logic_chunk_data)
    architecture_map = build_architecture_map(
        workspace,
        index,
        logic_chunk_data,
        digest_data=digest_data,
    )
    _write_json(architecture_map_path, architecture_map)

    workspace_digest_md = render_workspace_digest_md(workspace_root, workspace, index, refresh_stats)
    _write_text(workspace_digest_path, workspace_digest_md)

    repo_summary_paths: Dict[str, str] = {}
    repos_summary_root = summaries_dir / "repos"
    for repo_name, repo_data in (index.get("repos") or {}).items():
        repo_summary_path = repos_summary_root / repo_name / "repo_summary.md"
        _write_text(repo_summary_path, render_repo_summary_md(repo_name, repo_data))
        repo_summary_paths[repo_name] = str(repo_summary_path)

    # Write workspace context markdown
    ctx_md = render_workspace_context_md(workspace_root, workspace, index)
    _write_text(ctx_path_upper, ctx_md)
    _write_text(ctx_path_lower, ctx_md)
    _write_text(ctx_path_generic, ctx_md)

    # Write stable clinerules (minimal-diff contract + "read/update context")
    rules = render_clinerules(workspace_root)
    _write_text(clinerules_path, rules)

    # Optional: generate a .code-workspace file (do NOT auto-open it)
    code_ws_path = None
    if generate_code_workspace_file:
        code_ws_path = workspace_root / f"{workspace.name}.code-workspace"
        _write_text(code_ws_path, json.dumps(render_code_workspace(workspace_root, workspace), indent=2))

    out = {
        "clinerules": str(clinerules_path),
        "workspace_context_upper": str(ctx_path_upper),
        "workspace_context_lower": str(ctx_path_lower),
        "workspace_context_generic": str(ctx_path_generic),
        "repo_index": str(index_path),
        "digests": str(digests_path),
        "retrieval_chunks": str(retrieval_chunks_path),
        "logic_chunks": str(logic_chunks_path),
        "architecture_map": str(architecture_map_path),
        "workspace_digest": str(workspace_digest_path),
        "repo_summaries": repo_summary_paths,
        "refresh": refresh_stats,
    }
    if code_ws_path:
        out["code_workspace"] = str(code_ws_path)
    return out


def render_clinerules(workspace_root: Path) -> str:
    return "\n".join([
        "# Cline rules for this workspace",
        "",
        "## Always do this first",
        f"- Read `{(workspace_root / 'WORKSPACE_CONTEXT.md').name}` before making changes.",
        "- If a Linear ticket is provided, use it as *signal*, then ground in the codebase.",
        "- Use `workspace_locate` (MCP tool) before broad searches.",
        "- After workspace setup, continue automatically through context preparation. If a ticket exists, continue through ticket analysis unless required inputs are missing.",
        "",
        "## Minimal-diff contract (IMPORTANT)",
        "- Make the smallest change that satisfies the request.",
        "- Do NOT refactor, reformat, rename, or reorganize code unless explicitly requested.",
        "- Do NOT optimize unrelated code.",
        "- Preserve existing style and patterns in the touched files.",
        "- If you think refactoring is necessary, ask before doing it.",
        "",
        "## Scope guardrails",
        "- Prefer changing <= 3 files for a task.",
        "- Prefer <= 80 changed lines total.",
        "- If changes exceed these, stop and explain why, and propose a smaller patch.",
        "",
        "## After each task",
        "- Update `WORKSPACE_CONTEXT.md` under the 'Recent task log' section with:",
        "  - what changed (files)",
        "  - why",
        "  - how to verify (tests/commands)",
    ])


def render_workspace_context_md(workspace_root: Path, workspace: Workspace, index: Dict[str, Any]) -> str:
    repos = index.get("repos", {})
    lines: List[str] = []
    lines.append(f"# Workspace Context: {workspace.name}")
    lines.append("")
    lines.append("This file is generated by the MCP server after cloning repos. Update it after completing tasks.")
    lines.append("")
    lines.append("## Quick start")
    lines.append(f"- Workspace root: `{workspace_root}`")
    lines.append("- Prefer using MCP tool `workspace_locate` before doing broad searches.")
    lines.append("")
    lines.append("## Repositories")
    for repo_name, r in repos.items():
        lines.append(f"### {repo_name}")
        lines.append(f"- Path: `{r.get('path')}`")
        if r.get("url"):
            lines.append(f"- URL: {r.get('url')}")
        if r.get("primary_language"):
            lines.append(f"- Primary language: **{r.get('primary_language')}**")
        if r.get("entrypoints"):
            ep = ", ".join([f"`{p}`" for p in r["entrypoints"][:8]])
            lines.append(f"- Likely entrypoints: {ep}")
        if r.get("top_level_dirs"):
            tl = ", ".join([f"`{p}`" for p in r["top_level_dirs"][:10]])
            lines.append(f"- Top-level dirs: {tl}")
        if r.get("how_to_run"):
            lines.append("- How to run/test (best-effort):")
            for cmd in r["how_to_run"][:8]:
                lines.append(f"  - `{cmd}`")
        if r.get("notes"):
            lines.append(f"- Notes: {r['notes']}")
        lines.append("")
    lines.append("## Workspace locate usage")
    lines.append("Use this to jump to relevant logic quickly:")
    lines.append("```")
    lines.append('workspace_locate({"workspace_name": "<workspace-name>", "query": "what you need", "limit": 8})')
    lines.append("```")
    lines.append("")
    lines.append("## Generalized architecture artifacts")
    lines.append("- `.mcp/architecture_map.json` contains controller/service/view/model/config mappings and route-to-file hints.")
    lines.append("- `.mcp/retrieval/logic_chunks.json` stores reusable logic chunks for later retrieval; it is not ticket-specific.")
    lines.append("")
    lines.append("## Recent task log")
    lines.append("- (append entries here)")
    lines.append("")
    return "\n".join(lines)


def render_workspace_digest_md(
    workspace_root: Path,
    workspace: Workspace,
    index: Dict[str, Any],
    refresh_stats: Dict[str, Any],
) -> str:
    """Render a compact workspace digest focused on orientation and refresh state."""
    repos = index.get("repos", {})
    lines: List[str] = []
    lines.append(f"# Workspace Digest: {workspace.name}")
    lines.append("")
    lines.append(f"- Workspace root: `{workspace_root}`")
    lines.append(f"- Refresh mode: `{refresh_stats.get('mode', 'delta')}`")
    lines.append(f"- Generated at: `{refresh_stats.get('generated_at')}`")
    lines.append(f"- Changed repos: {', '.join(refresh_stats.get('changed_repos', [])) or 'None'}")
    lines.append(f"- Reused repos: {', '.join(refresh_stats.get('reused_repos', [])) or 'None'}")
    lines.append(f"- Missing repos: {', '.join(refresh_stats.get('missing_repos', [])) or 'None'}")
    lines.append("")
    lines.append("## Repo Overview")
    for repo_name, repo_data in repos.items():
        lines.append(f"### {repo_name}")
        if repo_data.get("primary_language"):
            lines.append(f"- Primary language: {repo_data['primary_language']}")
        if repo_data.get("entrypoints"):
            lines.append(f"- Entrypoints: {', '.join(repo_data['entrypoints'][:4])}")
        if repo_data.get("key_files"):
            lines.append(f"- Key files: {', '.join(repo_data['key_files'][:4])}")
        if repo_data.get("how_to_run"):
            lines.append(f"- Verify/run hints: {', '.join(repo_data['how_to_run'][:3])}")
        lines.append("")
    return "\n".join(lines)


def render_repo_summary_md(repo_name: str, repo_data: Dict[str, Any]) -> str:
    """Render a compact repo-level summary artifact."""
    lines: List[str] = []
    lines.append(f"# Repo Summary: {repo_name}")
    lines.append("")
    lines.append(f"- Path: `{repo_data.get('path')}`")
    if repo_data.get("primary_language"):
        lines.append(f"- Primary language: {repo_data['primary_language']}")
    if repo_data.get("top_level_dirs"):
        lines.append(f"- Top-level dirs: {', '.join(repo_data['top_level_dirs'][:10])}")
    if repo_data.get("entrypoints"):
        lines.append(f"- Entrypoints: {', '.join(repo_data['entrypoints'][:8])}")
    if repo_data.get("key_files"):
        lines.append(f"- Key files: {', '.join(repo_data['key_files'][:10])}")
    if repo_data.get("how_to_run"):
        lines.append("- How to run/test:")
        for command in repo_data["how_to_run"][:5]:
            lines.append(f"  - `{command}`")
    if repo_data.get("route_hints"):
        lines.append("- Route hints:")
        for route in repo_data["route_hints"][:6]:
            lines.append(f"  - `{route.get('route')}` in `{route.get('path')}`")
    if repo_data.get("symbols"):
        lines.append("- Key symbols:")
        for symbol in repo_data["symbols"][:10]:
            lines.append(f"  - `{symbol.get('name')}` ({symbol.get('kind')}) in `{symbol.get('path')}`")
    lines.append("")
    return "\n".join(lines)


def build_retrieval_metadata(
    workspace: Workspace,
    index: Dict[str, Any],
    digest_data: Dict[str, Any],
    *,
    previous_retrieval: Optional[Dict[str, Any]] = None,
    mode: str = "delta",
) -> Dict[str, Any]:
    """Build compact retrieval chunks for important files, reusing unchanged repos."""
    previous_repos = (previous_retrieval or {}).get("repos") or {}
    digest_repos = (digest_data or {}).get("repos") or {}
    normalized_mode = "full" if mode == "full" else "delta"
    previous_schema_version = int((previous_retrieval or {}).get("schema_version") or 0)
    retrieval_repos: Dict[str, Any] = {}

    for repo in workspace.repos:
        repo_path = Path(repo.local_path)
        if not repo_path.exists():
            continue

        repo_digest = digest_repos.get(repo.name) or {}
        fingerprint = repo_digest.get("fingerprint")
        previous_entry = previous_repos.get(repo.name) or {}
        should_reuse = (
            normalized_mode == "delta"
            and previous_schema_version == _RETRIEVAL_SCHEMA_VERSION
            and previous_entry.get("fingerprint") == fingerprint
            and bool(previous_entry.get("chunks"))
        )

        if should_reuse:
            retrieval_repos[repo.name] = previous_entry
            continue

        repo_data = (index.get("repos") or {}).get(repo.name) or {}
        chunks = _build_repo_retrieval_chunks(repo.name, repo_path, repo_data)
        retrieval_repos[repo.name] = {
            "fingerprint": fingerprint,
            "chunk_count": len(chunks),
            "chunks": chunks,
        }

    return {
        "schema_version": _RETRIEVAL_SCHEMA_VERSION,
        "workspace_name": workspace.name,
        "generated_at": (digest_data or {}).get("generated_at"),
        "repos": retrieval_repos,
    }


def build_logic_chunk_metadata(
    workspace: Workspace,
    index: Dict[str, Any],
    digest_data: Dict[str, Any],
    *,
    previous_logic_chunks: Optional[Dict[str, Any]] = None,
    mode: str = "delta",
) -> Dict[str, Any]:
    """Build persistent logic-oriented chunks with incremental reuse."""
    previous_repos = (previous_logic_chunks or {}).get("repos") or {}
    digest_repos = (digest_data or {}).get("repos") or {}
    normalized_mode = "full" if mode == "full" else "delta"
    previous_schema_version = int((previous_logic_chunks or {}).get("schema_version") or 0)
    logic_repos: Dict[str, Any] = {}

    for repo in workspace.repos:
        repo_path = Path(repo.local_path)
        if not repo_path.exists():
            continue

        repo_digest = digest_repos.get(repo.name) or {}
        fingerprint = repo_digest.get("fingerprint")
        previous_entry = previous_repos.get(repo.name) or {}
        should_reuse = (
            normalized_mode == "delta"
            and previous_schema_version == _LOGIC_CHUNK_SCHEMA_VERSION
            and previous_entry.get("fingerprint") == fingerprint
            and bool(previous_entry.get("chunks"))
        )
        if should_reuse:
            logic_repos[repo.name] = previous_entry
            continue

        repo_data = (index.get("repos") or {}).get(repo.name) or {}
        repo_logic = _build_repo_logic_chunks(
            repo.name,
            repo_path,
            repo_data,
            previous_entry=previous_entry if previous_schema_version == _LOGIC_CHUNK_SCHEMA_VERSION else None,
            allow_reuse=normalized_mode == "delta",
        )
        repo_logic["fingerprint"] = fingerprint
        logic_repos[repo.name] = repo_logic

    return {
        "schema_version": _LOGIC_CHUNK_SCHEMA_VERSION,
        "workspace_name": workspace.name,
        "generated_at": (digest_data or {}).get("generated_at"),
        "repos": logic_repos,
    }


def build_architecture_map(
    workspace: Workspace,
    index: Dict[str, Any],
    logic_chunk_data: Dict[str, Any],
    *,
    digest_data: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build a generalized architecture map from repo index + logic chunks."""
    logic_repos = (logic_chunk_data or {}).get("repos") or {}
    repos_payload: Dict[str, Any] = {}

    for repo in workspace.repos:
        repo_data = (index.get("repos") or {}).get(repo.name) or {}
        repo_logic = logic_repos.get(repo.name) or {}
        components = _build_repo_architecture_components(
            repo_data,
            repo_logic,
        )
        repos_payload[repo.name] = {
            "primary_language": repo_data.get("primary_language"),
            "entrypoints": (repo_data.get("entrypoints") or [])[:20],
            "key_files": (repo_data.get("key_files") or [])[:30],
            "top_level_dirs": (repo_data.get("top_level_dirs") or [])[:30],
            "top_level_files": (repo_data.get("top_level_files") or [])[:40],
            "how_to_run": (repo_data.get("how_to_run") or [])[:20],
            "roles": components["roles"],
            "components": components["components"],
            "route_map": components["route_map"],
            "stats": components["stats"],
        }

    return {
        "schema_version": _ARCHITECTURE_SCHEMA_VERSION,
        "workspace_name": workspace.name,
        "generated_at": (digest_data or {}).get("generated_at"),
        "repos": repos_payload,
    }


def _build_repo_architecture_components(
    repo_data: Dict[str, Any],
    repo_logic: Dict[str, Any],
) -> Dict[str, Any]:
    components_by_path: Dict[str, Dict[str, Any]] = {}

    def get_component(path: str) -> Dict[str, Any]:
        normalized = str(path or "").replace("\\", "/")
        component = components_by_path.get(normalized)
        if component is None:
            component = {
                "path": normalized,
                "roles": set(),
                "kinds": set(),
                "symbols": [],
                "routes": [],
                "imports": [],
                "summary": "",
            }
            components_by_path[normalized] = component
        return component

    for chunk in repo_logic.get("chunks") or []:
        path = str(chunk.get("path") or "").replace("\\", "/")
        if not path:
            continue
        component = get_component(path)
        roles = _architecture_roles_for_chunk(path, chunk)
        component["roles"].update(roles)
        kind = str(chunk.get("kind") or "").strip()
        if kind:
            component["kinds"].add(kind)
        symbol = str(chunk.get("symbol") or "").strip()
        if symbol and symbol not in component["symbols"]:
            component["symbols"].append(symbol)
        for route in chunk.get("routes") or []:
            if route and route not in component["routes"]:
                component["routes"].append(route)
        for statement in chunk.get("imports") or []:
            if statement and statement not in component["imports"]:
                component["imports"].append(statement)
        if not component["summary"] and chunk.get("summary"):
            component["summary"] = str(chunk.get("summary"))

    for path in repo_data.get("entrypoints") or []:
        get_component(path)["roles"].add("entrypoint")
    for path in repo_data.get("key_files") or []:
        component = get_component(path)
        component["roles"].add("config" if _looks_like_config_file(path) else "key_file")
    for symbol in repo_data.get("symbols") or []:
        path = str(symbol.get("path") or "").replace("\\", "/")
        if not path:
            continue
        component = get_component(path)
        for role in _architecture_roles_from_path(path):
            component["roles"].add(role)
        name = str(symbol.get("name") or "").strip()
        if name and name not in component["symbols"]:
            component["symbols"].append(name)
    for route in repo_data.get("route_hints") or []:
        path = str(route.get("path") or "").replace("\\", "/")
        if not path:
            continue
        component = get_component(path)
        component["roles"].update({"route", "api"})
        route_text = str(route.get("route") or "").strip()
        if route_text and route_text not in component["routes"]:
            component["routes"].append(route_text)

    role_names = [
        "entrypoint",
        "controller",
        "service",
        "repository",
        "model",
        "view",
        "config",
        "api",
        "utility",
        "job",
        "test",
    ]
    role_entries: Dict[str, List[Dict[str, Any]]] = {role: [] for role in role_names}
    route_map: List[Dict[str, Any]] = []

    component_list: List[Dict[str, Any]] = []
    for component in components_by_path.values():
        roles = sorted(component["roles"])
        kinds = sorted(component["kinds"])
        entry = {
            "path": component["path"],
            "roles": roles,
            "kinds": kinds,
            "symbols": component["symbols"][:12],
            "routes": component["routes"][:8],
            "summary": component["summary"] or _component_summary(component["path"], roles, component["symbols"]),
        }
        component_list.append(entry)
        for role in roles:
            if role not in role_entries:
                continue
            role_entries[role].append(
                {
                    "path": component["path"],
                    "symbols": component["symbols"][:8],
                    "route_count": len(component["routes"]),
                    "summary": entry["summary"],
                }
            )

    for route in repo_data.get("route_hints") or []:
        path = str(route.get("path") or "").replace("\\", "/")
        matching_component = components_by_path.get(path) or {}
        route_map.append(
            {
                "framework": route.get("framework"),
                "route": route.get("route"),
                "path": path,
                "line": route.get("line"),
                "handler_symbols": (matching_component.get("symbols") or [])[:6],
            }
        )

    for role, entries in role_entries.items():
        entries.sort(key=lambda item: (-item.get("route_count", 0), item.get("path") or ""))
        role_entries[role] = entries[:25]

    component_list.sort(
        key=lambda item: (
            -len(item.get("routes") or []),
            -len(item.get("symbols") or []),
            item.get("path") or "",
        )
    )

    stats = {
        "component_count": len(component_list),
        "route_count": len(route_map),
        "controller_count": len(role_entries["controller"]),
        "service_count": len(role_entries["service"]),
        "repository_count": len(role_entries["repository"]),
        "view_count": len(role_entries["view"]),
        "model_count": len(role_entries["model"]),
    }

    return {
        "roles": role_entries,
        "components": component_list[:80],
        "route_map": route_map[:120],
        "stats": stats,
    }


def _build_repo_retrieval_chunks(repo_name: str, repo_path: Path, repo_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Capture small, high-signal chunks for retrieval from important files only."""
    candidates: Dict[str, Dict[str, Any]] = {}

    def add_candidate(
        rel_path: str,
        *,
        tag: str,
        anchor_line: Optional[int] = None,
        symbol_name: Optional[str] = None,
        route: Optional[str] = None,
    ) -> None:
        rel_path = (rel_path or "").replace("\\", "/").strip()
        if not rel_path:
            return
        entry = candidates.setdefault(
            rel_path,
            {
                "tags": set(),
                "anchor_lines": [],
                "symbol_names": [],
                "routes": [],
            },
        )
        entry["tags"].add(tag)
        for inferred_tag in _infer_retrieval_tags(rel_path):
            entry["tags"].add(inferred_tag)
        if anchor_line and anchor_line > 0:
            entry["anchor_lines"].append(int(anchor_line))
        if symbol_name and symbol_name not in entry["symbol_names"]:
            entry["symbol_names"].append(symbol_name)
        if route and route not in entry["routes"]:
            entry["routes"].append(route)

    for rel_path in repo_data.get("entrypoints") or []:
        add_candidate(rel_path, tag="entrypoint", anchor_line=1)
    for rel_path in repo_data.get("key_files") or []:
        add_candidate(rel_path, tag="key_file", anchor_line=1)
    for rel_path in repo_data.get("top_level_files") or []:
        lower = rel_path.lower()
        if lower.startswith("readme") or lower in {"dockerfile", "makefile"}:
            add_candidate(rel_path, tag="docs", anchor_line=1)
    for route_hint in (repo_data.get("route_hints") or [])[:80]:
        add_candidate(
            route_hint.get("path", ""),
            tag="route",
            anchor_line=route_hint.get("line"),
            route=route_hint.get("route"),
        )
    for symbol in (repo_data.get("symbols") or [])[:150]:
        add_candidate(
            symbol.get("path", ""),
            tag="symbol",
            anchor_line=symbol.get("line"),
            symbol_name=symbol.get("name"),
        )

    scored_candidates = sorted(
        candidates.items(),
        key=lambda item: _retrieval_candidate_priority(item[1]),
        reverse=True,
    )

    chunks: List[Dict[str, Any]] = []
    for rel_path, entry in scored_candidates[:_MAX_RETRIEVAL_FILES_PER_REPO]:
        full_path = repo_path / rel_path
        if not full_path.exists() or not full_path.is_file():
            continue
        if full_path.suffix.lower() not in _TEXT_EXTS and full_path.name not in {"Dockerfile", "Makefile"}:
            continue

        try:
            content = _read_text_limited(full_path)
        except Exception:
            continue
        if not content.strip():
            continue

        file_chunks = _extract_retrieval_chunks(
            repo_name,
            rel_path,
            content,
            tags=sorted(entry["tags"]),
            anchor_lines=entry["anchor_lines"],
            symbol_names=entry["symbol_names"][:8],
            routes=entry["routes"][:4],
            remaining=max(0, _MAX_RETRIEVAL_CHUNKS_PER_REPO - len(chunks)),
        )
        chunks.extend(file_chunks)
        if len(chunks) >= _MAX_RETRIEVAL_CHUNKS_PER_REPO:
            break

    return chunks[:_MAX_RETRIEVAL_CHUNKS_PER_REPO]


def _extract_retrieval_chunks(
    repo_name: str,
    rel_path: str,
    content: str,
    *,
    tags: List[str],
    anchor_lines: List[int],
    symbol_names: List[str],
    routes: List[str],
    remaining: int,
) -> List[Dict[str, Any]]:
    if remaining <= 0:
        return []

    lines = content.splitlines()
    if not lines:
        return []

    windows = _chunk_windows(len(lines), anchor_lines)
    chunks: List[Dict[str, Any]] = []
    for start_line, end_line in windows[: min(_MAX_RETRIEVAL_CHUNKS_PER_FILE, remaining)]:
        snippet = "\n".join(lines[start_line - 1:end_line]).strip()
        if len(snippet) < 40:
            continue
        content_excerpt = snippet[:_RETRIEVAL_CHUNK_CHAR_LIMIT]
        preview = re.sub(r"\s+", " ", content_excerpt).strip()[:240]
        chunks.append(
            {
                "id": f"{repo_name}:{rel_path}:{start_line}-{end_line}",
                "path": rel_path,
                "start_line": start_line,
                "end_line": end_line,
                "tags": tags,
                "symbol_names": symbol_names,
                "routes": routes,
                "preview": preview,
                "content": content_excerpt,
            }
        )
    return chunks


def _chunk_windows(line_count: int, anchor_lines: List[int]) -> List[Tuple[int, int]]:
    windows: List[Tuple[int, int]] = []
    seen: set[Tuple[int, int]] = set()

    effective_anchors = [line for line in anchor_lines if line and line > 0]
    if not effective_anchors:
        effective_anchors = [1]

    for anchor in effective_anchors:
        start_line = max(1, anchor - 8)
        end_line = min(line_count, start_line + _RETRIEVAL_CHUNK_LINE_COUNT - 1)
        start_line = max(1, end_line - _RETRIEVAL_CHUNK_LINE_COUNT + 1)
        window = (start_line, end_line)
        if window not in seen:
            seen.add(window)
            windows.append(window)
        if len(windows) >= _MAX_RETRIEVAL_CHUNKS_PER_FILE:
            break

    if windows and windows[0][0] != 1 and len(windows) < _MAX_RETRIEVAL_CHUNKS_PER_FILE:
        start_line = 1
        end_line = min(line_count, _RETRIEVAL_CHUNK_LINE_COUNT)
        window = (start_line, end_line)
        if window not in seen:
            windows.insert(0, window)

    return windows[:_MAX_RETRIEVAL_CHUNKS_PER_FILE]


def _infer_retrieval_tags(rel_path: str) -> List[str]:
    lower = rel_path.lower()
    tags: List[str] = []
    if "test" in lower or lower.endswith("_spec.ts") or lower.endswith("_test.py"):
        tags.append("test")
    if any(token in lower for token in ("controller", "route", "router", "endpoint", "api")):
        tags.append("api")
    if any(token in lower for token in ("service", "handler", "resolver")):
        tags.append("service")
    if any(token in lower for token in ("model", "entity", "schema", "dto")):
        tags.append("data")
    if any(token in lower for token in ("readme", "docs")):
        tags.append("docs")
    if any(lower.endswith(suffix) for suffix in ("package.json", "pyproject.toml", "requirements.txt", "go.mod", "pom.xml", "build.gradle")):
        tags.append("config")
    return tags


def _retrieval_candidate_priority(candidate: Dict[str, Any]) -> int:
    weights = {
        "entrypoint": 6,
        "route": 5,
        "key_file": 4,
        "api": 4,
        "symbol": 3,
        "service": 3,
        "config": 3,
        "data": 2,
        "docs": 2,
        "test": 1,
    }
    priority = sum(weights.get(tag, 1) for tag in candidate.get("tags") or [])
    priority += min(4, len(candidate.get("anchor_lines") or []))
    priority += min(2, len(candidate.get("routes") or []))
    priority += min(2, len(candidate.get("symbol_names") or []))
    return priority


def _build_repo_logic_chunks(
    repo_name: str,
    repo_path: Path,
    repo_data: Dict[str, Any],
    *,
    previous_entry: Optional[Dict[str, Any]] = None,
    allow_reuse: bool = True,
) -> Dict[str, Any]:
    route_hints_by_path: Dict[str, List[Dict[str, Any]]] = {}
    symbol_entries_by_path: Dict[str, List[Dict[str, Any]]] = {}
    for route_hint in repo_data.get("route_hints") or []:
        rel_path = str(route_hint.get("path") or "").replace("\\", "/")
        if rel_path:
            route_hints_by_path.setdefault(rel_path, []).append(route_hint)
    for symbol in repo_data.get("symbols") or []:
        rel_path = str(symbol.get("path") or "").replace("\\", "/")
        if rel_path:
            symbol_entries_by_path.setdefault(rel_path, []).append(symbol)

    entrypoints = {str(path).replace("\\", "/") for path in (repo_data.get("entrypoints") or [])}
    key_files = {str(path).replace("\\", "/") for path in (repo_data.get("key_files") or [])}
    previous_files = (previous_entry or {}).get("files") or {}

    candidate_files: List[Tuple[int, str, Path]] = []
    for file_path in _iter_repo_files(repo_path):
        if not _is_logic_candidate_file(file_path):
            continue
        rel_path = _rel_path(file_path, repo_path)
        priority = _logic_file_priority(
            rel_path,
            entrypoints=entrypoints,
            key_files=key_files,
            route_hints_by_path=route_hints_by_path,
            symbol_entries_by_path=symbol_entries_by_path,
        )
        if priority <= 0:
            continue
        candidate_files.append((priority, rel_path, file_path))

    candidate_files.sort(key=lambda item: (-item[0], item[1]))
    logic_chunks: List[Dict[str, Any]] = []
    file_entries: Dict[str, Any] = {}

    for _, rel_path, file_path in candidate_files[:_MAX_LOGIC_FILES_PER_REPO]:
        try:
            content = _read_text_limited(file_path)
        except Exception:
            continue
        if not content.strip():
            continue

        content_fingerprint = _content_fingerprint(content)
        previous_file = previous_files.get(rel_path) or {}
        if (
            allow_reuse
            and previous_file.get("fingerprint") == content_fingerprint
            and isinstance(previous_file.get("chunks"), list)
        ):
            file_chunks = previous_file.get("chunks") or []
        else:
            file_chunks = _extract_logic_chunks_for_file(
                repo_name,
                rel_path,
                content,
                route_hints=route_hints_by_path.get(rel_path) or [],
                symbol_entries=symbol_entries_by_path.get(rel_path) or [],
            )

        remaining = _MAX_LOGIC_CHUNKS_PER_REPO - len(logic_chunks)
        if remaining <= 0:
            break
        trimmed_chunks = file_chunks[:remaining]
        if not trimmed_chunks:
            continue
        file_entries[rel_path] = {
            "fingerprint": content_fingerprint,
            "chunk_count": len(trimmed_chunks),
            "chunks": trimmed_chunks,
        }
        logic_chunks.extend(trimmed_chunks)

    return {
        "chunk_count": len(logic_chunks),
        "files": file_entries,
        "chunks": logic_chunks,
    }


def _extract_logic_chunks_for_file(
    repo_name: str,
    rel_path: str,
    content: str,
    *,
    route_hints: List[Dict[str, Any]],
    symbol_entries: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    lines = content.splitlines()
    if not lines:
        return []

    base_tags = sorted(set(_infer_retrieval_tags(rel_path) + _infer_logic_tags(rel_path, content)))
    imports = _extract_logic_imports(lines)
    discovered_blocks = _discover_logic_blocks(rel_path, lines)
    chunks: List[Dict[str, Any]] = []

    if discovered_blocks:
        for index, block in enumerate(discovered_blocks[: _MAX_LOGIC_CHUNKS_PER_REPO]):
            start_line = block["start_line"]
            next_start = (
                discovered_blocks[index + 1]["start_line"] - 1
                if index + 1 < len(discovered_blocks)
                else len(lines)
            )
            end_line = min(next_start, start_line + _LOGIC_CHUNK_LINE_LIMIT - 1)
            snippet = "\n".join(lines[start_line - 1:end_line]).strip()
            if len(snippet) < 40:
                continue
            local_routes = [
                hint.get("route")
                for hint in route_hints
                if start_line <= int(hint.get("line") or 0) <= end_line and hint.get("route")
            ]
            local_symbols = [
                symbol.get("name")
                for symbol in symbol_entries
                if start_line <= int(symbol.get("line") or 0) <= end_line and symbol.get("name")
            ]
            if block.get("symbol") and block["symbol"] not in local_symbols:
                local_symbols.insert(0, block["symbol"])
            chunk_tags = sorted(
                set(
                    base_tags
                    + [block.get("kind", "logic")]
                    + _infer_logic_tags(rel_path, snippet)
                )
            )
            preview = re.sub(r"\s+", " ", snippet).strip()[:240]
            chunks.append(
                {
                    "id": f"{repo_name}:{rel_path}:{block.get('symbol') or block.get('kind') or 'logic'}:{start_line}-{end_line}",
                    "path": rel_path,
                    "language": _lang_from_ext(Path(rel_path).suffix.lower()) or "text",
                    "kind": block.get("kind") or "logic",
                    "symbol": block.get("symbol"),
                    "container": block.get("container"),
                    "start_line": start_line,
                    "end_line": end_line,
                    "tags": chunk_tags,
                    "imports": imports[:12],
                    "identifiers": _extract_logic_identifiers(snippet),
                    "routes": local_routes[:6],
                    "summary": _logic_chunk_summary(
                        rel_path=rel_path,
                        kind=block.get("kind") or "logic",
                        symbol=block.get("symbol"),
                        container=block.get("container"),
                        tags=chunk_tags,
                        routes=local_routes,
                    ),
                    "preview": preview,
                    "content": snippet[:_LOGIC_CHUNK_CHAR_LIMIT],
                    "neighbors": [],
                }
            )
            if len(chunks) >= _MAX_LOGIC_CHUNKS_PER_FILE:
                break

    if chunks:
        return chunks[:_MAX_LOGIC_CHUNKS_PER_FILE]

    anchor_lines = [
        int(item.get("line") or 0)
        for item in route_hints + symbol_entries
        if int(item.get("line") or 0) > 0
    ]
    windows = _chunk_windows(len(lines), anchor_lines or [1])
    for start_line, end_line in windows[:_MAX_LOGIC_CHUNKS_PER_FILE]:
        end_line = min(end_line, start_line + _LOGIC_CHUNK_LINE_LIMIT - 1)
        snippet = "\n".join(lines[start_line - 1:end_line]).strip()
        if len(snippet) < 40:
            continue
        preview = re.sub(r"\s+", " ", snippet).strip()[:240]
        chunks.append(
            {
                "id": f"{repo_name}:{rel_path}:logic:{start_line}-{end_line}",
                "path": rel_path,
                "language": _lang_from_ext(Path(rel_path).suffix.lower()) or "text",
                "kind": "logic",
                "symbol": None,
                "container": None,
                "start_line": start_line,
                "end_line": end_line,
                "tags": base_tags or ["logic"],
                "imports": imports[:12],
                "identifiers": _extract_logic_identifiers(snippet),
                "routes": [item.get("route") for item in route_hints if item.get("route")][:6],
                "summary": _logic_chunk_summary(
                    rel_path=rel_path,
                    kind="logic",
                    symbol=None,
                    container=None,
                    tags=base_tags or ["logic"],
                    routes=[item.get("route") for item in route_hints if item.get("route")],
                ),
                "preview": preview,
                "content": snippet[:_LOGIC_CHUNK_CHAR_LIMIT],
                "neighbors": [],
            }
        )
    return chunks[:_MAX_LOGIC_CHUNKS_PER_FILE]


def _is_logic_candidate_file(file_path: Path) -> bool:
    suffix = file_path.suffix.lower()
    if suffix in {
        ".py", ".js", ".ts", ".tsx", ".jsx", ".java", ".kt", ".go", ".rs", ".cs",
        ".php", ".rb", ".swift", ".scala", ".c", ".cc", ".cpp", ".h", ".hpp",
        ".jsp", ".jspx", ".html", ".htm", ".xhtml", ".xml", ".yml", ".yaml",
        ".json", ".toml", ".ini", ".properties",
    }:
        return True
    return file_path.name in {"Dockerfile", "Makefile"}


def _logic_file_priority(
    rel_path: str,
    *,
    entrypoints: set[str],
    key_files: set[str],
    route_hints_by_path: Dict[str, List[Dict[str, Any]]],
    symbol_entries_by_path: Dict[str, List[Dict[str, Any]]],
) -> int:
    lower = rel_path.lower()
    priority = 1
    if rel_path in entrypoints:
        priority += 7
    if rel_path in key_files:
        priority += 4
    if rel_path in route_hints_by_path:
        priority += 9
    if rel_path in symbol_entries_by_path:
        priority += 4 + min(4, len(symbol_entries_by_path.get(rel_path) or []))
    if any(token in lower for token in ("controller", "route", "router", "endpoint", "api")):
        priority += 6
    if any(token in lower for token in ("service", "handler", "resolver", "manager", "helper")):
        priority += 5
    if any(token in lower for token in ("repository", "repo", "dao", "mapper", "client", "adapter")):
        priority += 4
    if any(token in lower for token in ("model", "entity", "dto", "payload", "schema")):
        priority += 3
    if any(token in lower for token in ("component", "widget", "view", "template", "page", "screen")):
        priority += 4
    if any(token in lower for token in ("config", "settings", "properties", "application", "dockerfile", "makefile")):
        priority += 3
    if any(token in lower for token in ("job", "worker", "scheduler", "task")):
        priority += 2
    if any(token in lower for token in ("test", "spec")):
        priority -= 2
    return priority


def _discover_logic_blocks(rel_path: str, lines: List[str]) -> List[Dict[str, Any]]:
    suffix = Path(rel_path).suffix.lower()
    blocks: List[Dict[str, Any]] = []
    current_container: Optional[str] = None
    current_container_indent: Optional[int] = None

    for line_number, line in enumerate(lines, start=1):
        stripped = line.strip()
        indent = len(line) - len(line.lstrip(" "))

        if suffix == ".py":
            class_match = re.match(r"\s*class\s+([A-Za-z_][A-Za-z0-9_]*)\b", line)
            if class_match:
                current_container = class_match.group(1)
                current_container_indent = indent
                blocks.append({"start_line": line_number, "kind": "class", "symbol": current_container, "container": None})
                continue
            if current_container_indent is not None and indent <= current_container_indent and stripped and not stripped.startswith("@"):
                current_container = None
                current_container_indent = None
            func_match = re.match(r"\s*def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", line)
            if func_match:
                blocks.append({"start_line": line_number, "kind": "function", "symbol": func_match.group(1), "container": current_container})
        elif suffix in {".js", ".ts", ".tsx", ".jsx"}:
            class_match = re.match(r"\s*(export\s+)?class\s+([A-Za-z_$][A-Za-z0-9_$]*)", line)
            if class_match:
                current_container = class_match.group(2)
                blocks.append({"start_line": line_number, "kind": "class", "symbol": current_container, "container": None})
                continue
            func_patterns = [
                re.match(r"\s*(export\s+)?(async\s+)?function\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\(", line),
                re.match(r"\s*(export\s+)?const\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(async\s*)?\(", line),
                re.match(r"\s*(export\s+)?const\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(async\s*)?[^=]*=>", line),
            ]
            for match in func_patterns:
                if not match:
                    continue
                symbol = match.group(3) if match.lastindex and match.lastindex >= 3 else match.group(2)
                blocks.append({"start_line": line_number, "kind": "function", "symbol": symbol, "container": current_container})
                break
        elif suffix in {".java", ".kt", ".scala"}:
            class_match = re.match(r"\s*(public\s+|private\s+|protected\s+)?(class|interface|enum)\s+([A-Za-z_][A-Za-z0-9_]*)", line)
            if class_match:
                current_container = class_match.group(3)
                blocks.append({"start_line": line_number, "kind": class_match.group(2), "symbol": current_container, "container": None})
                continue
            method_match = re.match(
                r"\s*(public|private|protected)?\s*(static\s+)?[A-Za-z0-9_<>,\[\]?]+\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(",
                line,
            )
            if method_match:
                blocks.append({"start_line": line_number, "kind": "method", "symbol": method_match.group(3), "container": current_container})
        elif suffix in {".go"}:
            func_match = re.match(r"\s*func\s+(\([^)]+\)\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*\(", line)
            if func_match:
                kind = "method" if func_match.group(1) else "function"
                blocks.append({"start_line": line_number, "kind": kind, "symbol": func_match.group(2), "container": None})
        elif suffix in {".jsp", ".jspx", ".html", ".htm", ".xhtml"}:
            if re.search(r"(id|class)\s*=\s*[\"'][^\"']+[\"']", line):
                symbol = _first_match_group(r"(?:id|class)\s*=\s*[\"']([^\"']+)[\"']", line)
                blocks.append({"start_line": line_number, "kind": "template_block", "symbol": symbol, "container": None})

    deduped: List[Dict[str, Any]] = []
    seen: set[Tuple[int, str, Optional[str]]] = set()
    for block in blocks:
        key = (int(block.get("start_line") or 0), str(block.get("kind") or ""), block.get("symbol"))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(block)
    return deduped


def _extract_logic_imports(lines: List[str], limit: int = 12) -> List[str]:
    imports: List[str] = []
    patterns = [
        r"^\s*import\s+.+",
        r"^\s*from\s+\S+\s+import\s+.+",
        r"^\s*package\s+.+",
        r"^\s*#include\s+.+",
        r"^\s*using\s+.+",
        r"^\s*<%@\s*taglib.+%>",
    ]
    for line in lines[:200]:
        if any(re.match(pattern, line) for pattern in patterns):
            imports.append(line.strip())
        if len(imports) >= limit:
            break
    return imports


def _extract_logic_identifiers(text: str, limit: int = 12) -> List[str]:
    stopwords = {
        "public", "private", "protected", "return", "class", "function", "const", "void", "null",
        "true", "false", "this", "static", "final", "string", "boolean", "integer", "object", "request",
        "response", "modelandview", "httpservletrequest", "httpservletresponse",
    }
    identifiers: List[str] = []
    for token in re.findall(r"[A-Za-z_][A-Za-z0-9_]{2,31}", text):
        lowered = token.lower()
        if lowered in stopwords:
            continue
        if token not in identifiers:
            identifiers.append(token)
        if len(identifiers) >= limit:
            break
    return identifiers


def _logic_chunk_summary(
    *,
    rel_path: str,
    kind: str,
    symbol: Optional[str],
    container: Optional[str],
    tags: List[str],
    routes: List[str],
) -> str:
    subject = symbol or Path(rel_path).name
    if kind in {"class", "interface", "enum"}:
        prefix = f"Defines {kind} {subject}"
    elif kind in {"method", "function"}:
        if container:
            prefix = f"Defines {kind} {subject} in {container}"
        else:
            prefix = f"Defines {kind} {subject}"
    elif kind == "template_block":
        prefix = f"Defines template block {subject}"
    else:
        prefix = f"Logic from {subject}"
    extras: List[str] = []
    if routes:
        extras.append(f"handles {len(routes)} route(s)")
    if tags:
        extras.append(f"tags: {', '.join(tags[:4])}")
    return ". ".join([prefix] + extras) if extras else prefix


def _infer_logic_tags(rel_path: str, content: str) -> List[str]:
    lower_path = rel_path.lower()
    lower_content = content.lower()
    tags: List[str] = []
    generic_tag_map = {
        "controller": ("controller", "route", "router", "endpoint"),
        "service": ("service", "handler", "resolver", "manager"),
        "repository": ("repository", "repo", "dao", "mapper"),
        "view": ("component", "widget", "view", "template", "screen", "page"),
        "model": ("model", "entity", "schema", "dto", "payload"),
        "config": ("config", "settings", "properties", "yaml", "json", "toml", "xml"),
        "api": ("api", "requestmapping", "getmapping", "postmapping", "router."),
        "utility": ("util", "helper", "common", "shared"),
        "job": ("job", "task", "worker", "scheduler"),
        "test": ("test", "spec", "assert"),
    }
    for tag, tokens in generic_tag_map.items():
        if any(token in lower_path or token in lower_content for token in tokens):
            tags.append(tag)
    keyword_map = {
        "pdf": ("pdf", "document", "statement", "report"),
        "inspection": ("inspection", "condition report"),
        "vwfs": ("vwfs", "volkswagen"),
        "tenant": ("tenant", "brand", "customer type"),
        "validation": ("validate", "validation", "invalid"),
        "ui": ("widget", "template", "render", "viewmodel"),
    }
    for tag, tokens in keyword_map.items():
        if any(token in lower_path or token in lower_content for token in tokens):
            tags.append(tag)
    return tags


def _architecture_roles_for_chunk(rel_path: str, chunk: Dict[str, Any]) -> List[str]:
    path_roles = set(_architecture_roles_from_path(rel_path))
    roles = set(path_roles)
    symbol = str(chunk.get("symbol") or "")
    container = str(chunk.get("container") or "")
    kind = str(chunk.get("kind") or "").lower()
    path_lower = rel_path.lower()
    routes = [str(route).lower() for route in (chunk.get("routes") or [])]
    tags = {str(tag).lower() for tag in (chunk.get("tags") or [])}
    name_tokens = _tokenize_architecture_text(Path(rel_path).stem, symbol, container)

    if "controller" in name_tokens or routes:
        roles.update({"controller", "api"})
    strong_path_role = bool(path_roles.intersection({"controller", "repository", "view", "config", "test", "model"}))
    if not strong_path_role and name_tokens.intersection({"service", "manager", "resolver", "handler"}) and "controller" not in name_tokens:
        roles.add("service")
    if not strong_path_role and name_tokens.intersection({"repository", "repo", "dao", "mapper"}):
        roles.add("repository")
    if not strong_path_role and name_tokens.intersection({"model", "entity", "dto", "payload", "schema"}):
        roles.add("model")
    if not strong_path_role and name_tokens.intersection({"config", "properties", "settings", "application"}):
        roles.add("config")
    if not strong_path_role and name_tokens.intersection({"util", "utility", "helper", "common", "shared"}):
        roles.add("utility")
    if not strong_path_role and name_tokens.intersection({"job", "task", "worker", "scheduler"}):
        roles.add("job")
    if kind == "template_block":
        roles.add("view")
    if "entrypoint" in tags:
        roles.add("entrypoint")
    if "test" in path_lower:
        roles.add("test")
    if _looks_like_config_file(rel_path):
        roles.add("config")
    if not roles:
        roles.add("logic")
    return sorted(roles)


def _architecture_roles_from_path(rel_path: str) -> List[str]:
    tokens = _tokenize_architecture_text(rel_path, Path(rel_path).stem)
    roles: List[str] = []
    path_map = {
        "controller": {"controller", "route", "router", "endpoint"},
        "service": {"service", "resolver", "manager"},
        "repository": {"repository", "repo", "dao", "mapper"},
        "model": {"model", "entity", "dto", "payload", "schema"},
        "view": {"component", "widget", "view", "template", "screen", "page", "jsp", "html", "jspx", "xhtml"},
        "config": {"config", "application", "yaml", "yml", "xml", "json", "properties", "toml", "dockerfile", "makefile"},
        "api": {"api"},
        "utility": {"util", "utility", "helper", "common", "shared"},
        "job": {"job", "task", "worker", "scheduler"},
        "test": {"test", "spec"},
    }
    for role, aliases in path_map.items():
        if tokens.intersection(aliases):
            roles.append(role)
    return roles


def _looks_like_config_file(rel_path: str) -> bool:
    lower = rel_path.lower()
    return any(token in lower for token in ("config", "settings", "application", ".yml", ".yaml", ".xml", ".json", ".properties", ".toml"))


def _component_summary(path: str, roles: List[str], symbols: List[str]) -> str:
    label = Path(path).name
    if roles:
        role_text = ", ".join(roles[:3])
        if symbols:
            return f"{label} acts as {role_text} and exposes {', '.join(symbols[:3])}"
        return f"{label} acts as {role_text}"
    if symbols:
        return f"{label} exposes {', '.join(symbols[:3])}"
    return f"General logic in {label}"


def _tokenize_architecture_text(*values: str) -> set[str]:
    tokens: set[str] = set()
    for value in values:
        if not value:
            continue
        normalized = str(value).replace("\\", "/")
        for piece in re.split(r"[^A-Za-z0-9]+", normalized):
            if not piece:
                continue
            camel_parts = re.findall(r"[A-Z]+(?=[A-Z][a-z]|[0-9]|$)|[A-Z]?[a-z]+|[0-9]+", piece)
            if camel_parts:
                tokens.update(part.lower() for part in camel_parts if part)
            else:
                tokens.add(piece.lower())
    return tokens


def _content_fingerprint(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8", errors="ignore")).hexdigest()


def _first_match_group(pattern: str, line: str) -> Optional[str]:
    match = re.search(pattern, line)
    if not match:
        return None
    return match.group(1)


def render_code_workspace(workspace_root: Path, workspace: Workspace) -> Dict[str, Any]:
    # Multi-root workspace file. Keep root and each repo as folders.
    folders = [{"path": "."}]
    # detect whether repos are under repos/ subfolder
    repos_base = "repos" if (workspace_root / "repos").exists() else ""
    for repo in workspace.repos:
        rel = Path(repo.local_path)
        try:
            relpath = rel.relative_to(workspace_root)
            folders.append({"path": str(relpath)})
        except Exception:
            # fallback to expected layout
            if repos_base:
                folders.append({"path": f"repos/{repo.name}"})
            else:
                folders.append({"path": repo.name})
    return {
        "folders": folders,
        "settings": {
            # keep huge .git out of searches by default
            "files.exclude": {"**/.git": True},
        },
    }


def build_repo_index(
    workspace_root: Path,
    workspace: Workspace,
    *,
    previous_index: Optional[Dict[str, Any]] = None,
    previous_digests: Optional[Dict[str, Any]] = None,
    mode: str = "delta",
) -> Tuple[Dict[str, Any], Dict[str, Any], Dict[str, Any]]:
    repos_index: Dict[str, Any] = {}
    previous_repos = (previous_index or {}).get("repos") or {}
    previous_repo_digests = (previous_digests or {}).get("repos") or {}
    previous_index_version = int((previous_index or {}).get("version") or 0)
    previous_digest_version = int((previous_digests or {}).get("schema_version") or 0)
    changed_repos: List[str] = []
    reused_repos: List[str] = []
    missing_repos: List[str] = []
    repo_digests: Dict[str, Any] = {}
    normalized_mode = "full" if mode == "full" else "delta"

    for repo in workspace.repos:
        repo_path = Path(repo.local_path)
        if not repo_path.exists():
            missing_repos.append(repo.name)
            continue

        digest = _compute_repo_digest(repo_path)
        repo_digests[repo.name] = digest
        previous_digest = previous_repo_digests.get(repo.name, {})
        should_reuse = (
            normalized_mode == "delta"
            and previous_index_version == _REPO_INDEX_VERSION
            and previous_digest_version == _DIGEST_SCHEMA_VERSION
            and previous_digest.get("fingerprint") == digest.get("fingerprint")
            and repo.name in previous_repos
        )

        if should_reuse:
            repos_index[repo.name] = previous_repos[repo.name]
            reused_repos.append(repo.name)
        else:
            repos_index[repo.name] = index_one_repo(repo_path, repo.url)
            changed_repos.append(repo.name)

    generated_at = datetime.now(timezone.utc).isoformat()
    index = {
        "workspace_name": workspace.name,
        "workspace_root": str(workspace_root),
        "repos": repos_index,
        "version": _REPO_INDEX_VERSION,
        "refresh_mode": normalized_mode,
        "generated_at": generated_at,
    }
    digest_data = {
        "schema_version": _DIGEST_SCHEMA_VERSION,
        "workspace_name": workspace.name,
        "generated_at": generated_at,
        "repos": repo_digests,
    }
    refresh_stats = {
        "mode": normalized_mode,
        "generated_at": generated_at,
        "changed_repos": changed_repos,
        "reused_repos": reused_repos,
        "missing_repos": missing_repos,
        "repo_count": len(repos_index),
    }
    return index, digest_data, refresh_stats


def index_one_repo(repo_path: Path, url: str) -> Dict[str, Any]:
    files_scanned = 0
    lang_counts: Dict[str, int] = {}
    symbols: List[Dict[str, Any]] = []
    entrypoints: List[str] = []
    how_to_run: List[str] = []

    # Detect run commands from common manifests
    how_to_run.extend(_infer_run_commands(repo_path))

    # Entrypoints heuristics
    for p in [
        "README.md", "readme.md",
        "main.py", "app.py", "server.py",
        "src/main.py", "src/app.py", "src/index.ts", "src/index.js", "src/main.ts",
        "index.ts", "index.js",
        "manage.py",
        "cmd", "src",
    ]:
        cand = repo_path / p
        if cand.exists():
            _append_unique_path(entrypoints, _rel_path(cand, repo_path))

    # Scan files for language distribution + symbols + routes
    route_hints: List[Dict[str, Any]] = []
    key_files: List[str] = []
    top_level_dirs: List[str] = []
    top_level_files: List[str] = []

    # Top-level layout (very useful for quick orientation and routing)
    try:
        for child in repo_path.iterdir():
            if child.name.startswith('.'):
                continue
            if child.is_dir():
                top_level_dirs.append(child.name)
            elif child.is_file():
                top_level_files.append(child.name)
    except Exception:
        pass

    for file_path in _iter_repo_files(repo_path):
        files_scanned += 1
        ext = file_path.suffix.lower()
        lang = _lang_from_ext(ext)
        if lang:
            lang_counts[lang] = lang_counts.get(lang, 0) + 1

        # pick key config files
        if file_path.name in {"package.json", "pyproject.toml", "requirements.txt", "go.mod", "pom.xml", "build.gradle", "Dockerfile"}:
            _append_unique_path(key_files, _rel_path(file_path, repo_path))

        if ext not in _TEXT_EXTS:
            continue
        if len(symbols) >= _MAX_SYMBOLS_PER_REPO and len(route_hints) >= 200:
            continue

        try:
            content = _read_text_limited(file_path)
        except Exception:
            continue

        # Symbols
        if len(symbols) < _MAX_SYMBOLS_PER_REPO:
            symbols.extend(_extract_symbols(file_path, content, repo_path, limit=_MAX_SYMBOLS_PER_REPO - len(symbols)))

        # Routes/endpoints hints
        if len(route_hints) < 200:
            route_hints.extend(_extract_route_hints(file_path, content, repo_path, limit=200 - len(route_hints)))

    symbols = _dedupe_symbol_entries(symbols)
    route_hints = _dedupe_route_hints(route_hints)

    primary_language = max(lang_counts.items(), key=lambda kv: kv[1])[0] if lang_counts else None
    return {
        "path": str(repo_path),
        "url": url,
        "primary_language": primary_language,
        "language_counts": lang_counts,
        "top_level_dirs": sorted(top_level_dirs)[:40],
        "top_level_files": sorted(top_level_files)[:60],
        "entrypoints": entrypoints[:20],
        "key_files": key_files[:30],
        "how_to_run": how_to_run[:20],
        "route_hints": route_hints[:200],
        "symbols": symbols[:_MAX_SYMBOLS_PER_REPO],
    }


def locate_in_workspace_index(index: Dict[str, Any], query: str, limit: int = 8) -> Dict[str, Any]:
    """Return best candidates from a repo_index.json structure."""
    q = (query or "").strip().lower()
    if not q:
        return {"query": query, "results": []}
    terms = [t for t in re.split(r"\s+", q) if t]
    scored: List[Tuple[float, Dict[str, Any]]] = []

    for repo_name, r in (index.get("repos") or {}).items():
        # Symbols
        for s in (r.get("symbols") or []):
            score = _score_terms(terms, " ".join([repo_name, s.get("name",""), s.get("kind",""), s.get("path","")]).lower())
            if score > 0:
                item = {"repo": repo_name, "type": "symbol", **s}
                scored.append((score, item))
        # Routes
        for rh in (r.get("route_hints") or []):
            score = _score_terms(terms, " ".join([repo_name, rh.get("route",""), rh.get("framework",""), rh.get("path","")]).lower())
            if score > 0:
                item = {"repo": repo_name, "type": "route", **rh}
                scored.append((score + 0.2, item))
        # Entrypoints & key files
        for p in (r.get("entrypoints") or []) + (r.get("key_files") or []):
            score = _score_terms(terms, " ".join([repo_name, p]).lower())
            if score > 0:
                scored.append((score - 0.1, {"repo": repo_name, "type": "file", "path": p}))

        # Repo layout hints (top-level dirs/files)
        for p in (r.get("top_level_dirs") or []) + (r.get("top_level_files") or []):
            score = _score_terms(terms, " ".join([repo_name, p]).lower())
            if score > 0:
                scored.append((score - 0.35, {"repo": repo_name, "type": "repo_hint", "hint": p}))

    scored.sort(key=lambda x: x[0], reverse=True)
    results = [it for _, it in scored[:limit]]
    return {"query": query, "results": results}


def _score_terms(terms: List[str], hay: str) -> float:
    score = 0.0
    for t in terms:
        if t in hay:
            # reward exact substring
            score += 1.0
        else:
            # tiny reward for partial overlaps
            if len(t) >= 4 and any(t[:3] in w for w in hay.split()):
                score += 0.15
    return score


def _iter_repo_files(repo_path: Path) -> Iterable[Path]:
    count = 0
    for root, dirs, files in os.walk(repo_path):
        # skip heavy dirs
        dirs[:] = [d for d in dirs if d not in {".git", "node_modules", "dist", "build", ".venv", "venv", ".mypy_cache", ".pytest_cache", "__pycache__"}]
        for fn in files:
            if count >= _MAX_FILES_PER_REPO:
                return
            fp = Path(root) / fn
            count += 1
            yield fp


def _read_text_limited(path: Path) -> str:
    if path.stat().st_size > _MAX_BYTES_PER_FILE:
        return ""
    data = path.read_bytes()
    try:
        return data.decode("utf-8", errors="ignore")
    except Exception:
        return ""


def _extract_symbols(path: Path, content: str, repo_root: Path, limit: int) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    rel = _rel_path(path, repo_root)
    # Python
    if path.suffix.lower() == ".py":
        for i, line in enumerate(content.splitlines(), start=1):
            if len(out) >= limit:
                break
            m = re.match(r"\s*(def|class)\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", line)
            if m:
                kind = "function" if m.group(1) == "def" else "class"
                out.append({"name": m.group(2), "kind": kind, "path": rel, "line": i})
    # JS/TS
    if path.suffix.lower() in {".js", ".ts", ".tsx", ".jsx"}:
        for i, line in enumerate(content.splitlines(), start=1):
            if len(out) >= limit:
                break
            m = re.match(r"\s*(export\s+)?(async\s+)?function\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\(", line)
            if m:
                out.append({"name": m.group(3), "kind": "function", "path": rel, "line": i})
            m2 = re.match(r"\s*(export\s+)?class\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*(\{|extends)", line)
            if m2:
                out.append({"name": m2.group(2), "kind": "class", "path": rel, "line": i})
    # Java/Kotlin
    if path.suffix.lower() in {".java", ".kt"}:
        for i, line in enumerate(content.splitlines(), start=1):
            if len(out) >= limit:
                break
            m = re.match(r"\s*(public\s+|private\s+|protected\s+)?(class|interface)\s+([A-Za-z_][A-Za-z0-9_]*)", line)
            if m:
                out.append({"name": m.group(3), "kind": m.group(2), "path": rel, "line": i})
            m2 = re.match(r"\s*(public\s+|private\s+|protected\s+)?(static\s+)?[A-Za-z0-9_<>,\[\]]+\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", line)
            if m2:
                out.append({"name": m2.group(3), "kind": "method", "path": rel, "line": i})
    # Go
    if path.suffix.lower() == ".go":
        for i, line in enumerate(content.splitlines(), start=1):
            if len(out) >= limit:
                break
            m = re.match(r"\s*func\s+(\([^)]+\)\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*\(", line)
            if m:
                out.append({"name": m.group(2), "kind": "func", "path": rel, "line": i})
    return out


def _extract_route_hints(path: Path, content: str, repo_root: Path, limit: int) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    rel = _rel_path(path, repo_root)
    suffix = path.suffix.lower()
    lines = content.splitlines()
    for i, line in enumerate(lines, start=1):
        if len(out) >= limit:
            break
        if suffix == ".py":
            m = re.search(r"@app\.(get|post|put|delete|patch)\(\s*[\'\"]([^\'\"]+)[\'\"]", line)
            if m:
                out.append({"framework": "python", "route": f"{m.group(1).upper()} {m.group(2)}", "path": rel, "line": i})
            m2 = re.search(r"@app\.route\(\s*[\'\"]([^\'\"]+)[\'\"]", line)
            if m2:
                out.append({"framework": "flask", "route": m2.group(1), "path": rel, "line": i})
        elif suffix in {".js", ".ts", ".tsx", ".jsx"}:
            m3 = re.search(r"\b(app|router)\.(get|post|put|delete|patch)\(\s*[\'\"]([^\'\"]+)[\'\"]", line)
            if m3:
                out.append({"framework": "express", "route": f"{m3.group(2).upper()} {m3.group(3)}", "path": rel, "line": i})
        elif suffix in {".java", ".kt"}:
            if "@GetMapping" in line or "@PostMapping" in line or "@RequestMapping" in line:
                out.append({"framework": "spring", "route": line.strip(), "path": rel, "line": i})
        elif suffix == ".go":
            m4 = re.search(r"http\.HandleFunc\(\s*[\'\"]([^\'\"]+)[\'\"]", line)
            if m4:
                out.append({"framework": "go_http", "route": m4.group(1), "path": rel, "line": i})
    return out


def _infer_run_commands(repo_path: Path) -> List[str]:
    cmds: List[str] = []
    pj = repo_path / "package.json"
    if pj.exists():
        try:
            data = json.loads(pj.read_text(encoding="utf-8"))
            scripts = (data.get("scripts") or {})
            for k in ["test", "lint", "build", "dev", "start"]:
                if k in scripts:
                    cmds.append(f"npm run {k}")
        except Exception:
            pass
    pp = repo_path / "pyproject.toml"
    if pp.exists():
        cmds.append("python -m pytest  # if tests exist")
    req = repo_path / "requirements.txt"
    if req.exists():
        cmds.append("python -m pytest  # if tests exist")
    gm = repo_path / "go.mod"
    if gm.exists():
        cmds.append("go test ./...")
    gradle = repo_path / "build.gradle"
    if gradle.exists():
        cmds.append("./gradlew test")
    pom = repo_path / "pom.xml"
    if pom.exists():
        cmds.append("mvn test")
    return cmds


def _lang_from_ext(ext: str) -> Optional[str]:
    return {
        ".py": "python",
        ".js": "javascript",
        ".ts": "typescript",
        ".tsx": "typescript",
        ".jsx": "javascript",
        ".java": "java",
        ".kt": "kotlin",
        ".go": "go",
        ".rs": "rust",
        ".cs": "csharp",
        ".php": "php",
        ".rb": "ruby",
        ".swift": "swift",
        ".scala": "scala",
        ".c": "c",
        ".cc": "cpp",
        ".cpp": "cpp",
        ".h": "c/cpp",
        ".hpp": "c/cpp",
    }.get(ext)


def _load_json(path: Path) -> Optional[Dict[str, Any]]:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _compute_repo_digest(repo_path: Path) -> Dict[str, Any]:
    """Compute a stable fingerprint for incremental refresh decisions."""
    hasher = hashlib.sha256()
    file_count = 0
    latest_mtime = 0.0
    total_size = 0

    for file_path in _iter_repo_files(repo_path):
        try:
            stat = file_path.stat()
        except OSError:
            continue
        rel_path = _rel_path(file_path, repo_path)
        hasher.update(rel_path.encode("utf-8", errors="ignore"))
        hasher.update(str(stat.st_size).encode("ascii", errors="ignore"))
        hasher.update(str(int(stat.st_mtime_ns)).encode("ascii", errors="ignore"))
        file_count += 1
        total_size += stat.st_size
        latest_mtime = max(latest_mtime, stat.st_mtime)

    return {
        "fingerprint": hasher.hexdigest(),
        "file_count": file_count,
        "total_size": total_size,
        "latest_mtime": latest_mtime,
    }


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _rel_path(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


def _append_unique_path(paths: List[str], rel_path: str) -> None:
    normalized = (rel_path or "").replace("\\", "/").strip()
    if not normalized:
        return
    existing = {item.lower() for item in paths}
    if normalized.lower() not in existing:
        paths.append(normalized)


def _dedupe_symbol_entries(symbols: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen: set[Tuple[str, str, str, int]] = set()
    deduped: List[Dict[str, Any]] = []
    for symbol in symbols:
        path = str(symbol.get("path") or "").replace("\\", "/")
        line = int(symbol.get("line") or 0)
        key = (str(symbol.get("name") or ""), str(symbol.get("kind") or ""), path, line)
        if key in seen:
            continue
        seen.add(key)
        normalized = dict(symbol)
        normalized["path"] = path
        deduped.append(normalized)
    return deduped


def _dedupe_route_hints(route_hints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen: set[Tuple[str, str, str, int]] = set()
    deduped: List[Dict[str, Any]] = []
    for route_hint in route_hints:
        path = str(route_hint.get("path") or "").replace("\\", "/")
        line = int(route_hint.get("line") or 0)
        key = (str(route_hint.get("framework") or ""), str(route_hint.get("route") or ""), path, line)
        if key in seen:
            continue
        seen.add(key)
        normalized = dict(route_hint)
        normalized["path"] = path
        deduped.append(normalized)
    return deduped
