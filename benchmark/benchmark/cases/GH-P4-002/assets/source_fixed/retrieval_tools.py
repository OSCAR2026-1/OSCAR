"""Helpers for compact workspace context packets and retrieval hits."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Optional, Sequence


def build_context_packet(
    workspace_root: Path,
    index: Optional[dict],
    query: str,
    *,
    repo_names: Optional[Sequence[str]] = None,
    locate_hits: Optional[list[dict[str, Any]]] = None,
    digest_chars: int = 1600,
    repo_summary_chars: int = 700,
    chunk_limit: int = 6,
    repo_summary_limit: int = 3,
) -> dict[str, Any]:
    """Build a small context packet from digest, summaries, and retrieval hits."""
    query = (query or "").strip()
    locate_hits = locate_hits or []
    workspace_digest = _read_excerpt(
        workspace_root / ".mcp" / "summaries" / "workspace_digest.md",
        max_chars=digest_chars,
    )
    architecture_data = _load_json(workspace_root / ".mcp" / "architecture_map.json") or {}
    retrieval_data = _load_json(workspace_root / ".mcp" / "retrieval" / "chunks.json") or {}
    logic_chunk_data = _load_json(workspace_root / ".mcp" / "retrieval" / "logic_chunks.json") or {}
    preferred_paths = [hit.get("path") for hit in locate_hits if hit.get("path")]
    retrieval_hits = retrieve_workspace_chunks(
        index or {},
        retrieval_data,
        query,
        limit=chunk_limit,
        repo_names=repo_names,
        preferred_paths=preferred_paths,
    )
    logic_hits = retrieve_logic_chunks(
        index or {},
        logic_chunk_data,
        query,
        limit=max(2, min(chunk_limit, 8)),
        repo_names=repo_names,
        preferred_paths=preferred_paths,
    )
    selected_repos = select_relevant_repos(
        index or {},
        query,
        repo_names=repo_names,
        locate_hits=locate_hits,
        retrieval_hits=retrieval_hits,
        logic_hits=logic_hits,
        limit=repo_summary_limit,
    )
    architecture_overview = summarize_architecture(
        architecture_data,
        repo_names=selected_repos or repo_names,
        limit=repo_summary_limit,
    )

    repo_summaries = []
    for repo_name in selected_repos:
        summary_path = workspace_root / ".mcp" / "summaries" / "repos" / repo_name / "repo_summary.md"
        excerpt = _read_excerpt(summary_path, max_chars=repo_summary_chars)
        if excerpt["excerpt"]:
            repo_summaries.append(
                {
                    "repo": repo_name,
                    "excerpt": excerpt["excerpt"],
                    "truncated": excerpt["truncated"],
                }
            )

    return {
        "mode": "digest+architecture+repo_summaries+retrieval+logic",
        "query": query or None,
        "workspace_digest": workspace_digest,
        "architecture_overview": architecture_overview,
        "repo_summaries": repo_summaries,
        "retrieval_hits": retrieval_hits,
        "logic_hits": logic_hits,
    }


def retrieve_workspace_chunks(
    index: dict[str, Any],
    retrieval_data: dict[str, Any],
    query: str,
    *,
    limit: int = 6,
    repo_names: Optional[Sequence[str]] = None,
    preferred_paths: Optional[Sequence[str]] = None,
) -> list[dict[str, Any]]:
    """Return top chunk hits using lightweight hybrid scoring."""
    query_terms = _query_terms(query)
    if not query_terms:
        return []

    repo_filter = set(repo_names or [])
    preferred = {path.replace("\\", "/") for path in (preferred_paths or []) if path}
    scored: list[tuple[float, dict[str, Any]]] = []
    repo_entries = (retrieval_data or {}).get("repos") or {}

    for repo_name, repo_entry in repo_entries.items():
        if repo_filter and repo_name not in repo_filter:
            continue
        for chunk in repo_entry.get("chunks") or []:
            score = _score_chunk(repo_name, chunk, query_terms, preferred)
            if score <= 0:
                continue
            scored.append(
                (
                    score,
                    {
                        "repo": repo_name,
                        "path": chunk.get("path"),
                        "start_line": chunk.get("start_line"),
                        "end_line": chunk.get("end_line"),
                        "tags": chunk.get("tags") or [],
                        "symbol_names": chunk.get("symbol_names") or [],
                        "routes": chunk.get("routes") or [],
                        "preview": chunk.get("preview") or "",
                        "content": chunk.get("content") or "",
                        "score": round(score, 3),
                    },
                )
            )

    scored.sort(key=lambda item: item[0], reverse=True)

    results: list[dict[str, Any]] = []
    per_file_counts: dict[str, int] = {}
    for _, item in scored:
        key = f"{item.get('repo')}:{item.get('path')}"
        if per_file_counts.get(key, 0) >= 2:
            continue
        per_file_counts[key] = per_file_counts.get(key, 0) + 1
        results.append(item)
        if len(results) >= limit:
            break

    return results


def select_relevant_repos(
    index: dict[str, Any],
    query: str,
    *,
    repo_names: Optional[Sequence[str]] = None,
    locate_hits: Optional[list[dict[str, Any]]] = None,
    retrieval_hits: Optional[list[dict[str, Any]]] = None,
    logic_hits: Optional[list[dict[str, Any]]] = None,
    limit: int = 3,
) -> list[str]:
    """Select the smallest set of repo summaries worth including."""
    repos = (index or {}).get("repos") or {}
    if not repos:
        return []

    repo_filter = set(repo_names or [])
    query_terms = _query_terms(query)
    locate_hits = locate_hits or []
    retrieval_hits = retrieval_hits or []
    logic_hits = logic_hits or []
    repo_scores: dict[str, float] = {}

    for repo_name, repo_data in repos.items():
        if repo_filter and repo_name not in repo_filter:
            continue
        haystack = " ".join(
            [
                repo_name,
                " ".join(repo_data.get("entrypoints") or []),
                " ".join(repo_data.get("key_files") or []),
                " ".join(repo_data.get("top_level_dirs") or []),
            ]
        ).lower()
        score = _score_text(query_terms, haystack, exact_weight=1.5, partial_weight=0.2)
        score += sum(1.5 for hit in locate_hits if hit.get("repo") == repo_name)
        score += sum(2.0 for hit in retrieval_hits if hit.get("repo") == repo_name)
        score += sum(2.5 for hit in logic_hits if hit.get("repo") == repo_name)
        repo_scores[repo_name] = score

    ranked = sorted(repo_scores.items(), key=lambda item: item[1], reverse=True)
    selected = [repo_name for repo_name, score in ranked if score > 0][:limit]

    if not selected and repo_filter:
        selected = list(repo_filter)[:limit]
    if not selected:
        selected = list(repos.keys())[:limit]
    return selected


def summarize_architecture(
    architecture_data: dict[str, Any],
    *,
    repo_names: Optional[Sequence[str]] = None,
    limit: int = 3,
) -> list[dict[str, Any]]:
    repos = (architecture_data or {}).get("repos") or {}
    if not repos:
        return []

    repo_filter = set(repo_names or [])
    results: list[dict[str, Any]] = []
    for repo_name, repo_data in repos.items():
        if repo_filter and repo_name not in repo_filter:
            continue
        stats = repo_data.get("stats") or {}
        roles = repo_data.get("roles") or {}
        results.append(
            {
                "repo": repo_name,
                "primary_language": repo_data.get("primary_language"),
                "entrypoints": (repo_data.get("entrypoints") or [])[:5],
                "top_level_dirs": (repo_data.get("top_level_dirs") or [])[:8],
                "layer_counts": {
                    "controllers": stats.get("controller_count", len(roles.get("controller") or [])),
                    "services": stats.get("service_count", len(roles.get("service") or [])),
                    "repositories": stats.get("repository_count", len(roles.get("repository") or [])),
                    "views": stats.get("view_count", len(roles.get("view") or [])),
                    "models": stats.get("model_count", len(roles.get("model") or [])),
                    "routes": stats.get("route_count", len(repo_data.get("route_map") or [])),
                },
                "top_components": (repo_data.get("components") or [])[:6],
                "top_routes": (repo_data.get("route_map") or [])[:6],
            }
        )
        if len(results) >= limit:
            break
    return results


def _score_chunk(
    repo_name: str,
    chunk: dict[str, Any],
    query_terms: list[str],
    preferred_paths: set[str],
) -> float:
    tags = [str(tag).lower() for tag in (chunk.get("tags") or [])]
    symbol_names = [str(name).lower() for name in (chunk.get("symbol_names") or [])]
    routes = [str(route).lower() for route in (chunk.get("routes") or [])]
    path = str(chunk.get("path") or "").lower()
    preview = str(chunk.get("preview") or "").lower()
    content = str(chunk.get("content") or "").lower()

    metadata = " ".join([repo_name.lower(), path, " ".join(tags), " ".join(symbol_names), " ".join(routes)])
    score = _score_text(query_terms, metadata, exact_weight=2.1, partial_weight=0.35)
    score += _score_text(query_terms, preview, exact_weight=0.9, partial_weight=0.12)
    score += _score_text(query_terms, content[:400], exact_weight=0.45, partial_weight=0.08)

    tag_weights = {
        "entrypoint": 0.8,
        "route": 0.7,
        "key_file": 0.6,
        "api": 0.5,
        "config": 0.45,
        "service": 0.35,
        "data": 0.25,
        "docs": 0.2,
    }
    score += sum(tag_weights.get(tag, 0.0) for tag in tags)

    if path in preferred_paths:
        score += 2.5
    return score


def retrieve_logic_chunks(
    index: dict[str, Any],
    logic_chunk_data: dict[str, Any],
    query: str,
    *,
    limit: int = 6,
    repo_names: Optional[Sequence[str]] = None,
    preferred_paths: Optional[Sequence[str]] = None,
) -> list[dict[str, Any]]:
    """Return top logic-oriented chunk hits."""
    query_terms = _query_terms(query)
    if not query_terms:
        return []

    repo_filter = set(repo_names or [])
    preferred = {path.replace("\\", "/") for path in (preferred_paths or []) if path}
    scored: list[tuple[float, dict[str, Any]]] = []
    repo_entries = (logic_chunk_data or {}).get("repos") or {}

    for repo_name, repo_entry in repo_entries.items():
        if repo_filter and repo_name not in repo_filter:
            continue
        for chunk in repo_entry.get("chunks") or []:
            score = _score_logic_chunk(repo_name, chunk, query_terms, preferred)
            if score <= 0:
                continue
            scored.append(
                (
                    score,
                    {
                        "repo": repo_name,
                        "path": chunk.get("path"),
                        "kind": chunk.get("kind"),
                        "symbol": chunk.get("symbol"),
                        "container": chunk.get("container"),
                        "start_line": chunk.get("start_line"),
                        "end_line": chunk.get("end_line"),
                        "tags": chunk.get("tags") or [],
                        "identifiers": chunk.get("identifiers") or [],
                        "routes": chunk.get("routes") or [],
                        "summary": chunk.get("summary") or "",
                        "preview": chunk.get("preview") or "",
                        "content": chunk.get("content") or "",
                        "score": round(score, 3),
                    },
                )
            )

    scored.sort(key=lambda item: item[0], reverse=True)
    results: list[dict[str, Any]] = []
    per_file_counts: dict[str, int] = {}
    for _, item in scored:
        key = f"{item.get('repo')}:{item.get('path')}"
        if per_file_counts.get(key, 0) >= 2:
            continue
        per_file_counts[key] = per_file_counts.get(key, 0) + 1
        results.append(item)
        if len(results) >= limit:
            break
    return results


def _score_logic_chunk(
    repo_name: str,
    chunk: dict[str, Any],
    query_terms: list[str],
    preferred_paths: set[str],
) -> float:
    tags = [str(tag).lower() for tag in (chunk.get("tags") or [])]
    identifiers = [str(identifier).lower() for identifier in (chunk.get("identifiers") or [])]
    routes = [str(route).lower() for route in (chunk.get("routes") or [])]
    path = str(chunk.get("path") or "").lower()
    kind = str(chunk.get("kind") or "").lower()
    symbol = str(chunk.get("symbol") or "").lower()
    container = str(chunk.get("container") or "").lower()
    summary = str(chunk.get("summary") or "").lower()
    preview = str(chunk.get("preview") or "").lower()
    content = str(chunk.get("content") or "").lower()

    metadata = " ".join(
        [
            repo_name.lower(),
            path,
            kind,
            symbol,
            container,
            " ".join(tags),
            " ".join(identifiers),
            " ".join(routes),
        ]
    )
    score = _score_text(query_terms, metadata, exact_weight=2.4, partial_weight=0.4)
    score += _score_text(query_terms, summary, exact_weight=1.6, partial_weight=0.25)
    score += _score_text(query_terms, preview, exact_weight=1.0, partial_weight=0.12)
    score += _score_text(query_terms, content[:600], exact_weight=0.55, partial_weight=0.08)

    tag_weights = {
        "logic": 0.4,
        "method": 0.6,
        "function": 0.6,
        "class": 0.45,
        "service": 0.6,
        "api": 0.55,
        "ui": 0.45,
        "validation": 0.5,
        "tenant": 0.5,
        "pdf": 0.7,
        "inspection": 0.6,
        "vwfs": 0.7,
    }
    score += sum(tag_weights.get(tag, 0.0) for tag in tags)
    if path in preferred_paths:
        score += 2.5
    return score


def _score_text(
    query_terms: list[str],
    haystack: str,
    *,
    exact_weight: float,
    partial_weight: float,
) -> float:
    score = 0.0
    words = haystack.split()
    for term in query_terms:
        if term in haystack:
            score += exact_weight
        elif len(term) >= 4 and any(term[:4] in word for word in words):
            score += partial_weight
    return score


def _query_terms(query: str) -> list[str]:
    tokens = re.findall(r"[A-Za-z0-9_/-]+", (query or "").lower())
    terms: list[str] = []
    for token in tokens:
        normalized = token.strip("/-_")
        if len(normalized) >= 3 and normalized not in terms:
            terms.append(normalized)
        for part in re.split(r"[/_-]", normalized):
            if len(part) >= 3 and part not in terms:
                terms.append(part)
    return terms[:16]


def _read_excerpt(path: Path, *, max_chars: int) -> dict[str, Any]:
    if not path.exists():
        return {"excerpt": "", "truncated": False}
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return {"excerpt": "", "truncated": False}
    return {
        "excerpt": text[:max_chars],
        "truncated": len(text) > max_chars,
    }


def _load_json(path: Path) -> Optional[dict[str, Any]]:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
