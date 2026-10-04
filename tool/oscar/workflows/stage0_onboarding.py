"""Label-free Stage 0 case onboarding.

Stage 0 may consume the local candidate pool and explicitly supplied source
roots.  It never reads GT/evidence directories and never assigns a prediction.
The output is a blind case contract plus a machine-readable preparation report.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import unquote

from oscar.paths import RESEARCH_ROOT

try:
    from oscar.workflows.dependency_evidence import verify_dependency_pair
    from oscar.analysis.tool_discovery import discover_javascript_tool_paths, discover_python_tool_paths
    from oscar.contracts.component_contract import COMPONENT_ORIGINS, validate_component_advisory_evidence, validate_label_free_evidence, verify_osv_advisory_evidence
    from oscar.analysis.component_path import discover_component_tool_paths, validate_component_tool_path
    from oscar.workflows.linux_case_assembly import _verify_patch_explains_pair
except ImportError:  # direct script execution
    from oscar.workflows.dependency_evidence import verify_dependency_pair
    from oscar.analysis.tool_discovery import discover_javascript_tool_paths, discover_python_tool_paths
    from oscar.contracts.component_contract import COMPONENT_ORIGINS, validate_component_advisory_evidence, validate_label_free_evidence, verify_osv_advisory_evidence
    from oscar.analysis.component_path import discover_component_tool_paths, validate_component_tool_path
    from oscar.workflows.linux_case_assembly import _verify_patch_explains_pair


RELATION_STATUSES = {"affected_exact_direct_runtime", "affected_commit_direct_runtime"}
PYTHON_EXTENSIONS = {".py"}
NODE_EXTENSIONS = {".js", ".mjs", ".cjs", ".ts", ".mts", ".cts"}
ANALYSIS_EXTENSIONS = PYTHON_EXTENSIONS | NODE_EXTENSIONS | {".json", ".toml", ".txt", ".md"}


def _norm(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "-", str(value or "").lower()).strip("-")


def _repository_key(value: Any) -> str:
    text = str(value or "").strip().lower().rstrip("/")
    text = re.sub(r"^https?://(?:www\.)?github\.com/", "", text)
    return text.removesuffix(".git")


def _jsonl(path: Path) -> Iterable[dict[str, Any]]:
    if not path.exists():
        return
    with path.open(encoding="utf-8") as stream:
        for line in stream:
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(value, dict):
                yield value


def _pool_file(root: Path, name: str) -> Path:
    return root / "04_datasets" / "candidate_pool" / "data" / "direct_dependency" / name


def _aliases(row: dict[str, Any]) -> set[str]:
    return {
        str(row.get("canonical_vulnerability_id", "")).lower(),
        *(str(value).lower() for value in row.get("aliases", []) if value),
    }


def _candidate_matches(row: dict[str, Any], advisory: str, package: str, vulnerable: str, fixed: str) -> bool:
    return (
        advisory.lower() in _aliases(row)
        and _norm(row.get("dependency_name")) == _norm(package)
        and str(row.get("resolved_version", "")) == vulnerable
        and str(row.get("fixed_version_or_commit", "")) == fixed
    )


def _explicit_component_candidate(
    package: str,
    vulnerable_version: str,
    fixed_version: str,
    repository: str,
    component_repository: str | None,
    component_purl: str | None,
    entrypoint: str | None,
) -> dict[str, Any]:
    """Build a label-free component row when the candidate is not a pool row."""
    purl = component_purl or (
        package if str(package).startswith("pkg:") else f"pkg:pypi/{_norm(package)}"
    )
    return {
        "candidate_id": f"explicit-{_norm(package)}-{_norm(vulnerable_version)}",
        "dependency_name": package,
        "dependency_purl": purl,
        "resolved_version": vulnerable_version,
        "fixed_version_or_commit": fixed_version,
        "repository": component_repository or repository,
        "source_commit": vulnerable_version,
        "dependency_ecosystem": "npm" if purl.lower().startswith("pkg:npm/") else "pypi",
        "mcp_entrypoint": entrypoint,
        "status": "AFFECTED_EXACT_COMPONENT",
    }


def _origin_tool_path(
    source_root: Path | None,
    entrypoint: str | None,
    explicit_tool: str | None,
    component_name: str,
    origin: str,
    patch: str | None = None,
    analysis_root: Path | None = None,
    analysis_patch: str | None = None,
) -> dict[str, Any]:
    """Build an AST/tokenizer path proof; never use text token presence."""
    if source_root is None or not source_root.is_dir():
        return {"schema_version": "vulveil-tool-discovery/v2", "status": "UNRESOLVED", "tools": [],
                "component_origin": origin, "component_name": component_name,
                "graph": {"nodes": [], "edges": []}, "reason": "component entrypoint source root is missing"}
    return discover_component_tool_paths(
        source_root, entrypoint, explicit_tool, component_name, origin, patch,
        analysis_root=analysis_root, analysis_patch=analysis_patch,
    )


def discover_candidate(root: Path, advisory: str, package: str, vulnerable: str, fixed: str, repository: str | None = None) -> dict[str, Any]:
    """Resolve a candidate without consulting advisory services or GT files."""
    path = _pool_file(root, "affected_direct_dependencies.jsonl")
    rows = [row for row in _jsonl(path) if _candidate_matches(row, advisory, package, vulnerable, fixed)]
    if repository:
        rows = [row for row in rows if str(row.get("repository", "")) == repository]
    if not rows:
        return {"status": "UNRESOLVED_DIRECT_DEPENDENCY", "candidate_count": 0, "candidates": [], "evidence": str(path)}
    valid: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    for row in rows:
        reasons: list[str] = []
        if row.get("dependency_depth") != 1:
            reasons.append("dependency_depth must equal 1")
        if row.get("dependency_scope") != "runtime":
            reasons.append("dependency_scope must equal runtime")
        if row.get("status") not in RELATION_STATUSES:
            reasons.append("relation_status is not an allowed direct-runtime relation")
        purl_path = unquote(str(row.get("dependency_purl", ""))).split("?", 1)[0].split("#", 1)[0]
        purl_prefix, separator, purl_name = purl_path.rpartition("/")
        purl = purl_prefix + separator + purl_name.split("@", 1)[0]
        ecosystem = str(row.get("dependency_ecosystem", "")).lower()
        if ecosystem == "npm":
            expected_purl = f"pkg:npm/{str(row.get('dependency_name', '')).lower()}"
        elif ecosystem == "pypi":
            expected_purl = f"pkg:pypi/{_norm(row.get('dependency_name'))}"
        else:
            expected_purl = ""
        if not expected_purl or purl.lower() != expected_purl:
            reasons.append("dependency_purl does not identify the declared external dependency")
        if row.get("framework_only") is True:
            reasons.append("framework-only attribution is not a verified direct dependency case")
        if reasons:
            rejected.append({"candidate_id": row.get("candidate_id"), "reasons": reasons})
        else:
            valid.append(row)
    if not valid:
        return {
            "status": "UNRESOLVED_DIRECT_DEPENDENCY",
            "candidate_count": len(rows),
            "candidates": rejected,
            "evidence": str(path),
        }
    # A four-field identity must resolve to one unambiguous server/dependency relation.
    unique = {(row.get("repository"), row.get("source_commit"), row.get("candidate_id")) for row in valid}
    if len(unique) > 1:
        return {
            "status": "UNRESOLVED_DIRECT_DEPENDENCY",
            "candidate_count": len(rows),
            "candidates": [{"candidate_id": row.get("candidate_id"), "repository": row.get("repository")} for row in valid],
            "reason": "multiple direct-runtime candidates match the four-field identity",
            "evidence": str(path),
        }
    row = valid[0]
    return {"status": "CANDIDATE_MATCH", "candidate": row, "candidate_count": len(rows), "evidence": str(path)}


def _related_rows(root: Path, filename: str, candidate_id: str) -> list[dict[str, Any]]:
    return [row for row in _jsonl(_pool_file(root, filename)) if row.get("candidate_id") == candidate_id]


def _entrypoint(candidate: dict[str, Any], module_rows: list[dict[str, Any]]) -> str | None:
    for row in module_rows:
        value = row.get("mcp_entrypoint")
        if isinstance(value, str) and value:
            return value
        evidence = row.get("module_ownership", {})
        if isinstance(evidence, dict) and isinstance(evidence.get("entrypoint"), str):
            return evidence["entrypoint"]
    value = candidate.get("mcp_entrypoint")
    return value if isinstance(value, str) and value else None


def _tool_name(module_rows: list[dict[str, Any]], explicit: str | None, source_root: Path | None = None, entrypoint: str | None = None) -> str | None:
    if explicit:
        return explicit
    for row in module_rows:
        evidence = row.get("identification_evidence", {})
        for group in (evidence.get("tool_registration_evidence", []),):
            for item in group:
                for match in item.get("matches", []):
                    line = str(match.get("line", ""))
                    found = re.search(r"(?:tool|add_tool)\s*\(\s*['\"]([A-Za-z0-9_.:-]+)", line)
                    if found:
                        return found.group(1)
    if source_root and entrypoint:
        path = _find_entrypoint(source_root, entrypoint)
        if path and path.exists():
            text = path.read_text(encoding="utf-8", errors="replace")
            match = re.search(r"(?:\.tool|\.add_tool)\s*\(\s*['\"]([A-Za-z0-9_.:-]+)", text)
            if match:
                return match.group(1)
            match = re.search(r"@[^\n]*\.tool\([^\n]*\)\s*\n\s*(?:async\s+)?def\s+([A-Za-z_][A-Za-z0-9_]*)", text)
            if match:
                return match.group(1)
    return None


def _find_entrypoint(source_root: Path, entrypoint: str | None) -> Path | None:
    if not entrypoint:
        return None
    direct = source_root / entrypoint
    if direct.is_file():
        return direct
    matches = list(source_root.rglob(Path(entrypoint).name))
    return matches[0] if len(matches) == 1 else None


def infer_runner_adapter(source_root: Path | None, ecosystem: str, entrypoint: str | None, *, side: str, tool: str | None = None) -> dict[str, Any]:
    """Infer a conservative Python or Node stdio runner from local source."""
    if source_root is None or not source_root.is_dir():
        return {"status": "UNSUPPORTED_RUNNER_ADAPTER", "reason": "local source root is required"}
    path = _find_entrypoint(source_root, entrypoint)
    if path is None:
        return {"status": "UNSUPPORTED_RUNNER_ADAPTER", "reason": "production MCP entrypoint was not found"}
    suffix = path.suffix.lower()
    if suffix in PYTHON_EXTENSIONS:
        command = ["python3", str(path.relative_to(source_root))]
        language = "python"
    elif suffix in NODE_EXTENSIONS:
        if suffix in {".ts", ".mts", ".cts"}:
            if not (source_root / "node_modules" / ".bin" / "tsx").exists():
                return {"status": "UNSUPPORTED_RUNNER_ADAPTER", "reason": "TypeScript entrypoint requires local tsx"}
            command = ["node_modules/.bin/tsx", str(path.relative_to(source_root))]
        else:
            command = ["node", str(path.relative_to(source_root))]
        language = "node"
    else:
        return {"status": "UNSUPPORTED_RUNNER_ADAPTER", "reason": f"unsupported entrypoint extension: {suffix}"}
    return {
        "status": "SUPPORTED",
        "language": language,
        "transport": "stdio",
        "command": command,
        "cwd": str(source_root),
        "env": {},
        "tool": tool,
        "evidence_file": "blind_evidence.jsonl",
        "evidence_adapter": {
            "schema_version": "vulveil-evidence-adapter/v1",
            "type": "shared-host-l0-l4",
            "output": "blind_evidence.jsonl",
            "actual_next_model_request": True,
            "tool_message_role": "tool",
            "attest_input_digest": True,
        },
    }


def _git_patch(vulnerable_root: Path | None, fixed_root: Path | None) -> tuple[str | None, str | None]:
    if not vulnerable_root or not fixed_root or not vulnerable_root.is_dir() or not fixed_root.is_dir():
        return None, "both vulnerable and fixed source roots are required"
    try:
        result = subprocess.run(
            ["git", "diff", "--no-index", "--", str(vulnerable_root), str(fixed_root)],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return None, f"local git diff failed: {type(exc).__name__}"
    if result.returncode not in (0, 1):
        return None, "local git diff returned an error"
    if not result.stdout.strip():
        return None, "vulnerable/fixed source roots have no diff"
    # ``git diff --no-index`` emits absolute temporary-root paths.  Normalize
    # only the structured file headers so Stage 1/assembly can verify the
    # patch against the two supplied roots without accepting arbitrary paths.
    normalized: list[str] = []
    for line in result.stdout.splitlines(keepends=True):
        if line.startswith(("--- ", "+++ ", "rename from ", "rename to ")):
            if line.startswith("rename from "):
                marker, raw = "rename from ", line[len("rename from "):].rstrip("\r\n")
            elif line.startswith("rename to "):
                marker, raw = "rename to ", line[len("rename to "):].rstrip("\r\n")
            else:
                marker, raw = line[:4], line[4:].rstrip("\r\n")
            raw_path = raw.split("\t", 1)[0]
            root_for_side = vulnerable_root if marker in {"--- ", "rename from "} else fixed_root
            if raw_path == "/dev/null":
                normalized.append(marker + raw_path + ("\n" if line.endswith("\n") else ""))
                continue
            path_for_mapping = raw_path.removeprefix("a/").removeprefix("b/")
            candidates = [Path(path_for_mapping)]
            if not Path(path_for_mapping).is_absolute():
                candidates.append(Path("/") / path_for_mapping)
            try:
                candidate = next(item.resolve() for item in candidates if item.resolve().is_relative_to(root_for_side.resolve()))
                relative = candidate.relative_to(root_for_side.resolve()).as_posix()
                suffix = "\n" if line.endswith("\n") else ""
                prefix = "a/" if marker == "--- " else "b/" if marker == "+++ " else ""
                normalized.append(marker + prefix + relative + suffix)
                continue
            except (ValueError, OSError, StopIteration):
                pass
        normalized.append(line)
    return "".join(normalized), None


def _digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True, default=str).encode()).hexdigest()


def _analysis_inventory(root: Path) -> dict[str, Any]:
    """Return a deterministic inventory for dependency analysis material."""
    if not root.is_dir() or root.is_symlink():
        return {"status": "UNRESOLVED", "files": [], "sha256": None, "reason": "dependency analysis source root is missing"}
    files: dict[str, str] = {}
    excluded = {".git", ".venv", "venv", "node_modules", "__pycache__", ".pytest_cache"}
    for directory, directories, names in os.walk(root, followlinks=False):
        directories[:] = [name for name in directories if name not in excluded]
        for name in names:
            path = Path(directory) / name
            if path.is_symlink() or path.suffix.lower() not in ANALYSIS_EXTENSIONS:
                continue
            try:
                files[path.relative_to(root).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
            except OSError:
                return {"status": "UNRESOLVED", "files": [], "sha256": None, "reason": f"unable to read dependency analysis source {path}"}
    if not files:
        return {"status": "UNRESOLVED", "files": [], "sha256": None, "reason": "dependency analysis source has no supported files"}
    return {"status": "VERIFIED", "files": files, "sha256": _digest(files), "reason": None}


def _analysis_patch(
    vulnerable_root: Path | None,
    fixed_root: Path | None,
    explicit_patch: Path | None,
) -> tuple[str | None, str | None, str]:
    if explicit_patch is not None:
        if not explicit_patch.is_file():
            return None, "explicit dependency patch file is missing", "explicit-file"
        try:
            value = explicit_patch.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            return None, f"dependency patch file cannot be read: {type(exc).__name__}", "explicit-file"
        return (value, None, "explicit-file") if value.strip() else (None, "dependency patch file is empty", "explicit-file")
    value, error = _git_patch(vulnerable_root, fixed_root)
    return value, error, "dependency-source-diff"


def preparation_required_report(
    output: Path,
    reason: str,
    *,
    input_data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Persist a structured, label-free failure for CLI preparation input."""
    output.mkdir(parents=True, exist_ok=True)
    report = {
        "schema_version": "vulveil-preparation-report/v1",
        "status": "PREPARATION_REQUIRED",
        "input": input_data or {},
        "checks": {
            "vulnerability_component": {
                "status": "UNRESOLVED",
                "evidence": None,
                "unresolved_reason": reason,
                "suggested_machine_action": "provide valid structured advisory/component/source/patch evidence and rerun prepare-case",
                "requires_human_review": True,
            }
        },
        "unresolved_reason": reason,
        "suggested_machine_action": "provide valid structured advisory/component/source/patch evidence and rerun prepare-case",
        "requires_human_review": True,
    }
    (output / "preparation_report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return report


def prepare_case(
    root: Path,
    advisory: str,
    package: str,
    vulnerable_version: str,
    fixed_version: str,
    repository: str,
    output: Path,
    *,
    vulnerable_source_root: Path | None = None,
    fixed_source_root: Path | None = None,
    vulnerable_dependency_source_root: Path | None = None,
    fixed_dependency_source_root: Path | None = None,
    dependency_patch: Path | None = None,
    source_root: Path | None = None,
    tool: str | None = None,
    tool_input: dict[str, Any] | None = None,
    agent_task: str | None = None,
    experiment_type: str = "SENSITIVE_INFORMATION_DISCLOSURE",
    component_origin: str | None = None,
    component_repository: str | None = None,
    component_purl: str | None = None,
    component_entrypoint: str | None = None,
    component_source_evidence: Any = None,
    component_patch_evidence: Any = None,
    component_advisory_evidence: Any = None,
) -> dict[str, Any]:
    origin = component_origin or "DIRECT_RUNTIME_DEPENDENCY"
    legacy_direct_input = component_origin is None
    if origin not in COMPONENT_ORIGINS:
        raise ValueError(f"unsupported component_origin: {origin}")
    evidence_errors = [
        *validate_label_free_evidence(component_source_evidence, field="component_source_evidence"),
        *validate_label_free_evidence(component_patch_evidence, field="component_patch_evidence"),
    ]
    if evidence_errors:
        raise ValueError("component evidence is not label-free: " + "; ".join(evidence_errors))
    if origin == "MCP_FRAMEWORK" and not component_repository and not component_purl:
        output.mkdir(parents=True, exist_ok=True)
        report = {
            "schema_version": "vulveil-preparation-report/v1",
            "status": "PREPARATION_REQUIRED",
            "input": {"advisory": advisory, "package": package, "component_origin": origin, "component_repository": component_repository, "component_purl": component_purl, "component_entrypoint": component_entrypoint},
            "checks": {"vulnerability_component": {
                "status": "FAIL",
                "evidence": None,
                "unresolved_reason": "MCP_FRAMEWORK requires component_repository or component_purl",
                "suggested_machine_action": "provide the independent framework/SDK repository or package URL",
                "requires_human_review": True,
            }},
            "unresolved_reason": "MCP_FRAMEWORK requires component_repository or component_purl",
            "suggested_machine_action": "provide the independent framework/SDK repository or package URL",
            "requires_human_review": True,
        }
        (output / "preparation_report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        return report
    output.mkdir(parents=True, exist_ok=True)
    if origin != "DIRECT_RUNTIME_DEPENDENCY":
        advisory_errors = validate_component_advisory_evidence(
            advisory=advisory, package=package, repository=repository,
            component_repository=component_repository, component_purl=component_purl,
            vulnerable=vulnerable_version, fixed=fixed_version,
            evidence=component_advisory_evidence,
            source_evidence=component_source_evidence,
            patch_evidence=component_patch_evidence,
        )
        if not advisory_errors:
            advisory_errors, verified_evidence = verify_osv_advisory_evidence(
                advisory=advisory, package=package, repository=repository,
                component_repository=component_repository, component_purl=component_purl,
                vulnerable=vulnerable_version, fixed=fixed_version,
                evidence=component_advisory_evidence,
                source_evidence=component_source_evidence,
                patch_evidence=component_patch_evidence,
            )
            if verified_evidence is not None:
                component_advisory_evidence = verified_evidence
        if advisory_errors:
            report = {
                "schema_version": "vulveil-preparation-report/v1",
                "status": "PREPARATION_REQUIRED",
                "input": {"advisory": advisory, "package": package, "component_origin": origin,
                          "component_repository": component_repository, "component_purl": component_purl},
                "checks": {"vulnerability_component": {
                    "status": "UNRESOLVED", "evidence": {"component_origin": origin},
                    "unresolved_reason": "; ".join(advisory_errors),
                    "suggested_machine_action": "provide independently sourced structured advisory/component/version and source/patch relation evidence",
                    "requires_human_review": True,
                }},
                "unresolved_reason": "; ".join(advisory_errors),
                "suggested_machine_action": "provide independently sourced structured advisory/component/version and source/patch relation evidence",
                "requires_human_review": True,
            }
            (output / "preparation_report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            return report
    if origin == "DIRECT_RUNTIME_DEPENDENCY":
        candidate_result = discover_candidate(root, advisory, package, vulnerable_version, fixed_version, repository)
    else:
        candidate_result = {
            "status": "EXPLICIT_COMPONENT",
            "candidate": _explicit_component_candidate(
                package, vulnerable_version, fixed_version, repository,
                component_repository, component_purl, component_entrypoint,
            ),
            "candidate_count": 1,
            "evidence": "explicit component contract",
        }
    report: dict[str, Any] = {
        "schema_version": "vulveil-preparation-report/v1",
        "status": candidate_result["status"],
        "input": {"advisory": advisory, "package": package, "vulnerable_version": vulnerable_version, "fixed_version": fixed_version, "repository": repository, "component_origin": origin, "component_repository": component_repository, "component_purl": component_purl, "component_entrypoint": component_entrypoint},
        "checks": {},
        "unresolved_reason": None,
        "suggested_machine_action": None,
        "requires_human_review": False,
    }
    if candidate_result["status"] not in {"CANDIDATE_MATCH", "EXPLICIT_COMPONENT"}:
        report["unresolved_reason"] = candidate_result.get("reason", "component candidate was not resolved")
        report["suggested_machine_action"] = "select a unique affected component candidate or correct the identity input"
        report["checks"]["vulnerability_component"] = {"status": "FAIL", "evidence": candidate_result.get("evidence"), "unresolved_reason": report["unresolved_reason"], "suggested_machine_action": report["suggested_machine_action"], "requires_human_review": True}
        (output / "preparation_report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        return report
    candidate = candidate_result["candidate"]
    component_repository_key = _repository_key(candidate.get("repository"))
    server_repository_key = _repository_key(repository)
    if origin == "MCP_SERVER_SELF" and server_repository_key and component_repository_key != server_repository_key:
        report["status"] = "PREPARATION_REQUIRED"
        report["unresolved_reason"] = "MCP_SERVER_SELF component repository must match the MCP Server repository"
        report["suggested_machine_action"] = "use the Server repository for the Server-self component"
        report["requires_human_review"] = True
        report["checks"]["vulnerability_component"] = {
            "status": "FAIL",
            "evidence": {"server_repository": repository, "component_repository": candidate.get("repository")},
            "unresolved_reason": report["unresolved_reason"],
            "suggested_machine_action": report["suggested_machine_action"],
            "requires_human_review": True,
        }
        (output / "preparation_report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        return report
    if origin == "DIRECT_RUNTIME_DEPENDENCY" and repository and candidate.get("repository") and repository != candidate.get("repository"):
        report["status"] = "UNRESOLVED_DIRECT_DEPENDENCY"
        report["unresolved_reason"] = "repository does not match candidate pool relation"
        report["suggested_machine_action"] = "use the repository bound to the direct-runtime candidate"
        report["requires_human_review"] = True
        (output / "preparation_report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        return report
    candidate_id = str(candidate.get("candidate_id"))
    modules = _related_rows(root, "mcp_modules.jsonl", candidate_id)
    source_evidence = _related_rows(root, "module_source_evidence.jsonl", candidate_id)
    entrypoint = component_entrypoint or _entrypoint(candidate, modules)
    if source_root is not None:
        vulnerable_source_root = vulnerable_source_root or source_root / "vulnerable"
        fixed_source_root = fixed_source_root or source_root / "fixed"
    detected_tool = _tool_name(modules, tool, vulnerable_source_root, entrypoint)
    dependency_evidence = (
        verify_dependency_pair(
            vulnerable_source_root, fixed_source_root, package, vulnerable_version,
            fixed_version, str(candidate.get("dependency_ecosystem", "")),
        )
        if origin == "DIRECT_RUNTIME_DEPENDENCY"
        else {"status": "NOT_REQUIRED", "reasons": [], "component_origin": origin}
    )
    entrypoint_path = _find_entrypoint(vulnerable_source_root, entrypoint) if vulnerable_source_root else None
    if origin != "DIRECT_RUNTIME_DEPENDENCY" and vulnerable_source_root:
        tool_path_discovery = _origin_tool_path(vulnerable_source_root, entrypoint, detected_tool, package, origin)
    elif vulnerable_source_root and entrypoint_path and entrypoint_path.suffix.lower() in PYTHON_EXTENSIONS:
        tool_path_discovery = discover_python_tool_paths(vulnerable_source_root, package)
        path_tools = [item for item in tool_path_discovery.get("tools", []) if item.get("reaches_direct_dependency")]
        if not tool and len(path_tools) == 1:
            detected_tool = str(path_tools[0]["tool"])
    elif vulnerable_source_root and entrypoint_path and entrypoint_path.suffix.lower() in NODE_EXTENSIONS:
        tool_path_discovery = discover_javascript_tool_paths(vulnerable_source_root, package)
        path_tools = [item for item in tool_path_discovery.get("tools", []) if item.get("reaches_direct_dependency")]
        if not tool and len(path_tools) == 1:
            detected_tool = str(path_tools[0]["tool"])
    else:
        tool_path_discovery = {
            "schema_version": "vulveil-tool-discovery/v1", "status": "UNRESOLVED",
            "language": "unsupported-or-missing", "dependency_name": package, "tools": [],
            "reason": "structured Tool-to-dependency discovery requires a supported Python or JavaScript/TypeScript entrypoint",
        }
    path_key = "reaches_component" if origin != "DIRECT_RUNTIME_DEPENDENCY" else "reaches_direct_dependency"
    selected_path_tools = [
        item for item in tool_path_discovery.get("tools", [])
        if item.get("tool") == detected_tool and item.get(path_key)
    ]
    tool_path_ready = len(selected_path_tools) == 1
    vuln_adapter = infer_runner_adapter(vulnerable_source_root, str(candidate.get("dependency_ecosystem", "")), entrypoint, side="vulnerable", tool=detected_tool)
    fixed_adapter = infer_runner_adapter(fixed_source_root, str(candidate.get("dependency_ecosystem", "")), entrypoint, side="fixed", tool=detected_tool)
    patch, patch_error = _git_patch(vulnerable_source_root, fixed_source_root)
    if patch:
        try:
            _verify_patch_explains_pair(vulnerable_source_root, fixed_source_root, patch, "Server patch")
        except ValueError as exc:
            patch = None
            patch_error = str(exc)
    analysis_reasons: list[str] = []
    analysis_inventory: dict[str, Any] = {}
    analysis_patch_text: str | None = None
    analysis_patch_error: str | None = None
    analysis_patch_origin = "dependency-source-diff"
    analysis_required = origin in {"DIRECT_RUNTIME_DEPENDENCY", "MCP_FRAMEWORK"} and not legacy_direct_input
    if origin in {"DIRECT_RUNTIME_DEPENDENCY", "MCP_FRAMEWORK"}:
        if (vulnerable_dependency_source_root is None) != (fixed_dependency_source_root is None):
            analysis_reasons.append("both vulnerable and fixed component analysis source roots are required")
        elif vulnerable_dependency_source_root is None:
            analysis_reasons.append("component analysis source pair is missing")
        else:
            analysis_inventory = {
                "vulnerable": _analysis_inventory(vulnerable_dependency_source_root),
                "fixed": _analysis_inventory(fixed_dependency_source_root),
            }
            if any(item.get("status") != "VERIFIED" for item in analysis_inventory.values()):
                analysis_reasons.extend(str(item.get("reason")) for item in analysis_inventory.values() if item.get("reason"))
            analysis_patch_text, analysis_patch_error, analysis_patch_origin = _analysis_patch(
                vulnerable_dependency_source_root, fixed_dependency_source_root, dependency_patch
            )
            if analysis_patch_text:
                try:
                    _verify_patch_explains_pair(
                        vulnerable_dependency_source_root, fixed_dependency_source_root,
                        analysis_patch_text, "component analysis patch",
                    )
                except ValueError as exc:
                    analysis_patch_text = None
                    analysis_patch_error = str(exc)
            if analysis_patch_error:
                analysis_reasons.append(analysis_patch_error)
    if not analysis_reasons and analysis_patch_text:
        analysis_material_status = "VERIFIED"
    elif analysis_required:
        analysis_material_status = "UNRESOLVED_UPSTREAM_PATCH"
    elif origin == "MCP_SERVER_SELF":
        analysis_material_status = "NOT_REQUIRED"
    else:
        analysis_material_status = "UNRESOLVED_UPSTREAM_PATCH"
    if origin != "DIRECT_RUNTIME_DEPENDENCY":
        analysis_root = vulnerable_dependency_source_root if origin == "MCP_FRAMEWORK" else vulnerable_source_root
        tool_path_discovery = _origin_tool_path(
            vulnerable_source_root, entrypoint, detected_tool, package, origin,
            patch=patch,
            analysis_root=analysis_root,
            analysis_patch=analysis_patch_text,
        )
        if not detected_tool:
            discovered_tools = tool_path_discovery.get("tools", []) if isinstance(tool_path_discovery, dict) else []
            if len(discovered_tools) == 1:
                detected_tool = str(discovered_tools[0].get("tool") or "") or None
                tool_path_discovery = _origin_tool_path(
                    vulnerable_source_root, entrypoint, detected_tool, package, origin,
                    patch=patch, analysis_root=analysis_root, analysis_patch=analysis_patch_text,
                )
    runtime_inventory = _analysis_inventory(vulnerable_source_root) if vulnerable_source_root else {"files": {}}
    path_errors = validate_component_tool_path(tool_path_discovery, component_name=package, tool_name=detected_tool) if origin != "DIRECT_RUNTIME_DEPENDENCY" else []
    if origin != "DIRECT_RUNTIME_DEPENDENCY":
        selected_path_tools = [item for item in tool_path_discovery.get("tools", []) if item.get("tool") == detected_tool and item.get("reaches_component") is True]
    tool_path_ready = len(selected_path_tools) == 1 and not path_errors
    checks = {
        "vulnerability_component": {"status": "PASS", "evidence": {"origin": origin, "candidate_id": candidate.get("candidate_id"), "name": candidate.get("dependency_name"), "purl": candidate.get("dependency_purl"), "repository": candidate.get("repository"), "vulnerable_version": candidate.get("resolved_version"), "fixed_version": candidate.get("fixed_version_or_commit"), "advisory_evidence": component_advisory_evidence if origin != "DIRECT_RUNTIME_DEPENDENCY" else None}, "unresolved_reason": None, "suggested_machine_action": None, "requires_human_review": False},
        "independent_dependency_evidence": {"status": "PASS" if dependency_evidence["status"] == "VERIFIED" else ("NOT_REQUIRED" if origin != "DIRECT_RUNTIME_DEPENDENCY" else "UNRESOLVED"), "evidence": dependency_evidence, "unresolved_reason": "; ".join(dependency_evidence["reasons"]) or None, "suggested_machine_action": "provide matching production manifests and resolved dependency locks on both sides" if origin == "DIRECT_RUNTIME_DEPENDENCY" and dependency_evidence["status"] != "VERIFIED" else None, "requires_human_review": origin == "DIRECT_RUNTIME_DEPENDENCY" and dependency_evidence["status"] != "VERIFIED"},
        "server_manifest_and_tool": {"status": "PASS" if entrypoint and detected_tool else "UNRESOLVED", "evidence": {"entrypoint": entrypoint, "tool": detected_tool, "source_evidence_rows": len(source_evidence)}, "unresolved_reason": None if entrypoint and detected_tool else "manifest/entrypoint/tool registration evidence is incomplete", "suggested_machine_action": None if entrypoint and detected_tool else "supply --tool and a source root with a production MCP entrypoint", "requires_human_review": not bool(entrypoint and detected_tool)},
        "tool_to_dependency_path": {"status": "PASS" if tool_path_ready else ("PARTIAL" if tool_path_discovery.get("status") == "PARTIAL" else "UNRESOLVED"), "evidence": tool_path_discovery, "unresolved_reason": None if tool_path_ready else "; ".join(path_errors) or tool_path_discovery.get("reason") or ("selected Tool has no unique structured path to the framework component" if origin == "MCP_FRAMEWORK" else "selected Tool has no unique structured path to the target component"), "suggested_machine_action": None if tool_path_ready else "review structured Tool call graph and patch-anchor mapping", "requires_human_review": not tool_path_ready},
        "vulnerable_runner": {"status": vuln_adapter.get("status"), "evidence": vuln_adapter, "unresolved_reason": vuln_adapter.get("reason"), "suggested_machine_action": "provide a supported Python .py or Node .js/.ts stdio source" if vuln_adapter.get("status") != "SUPPORTED" else None, "requires_human_review": vuln_adapter.get("status") != "SUPPORTED"},
        "fixed_runner": {"status": fixed_adapter.get("status"), "evidence": fixed_adapter, "unresolved_reason": fixed_adapter.get("reason"), "suggested_machine_action": "provide a supported fixed source root" if fixed_adapter.get("status") != "SUPPORTED" else None, "requires_human_review": fixed_adapter.get("status") != "SUPPORTED"},
        "patch": {"status": "PASS" if patch else ("NOT_REQUIRED" if origin == "MCP_FRAMEWORK" and analysis_patch_text else "UNRESOLVED"), "evidence": {"generated_locally": bool(patch), "bytes": len(patch.encode()) if patch else 0}, "unresolved_reason": None if (patch or (origin == "MCP_FRAMEWORK" and analysis_patch_text)) else patch_error, "suggested_machine_action": None if (patch or (origin == "MCP_FRAMEWORK" and analysis_patch_text)) else "provide both local source roots or an explicit local Git revision pair", "requires_human_review": not bool(patch) and not (origin == "MCP_FRAMEWORK" and analysis_patch_text)},
        "analysis_source": {"status": "PASS" if analysis_inventory and all(item.get("status") == "VERIFIED" for item in analysis_inventory.values()) else ("NOT_REQUIRED" if origin == "MCP_SERVER_SELF" else "UNRESOLVED"), "evidence": analysis_inventory, "unresolved_reason": "; ".join(analysis_reasons) or None, "suggested_machine_action": ("provide vulnerable/fixed framework source roots" if origin == "MCP_FRAMEWORK" else "provide vulnerable/fixed component source roots") if analysis_reasons else None, "requires_human_review": bool(analysis_reasons) and analysis_required},
        "analysis_patch": {"status": "PASS" if analysis_patch_text else ("NOT_REQUIRED" if origin == "MCP_SERVER_SELF" else "UNRESOLVED"), "evidence": {"origin": analysis_patch_origin, "bytes": len(analysis_patch_text.encode()) if analysis_patch_text else 0}, "unresolved_reason": analysis_patch_error or (("framework repair patch is missing" if origin == "MCP_FRAMEWORK" else "component upstream repair patch is missing") if not analysis_patch_text and origin != "MCP_SERVER_SELF" else None), "suggested_machine_action": ("provide --dependency-patch or both framework source roots" if origin == "MCP_FRAMEWORK" else "provide --dependency-patch or both component source roots") if not analysis_patch_text and origin != "MCP_SERVER_SELF" else None, "requires_human_review": not bool(analysis_patch_text) and analysis_required},
    }
    report["checks"] = checks
    # Server onboarding can be prepared before upstream dependency analysis
    # material arrives, but it must remain explicitly unresolved until then.
    failures = [name for name, check in checks.items() if name not in {"analysis_source", "analysis_patch"} and check["status"] not in {"PASS", "SUPPORTED", "NOT_REQUIRED"}]
    if analysis_required and checks["analysis_source"]["status"] != "PASS":
        failures.append("analysis_source")
    if analysis_required and checks["analysis_patch"]["status"] != "PASS":
        failures.append("analysis_patch")
    if failures:
        if any(checks[name]["status"] == "UNSUPPORTED_RUNNER_ADAPTER" for name in failures):
            report["status"] = "UNSUPPORTED_RUNNER_ADAPTER"
        elif "patch" in failures or "vulnerable_runner" in failures or "fixed_runner" in failures:
            report["status"] = "UNRESOLVED_SOURCE_OR_PATCH"
        elif "independent_dependency_evidence" in failures:
            report["status"] = "UNRESOLVED_DIRECT_DEPENDENCY"
        else:
            report["status"] = "PREPARATION_REQUIRED"
        report["unresolved_reason"] = "; ".join(f"{name}: {checks[name]['unresolved_reason']}" for name in failures if checks[name].get("unresolved_reason"))
        report["suggested_machine_action"] = "resolve the failed preparation checks and rerun prepare-case"
        report["requires_human_review"] = any(checks[name].get("requires_human_review") for name in failures)
    else:
        case_id = f"{_norm(advisory)}-{_norm(package)}-{_norm(vulnerable_version)}"
        side_roots = {
            "vulnerable": Path(os.path.relpath(vulnerable_source_root, output)).as_posix(),
            "fixed": Path(os.path.relpath(fixed_source_root, output)).as_posix(),
        }
        server_runner = {"vulnerable": {**vuln_adapter, "cwd": "."}, "patched": {**fixed_adapter, "cwd": "."}}
        host_runner = {
            side: {
                "command": ["python3", "__VULVEIL_RUNNER_FILE__", "--case", "__VULVEIL_CASE_FILE__",
                            "--side", side, "--output", "__VULVEIL_OUTPUT_DIR__"],
                "cwd": ".", "env": {}, "evidence_file": "blind_evidence.jsonl",
            }
            for side in ("vulnerable", "patched")
        }
        case = {
            "schema_version": "vulveil-blind-case/v1",
            "case_id": case_id,
            "status": "prepared",
            "identity": {"advisory": advisory, "package": package, "vulnerable_version": vulnerable_version, "fixed_version": fixed_version},
            "experiment_type": experiment_type,
            "component_origin": origin,
            "server": {"repository": repository or candidate.get("repository"), "module": entrypoint, "tool": detected_tool},
            "agent_task": agent_task or f"Call the frozen {detected_tool} Tool and report only its returned result.",
            "tool_input": tool_input or {},
            "host_profile": {"id": "shared-research-host/v1", "model": "cli-mock", "temperature": 0},
            "vulnerability_component": {
                "origin": origin,
                "name": candidate.get("dependency_name"),
                "purl": candidate.get("dependency_purl"),
                "repository": candidate.get("repository"),
                "vulnerable_version": candidate.get("resolved_version"),
                "fixed_version": candidate.get("fixed_version_or_commit"),
                "relation_status": "AFFECTED_EXACT_COMPONENT",
                **({"dependency_depth": candidate.get("dependency_depth"), "dependency_scope": candidate.get("dependency_scope")} if origin == "DIRECT_RUNTIME_DEPENDENCY" else {}),
                "source_evidence": component_source_evidence or [
                    f"component-source:{path}"
                    for path in (runtime_inventory if origin == "MCP_SERVER_SELF" or not analysis_inventory else analysis_inventory.get("vulnerable", {})).get("files", {})
                ] or ["component-source-pair"],
                "patch_evidence": component_patch_evidence or [
                    f"component-patch:{path}"
                    for path in re.findall(r"^\+\+\+ b/(.+)$", (patch if origin == "MCP_SERVER_SELF" or not analysis_patch_text else analysis_patch_text) or "", re.MULTILINE)
                ] or [f"component-patch:{analysis_patch_origin}"],
                "advisory_evidence": component_advisory_evidence,
            },
            "source": {"vulnerable": {"root": side_roots["vulnerable"]}, "fixed": {"root": side_roots["fixed"]}, "role": "server_runtime", "source_commit": candidate.get("source_commit")},
            "patch": ({"unified_diff": patch, "generated_by": "local-git-diff", "source": "local source roots"}
                      if patch else {"status": "NOT_REQUIRED", "reason": "runnable Server source is parity-identical; component analysis patch is authoritative"}),
            "analysis_source": (
                {"vulnerable": {"root": Path(os.path.relpath(vulnerable_dependency_source_root, output)).as_posix()},
                 "fixed": {"root": Path(os.path.relpath(fixed_dependency_source_root, output)).as_posix()},
                 "role": "dependency_analysis", "status": "VERIFIED", "inventory": analysis_inventory}
                if analysis_material_status == "VERIFIED" else
                {"role": "component_analysis", "status": analysis_material_status, "reason": "; ".join(analysis_reasons)}
            ),
            "analysis_patch": (
                {"unified_diff": analysis_patch_text, "generated_by": analysis_patch_origin, "source": "dependency upstream repair"}
                if analysis_patch_text else
                {"status": analysis_material_status, "reason": "; ".join(analysis_reasons)}
            ),
            "tool": {"name": detected_tool, "configuration": {"transport": "stdio"}},
            "environment": {"os_policy": "Linux", "package_manager": candidate.get("dependency_ecosystem"), "source_commit": candidate.get("source_commit")},
            "external_boundary": {"kind": "unspecified-local-boundary", "initial_state": "requires-explicit-freeze"},
            "runner": {"repetitions": 3, "timeout_seconds": 120, "counterfactual_input_mode": "env-json/v1", "evidence_contract": {"required_levels": ["L0_RAW_MCP_RESULT", "L1_NORMALIZED_TOOL_RESULT", "L2_HOST_PROCESSED_TOOL_RESULT", "L3_SESSION_TOOL_RESULT", "L4_MODEL_VISIBLE_OBSERVATION"], "record_file": "blind_evidence.jsonl", "actual_next_model_request": True}, **host_runner},
            "server_runner": server_runner,
            "onboarding": {"candidate_pool_id": candidate_id, "candidate_evidence": candidate_result.get("evidence"), "source_evidence": str(_pool_file(root, "module_source_evidence.jsonl").relative_to(root)) if origin == "DIRECT_RUNTIME_DEPENDENCY" else "explicit component source evidence", "dependency_evidence": dependency_evidence, "tool_path_discovery": tool_path_discovery, "component_origin": origin, "analysis_material": {"status": analysis_material_status, "inventory": analysis_inventory, "patch_origin": analysis_patch_origin, "reasons": analysis_reasons}},
        }
        if legacy_direct_input and origin == "DIRECT_RUNTIME_DEPENDENCY":
            # Read compatibility for existing callers/tests; explicit new
            # onboarding emits only the unified component object.
            case["direct_runtime_dependency"] = {
                "dependency_name": candidate.get("dependency_name"),
                "dependency_purl": candidate.get("dependency_purl"),
                "dependency_depth": candidate.get("dependency_depth"),
                "dependency_scope": candidate.get("dependency_scope"),
                "vulnerable_version": candidate.get("resolved_version"),
                "fixed_version": candidate.get("fixed_version_or_commit"),
                "relation_status": candidate.get("status"),
            }
        case["case_hash"] = _digest(case)
        (output / "blind_case.json").write_text(json.dumps(case, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        report["status"] = "PREPARED_AWAITING_CONTAINER"
        report["case_id"] = case_id
        report["case_file"] = str((output / "blind_case.json").resolve())
        report["case_digest"] = case["case_hash"]
        report["unresolved_reason"] = "paired container images and external boundary are not yet frozen"
        report["suggested_machine_action"] = "assemble-linux-case with pinned base image, then verify image digests and boundary"
    (output / "preparation_report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return report


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Prepare a label-free OSCAR case")
    parser.add_argument("--root", type=Path, default=RESEARCH_ROOT)
    parser.add_argument("--advisory", required=True)
    parser.add_argument("--package", required=True)
    parser.add_argument("--vulnerable-version", required=True)
    parser.add_argument("--fixed-version", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-root", type=Path)
    parser.add_argument("--vulnerable-source-root", type=Path)
    parser.add_argument("--fixed-source-root", type=Path)
    parser.add_argument("--vulnerable-dependency-source-root", type=Path)
    parser.add_argument("--fixed-dependency-source-root", type=Path)
    parser.add_argument("--dependency-patch", type=Path)
    parser.add_argument("--tool")
    parser.add_argument("--component-origin", choices=sorted(COMPONENT_ORIGINS))
    parser.add_argument("--component-repository")
    parser.add_argument("--component-purl")
    parser.add_argument("--component-entrypoint")
    parser.add_argument("--component-source-evidence")
    parser.add_argument("--component-patch-evidence")
    parser.add_argument("--component-advisory-evidence")
    parser.add_argument("--experiment-type", default="SENSITIVE_INFORMATION_DISCLOSURE")
    args = parser.parse_args()

    def parse_evidence(raw: str | None) -> Any:
        if raw is None:
            return None
        value = Path(raw[1:]).read_text(encoding="utf-8") if raw.startswith("@") else raw
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            parsed = value
        errors = validate_label_free_evidence(parsed, field="stage0_component_evidence")
        if errors:
            raise ValueError("component evidence is not label-free: " + "; ".join(errors))
        return parsed

    try:
        parsed_source_evidence = parse_evidence(args.component_source_evidence)
        parsed_patch_evidence = parse_evidence(args.component_patch_evidence)
        parsed_advisory_evidence = parse_evidence(args.component_advisory_evidence)
        report = prepare_case(
            args.root.resolve(), args.advisory, args.package, args.vulnerable_version,
            args.fixed_version, args.repository, args.output.resolve(),
            vulnerable_source_root=args.vulnerable_source_root,
            fixed_source_root=args.fixed_source_root,
            vulnerable_dependency_source_root=args.vulnerable_dependency_source_root,
            fixed_dependency_source_root=args.fixed_dependency_source_root,
            dependency_patch=args.dependency_patch,
            source_root=args.source_root, tool=args.tool, experiment_type=args.experiment_type,
            component_origin=args.component_origin, component_repository=args.component_repository,
            component_purl=args.component_purl, component_entrypoint=args.component_entrypoint,
            component_source_evidence=parsed_source_evidence,
            component_patch_evidence=parsed_patch_evidence,
            component_advisory_evidence=parsed_advisory_evidence,
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        report = preparation_required_report(
            args.output.resolve(),
            f"Stage 0 input could not be validated: {type(exc).__name__}",
            input_data={
                "advisory": args.advisory,
                "package": args.package,
                "component_origin": args.component_origin or "DIRECT_RUNTIME_DEPENDENCY",
            },
        )
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report.get("status") in {"READY", "PREPARED_AWAITING_CONTAINER"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
