"""Main MCP server for multi-repository management."""

import json
import os
import sys
import re
import difflib
import subprocess
from pathlib import Path
from typing import Any, Optional
import asyncio
import uuid
from datetime import datetime, timezone

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import (
    Tool,
    TextContent,
    ImageContent,
)

from .workspace_manager import WorkspaceManager, Workspace
from .git_manager import GitManager
from .searcher import RepoSearcher
from .url_parser import normalize_repo_list
from .code_reviewer import CodeReviewer
from .linear_client import LinearClient
from .workspace_ai import ensure_workspace_ai_files
from .workflow_manager import WorkflowManager
from . import analysis_tools, resource_tools, subagent_tools, workflow_tools


class MultiRepoServer:
    """MCP Server for managing multiple repositories."""

    def __init__(self):
        self.server = Server("multi-repo-mcp")
        self.workspace_manager: Optional[WorkspaceManager] = None
        self.workflow_manager: Optional[WorkflowManager] = None
        self.git_manager: Optional[GitManager] = None
        self.searcher: Optional[RepoSearcher] = None
        # Background clone jobs to avoid MCP request timeouts for long-running operations
        self._clone_jobs: dict[str, dict[str, Any]] = {}
        self.config = self._load_config()
        self._initialize()
        self._setup_handlers()

    def _new_job_id(self) -> str:
        """Create a short job id for tracking background operations."""
        return uuid.uuid4().hex[:10]

    def _job_summary(self, job: dict[str, Any]) -> str:
        """Format a concise summary line for a clone job."""
        status = job.get("status", "unknown")
        done = job.get("completed", 0)
        total = job.get("total", 0)
        ok = job.get("success", 0)
        fail = job.get("failed", 0)
        ws = job.get("workspace_name")
        post_clone = job.get("post_clone") or {}
        ready = (
            " ready"
            if post_clone
            and status in {"completed", "completed_with_errors"}
            and not post_clone.get("error")
            and not (post_clone.get("generated") or {}).get("error")
            else ""
        )
        return f"{job.get('job_id')} [{status}{ready}] {ws}: {done}/{total} (ok={ok}, fail={fail})"

    @staticmethod
    def _bool_arg(args: dict, key: str, default: bool = False) -> bool:
        """Treat omitted/null boolean args as their semantic default."""
        value = (args or {}).get(key)
        if value is None:
            return default
        return bool(value)

    def _workflow_bootstrap_args(self, args: dict) -> dict[str, Any]:
        """Extract optional post-clone workflow bootstrap arguments."""
        objective = ((args or {}).get("objective") or "").strip()
        if not objective:
            return {}
        metadata = (args or {}).get("metadata")
        if not isinstance(metadata, dict):
            metadata = {}
        return {
            "objective": objective,
            "workflow_type": (args or {}).get("workflow_type") or "general",
            "metadata": metadata,
            "issue_id": (args or {}).get("issue_id"),
            "query": (args or {}).get("query"),
            "auto_continue": self._bool_arg(args, "auto_continue", True),
            "stop_after": (args or {}).get("stop_after"),
            "context_chars": int((args or {}).get("context_chars", 4000) or 4000),
            "limit": int((args or {}).get("limit", 8) or 8),
            "include_build_commands": self._bool_arg(args, "include_build_commands", True),
        }

    def _clone_async_mode(self, args: dict) -> bool:
        """Default clone operations to background jobs to avoid MCP client timeouts."""
        return self._bool_arg(args, "async_mode", True)

    async def _finalize_workspace_after_clone(
        self,
        workspace_name: str,
        *,
        bootstrap: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """Refresh workspace RAG artifacts and optionally bootstrap a workflow/searcher."""
        workspace = self.workspace_manager.get_workspace(workspace_name)
        if not workspace:
            return {"error": f"Workspace '{workspace_name}' not found after clone"}

        self._ensure_build_command_file(workspace)
        generated = self._ensure_workspace_ai_artifacts(workspace)
        result: dict[str, Any] = {"generated": generated}

        if bootstrap and bootstrap.get("objective"):
            workflow_args = {"workspace_name": workspace_name, **bootstrap}
            workflow_payload = await workflow_tools.start_workflow(self, workflow_args)
            if isinstance(workflow_payload, list):
                result["workflow_bootstrap"] = {
                    "error": workflow_payload[0].text if workflow_payload else "Workflow bootstrap failed"
                }
            else:
                result["workflow_bootstrap"] = workflow_payload
        return result

    def _format_post_clone_summary(self, post_clone: Optional[dict[str, Any]]) -> str:
        """Human-readable summary for post-clone refresh/workflow bootstrap."""
        if not post_clone:
            return ""
        lines: list[str] = []
        if post_clone.get("error"):
            lines.append(f"Post-clone finalization error: {post_clone['error']}")
        generated = post_clone.get("generated") or {}
        refresh = generated.get("refresh") or {}
        if generated.get("error"):
            lines.append(f"Context refresh error: {generated['error']}")
        elif refresh:
            lines.append(
                "Context refreshed: "
                f"{refresh.get('mode', 'delta')} "
                f"(indexed={refresh.get('repo_count', 0)}, "
                f"changed={len(refresh.get('changed_repos') or [])}, "
                f"missing={len(refresh.get('missing_repos') or [])})"
            )
        bootstrap = post_clone.get("workflow_bootstrap") or {}
        if bootstrap.get("error"):
            lines.append(f"Workflow bootstrap error: {bootstrap['error']}")
        elif bootstrap:
            workflow = bootstrap.get("workflow") or {}
            if workflow.get("workflow_id"):
                lines.append(f"Workflow bootstrapped: {workflow['workflow_id']} ({workflow.get('stage')})")
            auto_roles = [item.get("role") for item in (bootstrap.get("auto_subagents") or []) if item.get("role")]
            if auto_roles:
                lines.append("Auto subagents run: " + ", ".join(auto_roles))
        return "\n".join(lines)

    def _workflow_id_from_post_clone(self, post_clone: Optional[dict[str, Any]]) -> Optional[str]:
        bootstrap = (post_clone or {}).get("workflow_bootstrap") or {}
        workflow = bootstrap.get("workflow") or {}
        return workflow.get("workflow_id")

    def _default_storage_path(self) -> str:
        """Choose a default writable storage path outside the repo checkout."""
        candidates = []
        if sys.platform == "win32":
            candidates.extend(
                [
                    Path("D:/your-workspaces"),
                    Path("D:/workspaces"),
                    Path("C:/Workspaces"),
                    Path("C:/workspaces"),
                ]
            )
        candidates.extend(
            [
                Path.home() / "Workspaces",
                Path.home() / "workspaces",
                Path.home() / ".multi-repo-mcp",
            ]
        )
        for candidate in candidates:
            if candidate.exists():
                return str(candidate)
        return str(candidates[-1])

    def _user_config_path(self) -> Path:
        """Return the per-user override config path."""
        return Path.home() / ".multi-repo-mcp" / "config.json"

    def _merge_config(self, base: dict, override: dict) -> dict:
        """Recursively merge configuration dictionaries."""
        merged = dict(base)
        for key, value in (override or {}).items():
            if isinstance(value, dict) and isinstance(merged.get(key), dict):
                merged[key] = self._merge_config(merged[key], value)
            else:
                merged[key] = value
        return merged

    def _load_config(self) -> dict:
        """Load configuration from default config file."""
        config_path = Path(__file__).parent.parent.parent / "config" / "default_config.json"

        if config_path.exists():
            with open(config_path, "r", encoding="utf-8") as f:
                config = json.load(f)
        else:
            config = {}

        user_config_path = self._user_config_path()
        if user_config_path.exists():
            try:
                with open(user_config_path, "r", encoding="utf-8") as f:
                    user_config = json.load(f)
                config = self._merge_config(config, user_config)
            except Exception as e:
                print(f"Warning: failed to read user config '{user_config_path}': {e}", file=sys.stderr)

        env_storage = (
            os.getenv("MCP_WORKSPACE_ROOT")
            or os.getenv("MULTI_REPO_WORKSPACE_ROOT")
            or os.getenv("MCP_BASE_DIR")
            or os.getenv("MCP_STORAGE_PATH")
            or os.getenv("MCP_WORKSPACES_ROOT")
        )
        workspace_root = (
            env_storage
            or config.get("workspace_root")
            or config.get("storage_path")
            or self._default_storage_path()
        )
        config["workspace_root"] = workspace_root
        config["storage_path"] = workspace_root

        if not config.get("github_orgs") and config.get("github_org"):
            config["github_orgs"] = [config["github_org"]]

        env_github_token = (
            os.getenv("MULTI_REPO_GITHUB_TOKEN")
            or os.getenv("MCP_GITHUB_TOKEN")
            or os.getenv("GITHUB_TOKEN")
        )
        if env_github_token:
            config["github_token"] = env_github_token

        env_linear_key = (
            os.getenv("MULTI_REPO_LINEAR_API_KEY")
            or os.getenv("MCP_LINEAR_API_KEY")
            or os.getenv("LINEAR_API_KEY")
        )
        if env_linear_key:
            config["linear_api_key"] = env_linear_key

        code_review = config.get("code_review")
        if isinstance(code_review, dict):
            env_openai_key = (
                os.getenv("CODE_REVIEW_OPENAI_API_KEY")
                or os.getenv("OPENAI_API_KEY")
            )
            if env_openai_key:
                code_review["openai_api_key"] = env_openai_key
        
        return config

    def _effective_base_dir(self, args: dict) -> Optional[str]:
        """Resolve an effective base directory for workspace operations.

        Precedence:
          1) explicit tool argument: workspace_root
          2) explicit tool argument: base_dir
          3) environment variables: MCP_WORKSPACE_ROOT / MCP_BASE_DIR / MCP_STORAGE_PATH / MCP_WORKSPACES_ROOT
          4) explicit tool argument: storage_path (legacy)
          5) configured workspace_root / storage_path
        """
        if args.get("workspace_root"):
            return args.get("workspace_root")
        if args.get("base_dir"):
            return args.get("base_dir")
        env_storage = (
            os.getenv("MCP_WORKSPACE_ROOT")
            or os.getenv("MULTI_REPO_WORKSPACE_ROOT")
            or os.getenv("MCP_BASE_DIR")
            or os.getenv("MCP_STORAGE_PATH")
            or os.getenv("MCP_WORKSPACES_ROOT")
        )
        if env_storage:
            return env_storage
        if args.get("storage_path"):
            return args.get("storage_path")
        return self.config.get("workspace_root") or self.config.get("storage_path")

    def _initialize(self):
        """Initialize managers."""
        if self.config.get("auto_set_git_longpaths", False):
            self._set_git_longpaths()

        storage_path = Path(self.config['workspace_root'])
        storage_path.mkdir(parents=True, exist_ok=True)

        self.workspace_manager = WorkspaceManager(storage_path)
        self.workflow_manager = WorkflowManager(self.workspace_manager.workspaces_dir)
        self.git_manager = GitManager(
            ssh_key_path=self.config.get('ssh_key_path'),
            github_token=self.config.get('github_token'),
            token_injection_hosts=self.config.get('token_injection_hosts'),
            github_orgs=self.config.get('github_orgs'),
            log_ascii=self.config.get('log_ascii', False),
            git_clone_mode=self.config.get('git_clone_mode')
        )
        self.searcher = RepoSearcher(self.config.get('default_excludes', []))
        self.linear_client: Optional[LinearClient] = None
        if self.config.get("linear_api_key"):
            self.linear_client = LinearClient(self.config.get("linear_api_key"))
        
        # Initialize code reviewer if enabled
        self.code_reviewer: Optional[CodeReviewer] = None
        if self.config.get('code_review', {}).get('enabled'):
            try:
                api_key = self.config.get('code_review', {}).get('openai_api_key')
                model = self.config.get('code_review', {}).get('model', 'gpt-4')
                self.code_reviewer = CodeReviewer(api_key=api_key, model=model)
            except Exception as e:
                print(f"⚠️  Code reviewer initialization failed: {e}", file=sys.stderr)

    def _set_git_longpaths(self) -> None:
        """Enable Git long paths globally if configured."""
        try:
            subprocess.run(
                ["git", "config", "--global", "core.longpaths", "true"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
        except Exception:
            pass

    def _is_long_paths_enabled(self) -> Optional[bool]:
        """Check Windows long path support from registry."""
        if sys.platform != "win32":
            return None
        try:
            import winreg
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\\CurrentControlSet\\Control\\FileSystem"
            ) as key:
                value, _ = winreg.QueryValueEx(key, "LongPathsEnabled")
                return bool(value)
        except Exception:
            return None

    def _maybe_use_short_path(self, storage_path: Optional[str]) -> Optional[str]:
        """Switch to short_path_root when long paths are disabled."""
        if storage_path:
            return None
        short_root = self.config.get("short_path_root")
        if not short_root:
            return None
        enabled = self._is_long_paths_enabled()
        if enabled is False:
            err = self._set_storage_path(short_root)
            if err:
                return f"WARN: Failed to use short_path_root: {err}"
            return f"INFO: Using short_path_root: {short_root}"
        return None

    def _set_storage_path(self, storage_path: str) -> Optional[str]:
        """Switch storage path for workspaces."""
        if not storage_path:
            return "storage_path must be provided"

        try:
            path = Path(storage_path).expanduser()
            path.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            return f"Failed to use storage_path '{storage_path}': {str(e)}"

        self.config["workspace_root"] = str(path)
        self.config["storage_path"] = str(path)
        self.workspace_manager = WorkspaceManager(path)
        self.workflow_manager = WorkflowManager(self.workspace_manager.workspaces_dir)
        return None

    def _persist_user_workspace_root(self, workspace_root: str) -> Optional[str]:
        """Persist workspace root override into the per-user config file."""
        try:
            user_config_path = self._user_config_path()
            user_config_path.parent.mkdir(parents=True, exist_ok=True)
            current = {}
            if user_config_path.exists():
                current = json.loads(user_config_path.read_text(encoding="utf-8"))
            current["workspace_root"] = workspace_root
            current["storage_path"] = workspace_root
            user_config_path.write_text(json.dumps(current, indent=2), encoding="utf-8")
            return None
        except Exception as e:
            return f"Failed to persist workspace_root '{workspace_root}': {str(e)}"

    async def _run_subprocess(
        self,
        cmd: list[str] | str,
        cwd: Optional[str] = None,
        timeout: Optional[int] = None,
        env: Optional[dict] = None,
        shell: bool = False,
    ) -> subprocess.CompletedProcess:
        """Run a subprocess in a thread to avoid asyncio CreateProcess issues on Windows."""

        def runner():
            return subprocess.run(
                cmd,
                cwd=cwd,
                timeout=timeout,
                env=env,
                shell=shell,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

        return await asyncio.to_thread(runner)

    def _setup_handlers(self):
        """Setup MCP tool handlers."""
        
        @self.server.list_tools()
        async def list_tools() -> list[Tool]:
            """List available tools."""
            return [
                Tool(
                    name="ensure_workspace",
                    description="Ensure a workspace is ready for a workflow: activate it if it exists, or create it if repositories are provided.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "workspace_name": {
                                "type": "string",
                                "description": "Workspace name to activate or create (optional; uses active workspace if omitted)"
                            },
                            "repos": {
                                "type": "array",
                                "description": "Repositories to create the workspace with if it does not already exist",
                                "items": {"type": "string"}
                            },
                            "storage_path": {
                                "type": "string",
                                "description": "Optional base path for workspaces"
                            },
                            "workspace_root": {
                                "type": "string",
                                "description": "Optional workspace root folder. Preferred over legacy storage_path."
                            },
                            "base_dir": {
                                "type": "string",
                                "description": "Optional base directory to create or locate the workspace under"
                            },
                            "async_mode": {
                                "type": "boolean",
                                "description": "Clone in the background when creating a new workspace. Defaults to true to avoid MCP client timeouts; pass false only for small/local repos.",
                                "default": True
                            },
                            "max_concurrent": {
                                "type": "integer",
                                "description": "Max concurrent clones when creating a new workspace (default: 3)",
                                "default": 3
                            },
                            "skip_preflight": {
                                "type": "boolean",
                                "description": "Skip preflight checks during workspace creation",
                                "default": False
                            },
                            "objective": {
                                "type": "string",
                                "description": "Optional task objective; when provided, start a workflow after the workspace is ready and auto-prepare context/searcher."
                            },
                            "workflow_type": {
                                "type": "string",
                                "description": "Workflow type label for optional objective bootstrap",
                                "default": "general"
                            },
                            "metadata": {
                                "type": "object",
                                "description": "Optional workflow metadata for objective bootstrap"
                            },
                            "issue_id": {
                                "type": "string",
                                "description": "Optional Linear issue identifier for objective bootstrap"
                            },
                            "query": {
                                "type": "string",
                                "description": "Optional RAG/search query for initial context bundle"
                            },
                            "auto_continue": {
                                "type": "boolean",
                                "description": "When objective is provided, continue through context preparation/searcher automatically",
                                "default": True
                            }
                        }
                    }
                ),
                Tool(
                    name="get_active_workspace",
                    description="Return structured details for the active workspace, including key artifact paths.",
                    inputSchema={
                        "type": "object",
                        "properties": {}
                    }
                ),
                Tool(
                    name="set_workspace_root",
                    description="Set the workspace root folder used for future workspace creation, optionally persisting it to user config outside the repo.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "workspace_root": {
                                "type": "string",
                                "description": "Absolute or user-relative path to the folder that should contain the workspaces directory"
                            },
                            "persist": {
                                "type": "boolean",
                                "description": "Persist this setting to ~/.multi-repo-mcp/config.json so future server starts reuse it",
                                "default": True
                            }
                        },
                        "required": ["workspace_root"]
                    }
                ),
                Tool(
                    name="start_workflow",
                    description="Create a persisted workflow session for a task in the active or specified workspace. Linear/ticket workflows can continue automatically through context prep and ticket analysis.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "workspace_name": {
                                "type": "string",
                                "description": "Workspace name (optional; uses active workspace if omitted)"
                            },
                            "objective": {
                                "type": "string",
                                "description": "What this workflow is trying to accomplish"
                            },
                            "workflow_type": {
                                "type": "string",
                                "description": "Workflow type label (default: general)",
                                "default": "general"
                            },
                            "metadata": {
                                "type": "object",
                                "description": "Optional metadata to persist with the workflow"
                            },
                            "issue_id": {
                                "type": "string",
                                "description": "Optional Linear issue identifier to attach for auto-continued ticket workflows"
                            },
                            "query": {
                                "type": "string",
                                "description": "Optional query to seed the initial context bundle"
                            },
                            "auto_continue": {
                                "type": "boolean",
                                "description": "Continue automatically after workflow creation through context prep and, for ticket workflows, through ticket analysis",
                                "default": True
                            },
                            "stop_after": {
                                "type": "string",
                                "description": "Optional stop point for auto-continued workflows: workspace_ready, context, or ticket_context"
                            },
                            "context_chars": {
                                "type": "integer",
                                "description": "Maximum characters to include from digest/context artifacts when auto-preparing context",
                                "default": 4000
                            },
                            "limit": {
                                "type": "integer",
                                "description": "Maximum locate/retrieval hits to keep in the auto-prepared context bundle",
                                "default": 8
                            },
                            "include_build_commands": {
                                "type": "boolean",
                                "description": "Include build command summaries in the auto-prepared context bundle",
                                "default": True
                            }
                        },
                        "required": ["objective"]
                    }
                ),
                Tool(
                    name="get_workflow_status",
                    description="Read the current state of a persisted workflow session.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "workflow_id": {
                                "type": "string",
                                "description": "Workflow identifier"
                            },
                            "workspace_name": {
                                "type": "string",
                                "description": "Workspace name (optional if the workflow id is globally unique)"
                            }
                        },
                        "required": ["workflow_id"]
                    }
                ),
                Tool(
                    name="prepare_context_bundle",
                    description="Build a compact context bundle for a workflow from workspace artifacts instead of re-reading large text blobs.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "workflow_id": {
                                "type": "string",
                                "description": "Workflow identifier (optional but recommended)"
                            },
                            "workspace_name": {
                                "type": "string",
                                "description": "Workspace name (optional; uses workflow workspace or active workspace)"
                            },
                            "query": {
                                "type": "string",
                                "description": "Optional query used to pre-compute locate hits"
                            },
                            "context_chars": {
                                "type": "integer",
                                "description": "Maximum characters of context.md to include (default: 4000)",
                                "default": 4000
                            },
                            "limit": {
                                "type": "integer",
                                "description": "Maximum locate hits to include (default: 8)",
                                "default": 8
                            },
                            "include_build_commands": {
                                "type": "boolean",
                                "description": "Include summarized build commands in the bundle",
                                "default": True
                            }
                        }
                    }
                ),
                Tool(
                    name="prepare_subagent_packet",
                    description="Build a focused subagent packet from workflow artifacts so research or analysis can happen outside the main context window.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "workflow_id": {
                                "type": "string",
                                "description": "Workflow identifier"
                            },
                            "workspace_name": {
                                "type": "string",
                                "description": "Workspace name (optional if workflow_id is globally unique)"
                            },
                            "role": {
                                "type": "string",
                                "description": "Subagent role such as searcher, trace, fix_plan, verifier, or reviewer"
                            },
                            "query": {
                                "type": "string",
                                "description": "Optional focused query for this subagent task"
                            },
                            "context_chars": {
                                "type": "integer",
                                "description": "Maximum digest/context characters if the workflow bundle must be refreshed",
                                "default": 4000
                            },
                            "limit": {
                                "type": "integer",
                                "description": "Maximum retrieval/locate hits to include if the workflow bundle must be refreshed",
                                "default": 8
                            },
                            "include_build_commands": {
                                "type": "boolean",
                                "description": "Include build command summaries in the packet",
                                "default": True
                            },
                            "force_refresh": {
                                "type": "boolean",
                                "description": "Rebuild the workflow context bundle before preparing the packet",
                                "default": False
                            }
                        },
                        "required": ["workflow_id", "role"]
                    }
                ),
                Tool(
                    name="run_subagent",
                    description="Run a focused server-side subagent over the workflow packet and persist its structured advisory result.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "workflow_id": {
                                "type": "string",
                                "description": "Workflow identifier"
                            },
                            "workspace_name": {
                                "type": "string",
                                "description": "Workspace name (optional if workflow_id is globally unique)"
                            },
                            "role": {
                                "type": "string",
                                "description": "Subagent role such as searcher, trace, fix_plan, verifier, or reviewer"
                            },
                            "query": {
                                "type": "string",
                                "description": "Optional focused query for this subagent task"
                            },
                            "persist_result": {
                                "type": "boolean",
                                "description": "Persist the generated result into workflow artifacts",
                                "default": True
                            },
                            "context_chars": {
                                "type": "integer",
                                "description": "Maximum digest/context characters if the workflow bundle must be refreshed",
                                "default": 4000
                            },
                            "limit": {
                                "type": "integer",
                                "description": "Maximum retrieval/locate hits to include if the workflow bundle must be refreshed",
                                "default": 8
                            },
                            "include_build_commands": {
                                "type": "boolean",
                                "description": "Include build command summaries in the packet",
                                "default": True
                            },
                            "force_refresh": {
                                "type": "boolean",
                                "description": "Rebuild the workflow context bundle before running the subagent",
                                "default": False
                            }
                        },
                        "required": ["workflow_id", "role"]
                    }
                ),
                Tool(
                    name="store_subagent_result",
                    description="Persist a structured subagent result into workflow artifacts for later merge by the leader workflow.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "workflow_id": {
                                "type": "string",
                                "description": "Workflow identifier"
                            },
                            "workspace_name": {
                                "type": "string",
                                "description": "Workspace name (optional if workflow_id is globally unique)"
                            },
                            "role": {
                                "type": "string",
                                "description": "Subagent role that produced this result"
                            },
                            "status": {
                                "type": "string",
                                "description": "Subagent result status (default: completed)",
                                "default": "completed"
                            },
                            "summary": {
                                "type": "string",
                                "description": "Short summary of what the subagent concluded"
                            },
                            "result": {
                                "description": "Structured subagent output to persist"
                            }
                        },
                        "required": ["workflow_id", "role", "result"]
                    }
                ),
                Tool(
                    name="merge_subagent_results",
                    description="Return the currently saved subagent results for a workflow so the leader can merge them.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "workflow_id": {
                                "type": "string",
                                "description": "Workflow identifier"
                            },
                            "workspace_name": {
                                "type": "string",
                                "description": "Workspace name (optional if workflow_id is globally unique)"
                            }
                        },
                        "required": ["workflow_id"]
                    }
                ),
                Tool(
                    name="locate_candidates",
                    description="Use the workspace index to store a focused candidate file list for a workflow query.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "workflow_id": {
                                "type": "string",
                                "description": "Workflow identifier (optional but recommended)"
                            },
                            "workspace_name": {
                                "type": "string",
                                "description": "Workspace name (optional; uses workflow workspace or active workspace)"
                            },
                            "query": {
                                "type": "string",
                                "description": "What to locate"
                            },
                            "limit": {
                                "type": "integer",
                                "description": "Maximum candidates to keep (default: 8)",
                                "default": 8
                            }
                        },
                        "required": ["query"]
                    }
                ),
                Tool(
                    name="build_verification_plan",
                    description="Create a minimal per-repo verification plan from build_command.json and indexed run hints.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "workflow_id": {
                                "type": "string",
                                "description": "Workflow identifier (optional but recommended)"
                            },
                            "workspace_name": {
                                "type": "string",
                                "description": "Workspace name (optional; uses workflow workspace or active workspace)"
                            },
                            "repo_names": {
                                "type": "array",
                                "description": "Optional subset of repositories to plan for",
                                "items": {"type": "string"}
                            },
                            "mode": {
                                "type": "string",
                                "description": "Plan mode: minimal selects one best command, full keeps the top few commands",
                                "enum": ["minimal", "full"],
                                "default": "minimal"
                            }
                        }
                    }
                ),
                Tool(
                    name="get_clone_job_status",
                    description="Get status of background clone jobs. Completed jobs include context refresh/workflow bootstrap status, so workspace_info is usually unnecessary.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "job_id": {
                                "type": "string",
                                "description": "Job id returned by setup_workspace/add_repos_to_workspace (optional; if omitted, lists all jobs)."
                            },
                            "tail": {
                                "type": "integer",
                                "description": "How many recent log lines to show when logs are included (default: 12)",
                                "default": 12
                            },
                            "include_logs": {
                                "type": "boolean",
                                "description": "Include recent clone logs. Defaults to true while running/failing and false after a successful ready state.",
                                "default": False
                            }
                        }
                    }
                ),
                Tool(
                    name="analyze_ticket",
                    description="Fetch a Linear ticket, search across repos, and provide root-cause analysis and fix options. Can optionally attach the result to a workflow session.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "workflow_id": {
                                "type": "string",
                                "description": "Workflow identifier (optional; persists ticket analysis into the workflow session)"
                            },
                            "workspace_name": {
                                "type": "string",
                                "description": "Workspace name (optional; uses workflow workspace or active workspace)"
                            },
                            "issue_id": {
                                "type": "string",
                                "description": "Linear issue UUID or identifier (e.g., ENG-123)"
                            },
                            "repo_names": {
                                "type": "array",
                                "description": "Optional list of repository names to search",
                                "items": {"type": "string"}
                            },
                            "file_pattern": {
                                "type": "string",
                                "description": "Optional file pattern filter (e.g., '*.java', '*.py')"
                            },
                            "max_matches": {
                                "type": "integer",
                                "description": "Maximum matches to consider (default: 50)",
                                "default": 50
                            }
                        },
                        "required": ["issue_id"]
                    }
                ),
                Tool(
                    name="verify_repos",
                    description="Build/test repositories using per-workspace build_command.json and return structured execution results.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "workspace_name": {
                                "type": "string",
                                "description": "Workspace name (optional, uses active workspace if not specified)"
                            },
                            "repo_names": {
                                "type": "array",
                                "description": "Optional list of repository names to verify",
                                "items": {"type": "string"}
                            },
                            "timeout": {
                                "type": "integer",
                                "description": "Timeout in seconds for each command (default: 600)",
                                "default": 600
                            }
                        }
                    }
                ),
                Tool(
                    name="set_build_commands",
                    description="Update build_command.json with per-repo build/test commands.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "workspace_name": {
                                "type": "string",
                                "description": "Workspace name (optional, uses active workspace if not specified)"
                            },
                            "commands": {
                                "type": "object",
                                "description": "Map of repo name to list of commands",
                                "additionalProperties": {
                                    "type": "array",
                                    "items": {"type": "string"}
                                }
                            }
                        },
                        "required": ["commands"]
                    }
                ),
                Tool(
                    name="apply_fix",
                    description="Apply code changes to a repository. Returns a diff and asks for user review.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "repo_name": {
                                "type": "string",
                                "description": "Repository name"
                            },
                            "changes": {
                                "type": "array",
                                "description": "List of file changes with full content",
                                "items": {
                                    "type": "object",
                                    "properties": {
                                        "file_path": {
                                            "type": "string",
                                            "description": "Path to file relative to repository root"
                                        },
                                        "content": {
                                            "type": "string",
                                            "description": "New full file content"
                                        }
                                    },
                                    "required": ["file_path", "content"]
                                }
                            },
                            "apply": {
                                "type": "boolean",
                                "description": "Whether to write changes to disk (default: true). Set false for diff-only.",
                                "default": True
                            },
                            "workflow_id": {
                                "type": "string",
                                "description": "Optional workflow identifier to persist change, context refresh, and review-request artifacts."
                            }
                        },
                        "required": ["repo_name", "changes"]
                    }
                ),
                Tool(
                    name="preflight_check",
                    description="Run environment preflight checks (storage path write, git, command execution, long paths).",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "storage_path": {
                                "type": "string",
                                "description": "Optional base path for workspaces. Defaults to configured storage_path."
                            },
                            "workspace_root": {
                                "type": "string",
                                "description": "Optional workspace root folder. Preferred over legacy storage_path."
                            },
                            "test_git_clone": {
                                "type": "boolean",
                                "description": "Clone a public repo to verify git clone works (default: true).",
                                "default": True
                            },
                            "test_command_exec": {
                                "type": "boolean",
                                "description": "Run a simple shell command to verify execution (default: true).",
                                "default": True
                            },
                            "test_long_paths": {
                                "type": "boolean",
                                "description": "Test long path creation on Windows (default: true).",
                                "default": True
                            }
                        }
                    }
                ),
                Tool(
                    name="setup_workspace",
                    description="Create a new workspace and clone repositories. Supports multiple input formats: full URLs (https://github.com/org/repo.git), SSH URLs (git@github.com:org/repo.git), org/repo format (example-org/example-repo), or just repo name (example-repo) if default org is configured.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "repos": {
                                "type": "array",
                                "description": "List of repositories in any supported format: full URL, SSH URL, 'org/repo', or 'repo-name'",
                                "items": {"type": "string"}
                            },
                            "name": {
                                "type": "string",
                                "description": "Workspace name (optional, will auto-generate if not provided)"
                            },
                            "storage_path": {
                                "type": "string",
                                "description": "Optional legacy base path for workspaces."
                            },
                            "workspace_root": {
                                "type": "string",
                                "description": "Optional workspace root folder. Preferred over legacy storage_path."
                            },
                            "base_dir": {
                                "type": "string",
                                "description": "Optional base directory to create the workspace under (e.g., the folder you have open in VS Code). Overrides storage_path if provided."
                            },
                            "async_mode": {
                                "type": "boolean",
                                "description": "Start cloning in the background and return a job id immediately. Defaults to true to avoid MCP request timeouts; pass false only for small/local repos.",
                                "default": True
                            },
                            "max_concurrent": {
                                "type": "integer",
                                "description": "Max concurrent clones (default: 3).",
                                "default": 3
                            },
                            "skip_preflight": {
                                "type": "boolean",
                                "description": "Skip preflight checks (faster). Default false.",
                                "default": False
                            },
                            "objective": {
                                "type": "string",
                                "description": "Optional task objective; when provided, start a workflow after clone completes and auto-prepare context/searcher."
                            },
                            "query": {
                                "type": "string",
                                "description": "Optional RAG/search query for initial context bundle"
                            },
                            "auto_continue": {
                                "type": "boolean",
                                "description": "When objective is provided, continue through context preparation/searcher automatically",
                                "default": True
                            }
                        },
                        "required": ["repos"]
                    }
                ),
                Tool(
                    name="add_repos_to_workspace",
                    description="Add new repositories to an existing workspace. Skips repos that already exist.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "workspace_name": {
                                "type": "string",
                                "description": "Name of existing workspace to add repos to"
                            },
                            "repos": {
                                "type": "array",
                                "description": "List of repositories in any supported format: full URL, SSH URL, 'org/repo', or 'repo-name'",
                                "items": {"type": "string"}
                            },
                            "base_dir": {
                                "type": "string",
                                "description": "Optional base directory where the workspace is located (e.g., the folder you have open in VS Code). If provided, the server will switch storage_path to this directory before locating the workspace."
                            },
                            "workspace_root": {
                                "type": "string",
                                "description": "Optional workspace root folder. Preferred over legacy base_dir/storage_path."
                            },

                            "async_mode": {
                                "type": "boolean",
                                "description": "Start cloning in the background and return a job id immediately. Defaults to true to avoid MCP request timeouts; pass false only for small/local repos.",
                                "default": True
                            },
                            "max_concurrent": {
                                "type": "integer",
                                "description": "Max concurrent clones (default: 3).",
                                "default": 3
                            },
                            "objective": {
                                "type": "string",
                                "description": "Optional task objective; when provided, start a workflow after added repos finish cloning and auto-prepare context/searcher."
                            },
                            "query": {
                                "type": "string",
                                "description": "Optional RAG/search query for initial context bundle"
                            },
                            "auto_continue": {
                                "type": "boolean",
                                "description": "When objective is provided, continue through context preparation/searcher automatically",
                                "default": True
                            }
                        },
                        "required": ["workspace_name", "repos"]
                    }
                ),
                Tool(
                    name="remove_repo_from_workspace",
                    description="Remove a repository from a workspace. Deletes repository files by default to prevent conflicts when re-cloning.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "workspace_name": {
                                "type": "string",
                                "description": "Name of workspace"
                            },
                            "repo_name": {
                                "type": "string",
                                "description": "Name of repository to remove"
                            },
                            "delete_files": {
                                "type": "boolean",
                                "description": "Whether to delete repository files (default: true - recommended to avoid conflicts)",
                                "default": True
                            }
                        },
                        "required": ["workspace_name", "repo_name"]
                    }
                ),
                Tool(
                    name="git_status_all",
                    description="Get git status overview for all repositories in workspace. Shows which repos have uncommitted changes, unpushed commits, etc.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "workspace_name": {
                                "type": "string",
                                "description": "Workspace name (optional, uses active workspace if not specified)"
                            }
                        }
                    }
                ),
                Tool(
                    name="get_file_multiple",
                    description="Get the same file from multiple repositories for comparison. Useful for comparing configs, pom.xml, package.json, etc.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "repo_names": {
                                "type": "array",
                                "description": "List of repository names",
                                "items": {"type": "string"}
                            },
                            "file_path": {
                                "type": "string",
                                "description": "Path to file relative to repository root"
                            }
                        },
                        "required": ["repo_names", "file_path"]
                    }
                ),
                Tool(
                    name="list_workspaces",
                    description="List all available workspaces",
                    inputSchema={
                        "type": "object",
                        "properties": {}
                    }
                ),
                Tool(
                    name="switch_workspace",
                    description="Switch to a different workspace",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "name": {
                                "type": "string",
                                "description": "Workspace name to switch to"
                            }
                        },
                        "required": ["name"]
                    }
                ),
                Tool(
                    name="search_repos",
                    description="Search for text/code patterns across all repositories in active workspace",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "pattern": {
                                "type": "string",
                                "description": "Search pattern (regex supported)"
                            },
                            "file_pattern": {
                                "type": "string",
                                "description": "Optional file pattern filter (e.g., '*.java', '*.py')"
                            },
                            "context_lines": {
                                "type": "integer",
                                "description": "Number of context lines to show (default: 3)",
                                "default": 3
                            }
                        },
                        "required": ["pattern"]
                    }
                ),
                Tool(
                    name="get_file",
                    description="Get contents of a file from a repository",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "repo_name": {
                                "type": "string",
                                "description": "Repository name"
                            },
                            "file_path": {
                                "type": "string",
                                "description": "Path to file relative to repository root"
                            }
                        },
                        "required": ["repo_name", "file_path"]
                    }
                ),
                Tool(
                    name="find_file",
                    description="Find files by name across all repositories",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "filename": {
                                "type": "string",
                                "description": "File name to search for (can be partial)"
                            }
                        },
                        "required": ["filename"]
                    }
                ),
                Tool(
                    name="get_workspace_info",
                    description="Get detailed information about the active workspace and its repositories",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "workspace_name": {
                                "type": "string",
                                "description": "Workspace name (optional, uses active workspace if not specified)"
                            }
                        }
                    }
                ),
                Tool(
                    name="update_repos",
                    description="Pull latest changes for all repositories in active workspace",
                    inputSchema={
                        "type": "object",
                        "properties": {}
                    }
                ),
                Tool(
                    name="switch_branch_all",
                    description="Switch to a specific branch across all repositories in workspace. Creates branch if it doesn't exist.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "branch": {
                                "type": "string",
                                "description": "Branch name to switch to"
                            },
                            "create": {
                                "type": "boolean",
                                "description": "Create branch if it doesn't exist (default: false)",
                                "default": False
                            }
                        },
                        "required": ["branch"]
                    }
                ),
                Tool(
                    name="create_branch_all",
                    description="Create a new branch across all repositories in workspace",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "branch_name": {
                                "type": "string",
                                "description": "Name of new branch"
                            },
                            "checkout": {
                                "type": "boolean",
                                "description": "Checkout the new branch after creation (default: true)",
                                "default": True
                            }
                        },
                        "required": ["branch_name"]
                    }
                ),
                Tool(
                    name="list_branches_all",
                    description="List branches in all repositories in workspace",
                    inputSchema={
                        "type": "object",
                        "properties": {}
                    }
                ),
                Tool(
                    name="commit_and_push_all",
                    description="Stage all changes, commit, and push across all repositories with uncommitted changes",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "message": {
                                "type": "string",
                                "description": "Commit message"
                            },
                            "push": {
                                "type": "boolean",
                                "description": "Push changes after commit (default: true)",
                                "default": True
                            }
                        },
                        "required": ["message"]
                    }
                ),
                Tool(
                    name="stage_and_commit_repo",
                    description="Stage and commit changes in a specific repository with AI code review. Reviews uncommitted changes before committing to ensure code quality.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "repo_name": {
                                "type": "string",
                                "description": "Repository name"
                            },
                            "message": {
                                "type": "string",
                                "description": "Commit message"
                            },
                            "files": {
                                "type": "array",
                                "description": "Specific files to stage (optional, stages all if not provided)",
                                "items": {"type": "string"}
                            },
                            "review_depth": {
                                "type": "string",
                                "description": "Review depth: quick, standard, or thorough (default: standard)",
                                "enum": ["quick", "standard", "thorough"],
                                "default": "standard"
                            },
                            "auto_commit_on_pass": {
                                "type": "boolean",
                                "description": "Automatically commit if review score meets threshold (default: false)",
                                "default": False
                            },
                            "workflow_id": {
                                "type": "string",
                                "description": "Optional workflow identifier to persist review/commit state into the workflow session."
                            }
                        },
                        "required": ["repo_name", "message"]
                    }
                ),
                Tool(
                    name="fetch_all_repos",
                    description="Fetch latest changes from remote for all repositories (doesn't merge)",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "prune": {
                                "type": "boolean",
                                "description": "Remove remote tracking branches that no longer exist (default: true)",
                                "default": True
                            }
                        }
                    }
                ),
                Tool(
                    name="run_command_in_repos",
                    description="Run a shell command in multiple repositories. Useful for npm install, mvn clean install, tests, etc.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "command": {
                                "type": "string",
                                "description": "Shell command to execute"
                            },
                            "repo_names": {
                                "type": "array",
                                "description": "List of repository names (optional, runs in all repos if not provided)",
                                "items": {"type": "string"}
                            },
                            "timeout": {
                                "type": "integer",
                                "description": "Timeout in seconds for each command (default: 60)",
                                "default": 60
                            }
                        },
                        "required": ["command"]
                    }
                ),
                Tool(
                    name="get_commit_history",
                    description="Get commit history for a specific repository",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "repo_name": {
                                "type": "string",
                                "description": "Repository name"
                            },
                            "max_count": {
                                "type": "integer",
                                "description": "Maximum number of commits to retrieve (default: 10)",
                                "default": 10
                            }
                        },
                        "required": ["repo_name"]
                    }
                ),
                Tool(
                    name="get_detailed_status",
                    description="Get detailed git status for a specific repository including modified files, staged files, commits ahead/behind",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "repo_name": {
                                "type": "string",
                                "description": "Repository name"
                            }
                        },
                        "required": ["repo_name"]
                    }
                ),
                Tool(
                    name="commit_semantic_release_repo",
                    description="Commit changes in repositories that enforce semantic-release commit conventions. Runs linting, checks the current semantic version, and creates a properly formatted commit without interactive prompts.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "repo_name": {
                                "type": "string",
                                "description": "Repository name"
                            },
                            "commit_type": {
                                "type": "string",
                                "description": "Type of commit: feat, fix, docs, style, refactor, perf, test, build, ci, chore, revert",
                                "enum": ["feat", "fix", "docs", "style", "refactor", "perf", "test", "build", "ci", "chore", "revert"]
                            },
                            "scope": {
                                "type": "string",
                                "description": "Scope of changes (component/module name, e.g., 'auth', 'dashboard', 'api')"
                            },
                            "subject": {
                                "type": "string",
                                "description": "Short description of changes (lowercase, no period at end)"
                            },
                            "body": {
                                "type": "string",
                                "description": "Longer description of changes (optional)"
                            },
                            "breaking_changes": {
                                "type": "string",
                                "description": "Description of breaking changes (optional)"
                            },
                            "issues_closed": {
                                "type": "string",
                                "description": "Issues closed by this commit, e.g., '#123' or '#123, #456' (optional)"
                            },
                            "push": {
                                "type": "boolean",
                                "description": "Push changes after commit (default: false)",
                                "default": False
                            }
                        },
                        "required": ["repo_name", "commit_type", "scope", "subject"]
                    }
                ),
                Tool(
                    name="push_with_review",
                    description="Push repository changes with AI code review. Reviews uncommitted or unpushed changes before pushing to ensure code quality.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "repo_name": {
                                "type": "string",
                                "description": "Repository name"
                            },
                            "branch": {
                                "type": "string",
                                "description": "Branch to push (optional, uses current branch if not specified)"
                            },
                            "set_upstream": {
                                "type": "boolean",
                                "description": "Set upstream tracking (default: false)",
                                "default": False
                            },
                            "review_depth": {
                                "type": "string",
                                "description": "Review depth: quick, standard, or thorough (default: standard)",
                                "enum": ["quick", "standard", "thorough"],
                                "default": "standard"
                            },
                            "auto_push_on_pass": {
                                "type": "boolean",
                                "description": "Automatically push if review score meets threshold (default: false)",
                                "default": False
                            },
                            "workflow_id": {
                                "type": "string",
                                "description": "Optional workflow identifier to persist review/push state into the workflow session."
                            }
                        },
                        "required": ["repo_name"]
                    }
                ),
                Tool(
                    name="workspace_locate",
                    description="Use the workspace index (.mcp/repo_index.json) to locate likely files/symbols/routes for a query, reducing broad searches.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "workspace_name": {"type": "string", "description": "Workspace name (optional; uses active workspace if omitted)"},
                            "query": {"type": "string", "description": "What you're trying to find (feature, class, function, endpoint, etc.)"},
                            "limit": {"type": "integer", "description": "Max results (default 8)", "default": 8}
                        },
                        "required": ["query"]
                    }
                ),
                Tool(
                    name="refresh_workspace_context",
                    description="(Re)generate workspace AI artifacts and digests. Supports incremental refresh by default.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "workspace_name": {"type": "string", "description": "Workspace name (optional; uses active workspace if omitted)"},
                            "generate_code_workspace_file": {"type": "boolean", "description": "Also generate a .code-workspace file (default false)", "default": False},
                            "mode": {"type": "string", "description": "Refresh mode: delta or full (default delta)", "enum": ["delta", "full"], "default": "delta"}
                        }
                    }
                )

            ]

        @self.server.list_resources()
        async def list_resources():
            """List workspace resources exposed by the server."""
            return resource_tools.list_resources(self)

        @self.server.list_resource_templates()
        async def list_resource_templates():
            """List parameterized workspace resource templates."""
            return resource_tools.list_resource_templates(self)

        @self.server.read_resource()
        async def read_resource(uri):
            """Read a workspace resource by URI."""
            return resource_tools.read_resource(self, uri)

        @self.server.list_prompts()
        async def list_prompts():
            """List small workflow prompts for MCP clients."""
            return resource_tools.list_prompts()

        @self.server.get_prompt()
        async def get_prompt(name: str, arguments: dict[str, str] | None):
            """Return a workflow prompt template."""
            return resource_tools.get_prompt(name, arguments)

        @self.server.call_tool()
        async def call_tool(name: str, arguments: Any) -> Any:
            """Handle tool calls."""
            try:
                if name == "ensure_workspace":
                    return await workflow_tools.ensure_workspace(self, arguments)
                elif name == "get_active_workspace":
                    return await workflow_tools.get_active_workspace(self, arguments)
                elif name == "set_workspace_root":
                    return await workflow_tools.set_workspace_root(self, arguments)
                elif name == "start_workflow":
                    return await workflow_tools.start_workflow(self, arguments)
                elif name == "get_workflow_status":
                    return await workflow_tools.get_workflow_status(self, arguments)
                elif name == "prepare_context_bundle":
                    return await workflow_tools.prepare_context_bundle(self, arguments)
                elif name == "prepare_subagent_packet":
                    return await subagent_tools.prepare_subagent_packet(self, arguments)
                elif name == "run_subagent":
                    return await subagent_tools.run_subagent(self, arguments)
                elif name == "store_subagent_result":
                    return await subagent_tools.store_subagent_result(self, arguments)
                elif name == "merge_subagent_results":
                    return await subagent_tools.merge_subagent_results(self, arguments)
                elif name == "locate_candidates":
                    return await workflow_tools.locate_candidates(self, arguments)
                elif name == "build_verification_plan":
                    return await workflow_tools.build_verification_plan(self, arguments)
                elif name == "get_clone_job_status":
                    return await self._get_clone_job_status(arguments)
                elif name == "setup_workspace":
                    return await self._setup_workspace(arguments)
                elif name == "add_repos_to_workspace":
                    return await self._add_repos_to_workspace(arguments)
                elif name == "workspace_locate":
                    return await workflow_tools.workspace_locate(self, arguments)
                elif name == "refresh_workspace_context":
                    return await workflow_tools.refresh_workspace_context(self, arguments)
                elif name == "remove_repo_from_workspace":
                    return await self._remove_repo_from_workspace(arguments)
                elif name == "git_status_all":
                    return await self._git_status_all(arguments)
                elif name == "get_file_multiple":
                    return await self._get_file_multiple(arguments)
                elif name == "list_workspaces":
                    return await self._list_workspaces(arguments)
                elif name == "switch_workspace":
                    return await self._switch_workspace(arguments)
                elif name == "search_repos":
                    return await self._search_repos(arguments)
                elif name == "get_file":
                    return await self._get_file(arguments)
                elif name == "find_file":
                    return await self._find_file(arguments)
                elif name == "get_workspace_info":
                    return await workflow_tools.get_workspace_info(self, arguments)
                elif name == "update_repos":
                    return await self._update_repos(arguments)
                elif name == "switch_branch_all":
                    return await self._switch_branch_all(arguments)
                elif name == "create_branch_all":
                    return await self._create_branch_all(arguments)
                elif name == "list_branches_all":
                    return await self._list_branches_all(arguments)
                elif name == "commit_and_push_all":
                    return await self._commit_and_push_all(arguments)
                elif name == "stage_and_commit_repo":
                    return await self._stage_and_commit_repo(arguments)
                elif name == "fetch_all_repos":
                    return await self._fetch_all_repos(arguments)
                elif name == "run_command_in_repos":
                    return await self._run_command_in_repos(arguments)
                elif name == "get_commit_history":
                    return await self._get_commit_history(arguments)
                elif name == "get_detailed_status":
                    return await self._get_detailed_status(arguments)
                elif name == "commit_semantic_release_repo":
                    return await self._commit_semantic_release_repo(arguments)
                elif name == "push_with_review":
                    return await self._push_with_review(arguments)
                elif name == "analyze_ticket":
                    return await analysis_tools.analyze_ticket(self, arguments)
                elif name == "verify_repos":
                    return await workflow_tools.verify_repos(self, arguments)
                elif name == "set_build_commands":
                    return await self._set_build_commands(arguments)
                elif name == "apply_fix":
                    return await self._apply_fix(arguments)
                elif name == "preflight_check":
                    return await self._preflight_check(arguments)
                else:
                    return [TextContent(type="text", text=f"Unknown tool: {name}")]
            except Exception as e:
                return [TextContent(type="text", text=f"Error: {str(e)}")]

    def _get_workspace_or_active(self, workspace_name: Optional[str] = None) -> tuple[Optional[Any], Optional[str]]:
        """Get workspace by name or return active workspace. Returns (workspace, error_message)."""
        if workspace_name:
            workspace = self.workspace_manager.get_workspace(workspace_name)
            if not workspace:
                return None, f"Workspace '{workspace_name}' not found"
        else:
            workspace = self.workspace_manager.get_active_workspace()
            if not workspace:
                return None, "No active workspace"
        return workspace, None

    def _default_org(self) -> Optional[str]:
        """Return the default GitHub org for short repo names."""
        default_org = self.config.get("github_org")
        if default_org:
            return default_org
        orgs = self.config.get("github_orgs") or []
        return orgs[0] if orgs else None

    def _find_repo_in_workspace(self, workspace: Workspace, repo_name: str) -> tuple[Optional[Any], Optional[str]]:
        """Find repository in workspace. Returns (repo_info, error_message)."""
        for repo in workspace.repos:
            if repo.name == repo_name:
                return repo, None
        return None, f"Repository '{repo_name}' not found in workspace"

    def _sanitize_url(self, url: str) -> str:
        """Remove credentials from URLs for display."""
        if not url:
            return url
        # Strip https://token@host/... -> https://host/...
        if url.startswith("https://") and "@" in url:
            return "https://" + url.split("@", 1)[1]
        return url

    def _resolve_repo_path(self, repo_root: Path, rel_path: str) -> Optional[Path]:
        """Resolve a repo-relative path and prevent path traversal."""
        try:
            root = repo_root.resolve()
            full_path = (root / rel_path).resolve()
            full_path.relative_to(root)
            return full_path
        except Exception:
            return None

    async def _clone_repos_parallel(self, repos_to_clone: list, max_concurrent: int = 3) -> list:
        """Clone multiple repositories in parallel with concurrency limit."""
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def clone_one(repo_info):
            async with semaphore:
                try:
                    # Run sync clone in executor to avoid blocking
                    loop = asyncio.get_event_loop()
                    await loop.run_in_executor(
                        None,
                        self.git_manager.clone_repo,
                        repo_info.url,
                        repo_info.local_path,
                        self.config.get('clone_depth', 1),
                        None
                    )
                    return {"repo": repo_info, "success": True, "error": None}
                except Exception as e:
                    # Clean up empty directory if clone failed
                    repo_path = Path(repo_info.local_path)
                    if repo_path.exists() and not any(repo_path.iterdir()):
                        # Directory is empty, remove it
                        try:
                            repo_path.rmdir()
                        except:
                            pass  # Ignore errors during cleanup
                    return {"repo": repo_info, "success": False, "error": str(e)}
        
        tasks = [asyncio.create_task(clone_one(repo)) for repo in repos_to_clone]
        results: list[dict[str, Any]] = []
        for task in asyncio.as_completed(tasks):
            results.append(await task)
        return results

    def _append_job_log(self, job_id: str, line: str) -> None:
        """Append a log line to a job, keeping only the last N lines."""
        job = self._clone_jobs.get(job_id)
        if not job:
            return
        logs: list[str] = job.setdefault("logs", [])
        logs.append(line)
        if len(logs) > 300:
            del logs[: len(logs) - 300]

    async def _run_clone_job(
        self,
        job_id: str,
        workspace_name: str,
        repos_to_clone: list,
        max_concurrent: int,
        delete_workspace_if_all_fail: bool,
        bootstrap: Optional[dict[str, Any]] = None,
    ) -> None:
        """Run a background clone job and update job status incrementally."""
        job = self._clone_jobs.get(job_id)
        if not job:
            return

        job["status"] = "running"
        job["started_at"] = datetime.now().isoformat()
        job["total"] = len(repos_to_clone)
        job["completed"] = 0
        job["success"] = 0
        job["failed"] = 0

        async def clone_one_with_progress(repo_info):
            try:
                loop = asyncio.get_event_loop()
                await loop.run_in_executor(
                    None,
                    self.git_manager.clone_repo,
                    repo_info.url,
                    repo_info.local_path,
                    self.config.get('clone_depth', 1),
                    None,
                )
                # Update repo metadata
                branch = self.git_manager.get_current_branch(repo_info.local_path)
                last_updated = self.git_manager.get_last_commit_date(repo_info.local_path)
                self.workspace_manager.update_repo_info(
                    workspace_name,
                    repo_info.name,
                    branch=branch,
                    last_updated=last_updated,
                )
                return {"repo": repo_info, "success": True, "error": None}
            except Exception as e:
                # Clean up empty directory if clone failed
                try:
                    repo_path = Path(repo_info.local_path)
                    if repo_path.exists() and not any(repo_path.iterdir()):
                        repo_path.rmdir()
                except Exception:
                    pass
                return {"repo": repo_info, "success": False, "error": str(e)}

        semaphore = asyncio.Semaphore(max_concurrent)

        async def sem_task(repo_info):
            async with semaphore:
                res = await clone_one_with_progress(repo_info)
                repo = res["repo"]
                if res["success"]:
                    job["success"] += 1
                    self._append_job_log(job_id, f"✓ Cloned: {repo.name}")
                else:
                    job["failed"] += 1
                    self._append_job_log(job_id, f"✗ Failed: {repo.name}: {res['error']}")
                job["completed"] += 1
                return res

        tasks = [asyncio.create_task(sem_task(repo)) for repo in repos_to_clone]
        results: list[dict[str, Any]] = []
        for task in asyncio.as_completed(tasks):
            results.append(await task)

        # Finalize
        if job["success"] == 0 and delete_workspace_if_all_fail:
            job["status"] = "failed"
            self._append_job_log(job_id, "❌ All clones failed. Cleaning up workspace.")
            try:
                self.workspace_manager.delete_workspace(workspace_name, delete_repos=True)
            except Exception as e:
                self._append_job_log(job_id, f"Cleanup warning: {str(e)}")
            job["ended_at"] = datetime.now().isoformat()
        else:
            final_status = "completed" if job["failed"] == 0 else "completed_with_errors"
            job["status"] = "finalizing"
            post_error = False
            try:
                post_clone = await self._finalize_workspace_after_clone(workspace_name, bootstrap=bootstrap)
                job["post_clone"] = post_clone
                post_error = bool(post_clone.get("error") or (post_clone.get("generated") or {}).get("error"))
                summary = self._format_post_clone_summary(post_clone)
                if summary:
                    for line in summary.splitlines():
                        self._append_job_log(job_id, line)
            except Exception as exc:
                post_error = True
                job["post_clone"] = {"error": str(exc)}
                self._append_job_log(job_id, f"Post-clone finalization error: {str(exc)}")
            if post_error and final_status == "completed":
                final_status = "completed_with_errors"
            job["status"] = final_status
            job["ended_at"] = datetime.now().isoformat()


    async def _get_clone_job_status(self, args: dict) -> list[TextContent]:
        """Return status for clone jobs."""
        job_id = (args or {}).get("job_id")
        tail = int((args or {}).get("tail", 12) or 12)
        tail = max(5, min(200, tail))

        if job_id:
            job = self._clone_jobs.get(job_id)
            if not job:
                return [TextContent(type="text", text=f"Error: Job '{job_id}' not found")]
            status = job.get("status")
            post_clone = job.get("post_clone") or {}
            ready = (
                status in {"completed", "completed_with_errors"}
                and bool(post_clone)
                and not post_clone.get("error")
                and not (post_clone.get("generated") or {}).get("error")
            )
            include_logs_arg = (args or {}).get("include_logs")
            include_logs = bool(include_logs_arg) if include_logs_arg is not None else not ready
            logs = (job.get("logs") or [])[-tail:] if include_logs else []
            lines = [
                f"Clone Job: {job.get('job_id')}",
                f"Workspace: {job.get('workspace_name')}",
                f"Status: {status}",
                f"Progress: {job.get('completed', 0)}/{job.get('total', 0)} (ok={job.get('success', 0)}, fail={job.get('failed', 0)})",
            ]
            if job.get("started_at"):
                lines.append(f"Started: {job.get('started_at')}")
            if job.get("ended_at"):
                lines.append(f"Ended: {job.get('ended_at')}")
            workspace_path = None
            try:
                workspace_path = str(self.workspace_manager.workspaces_dir / job.get("workspace_name"))
            except Exception:
                pass
            if workspace_path:
                lines.append(f"Location: {workspace_path}")
            lines.append(f"Workspace Ready: {'yes' if ready else 'not yet'}")
            workflow_id = self._workflow_id_from_post_clone(post_clone)
            if workflow_id:
                lines.append(f"Workflow ID: {workflow_id}")
            post_summary = self._format_post_clone_summary(post_clone)
            if post_summary:
                lines.append("\nPost-clone:")
                lines.extend(post_summary.splitlines())
            if ready:
                lines.append("\nNext: use the listed workflow/context artifacts directly; workspace_info is not needed unless you need detailed git status.")
            if logs:
                lines.append("\nRecent logs:")
                lines.extend(logs)
            return [TextContent(type="text", text="\n".join(lines))]

        if not self._clone_jobs:
            return [TextContent(type="text", text="No clone jobs found.")]

        lines = ["Clone Jobs:\n"]
        for job in list(self._clone_jobs.values())[-20:]:
            lines.append("• " + self._job_summary(job))
        lines.append("\nTip: call get_clone_job_status({\"job_id\": \"...\"}) for details.")
        return [TextContent(type="text", text="\n".join(lines))]

    async def _setup_workspace(self, args: dict) -> list[TextContent]:
        """Setup a new workspace with repositories."""
        repos = args.get("repos", [])
        name = args.get("name")
        workspace_root = args.get("workspace_root")
        storage_path = args.get("storage_path")
        base_dir = args.get("base_dir")
        async_mode = self._clone_async_mode(args)
        max_concurrent = int(args.get("max_concurrent", 3) or 3)
        skip_preflight = bool(args.get("skip_preflight", False))
        bootstrap = self._workflow_bootstrap_args(args)
        
        if not repos:
            return [TextContent(type="text", text="Error: No repositories provided")]

        # Resolve effective base directory (supports explicit base_dir, env override, legacy storage_path)
        effective_storage = self._effective_base_dir(
            {"workspace_root": workspace_root, "base_dir": base_dir, "storage_path": storage_path}
        )

        if effective_storage:
            error = self._set_storage_path(effective_storage)
            if error:
                return [TextContent(type="text", text=f"Error: {error}")]

        # If configured to prefer shorter paths on Windows, optionally suggest it.
        # (Informational only; does not change behavior unless user updates config/env.)
        _ = self._maybe_use_short_path(effective_storage)

        preflight_text = ""
        if self.config.get("auto_preflight", False) and not skip_preflight:
            # For background clone setup, keep the initial MCP call cheap. A network
            # git-clone preflight can itself exceed the MCP client timeout before we
            # even create the background job. The actual repo clone job will surface
            # authentication/network failures asynchronously.
            preflight_result = await self._preflight_check({
                "storage_path": effective_storage or self.config.get("storage_path"),
                "test_git_clone": not async_mode,
                "test_command_exec": True,
                "test_long_paths": True,
            })
            if preflight_result:
                preflight_text = preflight_result[0].text or ""
            # Abort only if storage is not available
            fatal_markers = [
                "FAIL: Storage path write failed",
            ]
            if any(marker in preflight_text for marker in fatal_markers):
                abort_text = "Preflight check failed. Setup aborted.\n\n" + preflight_text
                return [TextContent(type="text", text=abort_text)]
        
        # Generate workspace name if not provided
        if not name:
            from datetime import datetime
            name = f"workspace-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        
        # Normalize repository inputs (supports multiple formats)
        normalized_repos = normalize_repo_list(
            repos,
            default_org=self._default_org(),
            github_token=self.config.get('github_token'),
            token_injection_hosts=self.config.get('token_injection_hosts')
        )
        
        # Check for errors in normalization
        errors = [r for r in normalized_repos if 'error' in r]
        if errors:
            error_msgs = [f"✗ {r['input']}: {r['error']}" for r in errors]
            return [TextContent(type="text", text="Error parsing repositories:\n" + "\n".join(error_msgs))]
        
        # Show what will be cloned
        info_lines = []
        if 'short_path_note' in locals() and short_path_note and not short_path_note.startswith("Failed"):
            info_lines.append(short_path_note + "\n")
        if preflight_text:
            info_lines.append("Preflight:\n" + preflight_text + "\n")
        info_lines.append("Repository Input Summary:\n")
        for repo in normalized_repos:
            info_lines.append(f"  • {repo['display_name']}")
            info_lines.append(f"    URL: {repo['url']}")
        info_lines.append("")
        
        # Prepare repo list for workspace manager
        repo_list = [{"url": r['url']} for r in normalized_repos]
        
        # Create workspace
        workspace = self.workspace_manager.create_workspace(name, repo_list)

        if async_mode:
            # Run clones in background to avoid MCP timeouts
            self.workspace_manager.set_active_workspace(name)
            job_id = self._new_job_id()
            self._clone_jobs[job_id] = {
                "job_id": job_id,
                "workspace_name": name,
                "status": "queued",
                "logs": [],
                "bootstrap_requested": bool(bootstrap),
            }
            self._append_job_log(job_id, "Starting background clone job...")
            asyncio.create_task(
                self._run_clone_job(
                    job_id=job_id,
                    workspace_name=name,
                    repos_to_clone=workspace.repos,
                    max_concurrent=max_concurrent,
                    delete_workspace_if_all_fail=True,
                    bootstrap=bootstrap,
                )
            )
            workspace_path = self.workspace_manager.workspaces_dir / name
            text = (
                f"⏳ Workspace '{name}' created and activated. Cloning started in background.\n\n"
                + "\n".join(info_lines)
                + f"\nJob ID: {job_id}\n"
                + f"Workspace Location: {workspace_path}\n\n"
                + "Post-clone finalization: refresh workspace RAG artifacts"
                + (" and bootstrap workflow/searcher" if bootstrap else "")
                + ".\n"
                + "Check progress with: get_clone_job_status({\"job_id\": \"" + job_id + "\"})"
            )
            return [TextContent(type="text", text=text)]
        
        # Clone repositories in parallel
        clone_results = await self._clone_repos_parallel(workspace.repos, max_concurrent=max_concurrent)
        
        # Process results
        results = []
        successful_repos = []
        failed_repos = []
        
        for result in clone_results:
            repo_info = result["repo"]
            if result["success"]:
                results.append(f"✓ Cloned: {repo_info.name}")
                successful_repos.append(repo_info.name)
                
                # Update repo info
                branch = self.git_manager.get_current_branch(repo_info.local_path)
                last_updated = self.git_manager.get_last_commit_date(repo_info.local_path)
                self.workspace_manager.update_repo_info(
                    name, repo_info.name,
                    branch=branch,
                    last_updated=last_updated
                )
            else:
                results.append(f"✗ Failed to clone {repo_info.name}: {result['error']}")
                failed_repos.append(repo_info.name)
        
        # Evaluate clone results and handle failures
        total_repos = len(workspace.repos)
        success_count = len(successful_repos)
        failure_count = len(failed_repos)
        
        if success_count == 0:
            # ALL REPOS FAILED - Delete workspace completely
            cleanup_error = None
            try:
                self.workspace_manager.delete_workspace(name, delete_repos=True)
            except Exception as e:
                cleanup_error = str(e)
            error_text = f"❌ Workspace creation failed! All {total_repos} repositories failed to clone.\n\n"
            error_text += "\n".join(results)
            error_text += f"\n\nWorkspace '{name}' was not created (automatic cleanup performed)."
            if cleanup_error:
                error_text += f"\nCleanup warning: {cleanup_error}"
            return [TextContent(type="text", text=error_text)]
        
        elif failure_count > 0:
            # PARTIAL SUCCESS - Keep workspace but warn user
            self.workspace_manager.set_active_workspace(name)
            post_clone = await self._finalize_workspace_after_clone(name, bootstrap=bootstrap)
            warning_text = f"⚠️  Workspace '{name}' created with partial success!\n\n"
            warning_text += "\n".join(info_lines)
            warning_text += "\n".join(results)
            warning_text += f"\n\n⚠️  Warning: {failure_count} of {total_repos} repositories failed to clone."
            warning_text += f"\n✓ Successfully cloned: {success_count} repository(ies)"
            post_summary = self._format_post_clone_summary(post_clone)
            if post_summary:
                warning_text += "\n\n" + post_summary
            warning_text += "\n\nYou can work with the successful repositories or delete this workspace and retry."
            return [TextContent(type="text", text=warning_text)]
        
        else:
            # ALL SUCCEEDED - Normal success
            self.workspace_manager.set_active_workspace(name)
            post_clone = await self._finalize_workspace_after_clone(name, bootstrap=bootstrap)
            workspace_path = self.workspace_manager.workspaces_dir / name
            
            result_text = f"✅ Workspace '{name}' created and activated successfully!\n\n"
            result_text += "\n".join(info_lines)
            result_text += "\n".join(results)
            post_summary = self._format_post_clone_summary(post_clone)
            if post_summary:
                result_text += "\n\n" + post_summary
            result_text += f"\n\n📁 Workspace Location:\n{workspace_path}"
            result_text += f"\n\n💡 Add to current VS Code window:"
            result_text += f"\ncode --add \"{workspace_path}\""
            result_text += f"\n\nThis adds the workspace to your current window - Cline will make changes via MCP, and you can review them in the sidebar."
            return [TextContent(type="text", text=result_text)]

    async def _add_repos_to_workspace(self, args: dict) -> list[TextContent]:
        """Add repositories to an existing workspace."""
        workspace_name = args.get("workspace_name")
        repos = args.get("repos", [])
        base_dir = (
            args.get("workspace_root")
            or args.get("base_dir")
            or os.getenv("MCP_WORKSPACE_ROOT")
            or os.getenv("MULTI_REPO_WORKSPACE_ROOT")
            or os.getenv("MCP_BASE_DIR")
            or os.getenv("MCP_STORAGE_PATH")
            or os.getenv("MCP_WORKSPACES_ROOT")
        )
        async_mode = self._clone_async_mode(args)
        max_concurrent = int(args.get("max_concurrent", 3) or 3)
        bootstrap = self._workflow_bootstrap_args(args)
        
        if not workspace_name:
            return [TextContent(type="text", text="Error: Workspace name required")]
        
        if not repos:
            return [TextContent(type="text", text="Error: No repositories provided")]
        
        if base_dir:
            error = self._set_storage_path(base_dir)
            if error:
                return [TextContent(type="text", text=f"Error: {error}")]

        # Check if workspace exists
        workspace = self.workspace_manager.get_workspace(workspace_name)
        if not workspace:
            return [TextContent(type="text", text=f"Error: Workspace '{workspace_name}' not found")]
        
        # Normalize repository inputs (supports multiple formats)
        normalized_repos = normalize_repo_list(
            repos,
            default_org=self._default_org(),
            github_token=self.config.get('github_token'),
            token_injection_hosts=self.config.get('token_injection_hosts')
        )
        
        # Check for errors in normalization
        errors = [r for r in normalized_repos if 'error' in r]
        if errors:
            error_msgs = [f"✗ {r['input']}: {r['error']}" for r in errors]
            return [TextContent(type="text", text="Error parsing repositories:\n" + "\n".join(error_msgs))]
        
        # Show what will be added
        info_lines = [f"Adding to workspace '{workspace_name}':\n"]
        for repo in normalized_repos:
            info_lines.append(f"  • {repo['display_name']}")
            info_lines.append(f"    URL: {repo['url']}")
        info_lines.append("")
        
        # Prepare repo list for workspace manager
        repo_list = [{"url": r['url']} for r in normalized_repos]
        
        # Add repos to workspace
        workspace, new_repos = self.workspace_manager.add_repos_to_workspace(workspace_name, repo_list)
        
        if not new_repos:
            msg = f"All repositories already exist in workspace '{workspace_name}'."
            if bootstrap:
                post_clone = await self._finalize_workspace_after_clone(workspace_name, bootstrap=bootstrap)
                post_summary = self._format_post_clone_summary(post_clone)
                if post_summary:
                    msg += "\n\n" + post_summary
            return [TextContent(type="text", text=msg)]
        
        # Clone new repositories in parallel
        skipped_repos = len(normalized_repos) - len(new_repos)

        if async_mode:
            job_id = self._new_job_id()
            self._clone_jobs[job_id] = {
                "job_id": job_id,
                "workspace_name": workspace_name,
                "status": "queued",
                "logs": [],
                "bootstrap_requested": bool(bootstrap),
            }
            self._append_job_log(job_id, f"Starting background clone job for {len(new_repos)} repo(s)...")
            asyncio.create_task(
                self._run_clone_job(
                    job_id=job_id,
                    workspace_name=workspace_name,
                    repos_to_clone=new_repos,
                    max_concurrent=max_concurrent,
                    delete_workspace_if_all_fail=False,
                    bootstrap=bootstrap,
                )
            )
            workspace_path = self.workspace_manager.workspaces_dir / workspace_name
            msg = (
                f"⏳ Started background clone for {len(new_repos)} repo(s) into workspace '{workspace_name}'.\n\n"
                + "\n".join(info_lines)
                + (f"\nℹ️  Skipped {skipped_repos} repository(ies) - already exist in workspace\n" if skipped_repos > 0 else "")
                + f"\nJob ID: {job_id}\n"
                + f"Workspace Location: {workspace_path}\n\n"
                + "Post-clone finalization: refresh workspace RAG artifacts"
                + (" and bootstrap workflow/searcher" if bootstrap else "")
                + ".\n"
                + "Check progress with: get_clone_job_status({\"job_id\": \"" + job_id + "\"})"
            )
            return [TextContent(type="text", text=msg)]

        clone_results = await self._clone_repos_parallel(new_repos, max_concurrent=max_concurrent)
        
        # Process results
        results = []
        successful_repos = []
        failed_repos = []
        
        for result in clone_results:
            repo_info = result["repo"]
            if result["success"]:
                results.append(f"✓ Cloned: {repo_info.name}")
                successful_repos.append(repo_info.name)
                
                # Update repo info
                branch = self.git_manager.get_current_branch(repo_info.local_path)
                last_updated = self.git_manager.get_last_commit_date(repo_info.local_path)
                self.workspace_manager.update_repo_info(
                    workspace_name, repo_info.name,
                    branch=branch,
                    last_updated=last_updated
                )
            else:
                results.append(f"✗ Failed to clone {repo_info.name}: {result['error']}")
                failed_repos.append(repo_info.name)
        
        # Build result message
        result_text = f"📦 Added repositories to workspace '{workspace_name}'!\n\n"
        result_text += "\n".join(info_lines)
        
        if skipped_repos > 0:
            result_text += f"\nℹ️  Skipped {skipped_repos} repository(ies) - already exist in workspace\n"
        
        result_text += "\n".join(results)
        
        success_count = len(successful_repos)
        failure_count = len(failed_repos)
        
        if failure_count > 0:
            result_text += f"\n\n⚠️  Warning: {failure_count} of {len(new_repos)} new repositories failed to clone."
            result_text += f"\n✓ Successfully cloned: {success_count} repository(ies)"
        else:
            result_text += f"\n\n✅ All {success_count} new repositories cloned successfully!"

        post_clone = await self._finalize_workspace_after_clone(workspace_name, bootstrap=bootstrap)
        post_summary = self._format_post_clone_summary(post_clone)
        if post_summary:
            result_text += "\n\n" + post_summary

        workspace_path = self.workspace_manager.workspaces_dir / workspace_name
        result_text += f"\n\n📁 Workspace Location:\n{workspace_path}"
        
        return [TextContent(type="text", text=result_text)]

    async def _remove_repo_from_workspace(self, args: dict) -> list[TextContent]:
        """Remove repository from workspace."""
        workspace_name = args.get("workspace_name")
        repo_name = args.get("repo_name")
        delete_files = args.get("delete_files", True)  # Default changed to True to prevent conflicts
        
        if not workspace_name:
            return [TextContent(type="text", text="Error: Workspace name required")]
        
        if not repo_name:
            return [TextContent(type="text", text="Error: Repository name required")]
        
        try:
            self.workspace_manager.remove_repo_from_workspace(workspace_name, repo_name, delete_files)
            
            result = f"✅ Removed '{repo_name}' from workspace '{workspace_name}'"
            if delete_files:
                result += "\n🗑️  Repository files were deleted (prevents conflicts when re-cloning)"
            else:
                result += "\n💾 Repository files were kept (only removed from tracking)"
            
            return [TextContent(type="text", text=result)]
        except ValueError as e:
            return [TextContent(type="text", text=f"Error: {str(e)}")]

    async def _get_file_multiple(self, args: dict) -> list[TextContent]:
        """Get same file from multiple repos for comparison."""
        repo_names = args.get("repo_names", [])
        file_path = args.get("file_path")
        
        if not repo_names:
            return [TextContent(type="text", text="Error: No repository names provided")]
        
        if not file_path:
            return [TextContent(type="text", text="Error: File path required")]
        
        workspace = self.workspace_manager.get_active_workspace()
        if not workspace:
            return [TextContent(type="text", text="Error: No active workspace")]
        
        lines = [f"Comparing '{file_path}' across {len(repo_names)} repositories:\n"]
        lines.append("=" * 80)
        lines.append("")
        
        found_count = 0
        not_found_count = 0
        
        for repo_name in repo_names:
            # Find repository
            repo_info = None
            for repo in workspace.repos:
                if repo.name == repo_name:
                    repo_info = repo
                    break
            
            if not repo_info:
                lines.append(f"❌ {repo_name}: Repository not found in workspace")
                not_found_count += 1
                continue
            
            full_path = self._resolve_repo_path(Path(repo_info.local_path), file_path)
            
            if not full_path or not full_path.exists():
                lines.append(f"⚠️  {repo_name}: File not found or invalid path")
                not_found_count += 1
            else:
                try:
                    max_size_mb = self.config.get("max_file_size_mb", 10)
                    if full_path.stat().st_size > max_size_mb * 1024 * 1024:
                        lines.append(f"⚠️  {repo_name}: File too large to display")
                        not_found_count += 1
                        continue
                    with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    
                    lines.append(f"📄 {repo_name}:")
                    lines.append("-" * 80)
                    lines.append(content)
                    lines.append("")
                    lines.append("=" * 80)
                    lines.append("")
                    found_count += 1
                except Exception as e:
                    lines.append(f"❌ {repo_name}: Error reading file - {str(e)}")
                    not_found_count += 1
        
        # Add summary at the end
        lines.append(f"\nSummary: Found in {found_count}/{len(repo_names)} repositories")
        
        return [TextContent(type="text", text="\n".join(lines))]

    async def _git_status_all(self, args: dict) -> list[TextContent]:
        """Get git status for all repositories."""
        workspace_name = args.get("workspace_name")
        
        # Use specified workspace or active workspace
        if workspace_name:
            workspace = self.workspace_manager.get_workspace(workspace_name)
        else:
            workspace = self.workspace_manager.get_active_workspace()
        
        if not workspace:
            return [TextContent(type="text", text="Error: No workspace found")]
        
        lines = [f"Git Status for workspace '{workspace.name}':\n"]
        
        clean_repos = []
        dirty_repos = []
        error_repos = []
        
        for repo in workspace.repos:
            if not os.path.exists(repo.local_path):
                error_repos.append(f"⚠️  {repo.name}: Repository not found")
                continue
            
            info = self.git_manager.get_repo_info(repo.local_path)
            
            if "error" in info:
                error_repos.append(f"✗ {repo.name}: {info['error']}")
            elif info.get("is_dirty") or info.get("untracked_files", 0) > 0:
                status = []
                if info.get("is_dirty"):
                    status.append("modified files")
                if info.get("untracked_files", 0) > 0:
                    status.append(f"{info['untracked_files']} untracked")
                dirty_repos.append(f"🔶 {repo.name} ({info.get('branch', 'unknown')}): {', '.join(status)}")
            else:
                clean_repos.append(f"✅ {repo.name} ({info.get('branch', 'unknown')}): Clean")
        
        # Show dirty repos first (most important)
        if dirty_repos:
            lines.append("Repositories with changes:")
            lines.extend(dirty_repos)
            lines.append("")
        
        # Then clean repos
        if clean_repos:
            lines.append("Clean repositories:")
            lines.extend(clean_repos)
            lines.append("")
        
        # Then errors
        if error_repos:
            lines.append("Errors:")
            lines.extend(error_repos)
            lines.append("")
        
        # Summary
        lines.append(f"\nSummary: {len(clean_repos)} clean, {len(dirty_repos)} with changes, {len(error_repos)} errors")
        
        return [TextContent(type="text", text="\n".join(lines))]


    async def _list_workspaces(self, args: dict) -> list[TextContent]:
        """List all workspaces."""
        workspaces = self.workspace_manager.list_workspaces()
        
        if not workspaces:
            return [TextContent(type="text", text="No workspaces found.")]
        
        lines = ["Available Workspaces:\n"]
        for ws in workspaces:
            active_marker = " (active)" if ws.active else ""
            lines.append(f"• {ws.name}{active_marker}")
            lines.append(f"  Repositories: {len(ws.repos)}")
            lines.append(f"  Created: {ws.created_at}")
            lines.append("")
        
        return [TextContent(type="text", text="\n".join(lines))]

    async def _switch_workspace(self, args: dict) -> list[TextContent]:
        """Switch to a different workspace."""
        name = args.get("name")
        
        if not name:
            return [TextContent(type="text", text="Error: Workspace name required")]
        
        workspace = self.workspace_manager.set_active_workspace(name)
        
        return [TextContent(
            type="text",
            text=f"Switched to workspace '{name}' with {len(workspace.repos)} repositories."
        )]

    async def _search_repos(self, args: dict) -> list[TextContent]:
        """Search across repositories."""
        workspace = self.workspace_manager.get_active_workspace()
        
        if not workspace:
            return [TextContent(type="text", text="Error: No active workspace. Use setup_workspace first.")]
        
        pattern = args.get("pattern")
        file_pattern = args.get("file_pattern")
        context_lines = args.get("context_lines", 3)
        max_context = self.config.get("max_context_lines", 10)
        if context_lines > max_context:
            context_lines = max_context
        
        # Prepare repo list for searcher
        repos = [
            {"name": repo.name, "path": repo.local_path}
            for repo in workspace.repos
        ]
        
        # Perform search
        try:
            matches = self.searcher.search_all_repos(
                repos, pattern, file_pattern, context_lines
            )
        except ValueError as e:
            return [TextContent(type="text", text=f"Error: {str(e)}")]
        
        if not matches:
            return [TextContent(type="text", text=f"No matches found for pattern: {pattern}")]
        
        # Format results
        lines = [f"Found {len(matches)} matches for '{pattern}':\n"]
        
        for i, match in enumerate(matches[:50], 1):  # Limit to 50 results
            lines.append(f"{i}. {match.repo_name}:{match.file_path}:{match.line_number}")
            if match.context_before:
                for ctx in match.context_before[-2:]:  # Show last 2 context lines
                    lines.append(f"   {ctx}")
            lines.append(f"-> {match.line_content}")
            if match.context_after:
                for ctx in match.context_after[:2]:  # Show first 2 context lines
                    lines.append(f"   {ctx}")
            lines.append("")
        
        if len(matches) > 50:
            lines.append(f"... and {len(matches) - 50} more matches")
        
        return [TextContent(type="text", text="\n".join(lines))]

    def _extract_keywords(self, text: str, limit: int = 6) -> list[str]:
        """Extract simple keywords from text for searching."""
        if not text:
            return []
        sanitized = re.sub(r"https?://\S+", " ", text, flags=re.IGNORECASE)
        sanitized = re.sub(r"www\.\S+", " ", sanitized, flags=re.IGNORECASE)

        tokens = []
        for raw in re.findall(r"[A-Za-z0-9]+(?:[-_][A-Za-z0-9]+)*", sanitized.lower()):
            word = raw.strip("-_")
            if len(word) < 4:
                continue
            if len(word) > 40:
                continue
            if word in {"http", "https", "www", "figma", "design"}:
                continue
            tokens.append(word)
        seen = []
        for t in tokens:
            if t not in seen:
                seen.append(t)
        return seen[:limit]

    def _workspace_build_commands_path(self, workspace_name: str) -> Path:
        return self.workspace_manager.workspaces_dir / workspace_name / "build_command.json"

    def _extract_commands_from_readme(self, readme_path: Path) -> list[str]:
        patterns = self.config.get("readme_command_patterns", [])
        if not patterns or not readme_path.exists():
            return []
        try:
            content = readme_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return []

        found = []
        for pat in patterns:
            try:
                for match in re.findall(pat, content, flags=re.IGNORECASE):
                    if isinstance(match, tuple):
                        match = match[0]
                    cmd = match.strip()
                    if cmd and cmd not in found:
                        found.append(cmd)
            except Exception:
                continue

        filtered = []
        normalized = [command.lower().split() for command in found]
        for idx, command in enumerate(found):
            tokens = normalized[idx]
            redundant = False
            for other_idx, other_tokens in enumerate(normalized):
                if other_idx == idx or len(other_tokens) <= len(tokens):
                    continue
                if other_tokens[-len(tokens):] == tokens:
                    redundant = True
                    break
            if not redundant:
                filtered.append(command)
        return filtered

    def _build_default_commands(self, workspace: Workspace) -> dict:
        """Create a build_command.json structure from READMEs."""
        repo_entries = {}
        for repo in workspace.repos:
            repo_path = Path(repo.local_path)
            readme = next(
                (
                    repo_path / candidate
                    for candidate in ("README.md", "README.MD", "readme.md", "Readme.md")
                    if (repo_path / candidate).exists()
                ),
                repo_path / "README.md",
            )
            commands = self._extract_commands_from_readme(readme)
            repo_entries[repo.name] = {
                "path": repo.local_path,
                "commands": commands,
                "source": "readme" if commands else "missing"
            }

        return {
            "workspace": workspace.name,
            "order": [r.name for r in workspace.repos],
            "repos": repo_entries
        }

    def _ensure_build_command_file(self, workspace: Workspace) -> Path:
        path = self._workspace_build_commands_path(workspace.name)
        if path.exists():
            return path
        data = self._build_default_commands(workspace)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        return path


    def _ensure_workspace_ai_artifacts(self, workspace: Workspace, mode: str = "delta") -> dict:
        """
        Generate/refresh per-workspace AI artifacts:
        - .clinerules
        - WORKSPACE_CONTEXT.md (+ workspace_context.md)
        - .mcp/repo_index.json
        """
        try:
            return ensure_workspace_ai_files(
                workspace,
                generate_code_workspace_file=bool(self.config.get("generate_code_workspace_file", False)),
                mode=mode,
            )
        except Exception as exc:
            return {"error": str(exc), "refresh": {"mode": mode, "error": str(exc)}}

    def _workspace_root(self, workspace: Workspace) -> Optional[Path]:
        """Infer workspace root from any repository path in the workspace."""
        if not workspace.repos:
            return None
        try:
            return Path(workspace.repos[0].local_path).parent
        except Exception:
            return None

    def _read_workspace_context(self, workspace: Workspace) -> Optional[str]:
        """Read the generated workspace context file if present."""
        workspace_root = self._workspace_root(workspace)
        if not workspace_root:
            return None

        for filename in ("context.md", "WORKSPACE_CONTEXT.md", "workspace_context.md"):
            path = workspace_root / filename
            if path.exists():
                try:
                    return path.read_text(encoding="utf-8")
                except Exception:
                    continue
        return None

    def _read_workspace_index(self, workspace: Workspace) -> Optional[dict]:
        """Read the generated workspace repo index if present."""
        workspace_root = self._workspace_root(workspace)
        if not workspace_root:
            return None

        index_path = workspace_root / ".mcp" / "repo_index.json"
        if not index_path.exists():
            return None

        try:
            return json.loads(index_path.read_text(encoding="utf-8"))
        except Exception:
            return None

    def _get_workflow_session_for_workspace(
        self,
        workspace: Workspace,
        workflow_id: Optional[str],
    ) -> tuple[Optional[dict[str, Any]], Optional[str]]:
        """Resolve an optional workflow session for the active workspace."""
        if not workflow_id:
            return None, None
        workflow = self.workflow_manager.find_session(workflow_id, workspace.name)
        if not workflow:
            return None, f"Workflow '{workflow_id}' not found in workspace '{workspace.name}'"
        return workflow, None

    def _record_workflow_change_artifacts(
        self,
        workspace: Workspace,
        workflow_id: str,
        *,
        repo_name: str,
        changed_files: list[str],
        diff_text: str,
        review_message: str,
        stage: str,
        event_type: str,
    ) -> dict[str, str]:
        """Persist change/review artifacts and refresh workflow context after code writes."""
        diff_path = self.workflow_manager.write_text_artifact(
            workspace.name,
            workflow_id,
            "latest_change.diff",
            diff_text,
        )
        review_request = {
            "repo": repo_name,
            "changed_files": changed_files,
            "review_message": review_message,
            "requested_at": datetime.now(timezone.utc).isoformat(),
            "next_step": "Review the applied diff, then run stage_and_commit_repo or push_with_review.",
        }
        review_request_path = self.workflow_manager.write_json_artifact(
            workspace.name,
            workflow_id,
            "review_request.json",
            review_request,
        )
        generated = self._ensure_workspace_ai_artifacts(workspace, mode="delta")
        artifact_paths = workflow_tools.workspace_artifact_paths(self, workspace)
        self.workflow_manager.update_session(
            workspace.name,
            workflow_id,
            fields={"stage": stage},
            artifacts={
                **artifact_paths,
                "generated": generated,
                "latest_change_diff_path": diff_path,
                "review_request_path": review_request_path,
                "last_changed_repo": repo_name,
                "last_changed_files": changed_files,
            },
            event_type=event_type,
            event_payload={"repo": repo_name, "changed_files": changed_files},
        )
        self.workflow_manager.update_session(
            workspace.name,
            workflow_id,
            event_type="context_refreshed_after_changes",
            event_payload={"repo": repo_name, "changed_files": changed_files},
        )
        self.workflow_manager.update_session(
            workspace.name,
            workflow_id,
            event_type="developer_review_requested",
            event_payload={"repo": repo_name, "review_request_path": review_request_path},
        )
        return {
            "latest_change_diff": diff_path,
            "review_request": review_request_path,
        }

    async def _set_build_commands(self, args: dict) -> list[TextContent]:
        """Update build_command.json with user-provided commands."""
        workspace_name = args.get("workspace_name")
        commands_map = args.get("commands") or {}

        if not commands_map:
            return [TextContent(type="text", text="Error: commands map is required")]
        if not isinstance(commands_map, dict):
            return [TextContent(type="text", text="Error: commands must be a map of repo_name to commands list")]

        workspace, error = self._get_workspace_or_active(workspace_name)
        if error:
            return [TextContent(type="text", text=f"Error: {error}")]

        build_file = self._ensure_build_command_file(workspace)
        try:
            with open(build_file, "r", encoding="utf-8") as f:
                build_data = json.load(f)
        except Exception:
            build_data = self._build_default_commands(workspace)

        repo_entries = build_data.get("repos", {})
        updated = []
        unknown = []

        for repo_name, commands in commands_map.items():
            repo_info, repo_error = self._find_repo_in_workspace(workspace, repo_name)
            if repo_error:
                unknown.append(repo_name)
                continue

            if isinstance(commands, str):
                commands_list = [commands]
            elif isinstance(commands, list):
                commands_list = [c for c in commands if isinstance(c, str) and c.strip()]
            else:
                return [TextContent(
                    type="text",
                    text=f"Error: commands for '{repo_name}' must be a string or list of strings"
                )]

            repo_entries[repo_name] = {
                "path": repo_info.local_path,
                "commands": commands_list,
                "source": "user"
            }
            updated.append(repo_name)

        build_data["workspace"] = workspace.name
        build_data["repos"] = repo_entries
        if not build_data.get("order"):
            build_data["order"] = [r.name for r in workspace.repos]

        try:
            with open(build_file, "w", encoding="utf-8") as f:
                json.dump(build_data, f, indent=2)
        except Exception as e:
            return [TextContent(type="text", text=f"Error writing build_command.json: {str(e)}")]

        response = [f"Updated build commands for {len(updated)} repo(s): {', '.join(updated)}."]
        if unknown:
            response.append(f"Unknown repos ignored: {', '.join(unknown)}.")
        response.append(f"Saved to: {build_file}")
        return [TextContent(type="text", text="\n".join(response))]

    async def _apply_fix(self, args: dict) -> list[TextContent]:
        """Apply code changes to a repository and return a diff for review."""
        workspace = self.workspace_manager.get_active_workspace()
        if not workspace:
            return [TextContent(type="text", text="Error: No active workspace")]

        repo_name = args.get("repo_name")
        changes = args.get("changes", [])
        apply_changes = args.get("apply", True)
        workflow_id = args.get("workflow_id")

        if not repo_name or not changes:
            return [TextContent(type="text", text="Error: repo_name and changes are required")]

        repo_info, error = self._find_repo_in_workspace(workspace, repo_name)
        if error:
            return [TextContent(type="text", text=f"Error: {error}")]

        if not os.path.exists(repo_info.local_path):
            return [TextContent(type="text", text=f"Error: Repository not found at {repo_info.local_path}")]

        workflow, workflow_error = self._get_workflow_session_for_workspace(workspace, workflow_id)
        if workflow_error:
            return [TextContent(type="text", text=f"Error: {workflow_error}")]

        diffs = []
        changed_files: list[str] = []
        for change in changes:
            file_path = change.get("file_path")
            new_content = change.get("content", "")
            if not file_path:
                return [TextContent(type="text", text="Error: Each change must include file_path")]

            full_path = self._resolve_repo_path(Path(repo_info.local_path), file_path)
            if not full_path:
                return [TextContent(type="text", text=f"Error: Invalid file path: {file_path}")]

            old_content = ""
            if full_path.exists():
                try:
                    old_content = full_path.read_text(encoding="utf-8", errors="ignore")
                except Exception:
                    old_content = ""

            if apply_changes:
                # Write new content
                full_path.parent.mkdir(parents=True, exist_ok=True)
                full_path.write_text(new_content, encoding="utf-8")
                changed_files.append(file_path)

            diff = difflib.unified_diff(
                old_content.splitlines(keepends=True),
                new_content.splitlines(keepends=True),
                fromfile=f"a/{file_path}",
                tofile=f"b/{file_path}",
            )
            diffs.append("".join(diff))

        combined = "\n".join(diffs).strip()
        if not combined:
            combined = "No changes detected."

        action = "Applied" if apply_changes else "Proposed"
        report = f"{action} {len(changes)} change(s) to '{repo_name}'.\n\nReview diff:\n\n{combined}"
        if not apply_changes:
            report += "\n\nNo files were written. Re-run apply_fix with apply=true to write changes."
        report += "\n\nPlease review these changes. If approved, run stage_and_commit_repo or commit_and_push_all."
        if workflow:
            if apply_changes:
                changed_file_list = changed_files or [change.get("file_path") for change in changes if change.get("file_path")]
                artifact_paths = self._record_workflow_change_artifacts(
                    workspace,
                    workflow["workflow_id"],
                    repo_name=repo_name,
                    changed_files=changed_file_list,
                    diff_text=combined,
                    review_message="Review the applied code changes and approve before commit.",
                    stage="review_requested",
                    event_type="changes_applied",
                )
                report += (
                    f"\n\nWorkflow '{workflow['workflow_id']}' updated:"
                    f"\n- Context refreshed after applied changes"
                    f"\n- Change diff saved to: {artifact_paths['latest_change_diff']}"
                    f"\n- Review request saved to: {artifact_paths['review_request']}"
                    f"\n- Review status: pending developer review"
                )
                latest_workflow = self.workflow_manager.get_session(workspace.name, workflow["workflow_id"]) or workflow
                reviewer_query = " ".join(
                    filter(
                        None,
                        [
                            repo_name,
                            "review applied changes",
                            " ".join(changed_file_list),
                        ],
                    )
                ).strip()
                latest_workflow, auto_results = subagent_tools.auto_run_subagent_roles(
                    self,
                    workspace,
                    latest_workflow,
                    ["reviewer"],
                    query=reviewer_query,
                    reason="changes_applied",
                )
                if auto_results:
                    roles = ", ".join(item["role"] for item in auto_results)
                    report += f"\n- Auto subagents run: {roles}"
            else:
                proposal_diff_path = self.workflow_manager.write_text_artifact(
                    workspace.name,
                    workflow["workflow_id"],
                    "proposed_change.diff",
                    combined,
                )
                self.workflow_manager.update_session(
                    workspace.name,
                    workflow["workflow_id"],
                    fields={"stage": "changes_proposed"},
                    artifacts={"proposed_change_diff_path": proposal_diff_path},
                    event_type="changes_proposed",
                    event_payload={"repo": repo_name, "changed_files": [change.get("file_path") for change in changes if change.get("file_path")]},
                )
                report += f"\n\nWorkflow '{workflow['workflow_id']}' updated with a proposed diff at: {proposal_diff_path}"
        return [TextContent(type="text", text=report)]

    async def _preflight_check(self, args: dict) -> list[TextContent]:
        """Run preflight checks for storage path, git, command execution, and long paths."""
        storage_path = args.get("workspace_root") or args.get("storage_path")
        base_dir = (
            args.get("workspace_root")
            or args.get("base_dir")
            or os.getenv("MCP_WORKSPACE_ROOT")
            or os.getenv("MULTI_REPO_WORKSPACE_ROOT")
            or os.getenv("MCP_BASE_DIR")
            or os.getenv("MCP_STORAGE_PATH")
            or os.getenv("MCP_WORKSPACES_ROOT")
            or self.config.get("workspace_root")
            or self.config.get("storage_path")
        )
        test_git_clone = args.get("test_git_clone", True)
        test_command_exec = args.get("test_command_exec", True)
        test_long_paths = args.get("test_long_paths", True)

        results: list[str] = []

        if storage_path:
            error = self._set_storage_path(storage_path)
            if error:
                return [TextContent(type="text", text=f"Error: {error}")]

        # Storage write test
        try:
            base = Path(self.config["storage_path"]).resolve()
            test_dir = base / "_preflight"
            test_dir.mkdir(parents=True, exist_ok=True)
            test_file = test_dir / "write_test.txt"
            test_file.write_text("ok", encoding="utf-8")
            test_file.unlink(missing_ok=True)
            test_dir.rmdir()
            results.append("OK: Storage path is writable.")
        except Exception as e:
            results.append(f"FAIL: Storage path write failed: {str(e)}")

        # Command execution test
        if test_command_exec:
            try:
                if sys.platform == "win32":
                    cmd = ["cmd", "/c", "echo", "preflight"]
                else:
                    cmd = ["sh", "-c", "echo preflight"]
                result = await self._run_subprocess(cmd)
                if result.returncode == 0:
                    results.append("OK: Command execution works.")
                else:
                    err = (result.stderr or "").strip()
                    results.append(f"FAIL: Command execution failed (exit {result.returncode}): {err}")
            except Exception as e:
                results.append(f"FAIL: Command execution failed: {str(e)}")

        # Git availability test
        git_ok = False
        try:
            result = await self._run_subprocess(["git", "--version"])
            if result.returncode == 0:
                version = (result.stdout or "").strip()
                results.append(f"OK: Git available: {version}")
                git_ok = True
            else:
                err = (result.stderr or "").strip()
                results.append(f"FAIL: Git unavailable (exit {result.returncode}): {err}")
        except Exception as e:
            results.append(f"FAIL: Git unavailable: {str(e)}")

        # Long path test (Windows only)
        if test_long_paths and sys.platform == "win32":
            try:
                long_paths_enabled = self._is_long_paths_enabled()

                if long_paths_enabled is True:
                    results.append("OK: Long path support enabled (LongPathsEnabled=1).")
                elif long_paths_enabled is False:
                    results.append("FAIL: Long path support disabled (LongPathsEnabled=0).")
                else:
                    results.append("WARN: Unable to read LongPathsEnabled registry setting.")
            except Exception as e:
                results.append(f"FAIL: Long path creation failed: {str(e)}")

        # Git clone test (public repo)
        if test_git_clone and git_ok:
            try:
                base = Path(self.config["storage_path"]).resolve()
                import tempfile
                import shutil
                clone_dir = Path(tempfile.mkdtemp(prefix="_preflight_clone_", dir=str(base)))
                repo_dir = clone_dir / "hello-world"
                cmd = ["git", "clone", "-v", "-c", "core.longpaths=true", "--depth", "1",
                       "--", "https://github.com/octocat/Hello-World.git", str(repo_dir)]
                env = os.environ.copy()
                env.setdefault("GIT_TERMINAL_PROMPT", "0")
                env.setdefault("GIT_ASKPASS", "echo")
                env.setdefault("GCM_INTERACTIVE", "Never")

                result = await self._run_subprocess(cmd, env=env)
                if result.returncode == 0:
                    results.append("OK: Git clone works (public repo).")
                else:
                    err = (result.stderr or "").strip()
                    out = (result.stdout or "").strip()
                    results.append(f"FAIL: Git clone failed (exit {result.returncode}): {err or out}")
            except Exception as e:
                results.append(f"FAIL: Git clone failed: {str(e)}")
            finally:
                try:
                    def handle_remove_readonly(func, path, exc):
                        try:
                            if os.path.exists(path):
                                os.chmod(path, 0o666)
                                func(path)
                        except Exception:
                            pass

                    if 'clone_dir' in locals() and clone_dir.exists():
                        shutil.rmtree(clone_dir, ignore_errors=False, onerror=handle_remove_readonly)
                except Exception:
                    pass

        return [TextContent(type="text", text="\n".join(results))]

    async def _get_file(self, args: dict) -> list[TextContent]:
        """Get file contents."""
        workspace = self.workspace_manager.get_active_workspace()
        
        if not workspace:
            return [TextContent(type="text", text="Error: No active workspace")]
        
        repo_name = args.get("repo_name")
        file_path = args.get("file_path")
        
        # Find repository
        repo_info = None
        for repo in workspace.repos:
            if repo.name == repo_name:
                repo_info = repo
                break
        
        if not repo_info:
            return [TextContent(type="text", text=f"Error: Repository '{repo_name}' not found")]
        
        # Read file
        full_path = self._resolve_repo_path(Path(repo_info.local_path), file_path)
        
        if not full_path or not full_path.exists():
            return [TextContent(type="text", text=f"Error: File not found or invalid path: {file_path}")]
        
        try:
            max_size_mb = self.config.get("max_file_size_mb", 10)
            if full_path.stat().st_size > max_size_mb * 1024 * 1024:
                return [TextContent(type="text", text="Error: File too large to display")]
            with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            return [TextContent(
                type="text",
                text=f"File: {repo_name}:{file_path}\n\n{content}"
            )]
        except Exception as e:
            return [TextContent(type="text", text=f"Error reading file: {str(e)}")]

    async def _find_file(self, args: dict) -> list[TextContent]:
        """Find files by name."""
        workspace = self.workspace_manager.get_active_workspace()
        
        if not workspace:
            return [TextContent(type="text", text="Error: No active workspace")]
        
        filename = args.get("filename")
        
        repos = [
            {"name": repo.name, "path": repo.local_path}
            for repo in workspace.repos
        ]
        
        found = self.searcher.find_file(repos, filename)
        
        if not found:
            return [TextContent(type="text", text=f"No files found matching: {filename}")]
        
        result = f"Found {len(found)} files matching '{filename}':\n\n"
        result += "\n".join(found[:100])  # Limit to 100 results
        
        if len(found) > 100:
            result += f"\n\n... and {len(found) - 100} more files"
        
        return [TextContent(type="text", text=result)]

    async def _update_repos(self, args: dict) -> list[TextContent]:
        """Update all repositories."""
        workspace = self.workspace_manager.get_active_workspace()
        
        if not workspace:
            return [TextContent(type="text", text="Error: No active workspace")]
        
        results = []
        for repo in workspace.repos:
            if os.path.exists(repo.local_path):
                success = self.git_manager.pull_repo(repo.local_path)
                if success:
                    results.append(f"✓ Updated: {repo.name}")
                    # Update info
                    last_updated = self.git_manager.get_last_commit_date(repo.local_path)
                    self.workspace_manager.update_repo_info(
                        workspace.name, repo.name,
                        last_updated=last_updated
                    )
                else:
                    results.append(f"✗ Failed to update: {repo.name}")
            else:
                results.append(f"⚠ Repository not found: {repo.name}")
        
        return [TextContent(type="text", text="\n".join(results))]

    async def _switch_branch_all(self, args: dict) -> list[TextContent]:
        """Switch to a branch across all repositories."""
        workspace = self.workspace_manager.get_active_workspace()
        
        if not workspace:
            return [TextContent(type="text", text="Error: No active workspace")]
        
        branch = args.get("branch")
        create = args.get("create", False)
        
        results = []
        success_count = 0
        fail_count = 0
        
        for repo in workspace.repos:
            if not os.path.exists(repo.local_path):
                results.append(f"⚠️  {repo.name}: Repository not found")
                fail_count += 1
                continue
            
            success = self.git_manager.checkout_branch(repo.local_path, branch, create=create)
            if success:
                results.append(f"✓ {repo.name}: Switched to '{branch}'")
                success_count += 1
                
                # Update workspace info
                self.workspace_manager.update_repo_info(
                    workspace.name, repo.name,
                    branch=branch
                )
            else:
                results.append(f"✗ {repo.name}: Failed to switch branch")
                fail_count += 1
        
        summary = f"\n\nSummary: {success_count} succeeded, {fail_count} failed"
        return [TextContent(type="text", text="\n".join(results) + summary)]

    async def _create_branch_all(self, args: dict) -> list[TextContent]:
        """Create a branch across all repositories."""
        workspace = self.workspace_manager.get_active_workspace()
        
        if not workspace:
            return [TextContent(type="text", text="Error: No active workspace")]
        
        branch_name = args.get("branch_name")
        checkout = args.get("checkout", True)
        
        results = []
        success_count = 0
        fail_count = 0
        
        for repo in workspace.repos:
            if not os.path.exists(repo.local_path):
                results.append(f"⚠️  {repo.name}: Repository not found")
                fail_count += 1
                continue
            
            success = self.git_manager.create_branch(repo.local_path, branch_name, checkout=checkout)
            if success:
                results.append(f"✓ {repo.name}: Created branch '{branch_name}'")
                success_count += 1
                
                # Update workspace info if checked out
                if checkout:
                    self.workspace_manager.update_repo_info(
                        workspace.name, repo.name,
                        branch=branch_name
                    )
            else:
                results.append(f"✗ {repo.name}: Failed to create branch")
                fail_count += 1
        
        summary = f"\n\nSummary: {success_count} succeeded, {fail_count} failed"
        return [TextContent(type="text", text="\n".join(results) + summary)]

    async def _list_branches_all(self, args: dict) -> list[TextContent]:
        """List branches in all repositories."""
        workspace = self.workspace_manager.get_active_workspace()
        
        if not workspace:
            return [TextContent(type="text", text="Error: No active workspace")]
        
        lines = [f"Branches in workspace '{workspace.name}':\n"]
        
        for repo in workspace.repos:
            if not os.path.exists(repo.local_path):
                lines.append(f"⚠️  {repo.name}: Repository not found")
                continue
            
            branches = self.git_manager.list_branches(repo.local_path)
            current_branch = self.git_manager.get_current_branch(repo.local_path)
            
            lines.append(f"\n📁 {repo.name}:")
            if branches:
                for branch in branches:
                    marker = " (current)" if branch == current_branch else ""
                    lines.append(f"  • {branch}{marker}")
            else:
                lines.append("  No branches found")
        
        return [TextContent(type="text", text="\n".join(lines))]

    async def _commit_and_push_all(self, args: dict) -> list[TextContent]:
        """Commit and push changes across all repositories."""
        workspace = self.workspace_manager.get_active_workspace()
        
        if not workspace:
            return [TextContent(type="text", text="Error: No active workspace")]
        
        message = args.get("message")
        push = args.get("push", True)
        
        results = []
        committed_count = 0
        pushed_count = 0
        no_changes_count = 0
        fail_count = 0
        
        for repo in workspace.repos:
            if not os.path.exists(repo.local_path):
                results.append(f"⚠️  {repo.name}: Repository not found")
                fail_count += 1
                continue
            
            # Check if there are changes
            status = self.git_manager.get_repo_status(repo.local_path)
            if "error" in status:
                results.append(f"✗ {repo.name}: {status['error']}")
                fail_count += 1
                continue
            
            if not status.get("has_uncommitted_changes") and not status.get("untracked_files"):
                results.append(f"⊘ {repo.name}: No changes to commit")
                no_changes_count += 1
                continue
            
            # Stage all changes
            stage_success = self.git_manager.stage_files(repo.local_path)
            if not stage_success:
                results.append(f"✗ {repo.name}: Failed to stage changes")
                fail_count += 1
                continue
            
            # Commit
            commit_success = self.git_manager.commit_changes(repo.local_path, message)
            if commit_success:
                results.append(f"✓ {repo.name}: Committed changes")
                committed_count += 1
                
                # Push if requested
                if push:
                    push_success = self.git_manager.push_changes(repo.local_path)
                    if push_success:
                        results.append(f"  ↑ Pushed to remote")
                        pushed_count += 1
                    else:
                        results.append(f"  ✗ Failed to push")
                        fail_count += 1
            else:
                results.append(f"✗ {repo.name}: Failed to commit")
                fail_count += 1
        
        summary = f"\n\nSummary: {committed_count} committed"
        if push:
            summary += f", {pushed_count} pushed"
        summary += f", {no_changes_count} no changes, {fail_count} errors"
        
        return [TextContent(type="text", text="\n".join(results) + summary)]

    async def _stage_and_commit_repo(self, args: dict) -> list[TextContent]:
        """Stage and commit changes in a specific repository with AI code review."""
        workspace = self.workspace_manager.get_active_workspace()
        
        if not workspace:
            return [TextContent(type="text", text="Error: No active workspace")]
        
        repo_name = args.get("repo_name")
        message = args.get("message")
        files = args.get("files")
        review_depth = args.get("review_depth", "standard")
        auto_commit_on_pass = args.get("auto_commit_on_pass", False)
        workflow_id = args.get("workflow_id")
        
        # Find repository
        repo_info, error = self._find_repo_in_workspace(workspace, repo_name)
        if error:
            return [TextContent(type="text", text=f"Error: {error}")]
        
        if not os.path.exists(repo_info.local_path):
            return [TextContent(type="text", text=f"Error: Repository not found at {repo_info.local_path}")]

        workflow, workflow_error = self._get_workflow_session_for_workspace(workspace, workflow_id)
        if workflow_error:
            return [TextContent(type="text", text=f"Error: {workflow_error}")]
        
        # Check if code reviewer is available
        if not self.code_reviewer:
            return [TextContent(type="text", text="Error: Code review is not enabled. Please add OpenAI API key to config/default_config.json")]
        
        # Stage files first
        stage_success = self.git_manager.stage_files(repo_info.local_path, files)
        if not stage_success:
            return [TextContent(type="text", text="Error: Failed to stage files")]
        
        # Get diff of staged changes
        diff = self.git_manager.get_staged_diff(repo_info.local_path)
        
        if not diff:
            return [TextContent(type="text", text=f"ℹ️  No staged changes in '{repo_name}'. Nothing to review or commit.")]
        
        # Perform code review in executor to avoid blocking
        loop = asyncio.get_event_loop()
        review = await loop.run_in_executor(
            None,
            self.code_reviewer.review_code_changes,
            diff,
            repo_name,
            review_depth
        )
        
        if not review.get("success"):
            return [TextContent(type="text", text=f"Error during code review: {review.get('error', 'Unknown error')}")]
        
        # Format review report
        report = self.code_reviewer.format_review_report(review, repo_name)
        review_artifact_path = None
        if workflow:
            review_artifact_path = self.workflow_manager.write_json_artifact(
                workspace.name,
                workflow["workflow_id"],
                "code_review.json",
                {
                    "repo": repo_name,
                    "message": message,
                    "review_depth": review_depth,
                    "auto_commit_on_pass": auto_commit_on_pass,
                    "review": review,
                    "generated_at": datetime.now(timezone.utc).isoformat(),
                },
            )
        
        # Determine if we should auto-commit
        score = review.get("score", 0.0)
        threshold = self.config.get('code_review', {}).get('auto_push_threshold', 8.0)
        has_security_issues = len(review.get("security_issues", [])) > 0
        
        should_auto_commit = (
            auto_commit_on_pass and 
            score >= threshold and 
            not has_security_issues
        )
        
        if should_auto_commit:
            # Auto-commit approved
            commit_success = self.git_manager.commit_changes(repo_info.local_path, message)
            if commit_success:
                report += f"\n\n✅ AUTO-COMMITTED: Score {score:.1f}/10 meets threshold {threshold}"
                report += f"\n📝 Committed changes in '{repo_name}'"
                report += f"\nMessage: {message}"
                if workflow:
                    artifact_paths = self._record_workflow_change_artifacts(
                        workspace,
                        workflow["workflow_id"],
                        repo_name=repo_name,
                        changed_files=list(files or []),
                        diff_text=diff,
                        review_message="AI review passed and commit completed. Developer should review the committed diff.",
                        stage="changes_committed",
                        event_type="changes_committed",
                    )
                    self.workflow_manager.update_session(
                        workspace.name,
                        workflow["workflow_id"],
                        artifacts={"code_review_path": review_artifact_path, **artifact_paths},
                    )
                    report += (
                        f"\nWorkflow '{workflow['workflow_id']}' updated:"
                        f"\n- Code review saved to: {review_artifact_path}"
                        f"\n- Context refreshed after commit"
                        f"\n- Review request saved for developer approval"
                    )
            else:
                report += f"\n\n✗ Auto-commit failed. Please commit manually."
        else:
            # Show review, wait for manual commit
            report += f"\n\n⏸️  Commit NOT executed (requires manual approval)"
            report += f"\nReason: "
            if not auto_commit_on_pass:
                report += "auto_commit_on_pass is disabled"
            elif score < threshold:
                report += f"score {score:.1f} below threshold {threshold}"
            elif has_security_issues:
                report += "security issues found"
            
            report += f"\n\nChanges are staged. To commit manually, use:"
            report += f"\n  stage_and_commit_repo({{\"repo_name\": \"{repo_name}\", \"message\": \"{message}\", \"auto_commit_on_pass\": true}})"
            report += f"\n  OR fix issues and try again"
            if workflow:
                artifact_paths = self._record_workflow_change_artifacts(
                    workspace,
                    workflow["workflow_id"],
                    repo_name=repo_name,
                    changed_files=list(files or []),
                    diff_text=diff,
                    review_message="AI review completed. Developer approval is required before commit.",
                    stage="review_requested",
                    event_type="code_review_completed",
                )
                self.workflow_manager.update_session(
                    workspace.name,
                    workflow["workflow_id"],
                    artifacts={"code_review_path": review_artifact_path, **artifact_paths},
                )
                report += (
                    f"\n\nWorkflow '{workflow['workflow_id']}' updated:"
                    f"\n- Code review saved to: {review_artifact_path}"
                    f"\n- Context refreshed from current working tree"
                    f"\n- Developer review requested"
                )
        
        return [TextContent(type="text", text=report)]

    async def _fetch_all_repos(self, args: dict) -> list[TextContent]:
        """Fetch all repositories."""
        workspace = self.workspace_manager.get_active_workspace()
        
        if not workspace:
            return [TextContent(type="text", text="Error: No active workspace")]
        
        prune = args.get("prune", True)
        
        results = []
        success_count = 0
        fail_count = 0
        
        for repo in workspace.repos:
            if not os.path.exists(repo.local_path):
                results.append(f"⚠️  {repo.name}: Repository not found")
                fail_count += 1
                continue
            
            success = self.git_manager.fetch_all(repo.local_path, prune)
            if success:
                results.append(f"✓ {repo.name}: Fetched from remote")
                success_count += 1
            else:
                results.append(f"✗ {repo.name}: Failed to fetch")
                fail_count += 1
        
        summary = f"\n\nSummary: {success_count} fetched, {fail_count} failed"
        return [TextContent(type="text", text="\n".join(results) + summary)]

    async def _run_command_in_repos(self, args: dict) -> list[TextContent]:
        """Run a command in multiple repositories (optimized with parallel execution)."""
        workspace = self.workspace_manager.get_active_workspace()
        
        if not workspace:
            return [TextContent(type="text", text="Error: No active workspace")]
        
        command = args.get("command")
        repo_names = args.get("repo_names")
        timeout = args.get("timeout", 60)  # Default 60 seconds per command

        if not self.config.get("allow_run_commands", False):
            return [TextContent(type="text", text="Error: run_command_in_repos is disabled by configuration.")]
        
        # Determine which repos to run command in
        if repo_names:
            target_repos = []
            for repo_name in repo_names:
                repo_info, error = self._find_repo_in_workspace(workspace, repo_name)
                if error:
                    return [TextContent(type="text", text=f"Error: {error}")]
                target_repos.append(repo_info)
        else:
            target_repos = workspace.repos
        
        # Run commands in parallel
        async def run_in_repo(repo):
            """Run command in a single repository."""
            if not os.path.exists(repo.local_path):
                return {
                    "repo": repo.name,
                    "status": "not_found",
                    "message": "Repository not found"
                }
            
            try:
                try:
                    result = await self._run_subprocess(
                        command,
                        cwd=repo.local_path,
                        timeout=timeout,
                        shell=True
                    )
                except subprocess.TimeoutExpired:
                    return {
                        "repo": repo.name,
                        "status": "timeout",
                        "message": f"Timeout after {timeout} seconds"
                    }

                stdout_text = result.stdout or ""
                stderr_text = result.stderr or ""

                return {
                    "repo": repo.name,
                    "status": "success" if result.returncode == 0 else "failed",
                    "returncode": result.returncode,
                    "stdout": stdout_text[:500],
                    "stderr": stderr_text[:500]
                }
                    
            except Exception as e:
                return {
                    "repo": repo.name,
                    "status": "error",
                    "message": str(e)
                }
        
        # Execute commands in parallel across all repos
        tasks = [run_in_repo(repo) for repo in target_repos]
        command_results = await asyncio.gather(*tasks)
        
        # Format results
        results = [f"Running command in {len(target_repos)} repositories:\n"]
        results.append(f"Command: {command}\n")
        
        success_count = 0
        failed_count = 0
        timeout_count = 0
        error_count = 0
        
        for result in command_results:
            results.append(f"\n📁 {result['repo']}:")
            
            if result['status'] == 'success':
                results.append(f"✓ Success (exit code: {result['returncode']})")
                if result.get('stdout'):
                    results.append(f"Output: {result['stdout']}")
                success_count += 1
                
            elif result['status'] == 'failed':
                results.append(f"✗ Failed (exit code: {result['returncode']})")
                if result.get('stderr'):
                    results.append(f"Error: {result['stderr']}")
                failed_count += 1
                
            elif result['status'] == 'timeout':
                results.append(f"⏱️  {result['message']}")
                timeout_count += 1
                
            elif result['status'] == 'not_found':
                results.append(f"⚠️  {result['message']}")
                error_count += 1
                
            elif result['status'] == 'error':
                results.append(f"✗ Error: {result['message']}")
                error_count += 1
        
        # Add summary
        summary = f"\n\nSummary: {success_count} succeeded"
        if failed_count > 0:
            summary += f", {failed_count} failed"
        if timeout_count > 0:
            summary += f", {timeout_count} timed out"
        if error_count > 0:
            summary += f", {error_count} errors"
        
        results.append(summary)
        
        return [TextContent(type="text", text="\n".join(results))]

    async def _get_commit_history(self, args: dict) -> list[TextContent]:
        """Get commit history for a repository."""
        workspace = self.workspace_manager.get_active_workspace()
        
        if not workspace:
            return [TextContent(type="text", text="Error: No active workspace")]
        
        repo_name = args.get("repo_name")
        max_count = args.get("max_count", 10)
        
        # Find repository
        repo_info, error = self._find_repo_in_workspace(workspace, repo_name)
        if error:
            return [TextContent(type="text", text=f"Error: {error}")]
        
        if not os.path.exists(repo_info.local_path):
            return [TextContent(type="text", text=f"Error: Repository not found at {repo_info.local_path}")]
        
        commits = self.git_manager.get_commit_history(repo_info.local_path, max_count)
        
        if not commits:
            return [TextContent(type="text", text=f"No commit history found for '{repo_name}'")]
        
        lines = [f"Commit History for '{repo_name}' (last {len(commits)} commits):\n"]
        
        for commit in commits:
            lines.append(f"📝 {commit['hash']} - {commit['author']}")
            lines.append(f"   {commit['date']}")
            lines.append(f"   {commit['message']}")
            lines.append("")
        
        return [TextContent(type="text", text="\n".join(lines))]

    async def _get_detailed_status(self, args: dict) -> list[TextContent]:
        """Get detailed status for a repository."""
        workspace = self.workspace_manager.get_active_workspace()
        
        if not workspace:
            return [TextContent(type="text", text="Error: No active workspace")]
        
        repo_name = args.get("repo_name")
        
        # Find repository
        repo_info, error = self._find_repo_in_workspace(workspace, repo_name)
        if error:
            return [TextContent(type="text", text=f"Error: {error}")]
        
        if not os.path.exists(repo_info.local_path):
            return [TextContent(type="text", text=f"Error: Repository not found at {repo_info.local_path}")]
        
        status = self.git_manager.get_repo_status(repo_info.local_path)
        
        if "error" in status:
            return [TextContent(type="text", text=f"Error: {status['error']}")]
        
        lines = [f"Detailed Status for '{repo_name}':\n"]
        lines.append(f"Branch: {status.get('branch', 'unknown')}")
        lines.append(f"Status: {'Clean' if not status.get('is_dirty') else 'Modified'}")
        
        if status.get('commits_ahead', 0) > 0:
            lines.append(f"Commits ahead: {status['commits_ahead']}")
        if status.get('commits_behind', 0) > 0:
            lines.append(f"Commits behind: {status['commits_behind']}")
        
        if status.get('modified_files'):
            lines.append(f"\nModified files ({len(status['modified_files'])}):")
            for f in status['modified_files'][:20]:  # Limit to 20
                lines.append(f"  M {f}")
            if len(status['modified_files']) > 20:
                lines.append(f"  ... and {len(status['modified_files']) - 20} more")
        
        if status.get('staged_files'):
            lines.append(f"\nStaged files ({len(status['staged_files'])}):")
            for f in status['staged_files'][:20]:
                lines.append(f"  + {f}")
            if len(status['staged_files']) > 20:
                lines.append(f"  ... and {len(status['staged_files']) - 20} more")
        
        if status.get('untracked_files'):
            lines.append(f"\nUntracked files ({len(status['untracked_files'])}):")
            for f in status['untracked_files'][:20]:
                lines.append(f"  ? {f}")
            if len(status['untracked_files']) > 20:
                lines.append(f"  ... and {len(status['untracked_files']) - 20} more")
        
        return [TextContent(type="text", text="\n".join(lines))]

    async def _commit_semantic_release_repo(self, args: dict) -> list[TextContent]:
        """Commit changes in a repository that uses semantic-release commit rules."""
        workspace = self.workspace_manager.get_active_workspace()
        
        if not workspace:
            return [TextContent(type="text", text="Error: No active workspace")]
        
        repo_name = args.get("repo_name")
        commit_type = args.get("commit_type")
        scope = args.get("scope")
        subject = args.get("subject")
        body = args.get("body")
        breaking_changes = args.get("breaking_changes")
        issues_closed = args.get("issues_closed")
        push = args.get("push", False)
        
        # Find repository
        repo_info, error = self._find_repo_in_workspace(workspace, repo_name)
        if error:
            return [TextContent(type="text", text=f"Error: {error}")]
        
        if not os.path.exists(repo_info.local_path):
            return [TextContent(type="text", text=f"Error: Repository not found at {repo_info.local_path}")]
        
        # First, stage all changes
        stage_success = self.git_manager.stage_files(repo_info.local_path)
        if not stage_success:
            return [TextContent(type="text", text="Error: Failed to stage files")]
        
        # Run semantic-release commit workflow in executor to avoid blocking
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(
            None,
            self.git_manager.commit_semantic_release_repo,
            repo_info.local_path,
            commit_type,
            scope,
            subject,
            body,
            breaking_changes,
            issues_closed
        )
        
        if not result["success"]:
            return [TextContent(type="text", text=f"Error: {result['message']}")]
        
        # Format success response
        lines = [f"✅ Successfully committed changes in '{repo_name}' with semantic-release formatting\n"]
        lines.append(f"Commit: {commit_type}({scope}): {subject}")
        if result.get("version"):
            lines.append(f"Current version: {result['version']}")
        lines.append(f"\n✓ Linting passed")
        lines.append(f"✓ Semantic version checked")
        lines.append(f"✓ Commit created with --no-verify")
        
        # Push if requested
        if push:
            push_success = self.git_manager.push_changes(repo_info.local_path)
            if push_success:
                lines.append(f"\n✓ Changes pushed to remote")
            else:
                lines.append(f"\n✗ Failed to push changes")
                lines.append(f"   You can push manually with: git push")
        else:
            lines.append(f"\nℹ️  Changes committed locally. Push manually with:")
            lines.append(f"   cd {repo_info.local_path}")
            lines.append(f"   git push")
        
        return [TextContent(type="text", text="\n".join(lines))]

    async def _push_with_review(self, args: dict) -> list[TextContent]:
        """Push with AI code review."""
        workspace = self.workspace_manager.get_active_workspace()
        
        if not workspace:
            return [TextContent(type="text", text="Error: No active workspace")]
        
        repo_name = args.get("repo_name")
        branch = args.get("branch")
        set_upstream = args.get("set_upstream", False)
        review_depth = args.get("review_depth", "standard")
        auto_push_on_pass = args.get("auto_push_on_pass", False)
        workflow_id = args.get("workflow_id")
        
        # Find repository
        repo_info, error = self._find_repo_in_workspace(workspace, repo_name)
        if error:
            return [TextContent(type="text", text=f"Error: {error}")]
        
        if not os.path.exists(repo_info.local_path):
            return [TextContent(type="text", text=f"Error: Repository not found at {repo_info.local_path}")]

        workflow, workflow_error = self._get_workflow_session_for_workspace(workspace, workflow_id)
        if workflow_error:
            return [TextContent(type="text", text=f"Error: {workflow_error}")]
        
        # Check if code reviewer is available
        if not self.code_reviewer:
            return [TextContent(type="text", text="Error: Code review is not enabled. Please add OpenAI API key to config/default_config.json")]
        
        # Get diff of unpushed changes
        diff = self.git_manager.get_unpushed_diff(repo_info.local_path)
        
        if not diff:
            return [TextContent(type="text", text=f"ℹ️  No unpushed changes in '{repo_name}'. Nothing to review or push.")]
        
        # Perform code review in executor to avoid blocking
        loop = asyncio.get_event_loop()
        review = await loop.run_in_executor(
            None,
            self.code_reviewer.review_code_changes,
            diff,
            repo_name,
            review_depth
        )
        
        if not review.get("success"):
            return [TextContent(type="text", text=f"Error during code review: {review.get('error', 'Unknown error')}")]
        
        # Format review report
        report = self.code_reviewer.format_review_report(review, repo_name)
        review_artifact_path = None
        if workflow:
            review_artifact_path = self.workflow_manager.write_json_artifact(
                workspace.name,
                workflow["workflow_id"],
                "push_review.json",
                {
                    "repo": repo_name,
                    "branch": branch,
                    "set_upstream": set_upstream,
                    "review_depth": review_depth,
                    "auto_push_on_pass": auto_push_on_pass,
                    "review": review,
                    "generated_at": datetime.now(timezone.utc).isoformat(),
                },
            )
        
        # Determine if we should auto-push
        score = review.get("score", 0.0)
        threshold = self.config.get('code_review', {}).get('auto_push_threshold', 8.0)
        has_security_issues = len(review.get("security_issues", [])) > 0
        
        should_auto_push = (
            auto_push_on_pass and 
            score >= threshold and 
            not has_security_issues
        )
        
        if should_auto_push:
            # Auto-push approved
            success = self.git_manager.push_changes(repo_info.local_path, branch, set_upstream)
            if success:
                branch_name = branch or self.git_manager.get_current_branch(repo_info.local_path)
                report += f"\n\n✅ AUTO-PUSHED: Score {score:.1f}/10 meets threshold {threshold}"
                report += f"\n📤 Pushed '{repo_name}' branch '{branch_name}' to remote"
                if workflow:
                    artifact_paths = self._record_workflow_change_artifacts(
                        workspace,
                        workflow["workflow_id"],
                        repo_name=repo_name,
                        changed_files=[],
                        diff_text=diff,
                        review_message="AI review passed and changes were pushed. Developer should verify the remote branch.",
                        stage="changes_pushed",
                        event_type="changes_pushed",
                    )
                    self.workflow_manager.update_session(
                        workspace.name,
                        workflow["workflow_id"],
                        artifacts={"push_review_path": review_artifact_path, **artifact_paths},
                    )
                    report += (
                        f"\nWorkflow '{workflow['workflow_id']}' updated:"
                        f"\n- Push review saved to: {review_artifact_path}"
                        f"\n- Context refreshed after push"
                    )
            else:
                report += f"\n\n✗ Auto-push failed. Please push manually."
        else:
            # Show review, wait for manual push
            report += f"\n\n⏸️  Push NOT executed (requires manual approval)"
            report += f"\nReason: "
            if not auto_push_on_pass:
                report += "auto_push_on_pass is disabled"
            elif score < threshold:
                report += f"score {score:.1f} below threshold {threshold}"
            elif has_security_issues:
                report += "security issues found"
            
            report += f"\n\nTo push manually, run git push in the repo or fix issues and run push_with_review again"
            if workflow:
                artifact_paths = self._record_workflow_change_artifacts(
                    workspace,
                    workflow["workflow_id"],
                    repo_name=repo_name,
                    changed_files=[],
                    diff_text=diff,
                    review_message="AI review completed. Developer approval is required before push.",
                    stage="review_requested",
                    event_type="push_review_completed",
                )
                self.workflow_manager.update_session(
                    workspace.name,
                    workflow["workflow_id"],
                    artifacts={"push_review_path": review_artifact_path, **artifact_paths},
                )
                report += (
                    f"\n\nWorkflow '{workflow['workflow_id']}' updated:"
                    f"\n- Push review saved to: {review_artifact_path}"
                    f"\n- Developer review requested before push"
                )
        
        return [TextContent(type="text", text=report)]

    async def run(self):
        """Run the MCP server."""
        async with stdio_server() as (read_stream, write_stream):
            await self.server.run(
                read_stream,
                write_stream,
                self.server.create_initialization_options()
            )


def main():
    """Main entry point."""
    server = MultiRepoServer()
    asyncio.run(server.run())


if __name__ == "__main__":
    main()
