"""Workspace management for multi-repo projects."""

import json
import os
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict


@dataclass
class RepoInfo:
    """Information about a repository in a workspace."""
    name: str
    url: str
    local_path: str
    branch: Optional[str] = None
    last_updated: Optional[str] = None


@dataclass
class Workspace:
    """A workspace containing multiple repositories."""
    name: str
    repos: List[RepoInfo]
    created_at: str
    active: bool = False


class WorkspaceManager:
    """Manages workspaces containing multiple Git repositories."""

    def __init__(self, storage_path: Path):
        self.storage_path = storage_path
        self.workspaces_dir = storage_path / "workspaces"
        self.workspaces_dir.mkdir(parents=True, exist_ok=True)
        self.config_file = storage_path / "workspaces.json"
        self._workspaces: Dict[str, Workspace] = {}
        self._load_workspaces()

    def _load_workspaces(self) -> None:
        """Load workspaces from config file."""
        if self.config_file.exists():
            try:
                with open(self.config_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    for ws_data in data.get("workspaces", []):
                        repos = [RepoInfo(**repo) for repo in ws_data.get("repos", [])]
                        workspace = Workspace(
                            name=ws_data["name"],
                            repos=repos,
                            created_at=ws_data["created_at"],
                            active=ws_data.get("active", False)
                        )
                        self._workspaces[workspace.name] = workspace
            except Exception as e:
                print(f"Error loading workspaces: {e}")

    def _save_workspaces(self) -> None:
        """Save workspaces to config file."""
        data = {
            "workspaces": [
                {
                    "name": ws.name,
                    "repos": [asdict(repo) for repo in ws.repos],
                    "created_at": ws.created_at,
                    "active": ws.active
                }
                for ws in self._workspaces.values()
            ]
        }
        self.config_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.config_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def create_workspace(self, name: str, repos: List[Dict[str, str]]) -> Workspace:
        """Create a new workspace with the given repositories."""
        from datetime import datetime
        
        if name in self._workspaces:
            raise ValueError(f"Workspace '{name}' already exists")

        workspace_dir = self.workspaces_dir / name
        workspace_dir.mkdir(parents=True, exist_ok=True)

        repo_infos = []
        for repo in repos:
            repo_url = repo["url"]
            # Extract repo name from URL
            repo_name = repo_url.rstrip("/").split("/")[-1].replace(".git", "")
            local_path = str(workspace_dir / repo_name)
            
            repo_info = RepoInfo(
                name=repo_name,
                url=repo_url,
                local_path=local_path
            )
            repo_infos.append(repo_info)

        workspace = Workspace(
            name=name,
            repos=repo_infos,
            created_at=datetime.now().isoformat(),
            active=False
        )

        self._workspaces[name] = workspace
        self._save_workspaces()
        return workspace

    def get_workspace(self, name: str) -> Optional[Workspace]:
        """Get a workspace by name."""
        return self._workspaces.get(name)

    def list_workspaces(self) -> List[Workspace]:
        """List all workspaces."""
        return list(self._workspaces.values())

    def set_active_workspace(self, name: str) -> Workspace:
        """Set a workspace as active."""
        if name not in self._workspaces:
            raise ValueError(f"Workspace '{name}' not found")

        # Deactivate all workspaces
        for ws in self._workspaces.values():
            ws.active = False

        # Activate the selected workspace
        self._workspaces[name].active = True
        self._save_workspaces()
        return self._workspaces[name]

    def get_active_workspace(self) -> Optional[Workspace]:
        """Get the currently active workspace."""
        for ws in self._workspaces.values():
            if ws.active:
                return ws
        return None

    def remove_repo_from_workspace(self, workspace_name: str, repo_name: str, delete_files: bool = False) -> None:
        """
        Remove a repository from workspace.
        
        Args:
            workspace_name: Workspace name
            repo_name: Repository name to remove
            delete_files: Whether to delete the repository folder
        """
        if workspace_name not in self._workspaces:
            raise ValueError(f"Workspace '{workspace_name}' not found")
        
        workspace = self._workspaces[workspace_name]
        
        # Find and remove repo
        repo_to_remove = None
        for i, repo in enumerate(workspace.repos):
            if repo.name == repo_name:
                repo_to_remove = repo
                workspace.repos.pop(i)
                break
        
        if not repo_to_remove:
            raise ValueError(f"Repository '{repo_name}' not found in workspace '{workspace_name}'")
        
        # Delete files if requested
        if delete_files:
            import shutil
            import stat
            
            def handle_remove_readonly(func, path, exc):
                """Error handler for Windows read-only files."""
                if os.path.exists(path):
                    # Remove read-only attribute and retry
                    os.chmod(path, stat.S_IWRITE)
                    func(path)
            
            repo_path = Path(repo_to_remove.local_path)
            if repo_path.exists():
                shutil.rmtree(repo_path, onerror=handle_remove_readonly)
        
        self._save_workspaces()

    def delete_workspace(self, name: str, delete_repos: bool = False) -> None:
        """Delete a workspace."""
        if name not in self._workspaces:
            raise ValueError(f"Workspace '{name}' not found")

        workspace = self._workspaces[name]
        
        if delete_repos:
            workspace_dir = self.workspaces_dir / name
            if workspace_dir.exists():
                import shutil
                import stat

                def handle_remove_readonly(func, path, exc):
                    """Error handler for Windows read-only files."""
                    try:
                        if os.path.exists(path):
                            os.chmod(path, stat.S_IWRITE)
                            func(path)
                    except Exception:
                        pass

                try:
                    shutil.rmtree(workspace_dir, onerror=handle_remove_readonly)
                except Exception:
                    pass

        del self._workspaces[name]
        self._save_workspaces()

    def export_workspace_config(self, name: str) -> dict:
        """Export workspace configuration."""
        if name not in self._workspaces:
            raise ValueError(f"Workspace '{name}' not found")
        
        workspace = self._workspaces[name]
        return {
            "name": workspace.name,
            "repos": [{"name": repo.name, "url": repo.url} for repo in workspace.repos],
            "created_at": workspace.created_at
        }

    def import_workspace_config(self, config: dict, new_name: Optional[str] = None) -> Workspace:
        """Import workspace from configuration."""
        name = new_name or config["name"]
        repos = [{"url": repo["url"]} for repo in config["repos"]]
        return self.create_workspace(name, repos)

    def add_repos_to_workspace(self, name: str, repos: List[Dict[str, str]]) -> tuple[Workspace, List[RepoInfo]]:
        """
        Add new repositories to an existing workspace.
        
        Args:
            name: Workspace name
            repos: List of repository URLs to add
            
        Returns:
            Tuple of (workspace, list of new RepoInfo objects added)
            
        Raises:
            ValueError: If workspace doesn't exist
        """
        if name not in self._workspaces:
            raise ValueError(f"Workspace '{name}' not found")
        
        workspace = self._workspaces[name]
        workspace_dir = self.workspaces_dir / name
        
        # Get existing repo names to avoid duplicates
        existing_repo_names = {repo.name for repo in workspace.repos}
        
        new_repos = []
        for repo in repos:
            repo_url = repo["url"]
            # Extract repo name from URL
            repo_name = repo_url.rstrip("/").split("/")[-1].replace(".git", "")
            
            # Skip if repo already exists in workspace
            if repo_name in existing_repo_names:
                continue
            
            local_path = str(workspace_dir / repo_name)
            
            repo_info = RepoInfo(
                name=repo_name,
                url=repo_url,
                local_path=local_path
            )
            new_repos.append(repo_info)
            workspace.repos.append(repo_info)
        
        if new_repos:
            self._save_workspaces()
        
        return workspace, new_repos

    def update_repo_info(self, workspace_name: str, repo_name: str, **kwargs) -> None:
        """Update repository information in a workspace."""
        workspace = self.get_workspace(workspace_name)
        if not workspace:
            raise ValueError(f"Workspace '{workspace_name}' not found")

        for repo in workspace.repos:
            if repo.name == repo_name:
                for key, value in kwargs.items():
                    if hasattr(repo, key):
                        setattr(repo, key, value)
                self._save_workspaces()
                return

        raise ValueError(f"Repository '{repo_name}' not found in workspace '{workspace_name}'")
