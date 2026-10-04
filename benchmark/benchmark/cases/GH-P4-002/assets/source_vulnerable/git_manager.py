"""Git operations with configurable SSH key support."""

import os
import sys
import shutil
import subprocess
import re
from pathlib import Path
from typing import Optional, List, Iterable
from datetime import datetime
from urllib.parse import urlparse
from git import Repo, GitCommandError


class GitManager:
    """Manages Git operations for repositories with configurable SSH key and GitHub token."""

    def __init__(
        self,
        ssh_key_path: Optional[str] = None,
        github_token: Optional[str] = None,
        token_injection_hosts: Optional[Iterable[str]] = None,
        github_orgs: Optional[Iterable[str]] = None,
        log_ascii: bool = False,
        git_clone_mode: Optional[str] = None,
    ):
        """
        Initialize GitManager.
        
        Args:
            ssh_key_path: Path to SSH private key. User can specify any path.
                         If None, will try to auto-detect common keys.
            github_token: GitHub Personal Access Token for HTTPS authentication.
                         If provided, will be automatically injected into HTTPS URLs.
        """
        self.ssh_key_path = ssh_key_path
        self.github_token = github_token or os.environ.get('GITHUB_TOKEN')
        self.token_injection_hosts = {h.lower() for h in (token_injection_hosts or ["github.com"])}
        self.github_orgs = [o for o in (github_orgs or []) if o]
        self.log_ascii = log_ascii
        self.git_clone_mode = (git_clone_mode or "auto").lower()
        
        if self.ssh_key_path:
            # Expand user home directory if ~ is used
            self.ssh_key_path = os.path.expanduser(self.ssh_key_path)
            
        self._setup_ssh_env()

    def _log(self, message: str) -> None:
        """Log message safely on Windows consoles."""
        if self.log_ascii:
            try:
                message = message.encode("ascii", "ignore").decode("ascii")
            except Exception:
                message = str(message)
        print(message, file=sys.stderr)

    def _setup_ssh_env(self) -> None:
        """Setup SSH environment for Git operations."""
        # On Windows, use Windows OpenSSH which connects to the SSH agent
        if sys.platform == 'win32':
            # Use Windows OpenSSH that connects to the ssh-agent service
            os.environ['GIT_SSH_COMMAND'] = 'C:/Windows/System32/OpenSSH/ssh.exe -o StrictHostKeyChecking=no'
            self._log("✓ Using Windows OpenSSH with SSH agent")
        elif self.ssh_key_path and os.path.exists(self.ssh_key_path):
            # On Unix/Linux, use the specified SSH key
            os.environ['GIT_SSH_COMMAND'] = f'ssh -i "{self.ssh_key_path}" -o StrictHostKeyChecking=no'
            self._log(f"✓ Using SSH key: {self.ssh_key_path}")
        else:
            # Use default SSH configuration (git will use ~/.ssh/config)
            os.environ['GIT_SSH_COMMAND'] = 'ssh -o StrictHostKeyChecking=no'
            self._log("✓ Using default SSH configuration")

    def _inject_token_into_url(self, url: str) -> str:
        """
        Inject GitHub token into HTTPS URL if available.
        
        Args:
            url: Repository URL (SSH or HTTPS)
            
        Returns:
            URL with token injected if HTTPS and token available, otherwise original URL
        """
        # If no token, return original URL
        if not self.github_token:
            return url
        
        # Only process HTTPS URLs to trusted hosts
        if not url.startswith('https://'):
            return url

        try:
            host = urlparse(url).hostname or ""
        except Exception:
            return url

        if host.lower() not in self.token_injection_hosts:
            return url
        
        # Check if token is already in URL
        if '@' in url:
            return url
        
        # Inject token into HTTPS URL
        # Convert: https://github.com/org/repo.git
        # To: https://TOKEN@github.com/org/repo.git
        if url.startswith('https://github.com/'):
            url = url.replace('https://github.com/', f'https://{self.github_token}@github.com/')
            self._log("✓ Using GitHub token for authentication")
        elif url.startswith('https://'):
            # For other HTTPS URLs, try to inject token
            url = url.replace('https://', f'https://{self.github_token}@', 1)
            self._log("✓ Using token for HTTPS authentication")
        
        return url

    def _sanitize_url(self, url: str) -> str:
        """Mask credentials in URLs for logging."""
        if "://" in url:
            scheme, rest = url.split("://", 1)
            if "@" in rest:
                rest = rest.split("@", 1)[1]
                return f"{scheme}://***@{rest}"
        return url

    def _sanitize_text(self, text: str) -> str:
        """Mask any credentials in text."""
        return re.sub(r"(https?://)([^@/]+)@", r"\\1***@", text)

    def _use_cli_clone(self) -> bool:
        if self.git_clone_mode in {"cli", "command", "cmd", "git"}:
            return True
        if self.git_clone_mode in {"gitpython", "python", "lib"}:
            return False
        return sys.platform == "win32"

    def _is_local_clone_source(self, url: str) -> bool:
        """Return True when clone source is a local path or file URI."""
        if not url:
            return False
        if url.startswith("file://"):
            return True
        if re.match(r"^[A-Za-z]:[\\/]", url):
            return True
        if url.startswith(("./", "../", ".\\", "..\\")):
            return True
        try:
            return Path(url).exists()
        except Exception:
            return False

    def _normalize_clone_source(self, url: str) -> str:
        """Normalize clone source so local paths are unambiguous for Git on Windows."""
        if not self._is_local_clone_source(url):
            return url
        if url.startswith("file://"):
            return url
        try:
            return Path(url).resolve().as_uri()
        except Exception:
            return url

    def _local_source_path(self, url: str) -> Optional[Path]:
        """Resolve a local clone source into a filesystem path."""
        if not self._is_local_clone_source(url):
            return None
        if url.startswith("file://"):
            try:
                parsed = urlparse(url)
                return Path(parsed.path.lstrip("/")).resolve()
            except Exception:
                return None
        try:
            return Path(url).resolve()
        except Exception:
            return None

    def _clone_repo_local_copy(self, source: Path, destination: str, branch: Optional[str]) -> Repo:
        """Clone a local repository by copying the working tree and git metadata."""
        destination_path = Path(destination)
        if destination_path.exists():
            shutil.rmtree(destination_path)
        shutil.copytree(source, destination_path)
        repo = Repo(destination_path)
        if branch:
            try:
                repo.git.checkout(branch)
            except Exception:
                pass
        return repo

    def _clone_repo_cli(self, url: str, destination: str, depth: Optional[int], branch: Optional[str]) -> None:
        cmd: list[str] = ["git", "clone", "-v", "-c", "core.longpaths=true"]
        if depth:
            cmd += ["--depth", str(depth)]
        if branch:
            cmd += ["--branch", branch]
        cmd += ["--", url, destination]

        env = os.environ.copy()
        env.setdefault("GIT_TERMINAL_PROMPT", "0")
        env.setdefault("GIT_ASKPASS", "echo")
        env.setdefault("GCM_INTERACTIVE", "Never")

        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
            check=False,
        )
        if result.returncode != 0:
            stderr = (result.stderr or "").strip()
            stdout = (result.stdout or "").strip()
            details = stderr or stdout or f"git clone failed with exit {result.returncode}"
            raise Exception(self._sanitize_text(details))

    def _parse_github_url(self, url: str) -> tuple[Optional[str], Optional[str], bool]:
        """Extract org/repo from GitHub URL. Returns (org, repo, is_ssh)."""
        if url.startswith("git@"):
            try:
                host = url.split("@", 1)[1].split(":", 1)[0]
                if host.lower() != "github.com":
                    return None, None, True
                path = url.split(":", 1)[1]
                parts = path.strip("/").split("/")
                if len(parts) < 2:
                    return None, None, True
                org = parts[0]
                repo = parts[1].replace(".git", "")
                return org, repo, True
            except Exception:
                return None, None, True

        if url.startswith("https://") or url.startswith("http://"):
            try:
                parsed = urlparse(url)
                if (parsed.hostname or "").lower() != "github.com":
                    return None, None, False
                parts = parsed.path.strip("/").split("/")
                if len(parts) < 2:
                    return None, None, False
                org = parts[0]
                repo = parts[1].replace(".git", "")
                return org, repo, False
            except Exception:
                return None, None, False

        return None, None, False

    def _alternate_org_urls(self, url: str) -> list[str]:
        """Build alternate GitHub URLs using configured orgs."""
        if not self.github_orgs:
            return []

        org, repo, is_ssh = self._parse_github_url(url)
        if not repo:
            return []

        candidates: list[str] = []
        for org_name in self.github_orgs:
            if org and org_name.lower() == org.lower():
                continue
            if is_ssh:
                candidates.append(f"git@github.com:{org_name}/{repo}.git")
            else:
                candidates.append(f"https://github.com/{org_name}/{repo}.git")
        return candidates

    def clone_repo(
        self,
        url: str,
        destination: str,
        depth: Optional[int] = 1,
        branch: Optional[str] = None
    ) -> Repo:
        """
        Clone a Git repository.
        
        Args:
            url: Repository URL (supports git@github.com:... or https://...)
            destination: Local path where to clone
            depth: Clone depth (use 1 for shallow clone, None for full)
            branch: Specific branch to clone
            
        Returns:
            Cloned repository object
        """
        # Inject token into HTTPS URLs if available
        auth_url = self._inject_token_into_url(url)
        
        # Create parent directory if it doesn't exist
        Path(destination).parent.mkdir(parents=True, exist_ok=True)

        # If destination already exists, try to open existing repo
        if os.path.exists(destination):
            try:
                repo = Repo(destination)
                self._log(f"✓ Repository already exists: {destination}")
                return repo
            except Exception:
                pass  # If not a valid repo, we'll clone

        # Prepare clone options
        kwargs = {}
        if depth:
            kwargs['depth'] = depth
        if branch:
            kwargs['branch'] = branch

        candidates: list[str] = []

        def add_candidate(candidate: str) -> None:
            if candidate and candidate not in candidates:
                candidates.append(candidate)

        add_candidate(auth_url)
        if url != auth_url:
            add_candidate(url)

        for alt in self._alternate_org_urls(url):
            add_candidate(self._inject_token_into_url(alt))
            add_candidate(alt)

        errors: list[str] = []
        ssh_failed = False
        https_failed = False

        for candidate in candidates:
            try:
                normalized_candidate = self._normalize_clone_source(candidate)
                clone_kwargs = dict(kwargs)
                display_url = self._sanitize_url(normalized_candidate)
                self._log(f"Cloning {display_url} to {destination}...")
                local_source = self._local_source_path(normalized_candidate)
                if local_source and local_source.exists():
                    repo = self._clone_repo_local_copy(local_source, destination, branch)
                elif self._use_cli_clone() and not self._is_local_clone_source(normalized_candidate):
                    self._clone_repo_cli(normalized_candidate, destination, depth, branch)
                    repo = Repo(destination)
                else:
                    repo = Repo.clone_from(normalized_candidate, destination, **clone_kwargs)
                self._log(f"✓ Successfully cloned {display_url}")
                return repo
            except Exception as e:
                error_msg = self._sanitize_text(str(e))
                if "Permission denied" in error_msg or "publickey" in error_msg:
                    ssh_failed = True
                if "Authentication failed" in error_msg or "could not read Username" in error_msg:
                    https_failed = True
                errors.append(f"{self._sanitize_url(normalized_candidate)}: {error_msg}")
                if os.path.exists(destination):
                    try:
                        shutil.rmtree(destination)
                    except Exception:
                        pass

        if ssh_failed and https_failed:
            raise Exception(
                "Authentication failed for SSH and HTTPS. "
                "Check your SSH key and GitHub token.\nTried:\n" + "\n".join(errors)
            )
        if ssh_failed:
            raise Exception(
                f"SSH authentication failed for {self._sanitize_url(url)}. "
                f"Please check your SSH key: {self.ssh_key_path}\nTried:\n" + "\n".join(errors)
            )
        if https_failed:
            raise Exception(
                f"HTTPS authentication failed for {self._sanitize_url(url)}. "
                "Please add GitHub token to config/default_config.json\nTried:\n" + "\n".join(errors)
            )
        raise Exception(f"Failed to clone {self._sanitize_url(url)}:\n" + "\n".join(errors))

    def pull_repo(self, repo_path: str) -> bool:
        """
        Pull latest changes from remote.
        
        Args:
            repo_path: Path to local repository
            
        Returns:
            True if successful, False otherwise
        """
        try:
            repo = Repo(repo_path)
            if repo.bare:
                return False
            
            origin = repo.remotes.origin
            origin.pull()
            self._log(f"✓ Successfully pulled updates for {repo_path}")
            return True
        except Exception as e:
            self._log(f"✗ Failed to pull {repo_path}: {str(e)}")
            return False

    def get_current_branch(self, repo_path: str) -> Optional[str]:
        """Get current branch name."""
        try:
            repo = Repo(repo_path)
            return repo.active_branch.name
        except Exception:
            return None

    def get_last_commit_date(self, repo_path: str) -> Optional[str]:
        """Get last commit date in ISO format."""
        try:
            repo = Repo(repo_path)
            last_commit = repo.head.commit
            return datetime.fromtimestamp(last_commit.committed_date).isoformat()
        except Exception:
            return None

    def checkout_branch(self, repo_path: str, branch: str, create: bool = False) -> bool:
        """
        Checkout a branch.
        
        Args:
            repo_path: Path to local repository
            branch: Branch name
            create: Create branch if it doesn't exist
            
        Returns:
            True if successful, False otherwise
        """
        try:
            repo = Repo(repo_path)
            
            if create and branch not in repo.heads:
                # Create new branch
                repo.create_head(branch)
            
            # Checkout branch
            repo.heads[branch].checkout()
            self._log(f"✓ Checked out branch: {branch}")
            return True
        except Exception as e:
            self._log(f"✗ Failed to checkout branch {branch}: {str(e)}")
            return False

    def get_repo_info(self, repo_path: str) -> dict:
        """
        Get repository information.
        
        Returns:
            Dictionary with repo info (branch, remote, last_commit, etc.)
        """
        try:
            repo = Repo(repo_path)
            
            info = {
                "path": repo_path,
                "branch": repo.active_branch.name if not repo.head.is_detached else "detached",
                "remote_url": repo.remotes.origin.url if repo.remotes else None,
                "last_commit_date": self.get_last_commit_date(repo_path),
                "is_dirty": repo.is_dirty(),
                "untracked_files": len(repo.untracked_files)
            }
            
            return info
        except Exception as e:
            return {"error": str(e)}

    def list_branches(self, repo_path: str) -> List[str]:
        """List all branches in repository."""
        try:
            repo = Repo(repo_path)
            return [head.name for head in repo.heads]
        except Exception:
            return []

    def get_remote_url(self, repo_path: str) -> Optional[str]:
        """Get remote origin URL."""
        try:
            repo = Repo(repo_path)
            if repo.remotes:
                return repo.remotes.origin.url
            return None
        except Exception:
            return None

    def is_repo_valid(self, repo_path: str) -> bool:
        """Check if path is a valid Git repository."""
        try:
            Repo(repo_path)
            return True
        except Exception:
            return False

    def get_repo_status(self, repo_path: str) -> dict:
        """
        Get detailed repository status.
        
        Returns:
            Dictionary with detailed status information
        """
        try:
            repo = Repo(repo_path)
            
            # Get modified files
            modified = [item.a_path for item in repo.index.diff(None)]
            staged = [item.a_path for item in repo.index.diff('HEAD')]
            untracked = repo.untracked_files
            
            status = {
                "path": repo_path,
                "branch": repo.active_branch.name if not repo.head.is_detached else "detached",
                "is_dirty": repo.is_dirty(),
                "modified_files": modified,
                "staged_files": staged,
                "untracked_files": untracked,
                "has_uncommitted_changes": len(modified) > 0 or len(staged) > 0,
                "remote_url": repo.remotes.origin.url if repo.remotes else None,
            }
            
            # Check for unpushed commits
            try:
                if not repo.head.is_detached:
                    branch = repo.active_branch
                    if branch.tracking_branch():
                        commits_ahead = list(repo.iter_commits(f'{branch.tracking_branch()}..{branch}'))
                        commits_behind = list(repo.iter_commits(f'{branch}..{branch.tracking_branch()}'))
                        status["commits_ahead"] = len(commits_ahead)
                        status["commits_behind"] = len(commits_behind)
            except Exception:
                pass
            
            return status
        except Exception as e:
            return {"error": str(e)}

    def stage_files(self, repo_path: str, files: Optional[List[str]] = None) -> bool:
        """
        Stage files for commit.
        
        Args:
            repo_path: Path to local repository
            files: List of file paths to stage. If None, stages all changes.
            
        Returns:
            True if successful, False otherwise
        """
        try:
            repo = Repo(repo_path)
            
            if files:
                # Stage specific files
                repo.index.add(files)
                self._log(f"✓ Staged {len(files)} file(s)")
            else:
                # Stage all changes
                repo.git.add(A=True)
                self._log("✓ Staged all changes")
            
            return True
        except Exception as e:
            self._log(f"✗ Failed to stage files: {str(e)}")
            return False

    def commit_changes(self, repo_path: str, message: str, author_name: Optional[str] = None, 
                      author_email: Optional[str] = None) -> bool:
        """
        Commit staged changes.
        
        Args:
            repo_path: Path to local repository
            message: Commit message
            author_name: Optional author name (uses git config if not provided)
            author_email: Optional author email (uses git config if not provided)
            
        Returns:
            True if successful, False otherwise
        """
        try:
            repo = Repo(repo_path)
            
            # Check if there are staged changes
            if not repo.index.diff("HEAD"):
                self._log("✗ No staged changes to commit")
                return False
            
            # Set author if provided
            if author_name and author_email:
                author = f"{author_name} <{author_email}>"
                repo.index.commit(message, author=author)
            else:
                repo.index.commit(message)
            
            self._log(f"✓ Committed changes: {message}")
            return True
        except Exception as e:
            self._log(f"✗ Failed to commit: {str(e)}")
            return False

    def push_changes(self, repo_path: str, branch: Optional[str] = None, 
                    set_upstream: bool = False) -> bool:
        """
        Push changes to remote.
        
        Args:
            repo_path: Path to local repository
            branch: Branch to push (uses current branch if not specified)
            set_upstream: Set upstream tracking if True
            
        Returns:
            True if successful, False otherwise
        """
        try:
            repo = Repo(repo_path)
            origin = repo.remotes.origin
            
            if not branch:
                if repo.head.is_detached:
                    self._log("✗ Cannot push from detached HEAD")
                    return False
                branch = repo.active_branch.name
            
            # Push
            if set_upstream:
                origin.push(refspec=f'{branch}:{branch}', set_upstream=True)
            else:
                origin.push(branch)
            
            self._log(f"✓ Pushed {branch} to remote")
            return True
        except Exception as e:
            self._log(f"✗ Failed to push: {str(e)}")
            return False

    def create_branch(self, repo_path: str, branch_name: str, checkout: bool = True) -> bool:
        """
        Create a new branch.
        
        Args:
            repo_path: Path to local repository
            branch_name: Name of new branch
            checkout: Whether to checkout the new branch
            
        Returns:
            True if successful, False otherwise
        """
        try:
            repo = Repo(repo_path)
            
            # Check if branch already exists
            if branch_name in [head.name for head in repo.heads]:
                self._log(f"✗ Branch '{branch_name}' already exists")
                return False
            
            # Create branch
            new_branch = repo.create_head(branch_name)
            
            if checkout:
                new_branch.checkout()
                self._log(f"✓ Created and checked out branch: {branch_name}")
            else:
                self._log(f"✓ Created branch: {branch_name}")
            
            return True
        except Exception as e:
            self._log(f"✗ Failed to create branch: {str(e)}")
            return False

    def delete_branch(self, repo_path: str, branch_name: str, force: bool = False) -> bool:
        """
        Delete a branch.
        
        Args:
            repo_path: Path to local repository
            branch_name: Name of branch to delete
            force: Force delete even if not merged
            
        Returns:
            True if successful, False otherwise
        """
        try:
            repo = Repo(repo_path)
            
            # Cannot delete current branch
            if not repo.head.is_detached and repo.active_branch.name == branch_name:
                self._log("✗ Cannot delete current branch")
                return False
            
            # Delete branch
            if force:
                repo.delete_head(branch_name, force=True)
            else:
                repo.delete_head(branch_name)
            
            self._log(f"✓ Deleted branch: {branch_name}")
            return True
        except Exception as e:
            self._log(f"✗ Failed to delete branch: {str(e)}")
            return False

    def fetch_all(self, repo_path: str, prune: bool = True) -> bool:
        """
        Fetch all remotes.
        
        Args:
            repo_path: Path to local repository
            prune: Remove remote tracking branches that no longer exist
            
        Returns:
            True if successful, False otherwise
        """
        try:
            repo = Repo(repo_path)
            
            for remote in repo.remotes:
                if prune:
                    remote.fetch(prune=True)
                else:
                    remote.fetch()
            
            self._log("✓ Fetched all remotes")
            return True
        except Exception as e:
            self._log(f"✗ Failed to fetch: {str(e)}")
            return False

    def get_commit_history(self, repo_path: str, max_count: int = 10) -> List[dict]:
        """
        Get commit history.
        
        Args:
            repo_path: Path to local repository
            max_count: Maximum number of commits to retrieve
            
        Returns:
            List of commit information dictionaries
        """
        try:
            repo = Repo(repo_path)
            commits = []
            
            for commit in repo.iter_commits(max_count=max_count):
                commits.append({
                    "hash": commit.hexsha[:8],
                    "author": str(commit.author),
                    "date": datetime.fromtimestamp(commit.committed_date).isoformat(),
                    "message": commit.message.strip()
                })
            
            return commits
        except Exception:
            return []

    def get_uncommitted_diff(self, repo_path: str) -> Optional[str]:
        """
        Get diff of uncommitted changes (staged + unstaged).
        
        Args:
            repo_path: Path to local repository
            
        Returns:
            Diff string or None if no changes
        """
        try:
            repo = Repo(repo_path)
            
            # Get diff of uncommitted changes
            # This includes both staged and unstaged changes
            diff = repo.git.diff('HEAD')
            
            if not diff:
                # No changes
                return None
            
            return diff
        except Exception as e:
            self._log(f"✗ Failed to get diff: {str(e)}")
            return None

    def get_staged_diff(self, repo_path: str) -> Optional[str]:
        """
        Get diff of staged changes.
        
        Args:
            repo_path: Path to local repository
            
        Returns:
            Diff string or None if no staged changes
        """
        try:
            repo = Repo(repo_path)
            diff = repo.git.diff('--cached')
            if not diff:
                return None
            return diff
        except Exception as e:
            self._log(f"✗ Failed to get staged diff: {str(e)}")
            return None

    def get_unpushed_diff(self, repo_path: str) -> Optional[str]:
        """
        Get diff of unpushed commits.
        
        Args:
            repo_path: Path to local repository
            
        Returns:
            Diff string or None if no unpushed commits
        """
        try:
            repo = Repo(repo_path)
            
            # Get current branch
            if repo.head.is_detached:
                return None
            
            branch = repo.active_branch
            
            # Check if tracking branch exists
            if not branch.tracking_branch():
                # No tracking branch, diff from initial commit on this branch
                try:
                    root_commit = repo.git.rev_list('--max-parents=0', branch.name).splitlines()[-1]
                    diff = repo.git.diff(f'{root_commit}..{branch.name}')
                    return diff
                except Exception:
                    # Fallback to last commit if root lookup fails
                    diff = repo.git.diff(f'{branch.commit.hexsha}^..{branch.commit.hexsha}')
                    return diff
            
            # Get diff between local and remote
            tracking = branch.tracking_branch()
            diff = repo.git.diff(f'{tracking.name}..{branch.name}')
            
            if not diff:
                return None
            
            return diff
        except Exception as e:
            self._log(f"✗ Failed to get unpushed diff: {str(e)}")
            return None

    def get_latest_semantic_version(self, repo_path: str, branch: str = "develop") -> Optional[str]:
        """
        Get the latest semantic version from a branch by parsing commit messages.
        
        Args:
            repo_path: Path to local repository
            branch: Branch to check (default: develop)
            
        Returns:
            Latest version string or None
        """
        try:
            repo = Repo(repo_path)
            # Try to find version tags
            tags = sorted(repo.tags, key=lambda t: t.commit.committed_datetime, reverse=True)
            if tags:
                return str(tags[0])
            
            # If no tags, return default version
            return "0.0.0"
        except Exception as e:
            self._log(f"✗ Failed to get semantic version: {str(e)}")
            return None

    def commit_semantic_release_repo(
        self, 
        repo_path: str, 
        commit_type: str, 
        scope: str, 
        subject: str,
        body: Optional[str] = None,
        breaking_changes: Optional[str] = None,
        issues_closed: Optional[str] = None
    ) -> dict:
        """
        Commit changes for repositories that enforce semantic-release commit conventions.
        
        Args:
            repo_path: Path to local repository
            commit_type: Type of commit (feat, fix, docs, etc.)
            scope: Scope of changes (component/module name)
            subject: Short description of changes
            body: Longer description (optional)
            breaking_changes: Breaking changes description (optional)
            issues_closed: Issues closed by this commit (optional)
            
        Returns:
            Dictionary with status and message
        """
        try:
            import subprocess
            
            repo = Repo(repo_path)
            
            # Step 1: Run lint-staged:fix (pre-commit checks)
            self._log("🔍 Running lint-staged:fix...")
            try:
                lint_result = subprocess.run(
                    "npm run lint-staged:fix",
                    shell=True,
                    cwd=repo_path,
                    capture_output=True,
                    text=True,
                    timeout=60
                )
                if lint_result.returncode != 0:
                    return {
                        "success": False,
                        "message": f"Linting failed: {lint_result.stderr}"
                    }
                self._log("✓ Linting passed")
            except subprocess.TimeoutExpired:
                return {
                    "success": False,
                    "message": "Linting timed out after 60 seconds"
                }
            
            # Step 2: Get latest semantic version from develop
            self._log("📋 Checking semantic version...")
            version = self.get_latest_semantic_version(repo_path)
            self._log(f"✓ Current version: {version}")
            
            # Step 3: Format commit message
            commit_message = f"{commit_type}({scope}): {subject}"
            
            if body:
                commit_message += f"\n\n{body}"
            
            if breaking_changes:
                commit_message += f"\n\nBREAKING CHANGE: {breaking_changes}"
            
            if issues_closed:
                commit_message += f"\n\nCloses {issues_closed}"
            
            # Step 4: Commit with --no-verify to bypass interactive prompt
            self._log("💾 Committing changes...")
            try:
                commit_result = subprocess.run(
                    f'git commit -m "{commit_message}" --no-verify',
                    shell=True,
                    cwd=repo_path,
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                if commit_result.returncode == 0:
                    self._log("✓ Commit successful")
                    return {
                        "success": True,
                        "message": f"Successfully committed with message: {commit_message}",
                        "version": version
                    }
                else:
                    return {
                        "success": False,
                        "message": f"Commit failed: {commit_result.stderr}"
                    }
            except subprocess.TimeoutExpired:
                return {
                    "success": False,
                    "message": "Commit timed out after 30 seconds"
                }
                
        except Exception as e:
            self._log(f"✗ Semantic-release commit failed: {str(e)}")
            return {
                "success": False,
                "message": str(e)
            }
