"""Repository URL parser and normalizer for flexible input formats."""

import re
from typing import Optional, Dict, Iterable
from urllib.parse import urlparse


class RepoURLParser:
    """Parse and normalize repository URLs from various input formats."""
    
    def __init__(
        self,
        default_org: Optional[str] = None,
        github_token: Optional[str] = None,
        token_injection_hosts: Optional[Iterable[str]] = None,
    ):
        """
        Initialize the URL parser.
        
        Args:
            default_org: Default GitHub organization to use for short repo names
            github_token: GitHub token for HTTPS authentication
        """
        self.default_org = default_org
        self.github_token = github_token
        self.token_injection_hosts = {h.lower() for h in (token_injection_hosts or ["github.com"])}
    
    def normalize_repo_input(self, repo_input: str) -> Dict[str, str]:
        """
        Normalize repository input to a standard format.
        
        Supports multiple input formats:
        1. Full HTTPS URL: https://github.com/org/repo.git
        2. Full SSH URL: git@github.com:org/repo.git
        3. org/repo format: example-org/example-repo
        4. Just repo name: example-repo (requires default_org)
        
        Args:
            repo_input: Repository input in any supported format
            
        Returns:
            Dictionary with 'url' (HTTPS), 'ssh_url', 'org', 'repo_name'
            
        Raises:
            ValueError: If input format is invalid or default_org is missing
        """
        repo_input = repo_input.strip()
        
        # Check if it's a full URL
        if repo_input.startswith('http://') or repo_input.startswith('https://'):
            return self._parse_https_url(repo_input)
        elif repo_input.startswith('git@'):
            return self._parse_ssh_url(repo_input)
        elif '/' in repo_input:
            # org/repo format
            return self._parse_org_repo(repo_input)
        else:
            # Just repo name
            return self._parse_repo_name(repo_input)
    
    def _parse_https_url(self, url: str) -> Dict[str, str]:
        """Parse full HTTPS URL."""
        # Remove .git suffix if present
        clean_url = url.rstrip('/')
        if clean_url.endswith('.git'):
            clean_url = clean_url[:-4]
        
        # Parse URL
        parsed = urlparse(url)
        path_parts = parsed.path.strip('/').split('/')
        
        if len(path_parts) < 2:
            raise ValueError(f"Invalid GitHub URL format: {url}")
        
        org = path_parts[0]
        repo_name = path_parts[1].replace('.git', '')
        
        # Construct URLs
        https_url = f"https://github.com/{org}/{repo_name}.git"
        ssh_url = f"git@github.com:{org}/{repo_name}.git"
        
        return {
            'url': https_url,
            'ssh_url': ssh_url,
            'org': org,
            'repo_name': repo_name,
            'display_name': f"{org}/{repo_name}"
        }
    
    def _parse_ssh_url(self, url: str) -> Dict[str, str]:
        """Parse SSH URL format."""
        # Pattern: git@github.com:org/repo.git
        match = re.match(r'git@github\.com:(.+)/(.+?)(?:\.git)?$', url)
        
        if not match:
            raise ValueError(f"Invalid SSH URL format: {url}")
        
        org = match.group(1)
        repo_name = match.group(2)
        
        # Construct URLs
        https_url = f"https://github.com/{org}/{repo_name}.git"
        ssh_url = f"git@github.com:{org}/{repo_name}.git"
        
        return {
            'url': https_url,
            'ssh_url': ssh_url,
            'org': org,
            'repo_name': repo_name,
            'display_name': f"{org}/{repo_name}"
        }
    
    def _parse_org_repo(self, org_repo: str) -> Dict[str, str]:
        """Parse org/repo format."""
        parts = org_repo.split('/')
        
        if len(parts) != 2:
            raise ValueError(f"Invalid org/repo format: {org_repo}. Expected 'org/repo'")
        
        org, repo_name = parts
        repo_name = repo_name.replace('.git', '')
        
        # Construct URLs
        https_url = f"https://github.com/{org}/{repo_name}.git"
        ssh_url = f"git@github.com:{org}/{repo_name}.git"
        
        return {
            'url': https_url,
            'ssh_url': ssh_url,
            'org': org,
            'repo_name': repo_name,
            'display_name': f"{org}/{repo_name}"
        }
    
    def _parse_repo_name(self, repo_name: str) -> Dict[str, str]:
        """Parse just repository name (requires default_org)."""
        if not self.default_org:
            raise ValueError(
                f"Cannot parse '{repo_name}' without a default organization. "
                "Please provide 'org/repo' format or set 'github_org' in config."
            )
        
        repo_name = repo_name.replace('.git', '')
        
        # Construct URLs
        https_url = f"https://github.com/{self.default_org}/{repo_name}.git"
        ssh_url = f"git@github.com:{self.default_org}/{repo_name}.git"
        
        return {
            'url': https_url,
            'ssh_url': ssh_url,
            'org': self.default_org,
            'repo_name': repo_name,
            'display_name': f"{self.default_org}/{repo_name}"
        }
    
    def inject_token_if_https(self, url: str) -> str:
        """
        Inject GitHub token into HTTPS URL if available.
        
        Args:
            url: Repository URL
            
        Returns:
            URL with token injected if HTTPS and token available
        """
        if not self.github_token or not url.startswith('https://'):
            return url

        try:
            host = urlparse(url).hostname or ""
        except Exception:
            return url

        if host.lower() not in self.token_injection_hosts:
            return url
        
        # Check if token already in URL
        if '@' in url:
            return url
        
        # Inject token: https://github.com/... -> https://TOKEN@github.com/...
        return url.replace('https://github.com/', f'https://{self.github_token}@github.com/')


def normalize_repo_list(
    repos: list,
    default_org: Optional[str] = None,
    github_token: Optional[str] = None,
    token_injection_hosts: Optional[Iterable[str]] = None,
) -> list:
    """
    Normalize a list of repository inputs to standard format.
    
    Args:
        repos: List of repository inputs in various formats
        default_org: Default organization for short repo names
        github_token: GitHub token for authentication
        
    Returns:
        List of normalized repository dictionaries
    """
    parser = RepoURLParser(default_org, github_token, token_injection_hosts)
    normalized = []
    
    for repo in repos:
        try:
            repo_info = parser.normalize_repo_input(repo)
            # Avoid persisting tokens; keep auth_url identical to url for in-memory use
            repo_info['auth_url'] = repo_info['url']
            normalized.append(repo_info)
        except ValueError as e:
            # Return error info for this repo
            normalized.append({
                'error': str(e),
                'input': repo
            })
    
    return normalized
