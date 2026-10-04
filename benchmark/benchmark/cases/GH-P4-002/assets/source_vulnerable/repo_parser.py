"""Repository URL parser and normalizer."""

import re
from typing import Optional, Dict


class RepoParser:
    """Parse and normalize repository identifiers into proper URLs."""

    def __init__(self, default_org: Optional[str] = None, default_host: str = "github.com"):
        """
        Initialize RepoParser.

        Args:
            default_org: Default GitHub organization (e.g., "example-org")
            default_host: Default Git host (default: "github.com")
        """
        self.default_org = default_org
        self.default_host = default_host

    def parse(self, repo_input: str) -> Dict[str, str]:
        """
        Parse repository input and return normalized information.

        Supported formats:
        1. Full HTTPS URL: https://github.com/example-org/example-repo.git
        2. Full SSH URL: git@github.com:example-org/example-repo.git
        3. Org/Repo: example-org/example-repo
        4. Just repo name: example-repo (uses default_org)

        Args:
            repo_input: Repository identifier in any supported format

        Returns:
            Dictionary with:
            - url: HTTPS URL (for cloning)
            - org: Organization name
            - repo: Repository name
            - host: Git host
            - original: Original input
            - format: Parsed input format
        """
        repo_input = repo_input.strip()

        # Pattern 1: Full HTTPS URL
        https_match = re.match(
            r'https?://([^/]+)/([^/]+)/([^/\s]+?)(?:\.git)?$',
            repo_input
        )
        if https_match:
            host, org, repo = https_match.groups()
            repo = repo.rstrip('.git')
            return {
                'url': f'https://{host}/{org}/{repo}.git',
                'org': org,
                'repo': repo,
                'host': host,
                'original': repo_input,
                'format': 'https_url'
            }

        # Pattern 2: Full SSH URL
        ssh_match = re.match(
            r'git@([^:]+):([^/]+)/([^/\s]+?)(?:\.git)?$',
            repo_input
        )
        if ssh_match:
            host, org, repo = ssh_match.groups()
            repo = repo.rstrip('.git')
            return {
                'url': f'https://{host}/{org}/{repo}.git',
                'org': org,
                'repo': repo,
                'host': host,
                'original': repo_input,
                'format': 'ssh_url'
            }

        # Pattern 3: Org/Repo format
        org_repo_match = re.match(r'^([^/\s]+)/([^/\s]+?)(?:\.git)?$', repo_input)
        if org_repo_match:
            org, repo = org_repo_match.groups()
            repo = repo.rstrip('.git')
            return {
                'url': f'https://{self.default_host}/{org}/{repo}.git',
                'org': org,
                'repo': repo,
                'host': self.default_host,
                'original': repo_input,
                'format': 'org_repo'
            }

        # Pattern 4: Just repo name
        if self.default_org:
            repo = repo_input.rstrip('.git')
            return {
                'url': f'https://{self.default_host}/{self.default_org}/{repo}.git',
                'org': self.default_org,
                'repo': repo,
                'host': self.default_host,
                'original': repo_input,
                'format': 'repo_only'
            }

        raise ValueError(
            f"Cannot parse '{repo_input}' without a default organization. "
            "Please provide 'org/repo' format or set default_org."
        )
