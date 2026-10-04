"""Cross-repository search functionality."""

import os
import re
import fnmatch
from pathlib import Path
from typing import List, Dict, Optional, Set
from dataclasses import dataclass


@dataclass
class SearchMatch:
    """A search match result."""
    repo_name: str
    file_path: str
    line_number: int
    line_content: str
    context_before: List[str]
    context_after: List[str]


class RepoSearcher:
    """Search across multiple repositories."""

    def __init__(self, exclude_patterns: Optional[List[str]] = None):
        """
        Initialize searcher.
        
        Args:
            exclude_patterns: List of glob patterns to exclude (e.g., '**/node_modules/**')
        """
        self.exclude_patterns = exclude_patterns or []

    def _should_exclude(self, path: Path) -> bool:
        """Check if path should be excluded based on patterns."""
        path_str = path.as_posix()
        for pattern in self.exclude_patterns:
            # Use glob-style matching (supports ** in most patterns)
            if fnmatch.fnmatch(path_str, pattern):
                return True
        return False

    def _get_file_encoding(self, file_path: Path) -> str:
        """Detect file encoding."""
        try:
            # Try UTF-8 first
            with open(file_path, 'r', encoding='utf-8') as f:
                f.read()
            return 'utf-8'
        except UnicodeDecodeError:
            # Fallback to latin-1
            return 'latin-1'

    def search_in_file(
        self,
        file_path: Path,
        pattern: str,
        context_lines: int = 3,
        is_regex: bool = True
    ) -> List[SearchMatch]:
        """
        Search for pattern in a single file.
        
        Args:
            file_path: Path to file
            pattern: Search pattern (regex or plain text)
            context_lines: Number of context lines before/after match
            is_regex: Whether pattern is regex or plain text
            
        Returns:
            List of matches
        """
        matches = []
        
        try:
            encoding = self._get_file_encoding(file_path)
            with open(file_path, 'r', encoding=encoding, errors='ignore') as f:
                lines = f.readlines()
            
            # Compile pattern
            if is_regex:
                regex = re.compile(pattern, re.IGNORECASE)
            else:
                regex = re.compile(re.escape(pattern), re.IGNORECASE)
            
            # Search each line
            for i, line in enumerate(lines):
                if regex.search(line):
                    # Get context
                    start = max(0, i - context_lines)
                    end = min(len(lines), i + context_lines + 1)
                    
                    context_before = [l.rstrip() for l in lines[start:i]]
                    context_after = [l.rstrip() for l in lines[i+1:end]]
                    
                    match = SearchMatch(
                        repo_name="",  # Will be set by caller
                        file_path=str(file_path),
                        line_number=i + 1,
                        line_content=line.rstrip(),
                        context_before=context_before,
                        context_after=context_after
                    )
                    matches.append(match)
        
        except re.error as e:
            raise ValueError(f"Invalid search pattern: {e}") from e
        except Exception:
            # Skip files that can't be read
            pass
        
        return matches

    def search_in_repo(
        self,
        repo_path: str,
        repo_name: str,
        pattern: str,
        file_pattern: Optional[str] = None,
        context_lines: int = 3,
        is_regex: bool = True
    ) -> List[SearchMatch]:
        """
        Search in a single repository.
        
        Args:
            repo_path: Path to repository
            repo_name: Name of repository
            pattern: Search pattern
            file_pattern: Optional file pattern filter (e.g., '*.java')
            context_lines: Number of context lines
            is_regex: Whether pattern is regex
            
        Returns:
            List of matches across all files
        """
        matches = []
        repo_path_obj = Path(repo_path)
        
        if not repo_path_obj.exists():
            return matches
        
        # Compile file pattern if provided
        file_regex = None
        if file_pattern:
            # Convert glob to regex
            file_regex_pattern = file_pattern.replace('.', r'\.').replace('*', '.*')
            file_regex = re.compile(file_regex_pattern)
        
        # Walk through repository
        for root, dirs, files in os.walk(repo_path):
            root_path = Path(root)
            
            # Skip excluded directories
            if self._should_exclude(root_path):
                dirs[:] = []  # Don't recurse into this directory
                continue
            
            # Filter out excluded directories
            dirs[:] = [d for d in dirs if not self._should_exclude(root_path / d)]
            
            for file in files:
                file_path = root_path / file
                
                # Skip if excluded
                if self._should_exclude(file_path):
                    continue
                
                # Apply file pattern filter
                if file_regex and not file_regex.match(file):
                    continue
                
                # Skip binary files
                if file.endswith(('.png', '.jpg', '.jpeg', '.gif', '.pdf', '.zip', 
                                  '.jar', '.class', '.exe', '.dll', '.so', '.dylib')):
                    continue
                
                # Search in file
                file_matches = self.search_in_file(file_path, pattern, context_lines, is_regex)
                
                # Set repo name and make path relative
                for match in file_matches:
                    match.repo_name = repo_name
                    try:
                        match.file_path = str(Path(match.file_path).relative_to(repo_path))
                    except ValueError:
                        pass  # Keep absolute path if relative fails
                
                matches.extend(file_matches)
        
        return matches

    def search_all_repos(
        self,
        repos: List[Dict[str, str]],
        pattern: str,
        file_pattern: Optional[str] = None,
        context_lines: int = 3,
        is_regex: bool = True,
        max_matches: int = 100
    ) -> List[SearchMatch]:
        """
        Search across multiple repositories.
        
        Args:
            repos: List of dicts with 'name' and 'path' keys
            pattern: Search pattern
            file_pattern: Optional file pattern filter
            context_lines: Number of context lines
            is_regex: Whether pattern is regex
            max_matches: Maximum number of matches to return
            
        Returns:
            List of matches across all repos
        """
        all_matches = []
        
        for repo in repos:
            repo_name = repo.get('name', 'unknown')
            repo_path = repo.get('path', '')
            
            if not repo_path:
                continue
            
            repo_matches = self.search_in_repo(
                repo_path, repo_name, pattern, file_pattern, context_lines, is_regex
            )
            all_matches.extend(repo_matches)
            
            # Stop if we've reached max matches
            if len(all_matches) >= max_matches:
                all_matches = all_matches[:max_matches]
                break
        
        return all_matches

    def find_file(self, repos: List[Dict[str, str]], filename: str) -> List[str]:
        """
        Find files by name across repositories.
        
        Args:
            repos: List of repositories
            filename: File name to search for (can be partial)
            
        Returns:
            List of file paths
        """
        found_files = []
        
        for repo in repos:
            repo_name = repo.get('name', 'unknown')
            repo_path = repo.get('path', '')
            
            if not repo_path or not os.path.exists(repo_path):
                continue
            
            for root, dirs, files in os.walk(repo_path):
                root_path = Path(root)
                
                # Skip excluded directories
                if self._should_exclude(root_path):
                    dirs[:] = []
                    continue
                
                dirs[:] = [d for d in dirs if not self._should_exclude(root_path / d)]
                
                for file in files:
                    if filename.lower() in file.lower():
                        file_path = root_path / file
                        try:
                            rel_path = file_path.relative_to(repo_path)
                            found_files.append(f"{repo_name}:{rel_path}")
                        except ValueError:
                            found_files.append(f"{repo_name}:{file_path}")
        
        return found_files
