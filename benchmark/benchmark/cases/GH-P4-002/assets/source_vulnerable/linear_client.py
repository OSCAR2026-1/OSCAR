"""Linear API client for fetching and normalizing tickets."""

from __future__ import annotations

from typing import Any, Optional
import re

import requests


class LinearClientError(RuntimeError):
    """Base error for Linear client failures."""


class LinearValidationError(LinearClientError):
    """Raised when the caller provides invalid ticket input."""


class LinearAuthError(LinearClientError):
    """Raised when Linear authentication fails."""


class LinearRequestError(LinearClientError):
    """Raised for transport, schema, or response-shape failures."""


class LinearNotFoundError(LinearClientError):
    """Raised when the requested Linear issue does not exist."""


class LinearClient:
    """Small Linear GraphQL client with normalized issue output."""

    def __init__(self, api_key: str, base_url: str = "https://api.linear.app/graphql"):
        self.api_key = api_key
        self.base_url = base_url

    def _authorization_value(self) -> str:
        """Build Authorization header value."""
        token = (self.api_key or "").strip()
        if not token:
            return ""
        if token.lower().startswith("bearer "):
            token = token.split(" ", 1)[1].strip()
        return token

    def _post(self, query: str, variables: dict[str, Any]) -> dict[str, Any]:
        """Execute a GraphQL request and convert failures to typed errors."""
        token = self._authorization_value()
        if not token:
            raise LinearAuthError("Linear API key is missing")

        headers = {
            "Authorization": token,
            "Content-Type": "application/json",
        }
        payload = {"query": query, "variables": variables}

        try:
            resp = requests.post(self.base_url, headers=headers, json=payload, timeout=30)
        except requests.RequestException as exc:
            raise LinearRequestError(f"Linear API request failed: {str(exc)}") from exc

        if resp.status_code in {401, 403}:
            body = (resp.text or "").strip()
            body_preview = body[:1000] + ("..." if len(body) > 1000 else "")
            raise LinearAuthError(
                f"Linear API authentication failed (HTTP {resp.status_code}). "
                f"Response: {body_preview or '<empty>'}"
            )

        if resp.status_code != 200:
            body = (resp.text or "").strip()
            body_preview = body[:2000] + ("..." if len(body) > 2000 else "")
            raise LinearRequestError(
                f"Linear API HTTP {resp.status_code}. "
                f"Response: {body_preview or '<empty>'}"
            )

        try:
            data = resp.json() if resp.content else {}
        except ValueError as exc:
            raise LinearRequestError("Linear API returned invalid JSON") from exc

        errors = data.get("errors") or []
        if errors:
            message = self._format_graphql_errors(errors)
            lowered = message.lower()
            if "auth" in lowered or "permission" in lowered or "unauthorized" in lowered:
                raise LinearAuthError(f"Linear API error: {message}")
            raise LinearRequestError(f"Linear API error: {message}")

        if "data" not in data:
            raise LinearRequestError("Linear API response did not include a data payload")

        return data["data"]

    def get_issue(self, issue_id_or_identifier: str) -> dict[str, Any]:
        """Fetch an issue by UUID or identifier (e.g., ENG-123)."""
        issue_key = self._validate_issue_input(issue_id_or_identifier)
        ident_match = re.match(r"^([A-Za-z0-9]+)-(\d+)$", issue_key)

        if ident_match:
            team_key = ident_match.group(1)
            number = int(ident_match.group(2))
            issue = self._get_issue_by_identifier(team_key, number)
        else:
            issue = self._get_issue_by_id(issue_key)

        if not issue:
            raise LinearNotFoundError(f"Linear issue '{issue_key}' was not found")

        return self._normalize_issue(issue)

    def _validate_issue_input(self, issue_id_or_identifier: str) -> str:
        """Validate ticket input before making a network call."""
        if not isinstance(issue_id_or_identifier, str):
            raise LinearValidationError("issue_id must be a non-empty string")

        issue_key = issue_id_or_identifier.strip()
        if not issue_key:
            raise LinearValidationError("issue_id must be a non-empty string")

        return issue_key

    def _get_issue_by_id(self, issue_id: str) -> Optional[dict[str, Any]]:
        """Fetch a ticket using Linear's direct issue lookup."""
        query = """
        query IssueById($id: String!) {
          issue(id: $id) {
            id
            identifier
            title
            description
            url
            state { name }
            priorityLabel
            team { name }
            project { name }
            labels { nodes { name } }
            assignee { name }
          }
        }
        """
        data = self._post(query, {"id": issue_id})
        return data.get("issue")

    def _get_issue_by_identifier(self, team_key: str, number: int) -> Optional[dict[str, Any]]:
        """Fetch a ticket using team key plus issue number."""
        query = """
        query IssueByTeamAndNumber($teamKey: String!, $number: Float!) {
          issues(filter: { team: { key: { eq: $teamKey } }, number: { eq: $number } }) {
            nodes {
              id
              identifier
              title
              description
              url
              state { name }
              priorityLabel
              team { name }
              project { name }
              labels { nodes { name } }
              assignee { name }
            }
          }
        }
        """
        data = self._post(query, {"teamKey": team_key, "number": float(number)})
        nodes = data.get("issues", {}).get("nodes", [])
        return nodes[0] if nodes else None

    def _normalize_issue(self, issue: dict[str, Any]) -> dict[str, Any]:
        """Flatten the GraphQL issue shape into a stable workflow-friendly payload."""
        label_nodes = (issue.get("labels") or {}).get("nodes") or []
        labels = [node.get("name") for node in label_nodes if node.get("name")]

        return {
            "id": issue.get("id"),
            "identifier": issue.get("identifier"),
            "title": issue.get("title") or "",
            "description": issue.get("description") or "",
            "url": issue.get("url"),
            "state": (issue.get("state") or {}).get("name"),
            "priority_label": issue.get("priorityLabel"),
            "team": (issue.get("team") or {}).get("name"),
            "project": (issue.get("project") or {}).get("name"),
            "labels": labels,
            "assignee": (issue.get("assignee") or {}).get("name"),
        }

    def _format_graphql_errors(self, errors: list[Any]) -> str:
        """Render GraphQL errors into a compact readable message."""
        messages = []
        for error in errors:
            if isinstance(error, dict):
                message = error.get("message")
                if message:
                    messages.append(str(message))
                    continue
            messages.append(str(error))
        return "; ".join(messages) if messages else "Unknown GraphQL error"
