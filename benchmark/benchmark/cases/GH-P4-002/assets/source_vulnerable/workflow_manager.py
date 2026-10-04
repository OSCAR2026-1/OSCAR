"""Workflow session persistence for workspace-oriented task execution."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


_SCHEMA_VERSION = 1


def _utc_now() -> str:
    """Return a stable timestamp for persisted workflow state."""
    return datetime.now(timezone.utc).isoformat()


class WorkflowManager:
    """Persist lightweight workflow sessions under each workspace .mcp directory."""

    def __init__(self, workspaces_dir: Path):
        self.workspaces_dir = workspaces_dir

    def _workflows_dir(self, workspace_name: str) -> Path:
        path = self.workspaces_dir / workspace_name / ".mcp" / "workflows"
        path.mkdir(parents=True, exist_ok=True)
        return path

    def _session_path(self, workspace_name: str, workflow_id: str) -> Path:
        return self._workflows_dir(workspace_name) / f"{workflow_id}.json"

    def _artifact_dir(self, workspace_name: str, workflow_id: str) -> Path:
        path = self.workspaces_dir / workspace_name / ".mcp" / "workflow_artifacts" / workflow_id
        path.mkdir(parents=True, exist_ok=True)
        return path

    def create_session(
        self,
        workspace_name: str,
        objective: str,
        workflow_type: str = "general",
        metadata: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """Create and persist a new workflow session."""
        now = _utc_now()
        workflow_id = uuid.uuid4().hex[:12]
        session = {
            "schema_version": _SCHEMA_VERSION,
            "workflow_id": workflow_id,
            "workspace_name": workspace_name,
            "workflow_type": workflow_type,
            "objective": objective,
            "status": "active",
            "stage": "initialized",
            "created_at": now,
            "updated_at": now,
            "metadata": metadata or {},
            "artifacts": {},
            "context_bundle": {},
            "candidate_files": [],
            "verification_plan": {},
            "events": [
                {
                    "timestamp": now,
                    "type": "workflow_started",
                    "payload": {
                        "objective": objective,
                        "workflow_type": workflow_type,
                    },
                }
            ],
        }
        self._write_session(workspace_name, session)
        return session

    def get_session(self, workspace_name: str, workflow_id: str) -> Optional[dict[str, Any]]:
        """Read a persisted workflow session."""
        path = self._session_path(workspace_name, workflow_id)
        if not path.exists():
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return None

    def find_session(
        self,
        workflow_id: str,
        workspace_name: Optional[str] = None,
    ) -> Optional[dict[str, Any]]:
        """Locate a workflow session, optionally searching every workspace."""
        if workspace_name:
            return self.get_session(workspace_name, workflow_id)

        if not self.workspaces_dir.exists():
            return None

        for workspace_dir in self.workspaces_dir.iterdir():
            if not workspace_dir.is_dir():
                continue
            session_path = workspace_dir / ".mcp" / "workflows" / f"{workflow_id}.json"
            if not session_path.exists():
                continue
            try:
                return json.loads(session_path.read_text(encoding="utf-8"))
            except Exception:
                return None
        return None

    def update_session(
        self,
        workspace_name: str,
        workflow_id: str,
        *,
        fields: Optional[dict[str, Any]] = None,
        artifacts: Optional[dict[str, Any]] = None,
        context_bundle: Optional[dict[str, Any]] = None,
        candidate_files: Optional[list[dict[str, Any]]] = None,
        verification_plan: Optional[dict[str, Any]] = None,
        event_type: Optional[str] = None,
        event_payload: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """Update a workflow session in place."""
        session = self.get_session(workspace_name, workflow_id)
        if not session:
            raise ValueError(f"Workflow '{workflow_id}' not found in workspace '{workspace_name}'")

        if fields:
            session.update(fields)
        if artifacts:
            session.setdefault("artifacts", {}).update(artifacts)
        if context_bundle is not None:
            session["context_bundle"] = context_bundle
        if candidate_files is not None:
            session["candidate_files"] = candidate_files
        if verification_plan is not None:
            session["verification_plan"] = verification_plan

        now = _utc_now()
        session["updated_at"] = now
        if event_type:
            session.setdefault("events", []).append(
                {
                    "timestamp": now,
                    "type": event_type,
                    "payload": event_payload or {},
                }
            )

        self._write_session(workspace_name, session)
        return session

    def _write_session(self, workspace_name: str, session: dict[str, Any]) -> None:
        """Persist a workflow session atomically."""
        path = self._session_path(workspace_name, session["workflow_id"])
        temp_path = path.with_suffix(".json.tmp")
        temp_path.write_text(json.dumps(session, indent=2), encoding="utf-8")
        temp_path.replace(path)

    def write_json_artifact(
        self,
        workspace_name: str,
        workflow_id: str,
        filename: str,
        data: Any,
    ) -> str:
        """Persist a JSON artifact for a workflow and return its path."""
        path = self._artifact_dir(workspace_name, workflow_id) / filename
        path.parent.mkdir(parents=True, exist_ok=True)
        temp_path = path.with_suffix(path.suffix + ".tmp")
        temp_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        temp_path.replace(path)
        return str(path)

    def write_text_artifact(
        self,
        workspace_name: str,
        workflow_id: str,
        filename: str,
        text: str,
    ) -> str:
        """Persist a text artifact for a workflow and return its path."""
        path = self._artifact_dir(workspace_name, workflow_id) / filename
        path.parent.mkdir(parents=True, exist_ok=True)
        temp_path = path.with_suffix(path.suffix + ".tmp")
        temp_path.write_text(text, encoding="utf-8")
        temp_path.replace(path)
        return str(path)
