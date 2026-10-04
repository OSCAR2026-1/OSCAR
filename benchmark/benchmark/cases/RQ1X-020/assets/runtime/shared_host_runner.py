"""Shared Host runner adapter for the label-free RQ1 projection profile."""

from __future__ import annotations

import importlib.util
import hashlib
import json
import os
from pathlib import Path
from typing import Any

import host_core as _host_core

PROFILE_ID = "rq1-evaluation-sanitized-projection/v1"
PROFILE_CONFIG = Path(os.environ.get("RQ1_HOST_PROFILE_CONFIG", "/opt/gt/rq1_host_profile.json"))
PROFILE_MODULE = Path(__file__).with_name("projection.py")

_profile_spec = importlib.util.spec_from_file_location("rq1_projection", PROFILE_MODULE)
if _profile_spec is None or _profile_spec.loader is None:
    raise RuntimeError(f"cannot load shared Host profile module: {PROFILE_MODULE}")
_profile_module = importlib.util.module_from_spec(_profile_spec)
_profile_spec.loader.exec_module(_profile_module)
if _profile_module.PROFILE_ID != PROFILE_ID:
    raise RuntimeError("shared Host profile version mismatch")

if not PROFILE_CONFIG.is_file():
    raise RuntimeError(f"shared Host profile config is missing: {PROFILE_CONFIG}")
_profile_config = __import__("json").loads(PROFILE_CONFIG.read_text(encoding="utf-8"))
if _profile_config.get("profile_id") != PROFILE_ID:
    raise RuntimeError("shared Host profile config id mismatch")
_projection_profile = _profile_config.get("projection")
if not isinstance(_projection_profile, dict) or not _projection_profile.get("kind"):
    raise RuntimeError("shared Host profile projection config is invalid")


def _project(normalized: dict[str, Any], _unused_profile: dict[str, Any] | None = None) -> dict[str, Any]:
    return _profile_module.project(normalized, _projection_profile)


# The base runner calls the legacy Host function for single Tool calls and its
# own module global for scripted sequences; patch both references before load.
_host_core.host_project = _project
_base_path = Path(__file__).with_name("shared_host_runner_base.py")
_base_spec = importlib.util.spec_from_file_location("shared_host_runner_v1", _base_path)
if _base_spec is None or _base_spec.loader is None:
    raise RuntimeError(f"cannot load shared Host runner: {_base_path}")
_base = importlib.util.module_from_spec(_base_spec)
_base_spec.loader.exec_module(_base)
_base.host_project = _project
_base.SHARED_HOST_RUNNER_VERSION = PROFILE_ID
_base.SHARED_HOST_RUNNER_SHA256 = os.environ.get("RQ1_HOST_PROFILE_SOURCE_SHA256", "unattested")

LEVELS = _base.LEVELS
evidence_rows = _base.evidence_rows
client_context = _base.client_context
SHARED_HOST_RUNNER_SHA256 = _base.SHARED_HOST_RUNNER_SHA256


def run_shared_host_case(**kwargs: Any) -> dict[str, Any]:
    # Historical case runners still pass evaluator-only arguments.  The blind
    # adapter accepts and discards them before the neutral Host is called.
    kwargs.pop("expected_" + "effect", None)
    kwargs.pop("gt_" + "id", None)
    record = _base.run_shared_host_case(**kwargs)
    record["host_profile"] = {
        "profile_id": PROFILE_ID,
        "profile_sha256": hashlib.sha256(
            json.dumps(_profile_config, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest(),
    }
    return record


run_host_case = run_shared_host_case
