"""Shared label-free contract for the vulnerable OSS component.

The component origin selects Stage 0/1 material.  It is metadata only; it is
not a GT label and it does not select an effect kind or an observation gate.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from urllib.parse import unquote, urlsplit


COMPONENT_ORIGINS = {
    "MCP_SERVER_SELF",
    "DIRECT_RUNTIME_DEPENDENCY",
    "MCP_FRAMEWORK",
}
GENERIC_RELATION_STATUSES = {
    "AFFECTED_EXACT_COMPONENT",
    "AFFECTED_COMMIT_COMPONENT",
    "SERVER_OWN_SOURCE_RELEASE_PACKAGE",
}
LEGACY_DIRECT_RELATION_STATUSES = {
    "affected_exact_direct_runtime",
    "affected_commit_direct_runtime",
}
ALL_RELATION_STATUSES = GENERIC_RELATION_STATUSES | LEGACY_DIRECT_RELATION_STATUSES

_LABEL_FREE_FORBIDDEN_KEYS = {
    "ground_truth_label",
    "ground_truth",
    "gt",
    "gt_id",
    "active_gt_id",
    "vulnerable_label",
    "patched_trigger_blocked",
    "annotation_status",
    "included_in_gt",
    "active_agent_gt_id",
    "source_gt_id",
    "gt_label_schema",
}
_LABEL_FREE_FORBIDDEN_PATH_PARTS = {
    "active_agent_gt_pairs",
    "ground_truth",
    "gt_pilot",
    "gt_linux",
    "dsh_remaining",
    "dsh_controls",
    "recorder",
    "03_gt",
}
_LABEL_FREE_LABEL_RE = re.compile(r"(?<![A-Za-z])(POSITIVE|NEGATIVE|UNASSESSED)(?![A-Za-z])", re.IGNORECASE)
_GT_ID_RE = re.compile(r"(?<![A-Za-z])GT-\d+(?![A-Za-z0-9])", re.IGNORECASE)
_ADVISORY_ID_RE = re.compile(
    r"^(?:CVE-\d{4}-\d{4,}|GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}|"
    r"PYSEC-\d{4}-\d+|OSV-[0-9A-Z-]+)$",
    re.IGNORECASE,
)


def validate_label_free_evidence(value: Any, *, field: str = "evidence") -> list[str]:
    """Reject GT-derived labels, identifiers and paths from component evidence."""
    errors: list[str] = []

    def visit(item: Any, path: str) -> None:
        if isinstance(item, dict):
            for key, nested in item.items():
                key_text = str(key)
                lowered = key_text.lower()
                if lowered in _LABEL_FREE_FORBIDDEN_KEYS or "recorder" in lowered:
                    errors.append(f"{path}.{key_text}: GT/annotation field is forbidden")
                visit(nested, f"{path}.{key_text}")
        elif isinstance(item, list):
            for index, nested in enumerate(item):
                visit(nested, f"{path}[{index}]")
        elif isinstance(item, str):
            normalized = item.replace("\\", "/").lower()
            if _LABEL_FREE_LABEL_RE.search(item) or _GT_ID_RE.search(item):
                errors.append(f"{path}: GT label or identifier is forbidden")
            if "ground_truth_label" in normalized or "patched_trigger_blocked" in normalized:
                errors.append(f"{path}: GT field name is forbidden")
            if any(part in normalized for part in _LABEL_FREE_FORBIDDEN_PATH_PARTS):
                errors.append(f"{path}: hidden GT/evidence path fragment is forbidden")

    visit(value, field)
    return sorted(set(errors))


def _identity(spec: dict[str, Any]) -> dict[str, Any]:
    for key in ("identity", "case_identity"):
        value = spec.get(key)
        if isinstance(value, dict):
            return value
    return {}


def _repo_key(value: Any) -> str:
    text = str(value or "").strip().lower().rstrip("/")
    text = re.sub(r"^https?://(?:www\.)?github\.com/", "", text)
    return text.removesuffix(".git")


def _package_key(value: Any) -> str:
    text = str(value or "").strip().lower()
    if text.startswith("pkg:"):
        _, package = text.split(":", 1)
        text = package.split("/", 1)[1] if "/" in package else package
    text = unquote(text)
    version_marker = text.rfind("@")
    if version_marker > text.rfind("/"):
        text = text[:version_marker]
    return re.sub(r"[^a-z0-9@._/-]+", "", text)


def _pair_value(component: dict[str, Any], side: str) -> str | None:
    if side == "vulnerable":
        return str(component.get("vulnerable_version") or component.get("vulnerable_commit") or "") or None
    return str(component.get("fixed_version") or component.get("fixed_commit") or "") or None


def _evidence_strings(value: Any) -> set[str]:
    """Collect explicit evidence references without interpreting free text."""
    values: set[str] = set()
    if isinstance(value, str):
        values.add(value.strip())
    elif isinstance(value, list):
        for item in value:
            values.update(_evidence_strings(item))
    elif isinstance(value, dict):
        for key in ("ref", "path", "source_ref", "patch_ref", "url"):
            if isinstance(value.get(key), str):
                values.add(value[key].strip())
    return {value for value in values if value}


def _version_claim_matches(value: Any, expected: str) -> bool:
    if isinstance(value, str):
        return value == expected
    if isinstance(value, list):
        return expected in {str(item) for item in value}
    return False


def _record_version_matches(value: Any, expected: str) -> bool:
    """Match OSV's optional leading ``v`` without broad range guessing."""
    if isinstance(value, str):
        return value == expected or value.removeprefix("v") == expected
    if isinstance(value, (list, tuple, set)):
        return any(_record_version_matches(item, expected) for item in value)
    return False


def _record_claims(record: dict[str, Any]) -> tuple[set[str], dict[str, Any], dict[str, Any], dict[str, Any]]:
    aliases = record.get("aliases", [])
    identifiers = {str(value).strip().upper() for value in [record.get("id"), *aliases] if value}
    component = record.get("component") if isinstance(record.get("component"), dict) else {}
    vulnerable = record.get("vulnerable") if isinstance(record.get("vulnerable"), dict) else {}
    fixed = record.get("fixed") if isinstance(record.get("fixed"), dict) else {}
    affected = record.get("affected") if isinstance(record.get("affected"), dict) else {}
    return identifiers, component, vulnerable, {**affected, "fixed": fixed}


def _record_affected_entries(record: dict[str, Any]) -> list[dict[str, Any]]:
    """Return both normalized and standard OSV affected entries."""
    affected = record.get("affected")
    if isinstance(affected, dict):
        return [affected]
    if isinstance(affected, list):
        return [item for item in affected if isinstance(item, dict)]
    return []


def _record_repository(record: dict[str, Any]) -> str | None:
    """Derive a repository identity from an advisory package reference."""
    references = record.get("references", [])
    if not isinstance(references, list):
        return None
    for reference in references:
        url = reference.get("url") if isinstance(reference, dict) else None
        if not isinstance(url, str):
            continue
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"} or parsed.hostname not in {"github.com", "www.github.com"}:
            continue
        parts = [part for part in parsed.path.split("/") if part]
        if len(parts) >= 2 and parts[0] not in {"advisories", "security"}:
            return f"{parts[0]}/{parts[1]}"
    return None


def _record_entry_repository(entry: dict[str, Any]) -> str | None:
    ranges = entry.get("ranges", [])
    if not isinstance(ranges, list):
        return None
    for version_range in ranges:
        if isinstance(version_range, dict) and isinstance(version_range.get("repo"), str):
            return _repo_key(version_range["repo"])
    return None


def _record_range_values(entry: dict[str, Any], event_name: str) -> set[str]:
    values: set[str] = set()
    entry_database_specific = entry.get("database_specific")
    entry_extracted = (
        entry_database_specific.get("extracted_events", [])
        if isinstance(entry_database_specific, dict)
        else []
    )
    if isinstance(entry_extracted, list):
        for event in entry_extracted:
            if isinstance(event, dict) and isinstance(event.get(event_name), str):
                values.add(event[event_name])
    ranges = entry.get("ranges", [])
    if not isinstance(ranges, list):
        return values
    for version_range in ranges:
        if not isinstance(version_range, dict):
            continue
        events = version_range.get("events", [])
        if isinstance(events, list):
            for event in events:
                if isinstance(event, dict) and isinstance(event.get(event_name), str):
                    values.add(event[event_name])
        database_specific = version_range.get("database_specific")
        extracted = database_specific.get("extracted_events", []) if isinstance(database_specific, dict) else []
        if isinstance(extracted, list):
            for event in extracted:
                if isinstance(event, dict) and isinstance(event.get(event_name), str):
                    values.add(event[event_name])
    return values


def _record_supports_version(
    record: dict[str, Any], entries: list[dict[str, Any]], expected: str, *, fixed: bool,
) -> bool:
    """Check exact OSV versions/commits or explicit normalized claims.

    A range boundary is accepted only when the requested fixed revision is the
    advisory's explicit ``fixed`` event.  Arbitrary versions are not inferred
    from a free-form range because that would turn an unverified claim into a
    preparation decision.
    """
    if not fixed:
        vulnerable = record.get("vulnerable")
        if isinstance(vulnerable, dict) and (
            _version_claim_matches(vulnerable.get("version"), expected)
            or _version_claim_matches(vulnerable.get("commit"), expected)
        ):
            return True
    else:
        fixed_claim = record.get("fixed")
        if isinstance(fixed_claim, dict) and (
            _version_claim_matches(fixed_claim.get("version"), expected)
            or _version_claim_matches(fixed_claim.get("commit"), expected)
        ):
            return True
    affected = record.get("affected")
    if isinstance(affected, dict):
        values = (
            affected.get("fixed_versions") if fixed else affected.get("versions"),
            affected.get("fixed_commits") if fixed else affected.get("commits"),
        )
        if any(_version_claim_matches(value, expected) for value in values):
            return True
    for entry in entries:
        versions = entry.get("versions", [])
        commits = entry.get("commits", [])
        if _record_version_matches(versions, expected) or _record_version_matches(commits, expected):
            return True
        if _record_version_matches(_record_range_values(entry, "fixed" if fixed else "introduced"), expected):
            return True
    return False


def _validate_relation_records(
    value: Any,
    *,
    field: str,
    advisory: str,
    package: str,
    vulnerable: str,
    fixed: str,
    component_repository: str | None,
    component_purl: str | None,
    expected_refs: set[str],
) -> list[str]:
    """Require source/patch refs to carry an independently checkable relation."""
    records = value if isinstance(value, list) else [value]
    errors: list[str] = []
    if not records or not all(isinstance(item, dict) for item in records):
        return [f"{field} must contain structured advisory/component/version records"]
    matched_ref = False
    for index, record in enumerate(records):
        prefix = f"{field}[{index}]"
        ref = record.get("ref", record.get("source_ref", record.get("patch_ref", record.get("path"))))
        if not isinstance(ref, str) or not ref.strip():
            errors.append(f"{prefix}.ref is required")
        elif ref.strip() in expected_refs:
            matched_ref = True
        if str(record.get("advisory_id", record.get("advisory", ""))).strip().upper() != advisory.strip().upper():
            errors.append(f"{prefix}.advisory_id does not match the requested advisory")
        identity = record.get("component")
        if not isinstance(identity, dict) or str(identity.get("name", "")).strip().lower() != package.strip().lower():
            errors.append(f"{prefix}.component.name does not match the requested component")
        elif component_repository and _repo_key(identity.get("repository")) != _repo_key(component_repository):
            errors.append(f"{prefix}.component.repository does not match the requested component")
        elif component_purl and str(identity.get("purl", "")).lower() != str(component_purl).lower():
            errors.append(f"{prefix}.component.purl does not match the requested component")
        if field.endswith("source_evidence"):
            claim = record.get("version", record.get("vulnerable_version"))
            if not _version_claim_matches(claim, vulnerable):
                errors.append(f"{prefix}.version does not match the vulnerable version/commit")
        else:
            if not (_version_claim_matches(record.get("vulnerable_version"), vulnerable)
                    and _version_claim_matches(record.get("fixed_version"), fixed)):
                errors.append(f"{prefix} must identify both vulnerable and fixed versions/commits")
    if expected_refs and not matched_ref:
        errors.append(f"{field} does not reference the advisory-declared evidence refs")
    return errors


def validate_component_advisory_evidence(
    *,
    advisory: str,
    package: str,
    repository: str,
    component_repository: str | None,
    component_purl: str | None,
    vulnerable: str,
    fixed: str,
    evidence: Any,
    source_evidence: Any,
    patch_evidence: Any,
) -> list[str]:
    """Validate the independent, structured relation evidence for explicit cases.

    This is intentionally local and label-free.  It validates the claims and
    their cross-references; it does not consult GT files or infer a label.
    """
    errors = validate_label_free_evidence(evidence, field="component_advisory_evidence")
    errors.extend(validate_label_free_evidence(source_evidence, field="component_source_evidence"))
    errors.extend(validate_label_free_evidence(patch_evidence, field="component_patch_evidence"))
    if not isinstance(evidence, dict):
        return sorted(set(errors + ["component_advisory_evidence must be a structured object"]))
    advisory_ids = [evidence.get("advisory_id"), evidence.get("advisory")]
    aliases = evidence.get("aliases", [])
    if isinstance(aliases, list):
        advisory_ids.extend(aliases)
    normalized_ids = {str(item).strip().upper() for item in advisory_ids if item}
    if not isinstance(advisory, str) or not _ADVISORY_ID_RE.fullmatch(advisory.strip()):
        errors.append("advisory must be a recognized CVE/GHSA/PYSEC/OSV identifier")
    elif advisory.strip().upper() not in normalized_ids:
        errors.append("advisory evidence does not identify the requested advisory")
    source = evidence.get("source")
    if not isinstance(source, dict) or source.get("kind") not in {"OSV", "PUBLIC_ADVISORY", "UPSTREAM_ADVISORY"}:
        errors.append("component_advisory_evidence.source.kind must identify OSV or a public advisory")
    if not isinstance(source, dict) or not isinstance(source.get("url"), str) or not source["url"].startswith("https://"):
        errors.append("component_advisory_evidence.source.url must be an https public advisory URL")
    record = source.get("record") if isinstance(source, dict) else None
    if not isinstance(record, dict):
        errors.append("component_advisory_evidence.source.record must contain a structured public advisory record")
    else:
        record_ids, record_component, record_vulnerable, record_affected = _record_claims(record)
        record_entries = _record_affected_entries(record)
        if not record_component and record_entries:
            matching_entries = [
                item for item in record_entries
                if isinstance(item.get("package"), dict)
                and str(item["package"].get("name", "")).strip().lower() == str(package).strip().lower()
            ]
            if component_purl:
                matching_entries = [
                    item for item in matching_entries
                    if str(item.get("package", {}).get("purl", "")).strip().lower() == str(component_purl).strip().lower()
                ]
            if not matching_entries:
                requested_repository = _repo_key(component_repository or repository)
                matching_entries = [
                    item for item in record_entries
                    if _record_entry_repository(item) == requested_repository
                ]
            record_entries = matching_entries
            if matching_entries:
                record_component = matching_entries[0].get("package", {})
                if not record_component:
                    record_component = {
                        "name": package,
                        "purl": component_purl,
                        "repository": _record_entry_repository(matching_entries[0]),
                    }
        requested_id = advisory.strip().upper() if isinstance(advisory, str) else ""
        if requested_id not in record_ids:
            errors.append("public advisory record does not identify the requested advisory")
        record_url = str(source.get("url", "")).lower()
        if not any(identifier.lower() in record_url for identifier in record_ids | {requested_id}):
            errors.append("public advisory URL is not bound to the structured advisory record")
        if str(record_component.get("name", "")).strip().lower() != str(package).strip().lower():
            errors.append("public advisory record component name does not match the requested component")
        record_repository = record_component.get("repository") or _record_repository(record)
        if component_repository and _repo_key(record_repository) != _repo_key(component_repository):
            errors.append("public advisory record repository does not match the requested component")
        if component_purl and str(record_component.get("purl", "")).lower() != str(component_purl).lower():
            errors.append("public advisory record purl does not match the requested component")
        if not record_entries:
            errors.append("public advisory record has no affected entry for the requested component")
        if not _record_supports_version(record, record_entries, vulnerable, fixed=False):
            errors.append("public advisory record does not support the vulnerable version/commit")
        if not _record_supports_version(record, record_entries, fixed, fixed=True):
            errors.append("public advisory record does not support the fixed version/commit boundary")
    identity = evidence.get("component")
    if not isinstance(identity, dict):
        errors.append("component_advisory_evidence.component is required")
        identity = {}
    if str(identity.get("name", "")).strip().lower() != str(package).strip().lower():
        errors.append("advisory component name does not match the requested component")
    declared_repository = component_repository or repository
    evidence_repository = identity.get("repository")
    if evidence_repository and _repo_key(evidence_repository) != _repo_key(declared_repository):
        errors.append("advisory component repository does not match the requested component")
    declared_purl = component_purl
    if declared_purl and identity.get("purl") and str(identity["purl"]).lower() != str(declared_purl).lower():
        errors.append("advisory component purl does not match the requested component")
    identity_purl = identity.get("purl")
    if identity_purl and _package_key(identity_purl) != _package_key(package):
        errors.append("advisory component purl does not identify the requested component name")
    if not identity.get("purl") and not evidence_repository:
        errors.append("advisory component requires matching purl or repository")
    vulnerable_claim = evidence.get("vulnerable")
    fixed_claim = evidence.get("fixed")
    if not isinstance(vulnerable_claim, dict) or not isinstance(fixed_claim, dict):
        errors.append("advisory evidence must contain vulnerable and fixed claims")
        vulnerable_claim = vulnerable_claim if isinstance(vulnerable_claim, dict) else {}
        fixed_claim = fixed_claim if isinstance(fixed_claim, dict) else {}
    if not (_version_claim_matches(vulnerable_claim.get("version"), vulnerable)
            or _version_claim_matches(vulnerable_claim.get("commit"), vulnerable)):
        errors.append("advisory vulnerable claim does not match vulnerable version/commit")
    if not (_version_claim_matches(fixed_claim.get("version"), fixed)
            or _version_claim_matches(fixed_claim.get("commit"), fixed)):
        errors.append("advisory fixed claim does not match fixed version/commit")
    affected = evidence.get("affected", {})
    affected_versions = affected.get("versions", []) if isinstance(affected, dict) else []
    affected_commits = affected.get("commits", []) if isinstance(affected, dict) else []
    affected_ranges = affected.get("ranges", []) if isinstance(affected, dict) else []
    if not (_version_claim_matches(affected_versions, vulnerable)
            or _version_claim_matches(affected_commits, vulnerable)
            or _version_claim_matches(affected_ranges, vulnerable)
            or vulnerable_claim.get("supported_by_source") is True):
        errors.append("advisory evidence does not place vulnerable version/commit in the affected set")
    fixed_versions = affected.get("fixed_versions", []) if isinstance(affected, dict) else []
    fixed_commits = affected.get("fixed_commits", []) if isinstance(affected, dict) else []
    if not (_version_claim_matches(fixed_versions, fixed)
            or _version_claim_matches(fixed_commits, fixed)
            or fixed_claim.get("repair_commit") == fixed
            or fixed_claim.get("supported_by_patch") is True):
        errors.append("advisory evidence does not identify the fixed version/commit boundary")
    advisory_source_refs = _evidence_strings(evidence.get("source_refs"))
    advisory_patch_refs = _evidence_strings(evidence.get("patch_refs"))
    actual_source_refs = _evidence_strings(source_evidence)
    actual_patch_refs = _evidence_strings(patch_evidence)
    if not advisory_source_refs:
        errors.append("component_advisory_evidence.source_refs is required")
    if not advisory_patch_refs:
        errors.append("component_advisory_evidence.patch_refs is required")
    if not actual_source_refs:
        errors.append("component_source_evidence is required for explicit components")
    if not actual_patch_refs:
        errors.append("component_patch_evidence is required for explicit components")
    if advisory_source_refs and actual_source_refs.isdisjoint(advisory_source_refs):
        errors.append("component source evidence is not linked to advisory source_refs")
    if advisory_patch_refs and actual_patch_refs.isdisjoint(advisory_patch_refs):
        errors.append("component patch evidence is not linked to advisory patch_refs")
    relation_repository = evidence_repository or str(declared_repository or "")
    relation_purl = str(identity.get("purl") or declared_purl or "") or None
    errors.extend(_validate_relation_records(
        source_evidence,
        field="component_source_evidence",
        advisory=advisory,
        package=package,
        vulnerable=vulnerable,
        fixed=fixed,
        component_repository=relation_repository or None,
        component_purl=relation_purl,
        expected_refs=advisory_source_refs,
    ))
    errors.extend(_validate_relation_records(
        patch_evidence,
        field="component_patch_evidence",
        advisory=advisory,
        package=package,
        vulnerable=vulnerable,
        fixed=fixed,
        component_repository=relation_repository or None,
        component_purl=relation_purl,
        expected_refs=advisory_patch_refs,
    ))
    return sorted(set(errors))


def verify_osv_advisory_evidence(
    *,
    advisory: str,
    package: str,
    repository: str,
    component_repository: str | None,
    component_purl: str | None,
    vulnerable: str,
    fixed: str,
    evidence: Any,
    source_evidence: Any,
    patch_evidence: Any,
    timeout: float = 10.0,
) -> tuple[list[str], dict[str, Any] | None]:
    """Bind explicit OSV evidence to the fetched public OSV record.

    This is used only by Stage 0 preparation.  The blind runtime never makes
    an advisory request and never receives a GT-derived value from it.
    """
    if not isinstance(evidence, dict) or not isinstance(evidence.get("source"), dict):
        return ["OSV advisory verification requires a structured source object"], None
    source = evidence["source"]
    if source.get("kind") != "OSV":
        return ["automatic advisory verification requires source.kind=OSV"], None
    url = source.get("url")
    parsed = urlsplit(str(url or ""))
    if parsed.scheme != "https" or parsed.hostname != "api.osv.dev" or not parsed.path.startswith("/v1/vulns/"):
        return ["OSV source.url must be the HTTPS api.osv.dev/v1/vulns endpoint"], None
    try:
        request = Request(str(url), headers={"Accept": "application/json", "User-Agent": "OSCAR-Stage0/1"})
        with urlopen(request, timeout=timeout) as response:
            fetched = json.loads(response.read().decode("utf-8"))
    except (HTTPError, URLError, TimeoutError, OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        return [f"OSV advisory could not be independently fetched: {type(exc).__name__}"], None
    if not isinstance(fetched, dict):
        return ["OSV advisory response is not a JSON object"], None
    bound = copy.deepcopy(evidence)
    bound["source"]["record"] = fetched
    errors = validate_component_advisory_evidence(
        advisory=advisory,
        package=package,
        repository=repository,
        component_repository=component_repository,
        component_purl=component_purl,
        vulnerable=vulnerable,
        fixed=fixed,
        evidence=bound,
        source_evidence=source_evidence,
        patch_evidence=patch_evidence,
    )
    if errors:
        return ["fetched OSV advisory relation failed validation: " + "; ".join(errors)], None
    canonical = json.dumps(fetched, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    bound["source"]["verification"] = {
        "status": "VERIFIED",
        "method": "OSV_V1_FETCH",
        "url": str(url),
        "advisory_id": advisory,
        "record_sha256": hashlib.sha256(canonical).hexdigest(),
    }
    return [], bound


def _legacy_to_component(raw: dict[str, Any]) -> dict[str, Any]:
    relation = raw.get("relation_status")
    relation = {
        "affected_exact_direct_runtime": "AFFECTED_EXACT_COMPONENT",
        "affected_commit_direct_runtime": "AFFECTED_COMMIT_COMPONENT",
    }.get(relation, relation)
    return {
        "origin": "DIRECT_RUNTIME_DEPENDENCY",
        "name": raw.get("dependency_name", raw.get("name")),
        "purl": raw.get("dependency_purl", raw.get("purl")),
        "repository": raw.get("repository"),
        "vulnerable_version": raw.get("vulnerable_version"),
        "fixed_version": raw.get("fixed_version", raw.get("fixed_version_or_commit")),
        "vulnerable_commit": raw.get("vulnerable_commit"),
        "fixed_commit": raw.get("fixed_commit"),
        "dependency_depth": raw.get("dependency_depth"),
        "dependency_scope": raw.get("dependency_scope"),
        "relation_status": relation,
        "source_evidence": raw.get("source_evidence"),
        "patch_evidence": raw.get("patch_evidence"),
        "advisory_evidence": raw.get("advisory_evidence"),
    }


def _canonical_for_compare(raw: dict[str, Any], *, legacy: bool) -> dict[str, Any]:
    value = _legacy_to_component(raw) if legacy else copy.deepcopy(raw)
    return {
        key: value.get(key)
        for key in (
            "origin", "name", "purl", "repository", "vulnerable_version",
            "fixed_version", "vulnerable_commit", "fixed_commit",
            "dependency_depth", "dependency_scope", "relation_status",
        )
        if value.get(key) is not None
    }


def component_from_spec(spec: dict[str, Any]) -> tuple[dict[str, Any] | None, list[str], bool]:
    """Return ``(canonical_component, errors, legacy_input)``.

    A case may contain the old direct-runtime object for read compatibility or
    the new unified object.  If both are present they must describe the same
    component; otherwise the case is rejected rather than silently choosing a
    field set.
    """
    new = spec.get("vulnerability_component")
    old = spec.get("direct_runtime_dependency")
    errors: list[str] = []
    if new is not None and not isinstance(new, dict):
        errors.append("vulnerability_component must be an object")
        new = None
    if old is not None and not isinstance(old, dict):
        errors.append("direct_runtime_dependency must be an object")
        old = None
    if new is None and old is None:
        return None, ["vulnerability_component is required (legacy direct_runtime_dependency is accepted for compatibility)"], False
    if new is not None and old is not None:
        if _canonical_for_compare(new, legacy=False) != _canonical_for_compare(old, legacy=True):
            errors.append("vulnerability_component conflicts with direct_runtime_dependency")
        for field in ("source_evidence", "patch_evidence"):
            if new.get(field) is not None and old.get(field) is not None and new.get(field) != old.get(field):
                errors.append("vulnerability_component conflicts with direct_runtime_dependency")
        raw = new
        legacy = False
    elif new is not None:
        raw = new
        legacy = False
    else:
        raw = old
        legacy = True
    canonical = _legacy_to_component(raw) if legacy else copy.deepcopy(raw)
    return canonical, errors, legacy


def validate_vulnerability_component(spec: dict[str, Any], *, require_present: bool = True) -> list[str]:
    component, errors, legacy = component_from_spec(spec)
    if component is None:
        return errors if require_present else []
    origin = component.get("origin")
    if origin not in COMPONENT_ORIGINS:
        errors.append("vulnerability_component.origin is not a supported component origin")
    declared_origin = spec.get("component_origin")
    if declared_origin is not None and declared_origin != origin:
        errors.append("component_origin conflicts with vulnerability_component.origin")
    if not isinstance(component.get("name"), str) or not component.get("name"):
        errors.append("vulnerability_component.name is required")
    purl = component.get("purl")
    repository = component.get("repository")
    if not (isinstance(purl, str) and purl.startswith("pkg:") or isinstance(repository, str) and repository):
        errors.append("vulnerability_component requires purl or repository")
    vulnerable = _pair_value(component, "vulnerable")
    fixed = _pair_value(component, "fixed")
    if not vulnerable:
        errors.append("vulnerability_component vulnerable version or commit is required")
    if not fixed:
        errors.append("vulnerability_component fixed version or commit is required")
    if vulnerable and fixed and vulnerable == fixed:
        errors.append("vulnerable and fixed component revisions must differ")
    if component.get("relation_status") not in ALL_RELATION_STATUSES:
        errors.append("vulnerability_component.relation_status is invalid")
    if component.get("mcp_server_own_source_or_package_vulnerability") is True:
        errors.append("legacy server-self marker cannot be used to reclassify a component")
    server = spec.get("server") if isinstance(spec.get("server"), dict) else {}
    is_localization_artifact = spec.get("schema_version") == "vulveil-localization/v1"
    if origin == "DIRECT_RUNTIME_DEPENDENCY":
        if component.get("dependency_depth") != 1:
            errors.append("DIRECT_RUNTIME_DEPENDENCY requires dependency_depth=1")
        if component.get("dependency_scope") != "runtime":
            errors.append("DIRECT_RUNTIME_DEPENDENCY requires dependency_scope=runtime")
        if component.get("relation_status") not in GENERIC_RELATION_STATUSES | LEGACY_DIRECT_RELATION_STATUSES:
            errors.append("DIRECT_RUNTIME_DEPENDENCY relation status is invalid")
    elif component.get("relation_status") in LEGACY_DIRECT_RELATION_STATUSES and not legacy:
        errors.append("new vulnerability_component must use a generic component relation status")
    if not legacy:
        if not component.get("source_evidence"):
            errors.append("vulnerability_component.source_evidence is required")
        if not component.get("patch_evidence"):
            errors.append("vulnerability_component.patch_evidence is required")
        errors.extend(validate_label_free_evidence(component.get("source_evidence"), field="vulnerability_component.source_evidence"))
        errors.extend(validate_label_free_evidence(component.get("patch_evidence"), field="vulnerability_component.patch_evidence"))
        if not is_localization_artifact and not component.get("advisory_evidence"):
            errors.append("vulnerability_component.advisory_evidence is required for explicit components")
        errors.extend(validate_label_free_evidence(component.get("advisory_evidence"), field="vulnerability_component.advisory_evidence"))
        if not is_localization_artifact and isinstance(component.get("advisory_evidence"), dict):
            identity = _identity(spec)
            advisory_id = identity.get("advisory")
            if isinstance(advisory_id, str) and advisory_id:
                errors.extend(validate_component_advisory_evidence(
                    advisory=advisory_id,
                    package=str(component.get("name", "")),
                    repository=str(server.get("repository", "")) if isinstance(server, dict) else "",
                    component_repository=component.get("repository"),
                    component_purl=component.get("purl"),
                    vulnerable=str(vulnerable or ""),
                    fixed=str(fixed or ""),
                    evidence=component.get("advisory_evidence"),
                    source_evidence=component.get("source_evidence"),
                    patch_evidence=component.get("patch_evidence"),
                ))
    identity = _identity(spec)
    identity_package = identity.get("package")
    # A localized artifact carries the original case identity, where
    # ``identity.package`` historically names the server while the unified
    # component names its vulnerable dependency.  The input case still gets
    # strict identity matching; the compatibility-shaped output does not
    # reapply that check to the transformed component.
    if identity_package and component.get("name") and not legacy and not is_localization_artifact:
        component_package = _package_key(component.get("name"))
        declared_package = _package_key(identity_package)
        if component_package != declared_package:
            errors.append("vulnerability_component.name must match identity.package")
    for field, value in (("vulnerable_version", vulnerable), ("fixed_version", fixed)):
        identity_value = identity.get(field)
        if identity_value and str(identity_value) != str(value):
            errors.append(f"vulnerability_component.{field} must match identity.{field}")
    if origin == "MCP_SERVER_SELF" and component.get("repository") and server.get("repository"):
        if _repo_key(component.get("repository")) != _repo_key(server.get("repository")):
            errors.append("MCP_SERVER_SELF component repository must match the MCP Server repository")
    return sorted(set(errors))


def component_for_localization(spec: dict[str, Any]) -> dict[str, Any]:
    component, _, _ = component_from_spec(spec)
    return component or {}


def component_origin(spec: dict[str, Any]) -> str | None:
    return component_for_localization(spec).get("origin") or None


def component_revision(component: dict[str, Any], side: str) -> str:
    return str(_pair_value(component, side) or "")


def is_legacy_direct_runtime(spec: dict[str, Any]) -> bool:
    _, _, legacy = component_from_spec(spec)
    return legacy


__all__ = [
    "ALL_RELATION_STATUSES", "COMPONENT_ORIGINS", "GENERIC_RELATION_STATUSES",
    "LEGACY_DIRECT_RELATION_STATUSES", "component_for_localization",
    "component_from_spec", "component_origin", "component_revision",
    "is_legacy_direct_runtime", "validate_vulnerability_component",
    "validate_label_free_evidence",
    "validate_component_advisory_evidence", "verify_osv_advisory_evidence",
]
