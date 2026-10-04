import copy
import json
import hashlib
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from oscar.runtime.blind_runtime import run_blind_case
from oscar.analysis.effect_modeling import (
    build_carrier_projection,
    build_effect_model,
    classify_effect_role,
    inspect_l4_effect,
    normalize_effect_model,
    validate_effect_model,
    _trace_side,
    _trace_diff,
    _runtime_resource_events,
    _effect_produced_in_rows,
    _resource_state_predicates,
    _value_carrier_paths,
    _preferred_paired_carrier_digests,
)


FIXTURE_RUNNER = Path(__file__).parent / "fixtures" / "emit_blind_evidence.py"


def _rows(vulnerable_fields, fixed_fields, *, l4_vulnerable=None, l4_fixed=None):
    l4_vulnerable = vulnerable_fields if l4_vulnerable is None else l4_vulnerable
    l4_fixed = fixed_fields if l4_fixed is None else l4_fixed

    def side(fields, l4_fields):
        result = []
        for level in (
            "L0_RAW_MCP_RESULT",
            "L1_NORMALIZED_TOOL_RESULT",
            "L2_HOST_PROCESSED_TOOL_RESULT",
            "L3_SESSION_TOOL_RESULT",
            "L4_MODEL_VISIBLE_OBSERVATION",
        ):
            payload = {"tool_result": dict(l4_fields if level == "L4_MODEL_VISIBLE_OBSERVATION" else fields)}
            row = {"level": level, "content": payload, "anchor_reached": True}
            if level == "L4_MODEL_VISIBLE_OBSERVATION":
                row["actual_next_model_request"] = True
                row["model_request"] = {"messages": [{"role": "tool", "tool_call_id": "call-1", "content": payload}]}
            result.append(row)
        return result

    return {"vulnerable": side(vulnerable_fields, l4_vulnerable), "fixed": side(fixed_fields, l4_fixed)}


def _spec():
    return {
        "schema_version": "vulveil-blind-case/v1",
        "identity": {
            "advisory": "CVE-STAGE2-0001",
            "package": "fixture-package",
            "vulnerable_version": "1.0.0",
            "fixed_version": "1.0.1",
        },
        "experiment_type": "COMMAND_OR_QUERY_INJECTION",
        "direct_runtime_dependency": {
            "dependency_name": "fixture-package",
            "dependency_purl": "pkg:pypi/fixture-package",
            "dependency_depth": 1,
            "dependency_scope": "runtime",
            "vulnerable_version": "1.0.0",
            "fixed_version": "1.0.1",
            "relation_status": "affected_exact_direct_runtime"
        },
        "server": {"repository": "fixture/repository", "module": "fixture.server"},
        "tool": {"name": "probe"},
        "tool_input": {"command": "id"},
        "source": {
            "vulnerable": [{"path": "probe.py", "content": "import subprocess\ndef probe(command):\n    return subprocess.check_output(command, shell=True)\n"}],
            "fixed": [{"path": "probe.py", "content": "import subprocess\ndef probe(command):\n    if not isinstance(command, str) or \"|\" in command:\n        raise ValueError(\"rejected\")\n    return subprocess.check_output([\"echo\", command], shell=False)\n"}],
        },
        "patch": {"unified_diff": "--- a/probe.py\n+++ b/probe.py\n@@ -1,3 +1,5 @@\n import subprocess\n def probe(command):\n+    if not isinstance(command, str) or \"|\" in command:\n+        raise ValueError(\"rejected\")\n     return subprocess.check_output(command, shell=True)\n"},
        "agent_task": "Call the frozen probe and report the Tool result.",
        "host_profile": {"model": "fixture-model"},
        "environment": {"package_manager": "python"},
        "runner": {"repetitions": 1, "dynamic_budget": 1, "vulnerable": {}, "patched": {}},
    }


def _effect(model, kind):
    return next(item for item in model.get("effects", []) if item.get("effect_kind") == kind)


def _advisory_candidate_spec():
    spec = _spec()
    excerpt = "Public advisory states that the vulnerable operation writes an unintended external resource."
    spec["advisory_semantics"] = {
        "schema_version": "public-advisory-effect-semantics/v1",
        "advisory_id": spec["identity"]["advisory"],
        "source_url": "https://osv.dev/vulnerability/CVE-STAGE2-0001",
        "source_excerpt": excerpt,
        "source_excerpt_sha256": hashlib.sha256(excerpt.encode("utf-8")).hexdigest(),
        "review_method": "human-reviewed-public-advisory/v1",
        "claims": [{
            "claim_id": "unintended-resource-write",
            "effect_kind": "RESOURCE_EFFECT",
            "effect_role": "TERMINAL",
            "object_kind": "external-resource",
            "operation": "write",
            "exact_quote": "writes an unintended external resource",
            "runtime_oracle": {
                "kind": "fixture-resource-oracle/v1",
                "effect_event_operation": "write",
            },
        }],
    }
    return spec


def _rows_with_complete_oracle(vulnerable_fields, fixed_fields):
    traces = _rows(vulnerable_fields, fixed_fields)
    for side in ("vulnerable", "fixed"):
        traces[side].append({
            "level": "SERVER_OR_EXTERNAL_EFFECT",
            "anchor_reached": True,
            "oracle": {"kind": "fixture-resource-oracle/v1", "complete": True},
            "event": None,
        })
    return traces


class EffectModelTests(unittest.TestCase):
    def test_public_advisory_candidate_models_stable_not_realized_effect(self):
        traces = _rows_with_complete_oracle({"status": "ordinary"}, {"status": "ordinary"})
        model = build_effect_model(_advisory_candidate_spec(), traces)
        self.assertEqual(model["status"], "GENERATED", model.get("modeling_reasons"))
        self.assertEqual(model["generation_basis"], "ADVISORY_PATCH_CANDIDATE")
        self.assertIsNone(model["fixed_side_blocked"])
        self.assertEqual(model["effects"][0]["effect_realization"]["status"], "NOT_REALIZED")
        observation = inspect_l4_effect(model, traces["vulnerable"])
        self.assertEqual(observation["effects"][0]["effect_realization"]["status"], "NOT_REALIZED")
        self.assertTrue(observation["effects"][0]["evidence_refs"])

    def test_public_advisory_candidate_requires_complete_runtime_oracle(self):
        model = build_effect_model(
            _advisory_candidate_spec(),
            _rows({"status": "ordinary"}, {"status": "ordinary"}),
        )
        self.assertEqual(model["status"], "UNASSESSED")
        self.assertTrue(any("runtime oracle" in reason for reason in model["modeling_reasons"]))

    def test_public_advisory_candidate_rejects_tampered_excerpt_hash(self):
        spec = _advisory_candidate_spec()
        spec["advisory_semantics"]["source_excerpt_sha256"] = "0" * 64
        model = build_effect_model(
            spec,
            _rows_with_complete_oracle({"status": "ordinary"}, {"status": "ordinary"}),
        )
        self.assertEqual(model["status"], "UNASSESSED")
        self.assertTrue(any("excerpt hash" in reason for reason in model["modeling_reasons"]))

    def test_scalar_tool_result_has_root_provenance_path(self):
        rows = []
        for level in (
            "L0_RAW_MCP_RESULT", "L1_NORMALIZED_TOOL_RESULT",
            "L2_HOST_PROCESSED_TOOL_RESULT", "L3_SESSION_TOOL_RESULT",
            "L4_MODEL_VISIBLE_OBSERVATION",
        ):
            row = {"level": level, "content": "scalar Tool result", "tool_result": "scalar Tool result"}
            if level == "L4_MODEL_VISIBLE_OBSERVATION":
                row.update({
                    "actual_next_model_request": True,
                    "model_request": {"messages": [{"role": "tool", "tool_call_id": "call-1", "content": "scalar Tool result"}]},
                })
            rows.append(row)
        trace = _trace_side(rows)
        self.assertTrue(trace["tool_result_provenance"])
        self.assertTrue(trace["l4_tool_result_provenance"])
        self.assertEqual(trace["shared_paths"], ["$"])

    def test_effect_kind_and_role_are_orthogonal(self):
        self.assertEqual(classify_effect_role("CONTROL_EFFECT"), "TERMINAL")
        self.assertEqual(classify_effect_role("RESOURCE_EFFECT"), "TERMINAL")
        self.assertEqual(classify_effect_role("VALUE_EFFECT", explicit="INTERMEDIATE"), "INTERMEDIATE")
        self.assertEqual(classify_effect_role("VALUE_EFFECT", has_downstream=True, terminal_witness=False), "INTERMEDIATE")
        self.assertEqual(classify_effect_role("CONTROL_EFFECT", explicit="BOTH"), "BOTH")
        self.assertEqual(classify_effect_role("RESOURCE_EFFECT", has_downstream=True), "BOTH")
        self.assertEqual(classify_effect_role("CONTROL_EFFECT", has_downstream=True, vulnerability_category="AUTHENTICATION_OR_AUTHORIZATION_BYPASS"), "BOTH")

    def test_carrier_projection_supports_structured_content_and_projection_mapping(self):
        carrier = build_carrier_projection(
            "VALUE_EFFECT",
            ["result.structuredContent.records[0].content"],
            tool_name="read_records",
            field_mapping="structuredContent.records -> text.records",
        )
        self.assertEqual(carrier["kind"], "structured_content")
        self.assertTrue(carrier["l4_eligible"])
        self.assertEqual(carrier["field_mapping"], "structuredContent.records -> text.records")

    def test_side_effect_only_realization_is_not_agent_visibility(self):
        spec = _spec()
        spec["source"] = {
            "vulnerable": [{"path": "probe.py", "content": "def probe(path):\n    open(path, 'w').write('changed')\n    return {'status': 'ok'}\n"}],
            "fixed": [{"path": "probe.py", "content": "def probe(path):\n    if not path.startswith('/safe/'):\n        raise ValueError('blocked')\n    open(path, 'w').write('changed')\n    return {'status': 'ok'}\n"}],
        }
        spec["patch"] = {"unified_diff": "--- a/probe.py\n+++ b/probe.py\n@@ -1,3 +1,5 @@\n def probe(path):\n+    if not path.startswith('/safe/'):\n+        raise ValueError('blocked')\n     open(path, 'w').write('changed')\n     return {'status': 'ok'}\n"}
        traces = _rows({"status": "ok"}, {"status": "blocked"})
        traces["vulnerable"][2]["event"] = {"operation": "write", "state_write": True, "resource_id": "outside", "after_state": {"changed": True}, "function": "open", "location": "probe.py:2"}
        traces["fixed"][2]["event"] = {"operation": "blocked", "function": "probe", "error": {"type": "ValueError"}}
        model = build_effect_model(spec, traces)
        resource = _effect(model, "RESOURCE_EFFECT")
        self.assertEqual(resource["effect_realization"]["status"], "REALIZED")
        self.assertEqual(resource["propagation"]["tool_result"], "NOT_REACHED")
        self.assertEqual(resource["propagation"]["agent_observation"], "NOT_REACHED")

    def test_host_filter_separates_tool_result_from_agent_observation(self):
        spec = _spec()
        traces = _rows({"derived_value": "secret"}, {"status": "safe"}, l4_vulnerable={"status": "filtered"}, l4_fixed={"status": "safe"})
        for row in traces["vulnerable"]:
            if row["level"] in {"L3_SESSION_TOOL_RESULT", "L4_MODEL_VISIBLE_OBSERVATION"}:
                row["filtering"] = {"field": "tool_result.derived_value", "action": "drop"}
        model = build_effect_model(spec, traces)
        value = _effect(model, "VALUE_EFFECT")
        self.assertEqual(value["propagation"]["tool_result"], "REACHED")
        self.assertEqual(value["propagation"]["host"], "DROPPED")
        self.assertEqual(value["propagation"]["agent_observation"], "NOT_REACHED")

    def test_propagation_statuses_are_shared_by_validator_contract(self):
        model = build_effect_model(_spec(), _rows({"derived_value": "uid=0"}, {"status": "safe"}))
        effect = _effect(model, "VALUE_EFFECT")
        for status in ("DROPPED", "TRANSFORMED"):
            candidate = copy.deepcopy(model)
            _effect(candidate, "VALUE_EFFECT")["propagation"]["tool_result"] = status
            self.assertFalse(validate_effect_model(candidate), status)
        invalid = copy.deepcopy(model)
        _effect(invalid, "VALUE_EFFECT")["propagation"]["tool_result"] = "UNKNOWN"
        self.assertTrue(any("effect.propagation.tool_result is invalid" in item for item in validate_effect_model(invalid)))
        self.assertEqual(effect["propagation"]["tool_result"], "REACHED")

    def test_raw_normalized_tool_effect_is_modeled_before_host_projection(self):
        spec = _spec()
        traces = _rows({"status": "safe"}, {"status": "safe"})
        for side in ("vulnerable", "fixed"):
            native = {"native_value": "raw-only"} if side == "vulnerable" else {"status": "blocked"}
            for row in traces[side][:2]:
                row["content"] = {"tool_result": native}
            projected = {"status": "projected"} if side == "vulnerable" else {"status": "blocked"}
            for row in traces[side][2:4]:
                row["content"] = {"tool_result": projected}
        model = build_effect_model(spec, traces)
        self.assertNotEqual(model["status"], "UNASSESSED")
        self.assertTrue(model["effects"])
        self.assertTrue(any(item["effect_realization"]["status"] == "REALIZED" for item in model["effects"]))

    def test_fixed_projection_fields_do_not_preserve_blocked_raw_carrier(self):
        traces = _rows(
            {"result": {"content": [{"type": "image", "data": "native-v"}]}},
            {"result": {"content": [{"type": "text", "text": "blocked"}]}},
        )
        for side, rows in traces.items():
            for row in rows[:2]:
                row["content"] = {
                    "result": {
                        "content": [
                            {
                                "type": "image",
                                "data": "native-v",
                            }
                            if side == "vulnerable" else {
                                "type": "text",
                                "text": "blocked",
                            }
                        ],
                    },
                }
            for row in rows[2:4]:
                row["content"] = {
                    "result": {"content": [{"type": "text", "text": "diagnostic"}]},
                }
        trace_v = _trace_side(traces["vulnerable"])
        trace_f = _trace_side(traces["fixed"])
        self.assertTrue(trace_v["raw_tool_value_digests"])
        self.assertTrue(trace_f["raw_tool_value_digests"])
        vulnerable, fixed, sources = _preferred_paired_carrier_digests(
            trace_v,
            trace_f,
            ["result.content[0].type"],
        )
        self.assertEqual(sources["result.content[0].type"], "L0_L1_RAW_NORMALIZED")
        self.assertNotEqual(
            vulnerable["result.content[0].type"],
            fixed["result.content[0].type"],
        )

    def test_semantic_carriers_exclude_protocol_projection_and_fixed_only_paths(self):
        traces = _rows(
            {"content": [{"type": "image", "data": "raw-image", "mimeType": "image/jpeg"}], "isError": False},
            {"content": [{"type": "text", "text": "[unsupported content block]"}]},
        )
        vulnerable = _trace_side(traces["vulnerable"])
        fixed = _trace_side(traces["fixed"])
        paths = _value_carrier_paths(vulnerable, _trace_diff(vulnerable, fixed, {}), {})
        self.assertTrue(any(path.endswith("data") for path in paths), paths)
        self.assertFalse(any(path.endswith("type") for path in paths), paths)
        self.assertFalse(any(path.endswith("mimeType") for path in paths), paths)
        self.assertFalse(any(path.endswith("isError") for path in paths), paths)
        self.assertFalse(any(path.endswith("text") for path in paths), paths)

    def test_fixed_missing_raw_carrier_is_effect_specific_blocking_evidence(self):
        def rows(payload):
            result = []
            for level in (
                "L0_RAW_MCP_RESULT", "L1_NORMALIZED_TOOL_RESULT",
                "L2_HOST_PROCESSED_TOOL_RESULT", "L3_SESSION_TOOL_RESULT",
                "L4_MODEL_VISIBLE_OBSERVATION",
            ):
                row = {"level": level, "content": payload}
                if level == "L4_MODEL_VISIBLE_OBSERVATION":
                    row["actual_next_model_request"] = True
                    row["model_request"] = {
                        "messages": [{"role": "tool", "tool_call_id": "call-1", "content": payload}],
                    }
                result.append(row)
            return result

        model = {
            "schema_version": "vulveil-effect-model/v3",
            "status": "GENERATED",
            "effects": [{
                "effect_id": "effect-data",
                "effect_kind": "VALUE_EFFECT",
                "effect_role": "TERMINAL",
                "carrier": {
                    "paths": ["content[0].data"],
                    "vulnerable_value_digests": {"content[0].data": ["vulnerable-digest"]},
                    "fixed_value_digests": {},
                },
            }],
        }
        vulnerable = rows({"content": [{"data": "raw-image"}]})
        fixed = rows({"content": [{"text": "[unsupported content block]"}]})
        vulnerable_observation = inspect_l4_effect(model, vulnerable)["effects"][0]
        fixed_observation = inspect_l4_effect(model, fixed)["effects"][0]
        self.assertEqual(vulnerable_observation["production_status"], "PRODUCED")
        self.assertEqual(fixed_observation["effect_realization"]["status"], "NOT_REALIZED")
        self.assertEqual(fixed_observation["rejected_fixed_baseline_paths"], ["content[0].data"])

    def test_provenance_status_maps_checker_validation_conclusions_without_promotion(self):
        expected = {
            "CHECKER_SPECIFIC_VALIDATED": "SUPPORTED",
            "PAIRED_EFFECT_DIFFERENCE_ONLY": "PARTIAL",
            "UNASSESSED": "UNASSESSED",
            "EXPLICIT_CHECKER_EVENT": "UNASSESSED",
            "MISSING_OR_MISMATCHED": "UNASSESSED",
        }
        for runtime_status, provenance_status in expected.items():
            with self.subTest(runtime_status=runtime_status), patch(
                "oscar.analysis.effect_modeling.validate_paired_repair_predicate",
                return_value={"validation_conclusion": runtime_status, "checkers": [], "evidence_refs": []},
            ):
                model = build_effect_model(_spec(), _rows({"derived_value": "uid=0"}, {"status": "safe"}))
            self.assertTrue(model["effects"])
            self.assertTrue(all(item["provenance_status"] == provenance_status for item in model["effects"]))

    def test_anchor_reached_without_effect_witness_is_not_realized(self):
        model = build_effect_model(_spec(), _rows({"derived_value": "uid=0"}, {"status": "safe"}))
        rows = _rows({"status": "ordinary"}, {"status": "ordinary"})["vulnerable"]
        result = inspect_l4_effect(model, rows)
        self.assertTrue(result["effects"])
        self.assertTrue(all(item["effect_realization"]["status"] == "NOT_REALIZED" for item in result["effects"]))
        self.assertTrue(all(item["effect_status"] == "NOT_REACHED" for item in result["effects"]))

    def test_incomplete_or_invalid_trace_keeps_realization_unassessed(self):
        model = build_effect_model(_spec(), _rows({"derived_value": "uid=0"}, {"status": "safe"}))
        incomplete = _rows({"derived_value": "uid=0"}, {"status": "safe"})["vulnerable"][:-1]
        incomplete_result = inspect_l4_effect(model, incomplete)
        self.assertTrue(all(item["effect_realization"]["status"] == "UNASSESSED" for item in incomplete_result["effects"]))
        invalid = _rows({"derived_value": "uid=0"}, {"status": "safe"})["vulnerable"]
        invalid[2]["invalid_run"] = True
        invalid_result = inspect_l4_effect(model, invalid)
        self.assertTrue(all(item["effect_realization"]["status"] == "UNASSESSED" for item in invalid_result["effects"]))

    def test_structured_content_and_text_are_distinct_carriers(self):
        projection = build_carrier_projection("VALUE_EFFECT", ["result.structuredContent.records[0].content"])
        self.assertEqual(projection["kind"], "structured_content")
        self.assertNotEqual(projection["path"], "result.text")

    def test_input_echo_and_error_text_do_not_become_supported_effects(self):
        echo_spec = _spec()
        echo_spec["tool_input"] = {"value": "same"}
        echo_spec["source"] = {
            "vulnerable": [{"path": "probe.py", "content": "def probe(value):\n    return value\n"}],
            "fixed": [{"path": "probe.py", "content": "def probe(value):\n    return value\n"}],
        }
        echo_spec["patch"] = {"unified_diff": "--- a/probe.py\n+++ b/probe.py\n@@ -1 +1 @@\n-def probe(value):\n-    return value\n+def probe(value):\n+    return value\n"}
        echo_model = build_effect_model(echo_spec, _rows({"echo": "same"}, {"echo": "same"}))
        self.assertEqual(echo_model["status"], "UNASSESSED")

        error_spec = _spec()
        error_spec["source"] = {
            "vulnerable": [{"path": "probe.py", "content": "def probe(value):\n    return value\n"}],
            "fixed": [{"path": "probe.py", "content": "def probe(value):\n    return value\n"}],
        }
        error_spec["patch"] = {"unified_diff": "--- a/probe.py\n+++ b/probe.py\n@@ -1 +1 @@\n-def probe(value):\n-    return value\n+def probe(value):\n+    return value\n"}
        error_model = build_effect_model(error_spec, _rows({"error": "old"}, {"error": "new"}))
        self.assertEqual(error_model["status"], "UNASSESSED")

    def test_source_diff_without_runtime_witness_is_unresolved_or_partial(self):
        spec = _spec()
        traces = _rows({"status": "same"}, {"status": "same"})
        model = build_effect_model(spec, traces)
        self.assertIn(model["status"], {"UNASSESSED", "GENERATED"})
        if model["status"] == "GENERATED":
            self.assertTrue(all(item["classification_status"] != "SUPPORTED" for item in model["effects"]))

    def test_normalize_legacy_v3_artifact_marks_missing_semantics_unassessed(self):
        model = build_effect_model(_spec(), _rows({"derived_value": "uid=0"}, {"status": "safe"}))
        legacy = copy.deepcopy(model)
        for effect in legacy["effects"]:
            for key in ("effect_role", "classification_status", "provenance_status", "effect_realization", "propagation"):
                effect.pop(key, None)
            for key in ("kind", "field_mapping", "l4_eligible"):
                effect["carrier"].pop(key, None)
        normalized = normalize_effect_model(legacy)
        self.assertEqual(normalized["compatibility"]["status"], "UNASSESSED")
        self.assertTrue(all(effect["effect_realization"]["status"] == "UNASSESSED" for effect in normalized["effects"]))

    def test_same_source_scope_without_dependency_does_not_create_relation(self):
        model = build_effect_model(_spec(), _rows({"derived_value": "uid=0"}, {"status": "safe"}))
        for relation in model["effect_relations"]:
            self.assertTrue(relation["evidence_refs"])
            self.assertIn(relation["provenance_status"], {"SUPPORTED", "PARTIAL", "UNASSESSED"})
    def test_local_git_revisions_supply_source_and_patch_automatically(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            source = repo / "probe.py"
            source.write_text("import subprocess\ndef probe(command):\n    return subprocess.check_output(command, shell=True)\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(repo), "add", "probe.py"], check=True)
            subprocess.run(["git", "-C", str(repo), "-c", "user.name=OSCAR", "-c", "user.email=vulveil@example.invalid", "commit", "-q", "-m", "vulnerable"], check=True)
            vulnerable_revision = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
            source.write_text("import subprocess\ndef probe(command):\n    if not isinstance(command, str) or \"|\" in command:\n        raise ValueError(\"rejected\")\n    return subprocess.check_output([\"echo\", command], shell=False)\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(repo), "add", "probe.py"], check=True)
            subprocess.run(["git", "-C", str(repo), "-c", "user.name=OSCAR", "-c", "user.email=vulveil@example.invalid", "commit", "-q", "-m", "fixed"], check=True)
            fixed_revision = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
            spec = _spec()
            spec["source"] = {
                "vulnerable": {"git_repo": str(repo), "revision": vulnerable_revision, "paths": ["probe.py"]},
                "fixed": {"git_repo": str(repo), "revision": fixed_revision, "paths": ["probe.py"]},
            }
            spec["patch"] = {
                "git_repo": str(repo),
                "vulnerable_revision": vulnerable_revision,
                "fixed_revision": fixed_revision,
                "paths": ["probe.py"],
            }
            model = build_effect_model(spec, _rows({"derived_value": "uid=0"}, {"status": "safe"}))
        self.assertEqual(model["status"], "GENERATED")
        self.assertTrue(model["anchor_candidates"])
        self.assertTrue(any("patch:probe.py" in effect["evidence_refs"] for effect in model["effects"]))

    def test_model_generates_without_legacy_oracle_fields(self):
        spec = _spec()
        model = build_effect_model(spec, _rows({"derived_value": "uid=0"}, {"status": "safe"}))
        self.assertEqual(model["status"], "GENERATED")
        self.assertEqual(model["schema_version"], "vulveil-effect-model/v3")
        self.assertFalse(any(key in json.dumps(model) for key in ("vulnerability_specific_effect", "l4_signal_token")))
        self.assertEqual({item["status"] for item in model["counterfactual_checks"]}, {"GENERATED"})

    def test_stage2_can_model_from_l0_l3_without_requiring_l4(self):
        traces = _rows({"derived_value": "uid=0"}, {"status": "safe"})
        traces = {side: rows[:-1] for side, rows in traces.items()}
        model = build_effect_model(_spec(), traces)
        self.assertEqual(model["status"], "GENERATED")
        self.assertTrue(_effect(model, "VALUE_EFFECT")["carrier"]["paths"])
        self.assertNotIn("trace:vulnerable:L4", _effect(model, "VALUE_EFFECT")["evidence_refs"])

    def test_dynamic_call_parameter_and_return_differences_are_recorded(self):
        traces = _rows({"derived_value": "uid=0"}, {"status": "safe"})
        traces["vulnerable"][2]["event"] = {
            "function": "subprocess.check_output",
            "location": "probe.py:3",
            "arguments": {"command": "id | whoami"},
            "return": {"stdout": "uid=0"},
            "file_path": "/tmp/vulnerable-effect",
        }
        traces["fixed"][2]["event"] = {
            "function": "subprocess.check_output",
            "location": "probe.py:5",
            "arguments": {"command": ["echo", "id"]},
            "return": {"status": "rejected"},
            "error": {"type": "ValueError"},
        }
        model = build_effect_model(_spec(), traces)
        value_effect = _effect(model, "VALUE_EFFECT")
        dynamic = value_effect["condition"]["dynamic_difference"]
        self.assertTrue(dynamic["changed_paths"] or value_effect["origin"]["runtime_call_differences"])
        self.assertTrue(dynamic["exceptions_changed"])
        self.assertTrue(dynamic["resource_events_changed"])
        self.assertIn("state", {edge["edge_type"] for edge in _effect(model, "RESOURCE_EFFECT")["provenance"]})

    def test_category_is_metadata_and_does_not_select_effect_kind(self):
        base = _spec()
        base.pop("experiment_type", None)
        base["vulnerability_category"] = "CATEGORY_OUTSIDE_PRIORITY_SET"
        model_without_category = build_effect_model(base, _rows({"derived_value": "uid=0"}, {"status": "blocked"}))
        base["vulnerability_category"] = "PATH_TRAVERSAL_OR_ARBITRARY_FILE_IO"
        model_with_category = build_effect_model(base, _rows({"derived_value": "uid=0"}, {"status": "blocked"}))
        self.assertEqual(model_without_category["status"], "GENERATED")
        self.assertEqual(model_with_category["status"], "GENERATED")
        self.assertEqual(
            [item["effect_kind"] for item in model_without_category["effects"]],
            [item["effect_kind"] for item in model_with_category["effects"]],
        )
        self.assertNotIn("effect_type", json.dumps(model_without_category))

    def test_path_traversal_builds_three_effects_and_evidence_relations(self):
        spec = _spec()
        spec["vulnerability_category"] = "PATH_TRAVERSAL_OR_ARBITRARY_FILE_IO"
        spec["tool_input"] = {"path": "../../secret.txt"}
        spec["source"] = {
            "vulnerable": [{"path": "probe.py", "content": "def probe(path):\n    return open(path, 'rb').read()\n"}],
            "fixed": [{"path": "probe.py", "content": "def probe(path):\n    if not path.startswith('/safe/'):\n        raise ValueError('blocked')\n    return open(path, 'rb').read()\n"}],
        }
        spec["patch"] = {"unified_diff": "--- a/probe.py\n+++ b/probe.py\n@@ -1,2 +1,4 @@\n def probe(path):\n+    if not path.startswith('/safe/'):\n+        raise ValueError('blocked')\n     return open(path, 'rb').read()\n"}
        traces = _rows({"file_content": "secret"}, {"status": "blocked"})
        traces["vulnerable"][2]["event"] = {"operation": "read", "state_read": True, "resource_id": "outside-file", "file_path": "/etc/passwd", "function": "open", "location": "probe.py:2"}
        traces["fixed"][2]["event"] = {"operation": "blocked", "function": "probe", "location": "probe.py:2", "error": {"type": "ValueError"}}
        model = build_effect_model(spec, traces)
        self.assertEqual(model["status"], "GENERATED")
        self.assertEqual({item["effect_kind"] for item in model["effects"]}, {"CONTROL_EFFECT", "RESOURCE_EFFECT", "VALUE_EFFECT"})
        self.assertEqual({(item["from"], item["to"], item["relation"]) for item in model["effect_relations"]}, {
            ("effect-control-1", "effect-resource-1", "CAUSES"),
            ("effect-resource-1", "effect-value-1", "DERIVES_VALUE"),
        })
        self.assertEqual(_effect(model, "RESOURCE_EFFECT")["effect_role"], "INTERMEDIATE")
        self.assertEqual(_effect(model, "VALUE_EFFECT")["effect_role"], "TERMINAL")
        self.assertTrue(all(item["provenance_status"] for item in model["effect_relations"]))

    def test_value_only_evidence_does_not_create_control_or_resource_effect(self):
        spec = _spec()
        spec["source"] = {
            "vulnerable": [{"path": "probe.py", "content": "def probe(value):\n    return dependency.expose(value)\n"}],
            "fixed": [{"path": "probe.py", "content": "def probe(value):\n    return dependency.expose_safe(value)\n"}],
        }
        spec["patch"] = {"unified_diff": "--- a/probe.py\n+++ b/probe.py\n@@ -1,2 +1,2 @@\n def probe(value):\n-    return dependency.expose(value)\n+    return dependency.expose_safe(value)\n"}
        model = build_effect_model(spec, _rows({"derived": "vulnerable"}, {"derived": "fixed"}))
        self.assertEqual(model["status"], "GENERATED")
        self.assertEqual([item["effect_kind"] for item in model["effects"]], ["VALUE_EFFECT"])

    def test_resource_effect_without_tool_carrier_is_produced_but_not_reachable(self):
        spec = _spec()
        spec["tool_input"] = {"path": "secret.txt"}
        spec["source"] = {
            "vulnerable": [{"path": "probe.py", "content": "def probe(path):\n    return open(path, 'rb').read()\n"}],
            "fixed": [{"path": "probe.py", "content": "def probe(path):\n    return open('/safe/' + path, 'rb').read()\n"}],
        }
        spec["patch"] = {"unified_diff": "--- a/probe.py\n+++ b/probe.py\n@@ -1,2 +1,2 @@\n def probe(path):\n-    return open(path, 'rb').read()\n+    return open('/safe/' + path, 'rb').read()\n"}
        traces = _rows({"status": "ok"}, {"status": "ok"})
        traces["vulnerable"][2]["event"] = {"operation": "read", "state_read": True, "resource_id": "outside-file", "file_path": "/etc/passwd", "function": "open", "location": "probe.py:2"}
        traces["fixed"][2]["event"] = {"operation": "noop", "function": "open", "location": "probe.py:2"}
        model = build_effect_model(spec, traces)
        self.assertEqual(model["status"], "GENERATED")
        self.assertEqual([item["effect_kind"] for item in model["effects"]], ["RESOURCE_EFFECT"])
        result = inspect_l4_effect(model, traces["vulnerable"])
        resource_result = result["effects"][0]
        self.assertEqual(resource_result["production_status"], "PRODUCED")
        self.assertTrue(resource_result["external_resource_affected"])
        self.assertFalse(resource_result["reached_tool_result"])
        self.assertFalse(resource_result["reached_exact_l4"])
        self.assertEqual(resource_result["highest_witnessed_level"], "P2-R")
        self.assertEqual(resource_result["stop_layer"], "EXTERNAL_RESOURCE")
        self.assertEqual(resource_result["termination_reason"], "NO_READBACK")
        self.assertEqual(result["status"], "NOT_REACHED")

    def test_control_effect_without_readable_carrier_is_not_reachable(self):
        traces = _rows({"status": "ordinary"}, {"status": "ordinary"})
        traces["vulnerable"][2]["event"] = {"function": "subprocess.check_output", "location": "probe.py:3", "return": {"stdout": "uid=0"}}
        traces["fixed"][2]["event"] = {"function": "probe", "location": "probe.py:3", "error": {"type": "ValueError"}}
        spec = _spec()
        spec["source"] = {
            "vulnerable": [{"path": "probe.py", "content": "def probe(command):\n    return command\n"}],
            "fixed": [{"path": "probe.py", "content": "def probe(command):\n    if '|' in command:\n        raise ValueError('blocked')\n    return command\n"}],
        }
        spec["patch"] = {"unified_diff": "--- a/probe.py\n+++ b/probe.py\n@@ -1,2 +1,4 @@\n def probe(command):\n+    if '|' in command:\n+        raise ValueError('blocked')\n     return command\n"}
        model = build_effect_model(spec, traces)
        self.assertEqual(model["status"], "GENERATED")
        self.assertEqual([item["effect_kind"] for item in model["effects"]], ["CONTROL_EFFECT"])
        result = inspect_l4_effect(model, traces["vulnerable"])
        self.assertEqual(result["status"], "NOT_REACHED")
        self.assertEqual(result["not_reached_effect_ids"], ["effect-control-1"])

    def test_control_effect_can_keep_identity_through_status_carrier(self):
        traces = _rows({"status": "uid=0"}, {"status": "blocked"})
        traces["vulnerable"][2]["event"] = {"function": "probe", "location": "probe.py:3", "return": {"status": "uid=0"}}
        traces["fixed"][2]["event"] = {"function": "probe", "location": "probe.py:3", "error": {"type": "ValueError"}}
        spec = _spec()
        spec["source"] = {
            "vulnerable": [{"path": "probe.py", "content": "def probe(command):\n    return subprocess.check_output(command, shell=True)\n"}],
            "fixed": [{"path": "probe.py", "content": "def probe(command):\n    if '|' in command: raise ValueError('blocked')\n    return subprocess.check_output([command], shell=False)\n"}],
        }
        spec["patch"] = {"unified_diff": "--- a/probe.py\n+++ b/probe.py\n@@ -1,2 +1,2 @@\n def probe(command):\n-    return subprocess.check_output(command, shell=True)\n+    if '|' in command: raise ValueError('blocked')\n"}
        model = build_effect_model(spec, traces)
        control = _effect(model, "CONTROL_EFFECT")
        self.assertEqual(control["carrier"]["carrier_kind"], "CONTROL_STATE")
        self.assertTrue(control["carrier"]["paths"])
        self.assertTrue(any(item["rule"] == "control-event-to-return-status-carrier" for item in control["carrier"]["transformations"]))
        result = inspect_l4_effect(model, traces["vulnerable"])
        control_result = next(item for item in result["effects"] if item["effect_id"] == control["effect_id"])
        self.assertTrue(control_result["reached_exact_l4"])

    def test_resource_readback_reaches_l4_with_resource_identity(self):
        spec = _spec()
        spec["tool_input"] = {"path": "secret.txt"}
        spec["source"] = {
            "vulnerable": [{"path": "probe.py", "content": "def probe(path):\n    return open(path, 'rb').read()\n"}],
            "fixed": [{"path": "probe.py", "content": "def probe(path):\n    return open('/safe/' + path, 'rb').read()\n"}],
        }
        spec["patch"] = {"unified_diff": "--- a/probe.py\n+++ b/probe.py\n@@ -1,2 +1,2 @@\n def probe(path):\n-    return open(path, 'rb').read()\n+    return open('/safe/' + path, 'rb').read()\n"}
        traces = _rows({"structuredContent": {"file_content": "secret"}}, {"structuredContent": {"status": "blocked"}})
        traces["vulnerable"][2]["event"] = {"operation": "read", "state_read": True, "resource_id": "outside-file", "function": "open", "location": "probe.py:2", "return": {"file_content": "secret"}}
        traces["fixed"][2]["event"] = {"operation": "blocked", "function": "probe", "location": "probe.py:2", "error": {"type": "ValueError"}}
        model = build_effect_model(spec, traces)
        resource = _effect(model, "RESOURCE_EFFECT")
        self.assertTrue(resource["carrier"]["paths"])
        result = inspect_l4_effect(model, traces["vulnerable"])
        resource_result = next(item for item in result["effects"] if item["effect_id"] == resource["effect_id"])
        self.assertEqual(resource_result["production_status"], "PRODUCED")
        self.assertTrue(resource_result["reached_exact_l4"])

    def test_invalid_effect_relations_and_duplicate_ids_are_rejected(self):
        model = build_effect_model(_spec(), _rows({"derived_value": "uid=0"}, {"status": "safe"}))
        bad_relation = copy.deepcopy(model)
        bad_relation["effect_relations"] = [{"from": "missing", "to": "effect-value-1", "relation": "PRODUCES", "evidence_refs": ["test"]}]
        self.assertTrue(any("unknown effect ID" in item for item in validate_effect_model(bad_relation)))
        duplicate = copy.deepcopy(model)
        duplicate["effects"][1]["effect_id"] = duplicate["effects"][0]["effect_id"]
        self.assertTrue(any("unique" in item for item in validate_effect_model(duplicate)))

    def test_legacy_effect_model_is_rejected_explicitly(self):
        legacy = {"schema_version": "vulveil-effect-model/v1", "status": "GENERATED", "effects": [{"effect_id": "effect-1", "effect_type": "COMMAND_OR_QUERY_INJECTION", "object": {"dimensions": ["value"]}}]}
        errors = validate_effect_model(legacy)
        self.assertTrue(any("legacy v1" in item for item in errors))
        self.assertTrue(any("effect_type" in item for item in errors))

    def test_legacy_v2_effect_model_is_rejected_with_migration_reason(self):
        model = build_effect_model(_spec(), _rows({"derived_value": "uid=0"}, {"status": "safe"}))
        model["schema_version"] = "vulveil-effect-model/v2"
        errors = validate_effect_model(model)
        self.assertTrue(any("legacy v2" in item and "incompatible" in item for item in errors))

    def test_same_tool_result_field_with_different_value_is_modeled(self):
        model = build_effect_model(
            _spec(),
            _rows({"result": {"stdout": "uid=0"}}, {"result": {"stdout": "rejected"}}),
        )
        self.assertEqual(model["status"], "GENERATED")
        value_effect = _effect(model, "VALUE_EFFECT")
        dynamic = value_effect["condition"]["dynamic_difference"]
        self.assertTrue(any(path.endswith("result.stdout") for path in dynamic["changed_value_paths"]))
        self.assertTrue(any(path.endswith("result.stdout") for path in value_effect["carrier"]["paths"]))

    def test_generated_counterfactuals_separate_safe_and_field_only_inputs(self):
        spec = _spec()
        spec["tool_input"]["working_directory"] = "/tmp/work"
        model = build_effect_model(spec, _rows({"derived_value": "uid=0"}, {"status": "safe"}))
        checks = {item["kind"]: item for item in model["counterfactual_checks"]}
        self.assertNotEqual(checks["safe-input"]["input_digest"], checks["replace-trigger-field"]["input_digest"])

    def test_same_input_echo_field_value_is_not_modeled(self):
        model = build_effect_model(
            _spec(),
            _rows({"command": "id | whoami"}, {"command": "id"}),
        )
        self.assertEqual(model["status"], "UNASSESSED")
        self.assertFalse(model["effects"])

    def test_supplied_counterfactuals_require_effect_relation(self):
        spec = _spec()
        traces = _rows({"derived_value": "uid=0"}, {"status": "safe"})
        spec["counterfactuals"] = [
            {"name": "trigger", "trace": traces["vulnerable"]},
            {"name": "safe", "trace": traces["fixed"]},
        ]
        model = build_effect_model(spec, traces)
        statuses = {item["kind"]: item["status"] for item in model["counterfactual_checks"]}
        self.assertEqual(statuses["trigger"], "SUPPORTED")
        self.assertEqual(statuses["safe"], "SUPPORTED")

    def test_counterfactual_matrix_preserves_effect_for_unrelated_change(self):
        spec = _spec()
        traces = _rows({"derived_value": "uid=0"}, {"status": "safe"})
        spec["counterfactuals"] = [
            {"name": "trigger", "role": "trigger", "trace": traces["vulnerable"]},
            {"name": "safe", "role": "safe", "trace": traces["fixed"]},
            {"name": "field-only", "role": "field-only", "trace": traces["fixed"]},
            {"name": "unrelated", "role": "unrelated", "trace": traces["vulnerable"]},
            {"name": "fixed", "role": "fixed", "trace": traces["fixed"]},
        ]
        model = build_effect_model(spec, traces)
        statuses = {item["role"]: item["status"] for item in model["counterfactual_checks"]}
        self.assertEqual(statuses, {role: "SUPPORTED" for role in ("trigger", "safe", "field-only", "unrelated", "fixed")})

    def test_patch_anchor_type_origin_condition_and_provenance_are_structured(self):
        model = build_effect_model(_spec(), _rows({"query_result": "uid=0"}, {"status": "rejected"}))
        effect = _effect(model, "VALUE_EFFECT")
        self.assertEqual(effect["effect_kind"], "VALUE_EFFECT")
        self.assertIn("subprocess.check_output", effect["origin"]["apis"])
        self.assertTrue(effect["condition"]["patch_derived"])
        self.assertTrue({"call", "data", "serialize", "observe"}.issubset({edge["edge_type"] for edge in effect["provenance"]}))
        self.assertTrue(all(edge["evidence_refs"] for edge in effect["provenance"]))
        self.assertTrue(all(set(edge["slice_direction"]) == {"forward", "backward"} for edge in effect["provenance"]))
        self.assertTrue(model["fixed_side_blocked"])

    def test_same_file_change_outside_patch_hunk_is_not_an_anchor(self):
        spec = _spec()
        vulnerable = "# old header\n" + "\n" * 8 + "def helper(command):\n    return subprocess.check_output(command, shell=True)\n"
        fixed = "# new header\n" + "\n" * 8 + "def helper(command):\n    return subprocess.check_output([command], shell=False)\n"
        spec["source"] = {
            "vulnerable": [{"path": "probe.py", "content": vulnerable}],
            "fixed": [{"path": "probe.py", "content": fixed}],
        }
        spec["patch"] = {"unified_diff": "--- a/probe.py\n+++ b/probe.py\n@@ -1 +1 @@\n-# old header\n+# new header\n"}
        model = build_effect_model(spec, _rows({"derived_value": "uid=0"}, {"status": "safe"}))
        self.assertEqual(model["status"], "UNASSESSED")
        self.assertIn("no structured source anchor", " ".join(model["modeling_reasons"]))

    def test_input_echo_without_structural_effect_is_unassessed(self):
        model = build_effect_model(_spec(), _rows({"echo": "id"}, {"echo": "id"}))
        self.assertEqual(model["status"], "UNASSESSED")
        self.assertFalse(model["effects"])

    def test_resource_write_with_path_echo_does_not_create_value_effect(self):
        spec = _spec()
        spec["tool_input"] = {"saveTo": "../escape.png"}
        traces = _rows(
            {"content": [{"type": "text", "text": "Screenshot saved to: ../escape.png"}]},
            {"content": [{"type": "text", "text": "blocked"}]},
        )
        traces["vulnerable"][2]["event"] = {
            "operation": "write", "resource_id": "container-local-filesystem:escape.png",
            "state_write": True, "stable_resource_identity": True,
        }
        traces["fixed"][2]["event"] = {"operation": "blocked", "error": {"type": "ActionableError"}}
        model = build_effect_model(spec, traces)
        self.assertEqual(model["status"], "GENERATED")
        self.assertTrue(any(item["effect_kind"] == "RESOURCE_EFFECT" for item in model["effects"]))
        self.assertFalse(any(item["effect_kind"] == "VALUE_EFFECT" for item in model["effects"]))

    def test_stable_resource_identity_groups_repetitions(self):
        rows = []
        for repetition in (1, 2, 3):
            rows.append({
                "level": "L0_RAW_MCP_RESULT",
                "repetition": repetition,
                "trace_id": f"trace-{repetition}",
                "span_id": f"span-{repetition}",
                "event": {
                    "resource_id": "resource-sha256:stable",
                    "operation": "write",
                    "location": "controlled-external-boundary",
                    "function": "CASE-1",
                    "stable_resource_identity": True,
                },
            })

        events = _runtime_resource_events(rows)

        self.assertEqual(len(events), 1)
        self.assertNotIn("repetition", events[0])
        self.assertNotIn("trace_id", events[0])
        self.assertEqual(
            {ref for ref in events[0]["evidence_refs"] if ref.startswith("trace:L0")},
            {"trace:L0_RAW_MCP_RESULT:1", "trace:L0_RAW_MCP_RESULT:2", "trace:L0_RAW_MCP_RESULT:3"},
        )

    def test_root_scalar_input_echo_does_not_create_value_effect(self):
        spec = _spec()
        spec["tool_input"] = {"saveTo": "../escape.png"}
        traces = {"vulnerable": [], "fixed": []}
        for side, value in (
            ("vulnerable", "Screenshot saved to: ../escape.png"),
            ("fixed", "The requested path is outside the allowed directory"),
        ):
            for level in (
                "L0_RAW_MCP_RESULT",
                "L1_NORMALIZED_TOOL_RESULT",
                "L2_HOST_PROCESSED_TOOL_RESULT",
                "L3_SESSION_TOOL_RESULT",
                "L4_MODEL_VISIBLE_OBSERVATION",
            ):
                row = {"level": level, "content": value, "tool_result": value, "anchor_reached": True}
                if level == "L4_MODEL_VISIBLE_OBSERVATION":
                    row["actual_next_model_request"] = True
                    row["model_request"] = {"messages": [{"role": "tool", "tool_call_id": "call-1", "content": value}]}
                traces[side].append(row)
        traces["vulnerable"][0]["event"] = {
            "operation": "write",
            "resource_id": "resource-sha256:stable",
            "state_write": True,
            "stable_resource_identity": True,
        }
        traces["fixed"][0]["event"] = {
            "operation": "observe",
            "resource_id": "resource-sha256:stable",
            "state_write": False,
            "stable_resource_identity": True,
        }

        model = build_effect_model(spec, traces)

        self.assertEqual(model["status"], "GENERATED")
        self.assertTrue(any(item["effect_kind"] == "RESOURCE_EFFECT" for item in model["effects"]))
        self.assertFalse(any(item["effect_kind"] == "VALUE_EFFECT" for item in model["effects"]))

    def test_stable_absent_write_is_effect_specific_blocking_evidence(self):
        effect = {
            "effect_id": "effect-resource-1",
            "effect_kind": "RESOURCE_EFFECT",
            "object": {
                "resource_identity": "resource-sha256:stable",
                "operation": "write",
                "resource_events": [{
                    "resource_id": "resource-sha256:stable",
                    "operation": "write",
                }],
            },
            "origin": {},
            "carrier": {"paths": []},
        }
        rows = [{
            "level": "L0_RAW_MCP_RESULT",
            "event": {
                "resource_id": "resource-sha256:stable",
                "operation": "observe",
                "stable_resource_identity": True,
                "state_write": False,
            },
        }]

        status, refs = _effect_produced_in_rows(effect, rows)

        self.assertEqual(status, "NOT_PRODUCED")
        self.assertEqual(refs, ["trace:L0_RAW_MCP_RESULT:resource-effect-absent"])

    def test_resource_request_uses_stable_vulnerable_state_predicate(self):
        def rows(side):
            result = []
            for repetition in range(1, 4):
                result.append({
                    "level": "L0_RAW_MCP_RESULT",
                    "repetition": repetition,
                    "event": {
                        "resource_id": "resource-sha256:stable",
                        "operation": "request",
                        "location": "controlled-external-boundary",
                        "function": "CASE-1",
                        "stable_resource_identity": True,
                        "after_state": {
                            "path": "/admin/secret" if side == "vulnerable" else "/api/users",
                            "port": 41000 + repetition,
                            "user-agent": "package/1.0" if side == "vulnerable" else "package/1.1",
                        },
                    },
                })
            return result

        vulnerable_rows, fixed_rows = rows("vulnerable"), rows("fixed")
        resource_event = {
            "resource_id": "resource-sha256:stable",
            "operation": "request",
            "location": "controlled-external-boundary",
            "function": "CASE-1",
        }
        predicates, fixed_state = _resource_state_predicates(
            vulnerable_rows, fixed_rows, resource_event,
        )
        self.assertIn("path", predicates)
        self.assertNotIn("port", predicates)
        self.assertNotIn("user-agent", predicates)
        effect = {
            "effect_id": "effect-resource-1",
            "effect_kind": "RESOURCE_EFFECT",
            "object": {
                "resource_identity": "resource-sha256:stable",
                "operation": "request",
                "resource_events": [resource_event],
                "vulnerable_state_digests": predicates,
                "fixed_state_digests": fixed_state,
            },
            "origin": {},
            "carrier": {"paths": []},
        }
        self.assertEqual(_effect_produced_in_rows(effect, vulnerable_rows)[0], "PRODUCED")
        status, refs = _effect_produced_in_rows(effect, fixed_rows)
        self.assertEqual(status, "NOT_PRODUCED")
        self.assertEqual(refs, ["trace:L0_RAW_MCP_RESULT:resource-effect-absent"])

    def test_external_sink_without_tool_result_provenance_is_unassessed(self):
        traces = _rows({"external_state": "proxy-response"}, {"external_state": "none"})
        for side in traces.values():
            for row in side:
                if row["level"] in {"L2_HOST_PROCESSED_TOOL_RESULT", "L3_SESSION_TOOL_RESULT"}:
                    row["content"] = {"external_state": "proxy-response"}
                elif row["level"] == "L4_MODEL_VISIBLE_OBSERVATION":
                    row["content"] = {"observation": "ordinary completion"}
                else:
                    row["content"] = {"external_state": "proxy-response"}
        model = build_effect_model(_spec(), traces)
        self.assertEqual(model["status"], "UNASSESSED")
        self.assertIn("Tool result provenance", " ".join(model["modeling_reasons"]))

    def test_missing_source_patch_or_trace_is_unassessed(self):
        spec = _spec()
        spec.pop("source")
        self.assertEqual(build_effect_model(spec, _rows({"derived_value": "x"}, {"status": "safe"}))["status"], "UNASSESSED")
        spec = _spec()
        spec.pop("patch")
        self.assertEqual(build_effect_model(spec, _rows({"derived_value": "x"}, {"status": "safe"}))["status"], "UNASSESSED")
        self.assertEqual(build_effect_model(_spec(), {"vulnerable": [], "fixed": []})["status"], "UNASSESSED")

    def test_stage4_links_same_run_value_when_effect_text_changes(self):
        model = build_effect_model(_spec(), _rows({"derived_value": "first-token"}, {"status": "safe"}))
        changed_rows = copy.deepcopy(_rows({"derived_value": "first-token"}, {"status": "safe"})["vulnerable"])
        for row in changed_rows:
            if row["level"] in {"L2_HOST_PROCESSED_TOOL_RESULT", "L3_SESSION_TOOL_RESULT", "L4_MODEL_VISIBLE_OBSERVATION"}:
                row["content"]["tool_result"]["derived_value"] = "renamed-token"
        result = inspect_l4_effect(model, changed_rows)
        self.assertEqual(result["status"], "REACHED")
        self.assertEqual(result["reached_effect_ids"], ["effect-value-1"])
        self.assertIn("effect-control-1", result["not_reached_effect_ids"])
        value_result = next(item for item in result["effects"] if item["effect_kind"] == "VALUE_EFFECT")
        self.assertIn("derived_value", value_result["matched_l4_fields"])

    def test_stage4_rejects_same_field_with_unlinked_l4_value(self):
        model = build_effect_model(_spec(), _rows({"derived_value": "effect"}, {"derived_value": "safe"}))
        rows = copy.deepcopy(_rows({"derived_value": "ordinary"}, {"derived_value": "safe"})["vulnerable"])
        for row in rows:
            if row["level"] == "L4_MODEL_VISIBLE_OBSERVATION":
                row["content"]["tool_result"]["derived_value"] = "unrelated"
        self.assertEqual(inspect_l4_effect(model, rows)["status"], "NOT_REACHED")

    def test_stage4_rejects_l4_label_with_arbitrary_observation(self):
        model = build_effect_model(_spec(), _rows({"derived_value": "effect"}, {"status": "safe"}))
        rows = copy.deepcopy(_rows({"derived_value": "effect"}, {"status": "safe"})["vulnerable"])
        l4 = rows[-1]
        l4.pop("actual_next_model_request")
        l4.pop("model_request")
        l4["observation"] = {"tool_result": {"derived_value": "effect"}}
        result = inspect_l4_effect(model, rows)
        self.assertEqual(result["status"], "UNASSESSED")
        self.assertFalse(result["actual_next_model_request"])

    def test_stage4_rejects_non_tool_message_schema_and_input_echo(self):
        model = build_effect_model(_spec(), _rows({"derived_value": "effect"}, {"status": "safe"}))
        rows = copy.deepcopy(_rows({"derived_value": "effect"}, {"status": "safe"})["vulnerable"])
        rows[-1]["model_request"] = {
            "messages": [{"role": "user", "content": {"tool_result": {"derived_value": "effect"}}}],
            "tools": [{"input_schema": {"derived_value": "effect"}}],
            "tool_input": {"derived_value": "effect"},
        }
        self.assertEqual(inspect_l4_effect(model, rows)["status"], "UNASSESSED")

    def test_stage4_only_reads_exact_tool_message_content(self):
        model = build_effect_model(_spec(), _rows({"derived_value": "effect"}, {"status": "safe"}))
        rows = copy.deepcopy(_rows({"derived_value": "effect"}, {"status": "safe"})["vulnerable"])
        rows[-1]["model_request"] = {
            "messages": [
                {"role": "system", "content": {"tool_result": {"derived_value": "unrelated"}}},
                {"role": "tool", "tool_call_id": "call-1", "content": {"tool_result": {"derived_value": "effect"}}},
            ],
            "tools": [{"description": "effect"}],
        }
        result = inspect_l4_effect(model, rows)
        self.assertEqual(result["status"], "REACHED")
        self.assertEqual(result["tool_message_content_paths"], ["$.messages[1].content"])

    def test_stage4_does_not_link_values_across_repetitions(self):
        model = build_effect_model(_spec(), _rows({"derived_value": "effect"}, {"status": "safe"}))
        rows = copy.deepcopy(_rows({"derived_value": "effect"}, {"status": "safe"})["vulnerable"])
        for row in rows:
            row["repetition"] = 1
        rows[-1]["repetition"] = 2
        self.assertEqual(inspect_l4_effect(model, rows)["status"], "UNASSESSED")

    def test_stage4_rejects_fixed_baseline_value_on_same_path(self):
        model = build_effect_model(_spec(), _rows({"derived_value": "effect"}, {"derived_value": "safe"}))
        rows = _rows({"derived_value": "safe"}, {"derived_value": "safe"})["vulnerable"]
        result = inspect_l4_effect(model, rows)
        self.assertEqual(result["status"], "NOT_REACHED")
        value_result = next(item for item in result["effects"] if item["effect_kind"] == "VALUE_EFFECT")
        self.assertTrue(value_result["rejected_fixed_baseline_paths"])

    def test_stage4_preserves_raw_json_string_digest_for_fixed_baseline(self):
        def rows(value):
            content = json.dumps({"result": value}, separators=(",", ":"))
            result = []
            for level in (
                "L0_RAW_MCP_RESULT",
                "L1_NORMALIZED_TOOL_RESULT",
                "L2_HOST_PROCESSED_TOOL_RESULT",
                "L3_SESSION_TOOL_RESULT",
                "L4_MODEL_VISIBLE_OBSERVATION",
            ):
                row = {
                    "level": level,
                    "content": content,
                    "tool_result": content,
                    "tool_call_id": "call-1",
                    "anchor_reached": True,
                }
                if level == "L4_MODEL_VISIBLE_OBSERVATION":
                    row["actual_next_model_request"] = True
                    row["model_request"] = {
                        "messages": [{"role": "tool", "tool_call_id": "call-1", "content": content}],
                    }
                result.append(row)
            return result

        traces = {"vulnerable": rows("vulnerable-value"), "fixed": rows("fixed-value")}
        model = build_effect_model(_spec(), traces)
        vulnerable = inspect_l4_effect(model, traces["vulnerable"])
        fixed = inspect_l4_effect(model, traces["fixed"])
        vulnerable_value = next(item for item in vulnerable["effects"] if item["effect_kind"] == "VALUE_EFFECT")
        fixed_value = next(item for item in fixed["effects"] if item["effect_kind"] == "VALUE_EFFECT")
        self.assertTrue(vulnerable_value["reached_exact_l4"])
        self.assertFalse(fixed_value["reached_exact_l4"])
        self.assertEqual(fixed_value["rejected_fixed_baseline_paths"], ["$"])

    def test_l4_drop_is_not_promoted_to_reachability(self):
        model = build_effect_model(
            _spec(),
            _rows(
                {"derived_value": "uid=0"},
                {"status": "safe"},
                l4_vulnerable={"status": "filtered"},
                l4_fixed={"status": "safe"},
            ),
        )
        self.assertEqual(model["status"], "GENERATED")
        self.assertEqual(inspect_l4_effect(model, _rows({"derived_value": "uid=0"}, {"status": "safe"}, l4_vulnerable={"status": "filtered"}, l4_fixed={"status": "safe"})["vulnerable"])["status"], "NOT_REACHED")
        dropped = inspect_l4_effect(
            model,
            _rows(
                {"derived_value": "uid=0"},
                {"status": "safe"},
                l4_vulnerable={"status": "filtered"},
                l4_fixed={"status": "safe"},
            )["vulnerable"],
        )
        self.assertEqual(dropped["reached_effect_ids"], [])

    def test_l4_field_without_tool_result_provenance_is_not_reached(self):
        model = build_effect_model(_spec(), _rows({"derived_value": "uid=0"}, {"status": "safe"}))
        rows = _rows({"status": "ordinary"}, {"status": "safe"}, l4_vulnerable={"derived_value": "uid=0"})["vulnerable"]
        self.assertEqual(inspect_l4_effect(model, rows)["status"], "NOT_REACHED")

    def test_l4_without_same_effect_production_cannot_be_p3w(self):
        source_rows = _rows({"derived_value": "uid=0"}, {"status": "safe"})
        model = build_effect_model(_spec(), source_rows)
        rows = copy.deepcopy(source_rows)["vulnerable"]
        for row in rows:
            if row["level"] in {
                "L0_RAW_MCP_RESULT",
                "L1_NORMALIZED_TOOL_RESULT",
                "L2_HOST_PROCESSED_TOOL_RESULT",
                "L3_SESSION_TOOL_RESULT",
            }:
                row["content"] = {"tool_result": {"ordinary": "no-production-witness"}}
        result = inspect_l4_effect(model, rows)
        value = _effect(result, "VALUE_EFFECT")
        self.assertEqual(value["production_status"], "NOT_PRODUCED")
        self.assertNotEqual(value["effect_status"], "REACHED")
        self.assertNotEqual(value["highest_witnessed_level"], "P3-W")
        self.assertFalse(value["reached_exact_l4"])

    def test_other_tool_l4_same_value_cannot_complete_target_effect(self):
        source_rows = _rows({"derived_value": "uid=0"}, {"status": "safe"})
        model = build_effect_model(_spec(), source_rows)
        rows = copy.deepcopy(source_rows)["vulnerable"]
        for row in rows:
            if row["level"] in {"L0_RAW_MCP_RESULT", "L1_NORMALIZED_TOOL_RESULT", "L2_HOST_PROCESSED_TOOL_RESULT", "L3_SESSION_TOOL_RESULT"}:
                row["tool_call_id"] = "target-call"
            if row["level"] == "L4_MODEL_VISIBLE_OBSERVATION":
                row["model_request"]["messages"][0]["tool_call_id"] = "other-call"
        result = inspect_l4_effect(model, rows)
        self.assertNotIn("effect-value-1", result["reached_effect_ids"])
        self.assertIn("effect-value-1", result["unassessed_effect_ids"])

    def test_missing_call_id_with_two_same_trace_calls_is_unassessed(self):
        source_rows = _rows({"derived_value": "uid=0"}, {"status": "safe"})
        model = build_effect_model(_spec(), source_rows)
        rows = copy.deepcopy(source_rows)["vulnerable"]
        for index, row in enumerate(rows):
            row["trace_id"] = "trace:shared:1"
            row["span_id"] = f"span:call-a:{row['level']}"
            if row["level"] == "L4_MODEL_VISIBLE_OBSERVATION":
                row["model_request"]["messages"][0]["tool_call_id"] = "call-a"
        second = copy.deepcopy(rows[:-1])
        for row in second:
            row["span_id"] = f"span:call-b:{row['level']}"
            row["content"] = {"tool_result": {"derived_value": "other"}}
        rows = second + rows
        result = inspect_l4_effect(model, rows)
        self.assertNotIn("effect-value-1", result["reached_effect_ids"])
        self.assertIn("effect-value-1", result["unassessed_effect_ids"])

    def test_multiple_unqualified_l4_messages_are_unassessed(self):
        source_rows = _rows({"derived_value": "uid=0"}, {"status": "safe"})
        model = build_effect_model(_spec(), source_rows)
        rows = copy.deepcopy(source_rows)["vulnerable"]
        l4 = rows[-1]
        l4["model_request"]["messages"].append({"role": "tool", "content": l4["content"]})
        result = inspect_l4_effect(model, rows)
        self.assertNotIn("effect-value-1", result["reached_effect_ids"])
        self.assertIn("effect-value-1", result["unassessed_effect_ids"])

    def test_unrelated_transformation_witness_does_not_link_values(self):
        source_rows = _rows({"derived_value": "secret-A"}, {"status": "safe"})
        model = build_effect_model(_spec(), source_rows)
        rows = copy.deepcopy(source_rows)["vulnerable"]
        for row in rows:
            if row["level"] == "L4_MODEL_VISIBLE_OBSERVATION":
                row["content"] = {"tool_result": {"renamed_value": "totally-unrelated-B"}}
                row["model_request"]["messages"][0]["content"] = row["content"]
                row["transformation"] = {
                    "input": ["tool_result.derived_value"],
                    "output": ["tool_result.renamed_value"],
                    "rule": "rename-only",
                    "evidence_refs": ["trace:vulnerable:rename-only"],
                    "input_fingerprints": [hashlib.sha256(json.dumps("secret-A", ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()).hexdigest()],
                    "output_fingerprints": [hashlib.sha256(json.dumps("totally-unrelated-B", ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()).hexdigest()],
                }
        result = inspect_l4_effect(model, rows)
        self.assertNotIn("effect-value-1", result["reached_effect_ids"])

    def test_anchor_reached_without_control_effect_event_is_not_produced(self):
        source_rows = _rows({"derived_value": "uid=0"}, {"status": "safe"})
        source_rows["vulnerable"][2]["event"] = {
            "function": "probe",
            "location": "probe.py:3",
            "return": {"status": "uid=0"},
        }
        model = build_effect_model(_spec(), source_rows)
        rows = copy.deepcopy(source_rows)["vulnerable"]
        for row in rows:
            row.pop("event", None)
        result = inspect_l4_effect(model, rows)
        control_effects = [item for item in result["effects"] if item["effect_kind"] == "CONTROL_EFFECT"]
        self.assertTrue(control_effects)
        self.assertTrue(all(item["production_status"] == "NOT_PRODUCED" for item in control_effects))

    def test_javascript_adapter_models_ssrf_metadata(self):
        spec = _spec()
        spec["experiment_type"] = "SSRF_WITH_RESPONSE_OR_METADATA"
        spec["source"] = {
            "vulnerable": [{"path": "server.js", "content": "export function probe(url) { return axios.get(url); }"}],
            "fixed": [{"path": "server.js", "content": "export function probe(url) { if (new URL(url).hostname === 'localhost') throw Error('blocked'); return axios.get(url); }"}],
        }
        spec["patch"] = {"unified_diff": "--- a/server.js\n+++ b/server.js\n@@ -1 +1,1 @@\n-export function probe(url) { return axios.get(url); }\n+export function probe(url) { if (new URL(url).hostname === 'localhost') throw Error('blocked'); return axios.get(url); }\n"}
        model = build_effect_model(spec, _rows({"response_metadata": "loopback"}, {"status": "blocked"}))
        self.assertEqual(model["status"], "GENERATED")
        resource_effect = _effect(model, "RESOURCE_EFFECT")
        self.assertEqual(resource_effect["effect_kind"], "RESOURCE_EFFECT")
        self.assertEqual(resource_effect["object"]["kind"], "external resource/state")

    def test_blind_end_to_end_positive_negative_and_insufficient(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            positive = _spec()
            positive.update({"agent_task": "run", "host_profile": {"model": "fixture"}, "environment": {"package_manager": "python"}})
            positive["source"] = {
                "vulnerable": [{"path": "probe.py", "content": "import fixture_package\n@mcp.tool(\"probe\")\ndef probe(value):\n    return fixture_package.execute(value, shell=True)\n"}],
                "fixed": [{"path": "probe.py", "content": "import fixture_package\n@mcp.tool(\"probe\")\ndef probe(value):\n    if not isinstance(value, str):\n        raise ValueError(\"rejected\")\n    return fixture_package.execute([\"echo\", value], shell=False)\n"}],
            }
            positive["patch"] = {"unified_diff": "--- a/probe.py\n+++ b/probe.py\n@@ -1,3 +1,6 @@\n-import fixture_package\n+import fixture_package\n+@mcp.tool(\"probe\")\n def probe(value):\n+    if not isinstance(value, str):\n+        raise ValueError(\"rejected\")\n-    return fixture_package.execute(value, shell=True)\n+    return fixture_package.execute([\"echo\", value], shell=False)\n"}
            positive["runner"] = {
                "repetitions": 1,
                "dynamic_budget": 1,
                "counterfactual_input_mode": "env-json/v1",
                "counterfactual_budget": 3,
                "timeout_seconds": 30,
                "vulnerable": {"command": [sys.executable, str(FIXTURE_RUNNER)], "cwd": str(Path.cwd()), "env": {"VULVEIL_MODE": "effect"}, "evidence_file": "blind_evidence.jsonl"},
                "patched": {"command": [sys.executable, str(FIXTURE_RUNNER)], "cwd": str(Path.cwd()), "env": {"VULVEIL_MODE": "effect"}, "evidence_file": "blind_evidence.jsonl"},
            }
            negative = copy.deepcopy(positive)
            negative["runner"]["vulnerable"]["env"]["VULVEIL_MODE"] = "drop"
            negative["runner"]["patched"]["env"]["VULVEIL_MODE"] = "drop"
            insufficient = copy.deepcopy(positive)
            insufficient.pop("source")
            insufficient.pop("patch")
            positive_prediction = run_blind_case(positive, root / "reachable")
            negative_prediction = run_blind_case(negative, root / "dropped")
            insufficient_prediction = run_blind_case(insufficient, root / "no-model")
        self.assertEqual(positive_prediction["run_status"], "VALID")
        self.assertTrue(positive_prediction["predicted_reachability"])
        self.assertEqual(positive_prediction["witnessed_level"], "P3-W_WITNESSED_AGENT_REACHABLE")
        self.assertEqual(positive_prediction["counterfactual_execution"]["status"], "EXECUTED")
        self.assertEqual(
            {item["role"]: item["status"] for item in positive_prediction["effect_model"]["counterfactual_checks"]},
            {role: "SUPPORTED" for role in ("trigger", "safe", "field-only", "unrelated", "fixed")},
        )
        self.assertEqual(negative_prediction["run_status"], "VALID")
        self.assertIsNone(negative_prediction["invalid_reason"])
        self.assertIsNone(negative_prediction["predicted_reachability"])
        self.assertIsNone(negative_prediction["witnessed_level"])
        self.assertEqual(negative_prediction["stage4_analysis"]["status"], "NOT_REACHED")
        self.assertEqual(insufficient_prediction["run_status"], "UNASSESSED")
        self.assertIsNone(insufficient_prediction["predicted_reachability"])

    def test_model_validator_rejects_gt_fields(self):
        model = build_effect_model(_spec(), _rows({"derived_value": "x"}, {"status": "safe"}))
        bad = copy.deepcopy(model)
        bad["ground_truth_label"] = "POSITIVE"
        self.assertTrue(validate_effect_model(bad))


if __name__ == "__main__":
    unittest.main()
