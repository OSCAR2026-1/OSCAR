import copy
import json
import unittest

from oscar.runtime.blind_runtime import validate_blind_case
from oscar.contracts.component_contract import validate_vulnerability_component
from oscar.analysis.cross_layer_graph import build_cross_layer_graph, validate_cross_layer_graph
from oscar.analysis.effect_modeling import build_effect_model
from oscar.analysis.localization import build_localization
from oscar.workflows.stage2_readiness import assess_case

try:
    from test_effect_modeling import _rows, _spec
except ImportError:  # package-style invocation
    from .test_effect_modeling import _rows, _spec


def _component_spec(origin: str) -> dict:
    spec = _spec()
    spec["identity"]["advisory"] = "CVE-2026-0001"
    old = spec.pop("direct_runtime_dependency")
    component_repository = spec["server"]["repository"] if origin == "MCP_SERVER_SELF" else "component/fixture-package"
    component = {
        "origin": origin,
        "name": old["dependency_name"],
        "purl": old["dependency_purl"],
        "repository": component_repository,
        "vulnerable_version": old["vulnerable_version"],
        "fixed_version": old["fixed_version"],
        "relation_status": "AFFECTED_EXACT_COMPONENT",
        "source_evidence": [{"ref": "source:probe.py:2", "advisory_id": "CVE-2026-0001", "component": {"name": old["dependency_name"], "purl": old["dependency_purl"], "repository": component_repository}, "version": old["vulnerable_version"]}],
        "patch_evidence": [{"ref": "patch:probe.py", "advisory_id": "CVE-2026-0001", "component": {"name": old["dependency_name"], "purl": old["dependency_purl"], "repository": component_repository}, "vulnerable_version": old["vulnerable_version"], "fixed_version": old["fixed_version"]}],
        "advisory_evidence": {
            "advisory_id": "CVE-2026-0001",
            "source": {
                "kind": "OSV", "url": "https://osv.dev/vulnerability/CVE-2026-0001",
                "record": {
                    "id": "CVE-2026-0001", "aliases": [],
                    "component": {"name": old["dependency_name"], "purl": old["dependency_purl"], "repository": component_repository},
                    "vulnerable": {"version": old["vulnerable_version"]},
                    "fixed": {"version": old["fixed_version"]},
                    "affected": {"versions": [old["vulnerable_version"]], "fixed_versions": [old["fixed_version"]]},
                },
            },
            "component": {"name": old["dependency_name"], "purl": old["dependency_purl"], "repository": component_repository},
            "vulnerable": {"version": old["vulnerable_version"], "supported_by_source": True},
            "fixed": {"version": old["fixed_version"], "supported_by_patch": True},
            "affected": {"versions": [old["vulnerable_version"]], "fixed_versions": [old["fixed_version"]]},
            "source_refs": ["source:probe.py:2"], "patch_refs": ["patch:probe.py"],
        },
    }
    if origin == "DIRECT_RUNTIME_DEPENDENCY":
        component.update({"dependency_depth": 1, "dependency_scope": "runtime"})
    spec["component_origin"] = origin
    spec["vulnerability_component"] = component
    return spec


class ComponentOriginTests(unittest.TestCase):
    def test_server_self_does_not_require_dependency_depth_or_scope(self):
        self.assertEqual(validate_vulnerability_component(_component_spec("MCP_SERVER_SELF")), [])

    def test_direct_runtime_requires_depth_and_scope(self):
        spec = _component_spec("DIRECT_RUNTIME_DEPENDENCY")
        spec["vulnerability_component"].pop("dependency_depth")
        errors = validate_vulnerability_component(spec)
        self.assertTrue(any("dependency_depth" in error for error in errors))
        spec = _component_spec("DIRECT_RUNTIME_DEPENDENCY")
        spec["vulnerability_component"]["dependency_scope"] = "dev"
        self.assertTrue(any("dependency_scope" in error for error in validate_vulnerability_component(spec)))

    def test_framework_has_independent_component_identity(self):
        spec = _component_spec("MCP_FRAMEWORK")
        self.assertEqual(validate_vulnerability_component(spec), [])
        self.assertNotIn("dependency_depth", spec["vulnerability_component"])

    def test_standard_osv_affected_entries_bind_component_and_versions(self):
        spec = _component_spec("MCP_FRAMEWORK")
        evidence = spec["vulnerability_component"]["advisory_evidence"]
        evidence["source"]["record"] = {
            "id": "CVE-2026-0001",
            "aliases": [],
            "affected": [{
                "package": {"name": "fixture-package", "purl": "pkg:pypi/fixture-package"},
                "versions": ["1.0.0"],
                "ranges": [{"type": "ECOSYSTEM", "events": [
                    {"introduced": "0"}, {"fixed": "1.0.1"},
                ]}],
            }],
            "references": [{"type": "PACKAGE", "url": "https://github.com/component/fixture-package"}],
        }
        self.assertEqual(validate_vulnerability_component(spec), [])

    def test_advisory_record_must_bind_declared_component_identity(self):
        spec = _component_spec("MCP_FRAMEWORK")
        record = spec["vulnerability_component"]["advisory_evidence"]["source"]["record"]
        record["component"].pop("purl")
        record["component"].pop("repository")
        errors = validate_vulnerability_component(spec)
        self.assertTrue(any("public advisory record repository" in error for error in errors), errors)
        self.assertTrue(any("public advisory record purl" in error for error in errors), errors)

    def test_component_origin_conflict_fails_closed(self):
        spec = _component_spec("MCP_SERVER_SELF")
        spec["component_origin"] = "MCP_FRAMEWORK"
        self.assertTrue(any("component_origin" in error for error in validate_vulnerability_component(spec)))

    def test_component_and_legacy_contract_conflict_fails_closed(self):
        spec = _component_spec("MCP_SERVER_SELF")
        spec["direct_runtime_dependency"] = {
            "dependency_name": "other-package",
            "dependency_purl": "pkg:pypi/other-package",
            "dependency_depth": 1,
            "dependency_scope": "runtime",
            "vulnerable_version": "1.0.0",
            "fixed_version": "1.0.1",
            "relation_status": "affected_exact_direct_runtime",
        }
        self.assertTrue(any("conflicts" in error for error in validate_vulnerability_component(spec)))

    def test_missing_source_or_patch_is_unassessed_for_every_origin(self):
        for origin in ("MCP_SERVER_SELF", "DIRECT_RUNTIME_DEPENDENCY", "MCP_FRAMEWORK"):
            spec = _component_spec(origin)
            spec.pop("source")
            spec.pop("patch")
            localization = build_localization(spec)
            self.assertEqual(localization["status"], "UNASSESSED", origin)

    def test_all_origins_share_stage2_and_stage3_contract(self):
        traces = _rows({"derived_value": "uid=0"}, {"status": "safe"})
        for origin in ("MCP_SERVER_SELF", "DIRECT_RUNTIME_DEPENDENCY", "MCP_FRAMEWORK"):
            spec = _component_spec(origin)
            localization = build_localization(spec)
            model = build_effect_model(spec, traces, localization=localization)
            graph = build_cross_layer_graph(spec, model, traces, localization=localization)
            self.assertEqual(model["status"], "GENERATED", origin)
            self.assertEqual(model["component_origin"], origin)
            self.assertFalse(validate_cross_layer_graph(graph, effect_model=model), origin)
            self.assertIn(graph["status"], {"COMPLETE", "PARTIAL"}, origin)

    def test_five_categories_remain_sampling_metadata(self):
        categories = {
            "SENSITIVE_INFORMATION_DISCLOSURE",
            "COMMAND_OR_QUERY_INJECTION",
            "SSRF_WITH_RESPONSE_OR_METADATA",
            "PATH_TRAVERSAL_OR_ARBITRARY_FILE_IO",
            "AUTHENTICATION_OR_AUTHORIZATION_BYPASS",
        }
        kinds = []
        for category in categories:
            spec = _component_spec("MCP_SERVER_SELF")
            spec["vulnerability_category"] = category
            model = build_effect_model(spec, _rows({"derived_value": "uid=0"}, {"status": "safe"}))
            kinds.append({item["effect_kind"] for item in model["effects"]})
        self.assertTrue(kinds)
        self.assertTrue(all(item == kinds[0] for item in kinds))

    def test_hidden_gt_is_rejected_by_blind_case(self):
        spec = _component_spec("MCP_SERVER_SELF")
        spec["ground_truth_label"] = "POSITIVE"
        self.assertTrue(validate_blind_case(spec))

    def test_legacy_direct_runtime_case_remains_readable(self):
        spec = _spec()
        spec["runner"] = {
            "repetitions": 1,
            "dynamic_budget": 1,
            "vulnerable": {"command": ["python3", "-c", "pass"]},
            "patched": {"command": ["python3", "-c", "pass"]},
        }
        errors = validate_blind_case(spec)
        self.assertFalse(errors, errors)
        localization = build_localization(spec)
        self.assertEqual(localization["status"], "LOCALIZED")
        self.assertEqual(localization["vulnerability_component"]["origin"], "DIRECT_RUNTIME_DEPENDENCY")

    def test_partial_graph_gate_does_not_become_reachable(self):
        spec = _component_spec("MCP_FRAMEWORK")
        traces = _rows({"derived_value": "uid=0"}, {"status": "safe"})
        for rows in traces.values():
            for row in rows:
                if row.get("level") == "L4_MODEL_VISIBLE_OBSERVATION":
                    row.pop("model_request", None)
                    row.pop("actual_next_model_request", None)
        model = build_effect_model(spec, traces)
        graph = build_cross_layer_graph(spec, model, traces)
        self.assertNotEqual(graph["status"], "COMPLETE")
        self.assertFalse(any(item.get("exact_l4_observed") for item in graph.get("edges", [])))

    def test_readiness_routes_component_origin_without_gt(self):
        spec = _component_spec("MCP_SERVER_SELF")
        spec["runner"]["counterfactual_input_mode"] = "env-json/v1"
        readiness = assess_case(spec, "component-self")
        self.assertEqual(readiness["component_origin"], "MCP_SERVER_SELF")
        self.assertTrue(readiness["vulnerability_component_ready"])
        self.assertNotIn("ground_truth_label", json.dumps(readiness))

    def test_framework_readiness_names_missing_framework_material(self):
        spec = _component_spec("MCP_FRAMEWORK")
        spec.pop("source")
        spec.pop("patch")
        readiness = assess_case(spec, "framework-missing-material")
        self.assertEqual(readiness["checks"]["analysis_source"]["status"], "UNRESOLVED")
        self.assertIn("framework source pair", " ".join(readiness["reasons"]))
        self.assertIn("framework source/patch", " ".join(readiness["reasons"]))


if __name__ == "__main__":
    unittest.main()
