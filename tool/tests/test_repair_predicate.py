import copy
import json
import sys
import unittest

from oscar.analysis.effect_modeling import build_effect_model
from oscar.analysis.localization import build_localization
from oscar.analysis.repair_predicate import normalize_repair_predicate, validate_paired_repair_predicate, validate_repair_predicate
from test_effect_modeling import _rows, _spec


class RepairPredicateTests(unittest.TestCase):
    def _localized(self, vulnerable: str, fixed: str, patch: str):
        spec = _spec()
        spec["source"] = {
            "vulnerable": [{"path": "probe.py", "content": vulnerable}],
            "fixed": [{"path": "probe.py", "content": fixed}],
        }
        spec["patch"] = {"unified_diff": patch}
        return spec, build_localization(spec)

    def _checker(self, checker_id, source_ref="src/server.py:120-136"):
        return {
            "checker_id": checker_id,
            "source_ref": source_ref,
            "function": "probe",
            "expression": "guard(value)",
            "evidence_refs": [source_ref],
            "confidence": 0.9,
            "sink_ref": "src/server.py:135",
        }

    def _event(
        self,
        checker_id,
        *,
        digest="effect-digest",
        effect_id="effect-1",
        repetition=1,
        tool_call_id="call-001",
        invocation_id="invocation-001",
        trace_id="trace-001",
        span_id="span-001",
        source_ref="src/server.py:120",
        sink_ref="src/server.py:135",
        phase="before_sink",
        status="executed",
        blocked=False,
    ):
        return {
            "checker_id": checker_id,
            "source_ref": source_ref,
            "repetition": repetition,
            "tool_call_id": tool_call_id,
            "invocation_id": invocation_id,
            "trace_id": trace_id,
            "span_id": span_id,
            "effect_id": effect_id,
            "effect_witness": {"kind": "file_write", "digest": digest},
            "sink_ref": sink_ref,
            "phase": phase,
            "status": status,
            "blocked": blocked,
        }

    def _paired_events(self, vulnerable_events, fixed_events):
        traces = _rows({"derived_value": "vulnerable"}, {"status": "fixed"})
        for side, events in (("vulnerable", vulnerable_events), ("fixed", fixed_events)):
            for index, event in enumerate(events):
                traces[side][2 + index]["event"] = event
        return traces

    def _safe_rows(self, events):
        traces = _rows({"status": "safe"}, {"status": "safe"})
        for index, event in enumerate(events):
            traces["fixed"][2 + index]["event"] = event
        return traces

    def test_added_type_checker(self):
        localization = build_localization(_spec())
        predicate = localization["repair_predicate"]
        self.assertEqual(predicate["schema_version"], "vulveil-repair-predicate/v2")
        self.assertIn("added_type_check", {item["kind"] for item in predicate["conditions"]})
        self.assertTrue(any(item["checker_kind"] == "type_check" for item in predicate["checkers"]))

    def test_added_boundary_checker(self):
        spec, localization = self._localized(
            "def probe(value):\n    return dependency.fetch(value)\n",
            "def probe(value):\n    if len(value) > 16:\n        raise ValueError('blocked')\n    return dependency.fetch(value)\n",
            "--- a/probe.py\n+++ b/probe.py\n@@ -1,2 +1,4 @@\n def probe(value):\n+    if len(value) > 16:\n+        raise ValueError('blocked')\n     return dependency.fetch(value)\n",
        )
        self.assertEqual(localization["status"], "LOCALIZED")
        self.assertIn("added_boundary_check", {item["kind"] for item in localization["repair_predicate"]["conditions"]})
        self.assertTrue(any(item["checker_kind"] == "boundary_check" for item in localization["repair_predicate"]["checkers"]))

    def test_path_normalization_and_root_containment(self):
        spec, localization = self._localized(
            "import os\ndef probe(path, root):\n    return open(path).read()\n",
            "import os\ndef probe(path, root):\n    resolved = os.path.realpath(path)\n    allowed = os.path.realpath(root)\n    if os.path.commonpath([resolved, allowed]) != allowed:\n        raise ValueError('blocked')\n    return open(resolved).read()\n",
            "--- a/probe.py\n+++ b/probe.py\n@@ -1,3 +1,7 @@\n import os\n def probe(path, root):\n-    return open(path).read()\n+    resolved = os.path.realpath(path)\n+    allowed = os.path.realpath(root)\n+    if os.path.commonpath([resolved, allowed]) != allowed:\n+        raise ValueError('blocked')\n+    return open(resolved).read()\n",
        )
        predicate = localization["repair_predicate"]
        self.assertTrue(any(item["checker_kind"] == "path_containment" for item in predicate["checkers"]))
        self.assertTrue(predicate["path_constraints"])
        constraint = predicate["path_constraints"][0]
        self.assertIn("realpath", constraint["normalization"])
        self.assertEqual(constraint["relation"], "within")
        self.assertEqual(constraint["failure_action"], "reject")

    def test_sanitization_and_filtering_checker(self):
        _, localization = self._localized(
            "import shlex\ndef probe(command):\n    return dependency.execute(command)\n",
            "import shlex\ndef probe(command):\n    return dependency.execute(shlex.quote(command))\n",
            "--- a/probe.py\n+++ b/probe.py\n@@ -1,3 +1,3 @@\n import shlex\n def probe(command):\n-    return dependency.execute(command)\n+    return dependency.execute(shlex.quote(command))\n",
        )
        predicate = localization["repair_predicate"]
        self.assertIn("added_sanitization", {item["kind"] for item in predicate["conditions"]})
        self.assertTrue(any(item["checker_kind"] == "sanitization" for item in predicate["checkers"]))

    def test_changed_api_call_is_structured(self):
        _, localization = self._localized(
            "def probe(value):\n    return dependency.execute(value)\n",
            "def probe(value):\n    return dependency.execute_safe(value)\n",
            "--- a/probe.py\n+++ b/probe.py\n@@ -1,2 +1,2 @@\n def probe(value):\n-    return dependency.execute(value)\n+    return dependency.execute_safe(value)\n",
        )
        self.assertIn("changed_call", {item["kind"] for item in localization["repair_predicate"]["conditions"]})

    def test_changed_resource_operation_is_structured(self):
        _, localization = self._localized(
            "def probe(path):\n    return open(path).read()\n",
            "def probe(path):\n    return open(resolve(path)).read()\n",
            "--- a/probe.py\n+++ b/probe.py\n@@ -1,2 +1,2 @@\n def probe(path):\n-    return open(path).read()\n+    return open(resolve(path)).read()\n",
        )
        self.assertIn("changed_resource_operation", {item["kind"] for item in localization["repair_predicate"]["conditions"]})

    def test_changed_exception_behavior_is_structured(self):
        _, localization = self._localized(
            "def probe(value):\n    return dependency.execute(value)\n",
            "def probe(value):\n    if value == 'bad':\n        raise ValueError('blocked')\n    return dependency.execute(value)\n",
            "--- a/probe.py\n+++ b/probe.py\n@@ -1,2 +1,4 @@\n def probe(value):\n+    if value == 'bad':\n+        raise ValueError('blocked')\n     return dependency.execute(value)\n",
        )
        self.assertIn("changed_exception_behavior", {item["kind"] for item in localization["repair_predicate"]["conditions"]})

    def test_fixed_side_same_effect_is_not_supported(self):
        model = build_effect_model(_spec(), _rows({"derived_value": "same"}, {"derived_value": "same"}))
        self.assertEqual(model["status"], "UNASSESSED")
        self.assertIn("same patch-scoped effect", " ".join(model["modeling_reasons"]))

    def test_paired_runtime_checker_validation_records_blocking(self):
        localization = build_localization(_spec())
        predicate = dict(localization["repair_predicate"])
        predicate["checkers"] = predicate["checkers"][:1]
        checker = predicate["checkers"][0]
        vulnerable_event = self._event(checker["checker_id"], source_ref=checker["source_ref"], sink_ref=checker["source_ref"])
        fixed_event = self._event(checker["checker_id"], source_ref=checker["source_ref"], sink_ref=checker["source_ref"], status="blocked", blocked=True)
        traces = self._paired_events([vulnerable_event], [fixed_event])
        safe = self._safe_rows([self._event(checker["checker_id"], source_ref=checker["source_ref"], sink_ref=checker["source_ref"], status="passed")])
        result = validate_paired_repair_predicate(
            {**predicate, "fixed_side_blocked": True},
            traces["vulnerable"],
            traces["fixed"],
            safe_fixed_rows=safe["fixed"],
        )
        self.assertEqual(result["status"], "SUPPORTED")
        self.assertEqual(result["validation_conclusion"], "CHECKER_SPECIFIC_VALIDATED")
        self.assertEqual(result["checkers"][0]["trigger_case"], "blocked")
        self.assertTrue(result["checkers"][0]["blocking_supported"])

    def test_only_executed_checker_can_be_strictly_validated(self):
        predicate = {"checkers": [self._checker("checker-1"), self._checker("checker-2")]}
        traces = self._paired_events([self._event("checker-1")], [self._event("checker-1", status="blocked", blocked=True)])
        safe = self._safe_rows([self._event("checker-1", status="passed")])
        result = validate_paired_repair_predicate(predicate, traces["vulnerable"], traces["fixed"], safe_fixed_rows=safe["fixed"])
        by_checker = {item["checker_id"]: item for item in result["checkers"]}
        self.assertEqual(by_checker["checker-1"]["validation_conclusion"], "CHECKER_SPECIFIC_VALIDATED")
        self.assertNotEqual(by_checker["checker-2"]["validation_conclusion"], "CHECKER_SPECIFIC_VALIDATED")
        self.assertEqual(result["validation_conclusion"], "UNASSESSED")

    def test_global_digest_is_not_attributed_to_each_checker(self):
        predicate = {"checkers": [self._checker("checker-1"), self._checker("checker-2")]}
        traces = self._paired_events([], [])
        result = validate_paired_repair_predicate(
            predicate,
            traces["vulnerable"],
            traces["fixed"],
            vulnerable_value_digests={"tool_result.value": ["digest-v"]},
            fixed_value_digests={},
        )
        self.assertEqual(result["validation_conclusion"], "PAIRED_EFFECT_DIFFERENCE_ONLY")
        self.assertTrue(all(not item["vulnerable_effect_observed"] for item in result["checkers"]))
        self.assertTrue(all(not item["paired_effect_difference_observed"] for item in result["checkers"]))
        self.assertTrue(all(item["validation_conclusion"] == "UNASSESSED" for item in result["checkers"]))
        self.assertTrue(result["global_paired_effect_difference"])
        self.assertEqual(result["checker_attribution"], "UNSCOPED")

    def test_repetition_mismatch_cannot_form_a_pair(self):
        predicate = {"checkers": [self._checker("checker-1")]}
        traces = self._paired_events([self._event("checker-1", repetition=1)], [self._event("checker-1", repetition=2, status="blocked", blocked=True)])
        result = validate_paired_repair_predicate(predicate, traces["vulnerable"], traces["fixed"])
        self.assertEqual(result["validation_conclusion"], "UNASSESSED")
        self.assertEqual(result["checkers"][0]["matched_execution_pairs"], 0)

    def test_tool_call_or_invocation_mismatch_cannot_form_a_pair(self):
        predicate = {"checkers": [self._checker("checker-1")]}
        traces = self._paired_events(
            [self._event("checker-1", tool_call_id="call-v", invocation_id="inv-v")],
            [self._event("checker-1", tool_call_id="call-f", invocation_id="inv-f", status="blocked", blocked=True)],
        )
        result = validate_paired_repair_predicate(predicate, traces["vulnerable"], traces["fixed"])
        self.assertNotEqual(result["validation_conclusion"], "CHECKER_SPECIFIC_VALIDATED")
        self.assertEqual(result["checkers"][0]["matched_execution_pairs"], 0)

    def test_effect_digest_stays_with_its_checker(self):
        predicate = {"checkers": [self._checker("checker-1"), self._checker("checker-2")]}
        vulnerable = [
            self._event("checker-1", digest="digest-1", effect_id="effect-1"),
            self._event("checker-2", digest="digest-2", effect_id="effect-2", tool_call_id="call-002", invocation_id="invocation-002", trace_id="trace-002", span_id="span-002"),
        ]
        fixed = [
            self._event("checker-1", digest="digest-1", effect_id="effect-1", status="blocked", blocked=True),
            self._event("checker-2", digest="digest-2", effect_id="effect-2", tool_call_id="call-002", invocation_id="invocation-002", trace_id="trace-002", span_id="span-002", status="blocked", blocked=True),
        ]
        traces = self._paired_events(vulnerable, fixed)
        safe = self._safe_rows([
            self._event("checker-1", status="passed"),
            self._event("checker-2", tool_call_id="call-002", invocation_id="invocation-002", trace_id="trace-002", span_id="span-002", status="passed"),
        ])
        result = validate_paired_repair_predicate(predicate, traces["vulnerable"], traces["fixed"], safe_fixed_rows=safe["fixed"])
        self.assertTrue(all(item["validation_conclusion"] == "CHECKER_SPECIFIC_VALIDATED" for item in result["checkers"]))

    def test_checker_scoped_digest_can_supply_effect_provenance(self):
        predicate = {"checkers": [self._checker("checker-1")]}
        vulnerable_event = self._event("checker-1")
        vulnerable_event.pop("effect_id")
        vulnerable_event.pop("effect_witness")
        fixed_event = self._event("checker-1", digest="scoped-digest", effect_id="effect-scoped", status="blocked", blocked=True)
        traces = self._paired_events([vulnerable_event], [fixed_event])
        safe = self._safe_rows([self._event("checker-1", status="passed")])
        result = validate_paired_repair_predicate(
            predicate,
            traces["vulnerable"],
            traces["fixed"],
            scoped_vulnerable_value_digests={"checker-1": [{"effect_id": "effect-scoped", "digest": "scoped-digest"}]},
            safe_fixed_rows=safe["fixed"],
        )
        self.assertEqual(result["validation_conclusion"], "CHECKER_SPECIFIC_VALIDATED")

    def test_block_after_sink_is_not_before_sink_validation(self):
        predicate = {"checkers": [self._checker("checker-1")]}
        traces = self._paired_events(
            [self._event("checker-1")],
            [self._event("checker-1", phase="after_sink", status="blocked", blocked=True)],
        )
        result = validate_paired_repair_predicate(predicate, traces["vulnerable"], traces["fixed"])
        self.assertNotEqual(result["validation_conclusion"], "CHECKER_SPECIFIC_VALIDATED")
        self.assertEqual(result["checkers"][0]["blocking_boundary"], "unresolved")

    def test_unscoped_effect_difference_is_only_a_paired_difference(self):
        predicate = {"checkers": [self._checker("checker-1")]}
        traces = self._paired_events([], [])
        result = validate_paired_repair_predicate(
            predicate,
            traces["vulnerable"],
            traces["fixed"],
            vulnerable_value_digests={"tool_result.value": ["digest-v"]},
            fixed_value_digests={"tool_result.value": ["digest-f"]},
        )
        self.assertEqual(result["validation_conclusion"], "PAIRED_EFFECT_DIFFERENCE_ONLY")
        self.assertEqual(result["checkers"][0]["validation_conclusion"], "UNASSESSED")
        self.assertFalse(result["checkers"][0]["paired_effect_difference_observed"])

    def test_global_difference_with_one_checker_event_is_scoped_only_to_that_checker(self):
        predicate = {"checkers": [self._checker("checker-1"), self._checker("checker-2")]}
        traces = self._paired_events([self._event("checker-1")], [])
        result = validate_paired_repair_predicate(
            predicate,
            traces["vulnerable"],
            traces["fixed"],
            vulnerable_value_digests={"tool_result.value": ["digest-v"]},
            fixed_value_digests={},
        )
        by_checker = {item["checker_id"]: item for item in result["checkers"]}
        self.assertEqual(by_checker["checker-1"]["validation_conclusion"], "PAIRED_EFFECT_DIFFERENCE_ONLY")
        self.assertTrue(by_checker["checker-1"]["paired_effect_difference_observed"])
        self.assertEqual(by_checker["checker-2"]["validation_conclusion"], "UNASSESSED")
        self.assertFalse(by_checker["checker-2"]["paired_effect_difference_observed"])
        self.assertEqual(result["checker_attribution"], "MIXED")

    def test_scoped_digest_bound_to_one_checker_is_not_shared(self):
        predicate = {"checkers": [self._checker("checker-1"), self._checker("checker-2")]}
        traces = self._paired_events([], [])
        result = validate_paired_repair_predicate(
            predicate,
            traces["vulnerable"],
            traces["fixed"],
            scoped_vulnerable_value_digests={
                "checker-1": [{"checker_id": "checker-1", "effect_id": "effect-1", "digest": "digest-v", "repetition": 1, "tool_call_id": "call-001", "invocation_id": "invocation-001"}],
            },
            scoped_fixed_value_digests={},
        )
        by_checker = {item["checker_id"]: item for item in result["checkers"]}
        self.assertEqual(by_checker["checker-1"]["validation_conclusion"], "PAIRED_EFFECT_DIFFERENCE_ONLY")
        self.assertEqual(by_checker["checker-2"]["validation_conclusion"], "UNASSESSED")
        self.assertFalse(by_checker["checker-2"]["paired_effect_difference_observed"])

    def test_source_only_event_is_attributed_only_when_source_is_unique(self):
        predicate = {"checkers": [self._checker("checker-1", "src/server.py:120-136"), self._checker("checker-2", "src/server.py:200-220")]}
        source_only_event = self._event("checker-ignored", source_ref="src/server.py:120", sink_ref="src/server.py:135")
        source_only_event.pop("checker_id")
        traces = self._paired_events([source_only_event], [])
        result = validate_paired_repair_predicate(predicate, traces["vulnerable"], traces["fixed"])
        by_checker = {item["checker_id"]: item for item in result["checkers"]}
        self.assertEqual(by_checker["checker-1"]["validation_conclusion"], "PAIRED_EFFECT_DIFFERENCE_ONLY")
        self.assertEqual(by_checker["checker-2"]["validation_conclusion"], "UNASSESSED")

        ambiguous = {"checkers": [self._checker("checker-1"), self._checker("checker-2")]}
        ambiguous_result = validate_paired_repair_predicate(ambiguous, traces["vulnerable"], traces["fixed"])
        self.assertTrue(all(item["validation_conclusion"] == "UNASSESSED" for item in ambiguous_result["checkers"]))

    def test_missing_execution_identity_fails_closed(self):
        predicate = {"checkers": [self._checker("checker-1")]}
        vulnerable = self._event("checker-1", repetition=None, tool_call_id=None, invocation_id=None)
        fixed = self._event("checker-1", repetition=None, tool_call_id=None, invocation_id=None, status="blocked", blocked=True)
        traces = self._paired_events([vulnerable], [fixed])
        result = validate_paired_repair_predicate(predicate, traces["vulnerable"], traces["fixed"])
        self.assertEqual(result["validation_conclusion"], "UNASSESSED")

    def test_safe_input_blocking_prevents_strict_validation(self):
        predicate = {"checkers": [self._checker("checker-1")]}
        traces = self._paired_events([self._event("checker-1")], [self._event("checker-1", status="blocked", blocked=True)])
        safe = self._safe_rows([self._event("checker-1", status="blocked", blocked=True)])
        result = validate_paired_repair_predicate(predicate, traces["vulnerable"], traces["fixed"], safe_fixed_rows=safe["fixed"])
        self.assertEqual(result["checkers"][0]["safe_case"], "changed")
        self.assertNotEqual(result["validation_conclusion"], "CHECKER_SPECIFIC_VALIDATED")

    def test_legacy_runtime_artifact_is_compatible_but_degraded(self):
        predicate = {"checkers": [self._checker("checker-1")]}
        traces = self._paired_events(
            [{"checker_id": "checker-1", "effect_observed": True}],
            [{"checker_id": "checker-1", "blocked": True, "status": "blocked"}],
        )
        result = validate_paired_repair_predicate(
            predicate,
            traces["vulnerable"],
            traces["fixed"],
            vulnerable_value_digests={"tool_result.value": ["legacy-v"]},
            fixed_value_digests={},
        )
        self.assertEqual(result["validation_conclusion"], "PAIRED_EFFECT_DIFFERENCE_ONLY")
        self.assertFalse(result["checkers"][0]["blocking_supported"])

    def test_patch_outside_hunk_does_not_form_predicate(self):
        spec = _spec()
        spec["source"] = {
            "vulnerable": [{"path": "probe.py", "content": "# old\n" + "\n" * 8 + "def probe(command):\n    return dependency.execute(command)\n"}],
            "fixed": [{"path": "probe.py", "content": "# new\n" + "\n" * 8 + "def probe(command):\n    return dependency.execute_safe(command)\n"}],
        }
        spec["patch"] = {"unified_diff": "--- a/probe.py\n+++ b/probe.py\n@@ -1 +1 @@\n-# old\n+# new\n"}
        localization = build_localization(spec)
        self.assertEqual(localization["status"], "UNASSESSED")
        self.assertEqual(localization["repair_predicate"]["classification_status"], "UNRESOLVED")
        self.assertFalse(localization["repair_predicate"]["conditions"])

    def test_input_echo_cannot_become_effect_or_repair_proof(self):
        model = build_effect_model(_spec(), _rows({"command": "id"}, {"command": "id"}))
        self.assertEqual(model["status"], "UNASSESSED")
        self.assertFalse(model["effects"])

    def test_prefix_only_path_check_has_no_real_path_constraint(self):
        _, localization = self._localized(
            "def probe(path):\n    return open(path).read()\n",
            "def probe(path):\n    if not path.startswith('/safe/'):\n        raise ValueError('blocked')\n    return open(path).read()\n",
            "--- a/probe.py\n+++ b/probe.py\n@@ -1,2 +1,4 @@\n def probe(path):\n+    if not path.startswith('/safe/'):\n+        raise ValueError('blocked')\n     return open(path).read()\n",
        )
        predicate = localization["repair_predicate"]
        self.assertFalse(predicate["path_constraints"])
        self.assertIn("added_boundary_check", {item["kind"] for item in predicate["conditions"]})

    def test_predicate_is_consumed_by_effect_model_and_graph_alignment(self):
        from oscar.analysis.cross_layer_graph import build_cross_layer_graph

        spec = _spec()
        traces = _rows({"derived_value": "uid=0"}, {"status": "safe"})
        model = build_effect_model(spec, traces)
        self.assertEqual(model["status"], "GENERATED")
        self.assertEqual(model["repair_predicate"]["schema_version"], "vulveil-repair-predicate/v2")
        graph = build_cross_layer_graph(spec, model, traces)
        self.assertEqual(graph["repair_alignment"]["predicate"]["schema_version"], "vulveil-repair-predicate/v2")

    def test_old_repair_predicate_is_preserved_but_not_marked_supported(self):
        old = {
            "kind": "patched-structural-difference",
            "conditions_added_or_changed": ["if path is safe"],
            "anchor_ids": ["anchor-1"],
            "patch_refs": ["patch:probe.py"],
        }
        upgraded = normalize_repair_predicate(old)
        self.assertEqual(upgraded["conditions_added_or_changed"], ["if path is safe"])
        self.assertEqual(upgraded["classification_status"], "UNRESOLVED")
        self.assertFalse(validate_repair_predicate(upgraded))

    def test_predicate_and_effect_model_do_not_consume_gt_labels(self):
        spec = _spec()
        spec["oracle"] = {"ground_truth_label": "POSITIVE", "patched_trigger_blocked": True}
        localization = build_localization(spec)
        serialized = json.dumps(localization["repair_predicate"], sort_keys=True)
        self.assertNotIn("ground_truth_label", serialized)
        self.assertNotIn("patched_trigger_blocked", serialized)
        self.assertFalse(validate_repair_predicate(localization["repair_predicate"]))


if __name__ == "__main__":
    unittest.main()
