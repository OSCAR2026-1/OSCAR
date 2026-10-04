import unittest

from oscar.runtime.failure_diagnostics import aggregate_diagnostics, diagnose_prediction


class FailureDiagnosticTests(unittest.TestCase):
    def test_localization_and_timeout_are_distinct(self):
        localization = diagnose_prediction({
            "case_identity": {"case_id": "a"}, "run_status": "UNASSESSED",
            "invalid_reason": "localization_unassessed", "localization": {"reasons": ["patch missing"]},
        })
        timeout = diagnose_prediction({
            "case_identity": {"case_id": "b"}, "run_status": "BLOCKED", "invalid_reason": "runner_timeout",
        })
        self.assertEqual(localization["category"], "PATCH_MATERIAL_UNRESOLVED")
        self.assertEqual(localization["root_cause"], "PATCH_MATERIAL")
        self.assertEqual(timeout["category"], "RUNNER_TIMEOUT")
        self.assertTrue(timeout["retryable_environment_failure"])
        self.assertFalse(localization["gt_used"])

    def test_unassessed_root_causes_are_structured(self):
        cases = {
            "source": ("source root is missing", "SOURCE_MATERIAL"),
            "tool": ("Tool result provenance is missing", "TOOL_BINDING"),
            "evidence": ("paired trace does not provide a valid L0-L3 contract", "EVIDENCE_CONTRACT"),
            "l4": ("actual next model request is missing at L4", "OBSERVATION_BOUNDARY"),
        }
        for case_id, (reason, expected) in cases.items():
            with self.subTest(case_id=case_id):
                result = diagnose_prediction({
                    "case_identity": {"case_id": case_id}, "run_status": "UNASSESSED",
                    "invalid_reason": "effect_model_unassessed",
                    "effect_model": {"modeling_reasons": [reason]},
                })
                self.assertEqual(result["root_cause"], expected)
                self.assertFalse(result["retryable_environment_failure"])

    def test_evidence_failure_extracts_runner_details(self):
        prediction = {
            "case_identity": {"case_id": "case"}, "run_status": "INVALID",
            "invalid_reason": "runner_or_evidence_contract_failed",
            "vulnerable_fixed_evidence": {"vulnerable": {"runs": [{
                "exception": "RuntimeError: invalid MCP response", "output_contract_errors": ["missing L4"],
            }]}, "patched": {"runs": []}},
        }
        result = diagnose_prediction(prediction)
        self.assertEqual(result["category"], "TRANSPORT_OR_SERVER")
        self.assertIn("missing L4", result["details"])

    def test_cross_layer_graph_gates_have_explicit_diagnostics(self):
        result = diagnose_prediction({
            "case_identity": {"case_id": "partial"},
            "run_status": "UNASSESSED",
            "invalid_reason": "cross_layer_graph_incomplete",
            "cross_layer_graph": {"summary": {"unresolved_boundaries": ["Tool handler binding unresolved"]}},
        })
        self.assertEqual(result["category"], "CROSS_LAYER_GRAPH_INCOMPLETE")
        self.assertEqual(result["root_cause"], "TOOL_BINDING")
        self.assertIn("Tool handler binding unresolved", result["details"])
        self.assertFalse(result["gt_used"])

    def test_batch_aggregation_is_label_free(self):
        summary = aggregate_diagnostics([
            {"category": "COMPLETED", "requires_human_review": False},
            {"category": "RUNNER_TIMEOUT", "requires_human_review": True},
        ])
        self.assertEqual(summary["category_counts"], {"COMPLETED": 1, "RUNNER_TIMEOUT": 1})
        self.assertEqual(summary["requires_human_review_count"], 1)
        self.assertEqual(summary["retryable_environment_failure_count"], 0)
        self.assertFalse(summary["gt_used"])


if __name__ == "__main__":
    unittest.main()
