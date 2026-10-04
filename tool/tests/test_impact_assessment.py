import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator

from oscar.runtime.blind_runtime import BlindCaseError, _boundary_features, assert_prediction_blind
from oscar.evaluation.evaluate import evaluate
from oscar.analysis.impact_assessment import assess_concrete_impact
from oscar.contracts.prediction_contract import validate_prediction_contract


ROOT = Path(__file__).resolve().parents[1]


def effect(effect_id="effect-resource", kind="RESOURCE_EFFECT", role="TERMINAL", provenance="SUPPORTED"):
    return {
        "effect_id": effect_id,
        "effect_kind": kind,
        "effect_role": role,
        "provenance_status": provenance,
        "provenance": [{"from": "anchor", "to": f"effect:{effect_id}", "evidence_refs": ["source:1"]}],
        "origin": {"anchor_refs": ["anchor-1"]},
        "condition": {
            "patch_derived": True,
            "production_evidence": ["trace:vulnerable"],
            "production_predicate": {"anchor_reached": True, "effect_specific_witness": "resource_event"},
        },
        "sink_candidates": [{"layer": "PROGRAM_RUNTIME"}],
        "evidence_refs": ["source:1", "patch:server.py"],
    }


def observation(
    effect_id="effect-resource", *, realized=True, level="P2-R", reached_l4=False,
    reason=None, evidence=True,
):
    return {
        "status": "REACHED" if reached_l4 else "NOT_REACHED",
        "effects": [{
            "effect_id": effect_id,
            "effect_kind": "RESOURCE_EFFECT",
            "production_status": "PRODUCED" if realized else "NOT_PRODUCED",
            "effect_realization": {"status": "REALIZED" if realized else "NOT_REALIZED"},
            "highest_witnessed_level": level,
            "reached_exact_l4": reached_l4,
            "termination_reason": reason if reason is not None else (None if reached_l4 else "NO_READBACK"),
            "evidence_refs": [f"trace:{effect_id}"] if evidence else [],
        }],
    }


def run(row, repetition, *, valid=True, timed_out=False, digest="frozen-input"):
    return {
        **row,
        "repetition": repetition,
        "valid": valid,
        "timed_out": timed_out,
        "tool_input_digest": digest,
        "anchor_reached": True,
        "trace_levels": ["L0_RAW_MCP_RESULT", "L4_MODEL_VISIBLE_OBSERVATION"],
    }


def pairing_context():
    return {
        "parity_verified": True,
        "frozen_input_digest": "input",
        "agent_task_digest": "task",
        "host_session_digest": "host-session",
        "external_boundary_digest": "boundary",
        "environment_manifest_digest": "environment",
    }


def assess(
    effects, vulnerable, *, fixed=None, fixed_blocked=True, paired=True, context=None,
):
    vulnerable_runs = [run(row, index + 1) for index, row in enumerate(vulnerable)]
    if fixed is None:
        fixed = []
        for _ in vulnerable:
            fixed_row = {"status": "NOT_REACHED", "effects": []}
            for modeled_effect in effects:
                fixed_row["effects"].append(observation(
                    modeled_effect["effect_id"], realized=False, level="P1",
                    reason="PATCH_GUARD_BLOCKED",
                )["effects"][0])
            fixed.append(fixed_row)
    fixed_runs = [run(row, index + 1) for index, row in enumerate(fixed)]
    model = {
        "effects": effects,
        "fixed_side_blocked": fixed_blocked,
        "repair_predicate": {"classification_status": "SUPPORTED", "patch_refs": ["patch:server.py"]},
    }
    return assess_concrete_impact(
        model, vulnerable_runs, vulnerable_anchor_reached=[True] * len(vulnerable_runs),
        fixed_runs=fixed_runs, paired_execution_valid=paired,
        cross_layer_path_validated=True, pairing_context=context or pairing_context(),
    )


def prediction(case_id, *, impact=True, reachability=False):
    vulnerable = [observation(level="P2-R") for _ in range(3)]
    result = assess([effect()], vulnerable)
    result.update({
        "schema_version": "vulveil-prediction/v2",
        "case_identity": {"case_id": case_id},
        "run_status": "VALID",
        "predicted_reachability": reachability,
    })
    result["agent_visible"] = reachability
    if reachability:
        result["maximum_effect_boundary"] = "L4_MODEL_VISIBLE_OBSERVATION"
    if not impact:
        negative = assess([effect()], [observation(realized=False, level="P1") for _ in range(3)])
        result.update(negative)
        result["predicted_reachability"] = False
        result["agent_visible"] = False
    return result


class ConcreteImpactAssessmentTests(unittest.TestCase):
    def test_boundary_features_detect_explicit_tool_error(self):
        rows = [{"level": "L0_RAW_MCP_RESULT", "content": {"isError": True}}]
        self.assertTrue(_boundary_features(rows, {})["tool_result_failure"])

    def test_boundary_features_detect_failure_text(self):
        rows = [{
            "level": "L0_RAW_MCP_RESULT",
            "content": {"text": "Operation failed: process returned exit code 1"},
        }]
        self.assertTrue(_boundary_features(rows, {})["tool_result_failure"])

    def test_boundary_features_detect_same_field_input_echo(self):
        rows = [{
            "level": "L0_RAW_MCP_RESULT",
            "content": {"result": {"targetUrl": "https://example.test/source"}},
        }]
        result = _boundary_features(rows, {"url": "https://example.test/source"})
        self.assertTrue(result["input_echo_without_transition"])

    def test_boundary_features_do_not_treat_redirect_as_plain_echo(self):
        rows = [{
            "level": "L0_RAW_MCP_RESULT",
            "content": {
                "url": "https://example.test/source",
                "redirected": True,
                "finalUrl": "https://example.test/destination",
            },
        }]
        result = _boundary_features(rows, {"url": "https://example.test/source"})
        self.assertFalse(result["input_echo_without_transition"])

    def test_partial_provenance_is_not_promoted_by_complete_graph(self):
        result = assess([effect(provenance="PARTIAL")], [observation() for _ in range(3)])
        self.assertEqual(result["impact_status"], "UNASSESSED")
        self.assertEqual(result["per_effect"]["effect-resource"]["patch_attribution"], "UNASSESSED")

    def test_valid_fixed_runs_without_same_effect_evidence_are_unassessed(self):
        fixed = [observation(realized=False, level="P1", reason="PATCH_GUARD_BLOCKED", evidence=False) for _ in range(3)]
        for row in fixed:
            row["effects"][0]["evidence_refs"] = []
        fixed_runs = [run(row, index + 1) for index, row in enumerate(fixed)]
        model = {"effects": [effect()], "fixed_side_blocked": True,
                 "repair_predicate": {"classification_status": "SUPPORTED", "patch_refs": ["patch:x"]}}
        vulnerable = [run(observation(), index + 1) for index in range(3)]
        result = assess_concrete_impact(
            model, vulnerable, vulnerable_anchor_reached=[True] * 3,
            fixed_runs=fixed_runs, paired_execution_valid=True, pairing_context=pairing_context(),
        )
        self.assertEqual(result["impact_status"], "UNASSESSED")
        item = result["per_effect"]["effect-resource"]
        self.assertEqual(item["patch_attribution"], "UNASSESSED")
        self.assertTrue(all(not binding["evidence_refs"] for binding in item["fixed_repetition_bindings"]))
        prediction_row = {
            **result,
            "schema_version": "vulveil-prediction/v2",
            "case_identity": {"case_id": "missing-fixed-effect-refs"},
            "run_status": "VALID",
            "predicted_reachability": False,
        }
        self.assertEqual(validate_prediction_contract(prediction_row), [])

    def test_unrelated_fixed_crash_or_timeout_cannot_support_attribution(self):
        for reason in ("CRASH", "TIMEOUT"):
            fixed = [observation(realized=False, level="P1", reason=reason) for _ in range(3)]
            result = assess([effect()], [observation() for _ in range(3)], fixed=fixed)
            self.assertEqual(result["impact_status"], "UNASSESSED")
            self.assertEqual(result["per_effect"]["effect-resource"]["patch_attribution"], "UNASSESSED")

    def test_one_or_two_repetitions_cannot_form_formal_yes_or_no(self):
        for count in (1, 2):
            yes = assess([effect()], [observation() for _ in range(count)])
            no = assess([effect()], [observation(realized=False, level="P1") for _ in range(count)])
            for result in (yes, no):
                self.assertEqual(result["impact_status"], "UNASSESSED")
                self.assertIsNone(result["predicted_impact"])
                self.assertFalse(result["per_effect"]["effect-resource"]["stable_across_repetitions"])

    def test_three_stable_effect_level_pairs_form_impact_yes(self):
        result = assess([effect()], [observation() for _ in range(3)])
        self.assertEqual(result["impact_status"], "IMPACT_YES")
        self.assertTrue(result["predicted_impact"])
        item = result["per_effect"]["effect-resource"]
        self.assertEqual(item["patch_attribution"], "SUPPORTED")
        self.assertEqual(len(item["fixed_repetition_bindings"]), 3)
        self.assertTrue(all(binding["effect_status"] == "BLOCKED" for binding in item["fixed_repetition_bindings"]))

    def test_fixed_baseline_rejection_is_effect_specific_blocking_evidence(self):
        modeled = effect(provenance="PARTIAL")
        fixed = []
        for repetition in range(3):
            row = observation(realized=True, level="P2-H")
            row["effects"][0]["rejected_fixed_baseline_paths"] = ["result.text"]
            fixed.append(row)
        result = assess([modeled], [observation(level="P2-R") for _ in range(3)], fixed=fixed)
        self.assertEqual(result["impact_status"], "IMPACT_YES")
        item = result["per_effect"]["effect-resource"]
        self.assertEqual(item["patch_attribution"], "SUPPORTED")
        self.assertTrue(all(binding["effect_status"] == "BLOCKED" for binding in item["fixed_repetition_bindings"]))
        self.assertTrue(all(
            any(ref.startswith("stage4:fixed-baseline-rejected:") for ref in binding["evidence_refs"])
            for binding in item["fixed_repetition_bindings"]
        ))

    def test_stable_resource_absence_supports_partial_provenance_attribution(self):
        modeled = effect(provenance="PARTIAL")
        fixed = []
        for _ in range(3):
            row = observation(realized=False, level="P0", reason="NOT_PRODUCED")
            row["effects"][0]["evidence_refs"] = [
                "trace:L0_RAW_MCP_RESULT:resource-effect-absent"
            ]
            fixed.append(row)

        result = assess(
            [modeled],
            [observation(level="P2-R") for _ in range(3)],
            fixed=fixed,
        )

        self.assertEqual(result["impact_status"], "IMPACT_YES")
        item = result["per_effect"]["effect-resource"]
        self.assertEqual(item["patch_attribution"], "SUPPORTED")
        self.assertTrue(all(
            binding["effect_status"] == "BLOCKED"
            for binding in item["fixed_repetition_bindings"]
        ))

    def test_three_stable_not_realized_runs_form_impact_no(self):
        result = assess([effect()], [observation(realized=False, level="P1") for _ in range(3)])
        self.assertEqual(result["impact_status"], "IMPACT_NO")
        self.assertFalse(result["predicted_impact"])

    def test_missing_effect_or_changed_status_is_unassessed(self):
        missing = [observation(), observation(), {"effects": [], "status": "NOT_REACHED"}]
        changed = [observation(), observation(realized=False, level="P1"), observation()]
        self.assertEqual(assess([effect()], missing)["impact_status"], "UNASSESSED")
        self.assertEqual(assess([effect()], changed)["impact_status"], "UNASSESSED")

    def test_environment_only_impact_is_independent_of_reachability(self):
        result = assess([effect()], [observation(level="P2-R") for _ in range(3)])
        self.assertTrue(result["predicted_impact"])
        self.assertFalse(result["agent_visible"])

    def test_tool_visible_agent_invisible_impact(self):
        result = assess([effect()], [observation(level="P2-T") for _ in range(3)])
        self.assertTrue(result["predicted_impact"])
        self.assertFalse(result["agent_visible"])
        self.assertEqual(result["maximum_effect_boundary"], "L1_NORMALIZED_TOOL_RESULT")

    def test_intermediate_control_effect_does_not_form_impact_yes(self):
        result = assess([effect("control", "CONTROL_EFFECT", "TERMINAL")],
                        [observation("control") for _ in range(3)])
        self.assertEqual(result["impact_status"], "UNASSESSED")
        self.assertIsNone(result["predicted_impact"])

    def test_blind_contract_rejects_hidden_answers(self):
        for payload in ({"impact_label": "IMPACT_YES"}, {"annotation": {"answer": "yes"}},
                        {"expected_subtype": "environment-only"}, {"path": "hidden_gt/impact.json"}):
            with self.assertRaises(BlindCaseError):
                assert_prediction_blind(payload)


class PredictionContractTests(unittest.TestCase):
    def test_schema_and_semantics_accept_valid_yes_no_and_unassessed(self):
        schema = json.loads((ROOT / "oscar" / "schemas" / "prediction.schema.json").read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        self.assertEqual(validate_prediction_contract(prediction("yes")), [])
        self.assertEqual(validate_prediction_contract(prediction("no", impact=False)), [])
        unassessed = prediction("ua")
        unassessed.update({
            "impact_status": "UNASSESSED", "predicted_impact": None,
            "impact_effect_ids": [], "repetition_policy": {
                "schema_version": "vulveil-impact-repetitions/v1",
                "minimum_paired_repetitions": 3, "vulnerable_repetitions": 2,
                "fixed_repetitions": 2, "all_runs_valid_and_paired": False,
            },
        })
        for item in unassessed["per_effect"].values():
            item["stable_across_repetitions"] = False
            item["realization_status"] = "UNASSESSED"
            item["vulnerable_repetition_bindings"] = item["vulnerable_repetition_bindings"][:2]
            item["fixed_repetition_bindings"] = item["fixed_repetition_bindings"][:2]
        self.assertEqual(validate_prediction_contract(unassessed), [])

    def test_minimal_counterexamples_are_rejected(self):
        base = prediction("counterexample")
        mutations = []
        invalid = copy.deepcopy(base); invalid["run_status"] = "INVALID"; mutations.append(invalid)
        wrong_yes = copy.deepcopy(base); wrong_yes["predicted_impact"] = False; mutations.append(wrong_yes)
        empty_ids = copy.deepcopy(base); empty_ids["impact_effect_ids"] = []; mutations.append(empty_ids)
        missing_effect = copy.deepcopy(base); missing_effect["impact_effect_ids"] = ["missing"]; mutations.append(missing_effect)
        bad_effect = copy.deepcopy(base); bad_effect["per_effect"]["effect-resource"]["patch_attribution"] = "UNASSESSED"; mutations.append(bad_effect)
        visible = copy.deepcopy(base); visible["agent_visible"] = True; mutations.append(visible)
        reachable = copy.deepcopy(base); reachable["predicted_reachability"] = True; mutations.append(reachable)
        duplicate_ids = copy.deepcopy(base); duplicate_ids["impact_effect_ids"] *= 2; mutations.append(duplicate_ids)
        bad_binding = copy.deepcopy(base); bad_binding["per_effect"]["effect-resource"]["fixed_repetition_bindings"][0].pop("pair_identity"); mutations.append(bad_binding)
        missing_bindings = copy.deepcopy(base); missing_bindings["per_effect"]["effect-resource"]["fixed_repetition_bindings"] = []; mutations.append(missing_bindings)
        synthesized_refs = copy.deepcopy(base)
        synthesized_refs["per_effect"]["effect-resource"]["fixed_repetition_bindings"][0]["evidence_refs"] = [
            "effect:effect-resource:trace:fixed:repetition:1:L0_RAW_MCP_RESULT"
        ]
        mutations.append(synthesized_refs)
        impact_no = prediction("no-realized", impact=False)
        impact_no["per_effect"]["effect-resource"]["realization_status"] = "REALIZED"; mutations.append(impact_no)
        for candidate in mutations:
            self.assertTrue(validate_prediction_contract(candidate), candidate)

    def test_impact_no_without_effects_is_rejected(self):
        candidate = prediction("empty-impact-no", impact=False)
        candidate["per_effect"] = {}
        errors = validate_prediction_contract(candidate)
        self.assertIn("IMPACT_NO requires at least one concrete effect candidate", errors)

    def test_impact_no_with_only_intermediate_control_effect_is_rejected(self):
        candidate = prediction("control-only-impact-no", impact=False)
        item = candidate["per_effect"].pop("effect-resource")
        item["effect_kind"] = "CONTROL_EFFECT"
        item["consequence_role"] = "INTERMEDIATE"
        for binding in item["vulnerable_repetition_bindings"]:
            binding["effect_id"] = "effect-control"
        for binding in item["fixed_repetition_bindings"]:
            binding["effect_id"] = "effect-control"
        candidate["per_effect"]["effect-control"] = item
        errors = validate_prediction_contract(candidate)
        self.assertIn("IMPACT_NO requires at least one concrete effect candidate", errors)

    def test_v1_is_only_allowed_for_explicit_agent_observation_compatibility(self):
        legacy = {"schema_version": "vulveil-prediction/v1", "run_status": "VALID",
                  "predicted_reachability": True}
        self.assertEqual(validate_prediction_contract(
            legacy, target="agent-observation", allow_v1_agent_observation=True), [])
        self.assertTrue(validate_prediction_contract(legacy, target="concrete-impact"))


class ConcreteImpactEvaluatorTests(unittest.TestCase):
    def _evaluate(self, predictions, gt, target="concrete-impact"):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        (root / "predictions.jsonl").write_text(
            "".join(json.dumps(row) + "\n" for row in predictions), encoding="utf-8")
        (root / "gt.json").write_text(json.dumps({"cases": gt}), encoding="utf-8")
        return evaluate(root / "predictions.jsonl", root / "gt.json", root / "out.json", target=target)

    def test_contract_invalid_prediction_is_excluded(self):
        bad = prediction("bad")
        bad["impact_effect_ids"] = []
        result = self._evaluate([bad], [{"case_identity": {"case_id": "bad"}, "impact_label": "IMPACT_YES"}])
        self.assertEqual(result["counts"]["evaluated"], 0)
        self.assertEqual(result["counts"]["contract_invalid"], 1)
        self.assertEqual(result["join_audit"]["rows"][0]["status"], "INVALID_PREDICTION_CONTRACT")
        self.assertEqual(result["evaluation_status"], "FAILED")
        self.assertEqual(result["failure_reason"], "INVALID_PREDICTION_CONTRACT")
        self.assertFalse(result["statistics_policy"]["metrics_usable_for_formal_conclusions"])

    def test_evaluate_cli_returns_nonzero_for_contract_invalid_prediction(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bad = prediction("bad")
            bad["impact_effect_ids"] = []
            (root / "predictions.jsonl").write_text(json.dumps(bad) + "\n", encoding="utf-8")
            (root / "gt.json").write_text(json.dumps({"cases": [
                {"case_identity": {"case_id": "bad"}, "impact_label": "IMPACT_YES"}
            ]}), encoding="utf-8")
            completed = subprocess.run(
                [sys.executable, str(ROOT / "evaluate.py"), "--predictions", str(root / "predictions.jsonl"),
                 "--hidden-gt", str(root / "gt.json"), "--target", "concrete-impact",
                 "--output", str(root / "out.json")],
                capture_output=True, text=True, check=False,
            )
        self.assertNotEqual(completed.returncode, 0)

    def test_duplicate_prediction_or_gt_fails_closed(self):
        valid = prediction("duplicate")
        gt = [{"case_identity": {"case_id": "duplicate"}, "impact_label": "IMPACT_YES"}]
        for predictions, labels in (([valid, copy.deepcopy(valid)], gt), ([valid], gt + copy.deepcopy(gt))):
            result = self._evaluate(predictions, labels)
            self.assertEqual(result["evaluation_status"], "FAILED")
            self.assertEqual(result["counts"]["evaluated"], 0)
            self.assertIsNone(result["metrics"]["f1"])
            self.assertFalse(result["statistics_policy"]["metrics_usable_for_formal_conclusions"])

    def test_concrete_target_never_reads_agent_label(self):
        result = self._evaluate(
            [prediction("case")],
            [{"case_identity": {"case_id": "case"}, "ground_truth_label": "POSITIVE"}],
        )
        self.assertEqual(result["counts"]["evaluated"], 0)
        self.assertEqual(result["counts"]["unassessed"], 1)

    def test_agent_target_never_reads_impact_label_and_accepts_v1(self):
        legacy = {"schema_version": "vulveil-prediction/v1", "case_identity": {"case_id": "legacy"},
                  "run_status": "VALID", "predicted_reachability": True}
        result = self._evaluate(
            [legacy], [{"case_identity": {"case_id": "legacy"}, "impact_label": "IMPACT_YES"}],
            target="agent-observation",
        )
        self.assertEqual(result["counts"]["evaluated"], 0)
        self.assertEqual(result["counts"]["unassessed"], 1)

    def test_metrics_coverage_and_environment_mismatch(self):
        predictions = [prediction("tp"), prediction("fp"), prediction("tn", impact=False),
                       prediction("fn", impact=False), prediction("mismatch")]
        predictions[-1]["environment_manifest_digest"] = "prediction"
        labels = {"tp": "IMPACT_YES", "fp": "IMPACT_NO", "tn": "IMPACT_NO",
                  "fn": "IMPACT_YES", "mismatch": "IMPACT_YES", "missing": "IMPACT_NO"}
        gt = [{"case_identity": {"case_id": case_id}, "impact_label": label,
               **({"environment_manifest_digest": "gt"} if case_id == "mismatch" else {})}
              for case_id, label in labels.items()]
        result = self._evaluate(predictions, gt)
        self.assertEqual(result["confusion_matrix"], {"TP": 1, "TN": 1, "FP": 1, "FN": 1})
        self.assertEqual(result["counts"]["environment_mismatch"], 1)
        self.assertEqual(result["counts"]["ambiguous_metadata_join"], 1)

    def test_evaluate_cli_returns_nonzero_for_duplicate_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            valid = prediction("duplicate")
            (root / "predictions.jsonl").write_text(
                json.dumps(valid) + "\n" + json.dumps(valid) + "\n", encoding="utf-8")
            (root / "gt.json").write_text(json.dumps({"cases": [
                {"case_identity": {"case_id": "duplicate"}, "impact_label": "IMPACT_YES"}
            ]}), encoding="utf-8")
            completed = subprocess.run(
                [sys.executable, str(ROOT / "evaluate.py"), "--predictions", str(root / "predictions.jsonl"),
                 "--hidden-gt", str(root / "gt.json"), "--target", "concrete-impact",
                 "--output", str(root / "out.json")],
                capture_output=True, text=True, check=False,
            )
        self.assertNotEqual(completed.returncode, 0)


if __name__ == "__main__":
    unittest.main()
