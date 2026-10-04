import copy
import unittest

from oscar.analysis.localization import build_localization, validate_direct_runtime_dependency, validate_localization
from test_effect_modeling import _spec


class LocalizationTests(unittest.TestCase):
    def test_patch_mapped_localization_is_independent_and_versioned(self):
        localization = build_localization(_spec())
        self.assertEqual(localization["schema_version"], "vulveil-localization/v1")
        self.assertEqual(localization["status"], "LOCALIZED")
        self.assertTrue(localization["anchor_candidates"])
        self.assertTrue(localization["repair_predicate"])
        self.assertFalse(validate_localization(localization), localization)

    def test_legacy_oracle_anchor_is_not_consumed(self):
        spec = _spec()
        spec["oracle"] = {"vulnerability_anchor": "invented.py:999"}
        localization = build_localization(spec)
        self.assertEqual(localization["status"], "LOCALIZED")
        self.assertNotIn("invented.py", str(localization))

    def test_missing_or_invalid_direct_runtime_scope_is_unassessed(self):
        missing = _spec()
        missing.pop("direct_runtime_dependency")
        self.assertTrue(validate_direct_runtime_dependency(missing))
        self.assertEqual(build_localization(missing)["status"], "UNASSESSED")

        indirect = copy.deepcopy(_spec())
        indirect["direct_runtime_dependency"]["dependency_depth"] = 2
        localization = build_localization(indirect)
        self.assertEqual(localization["status"], "UNASSESSED")
        self.assertIn("dependency_depth", " ".join(localization["unresolved_reasons"]))

    def test_server_runtime_case_requires_independent_dependency_analysis_material(self):
        spec = _spec()
        spec["source"] = {"role": "server_runtime", "vulnerable": [{"path": "package-lock.json", "content": "requests==1.0.0"}], "fixed": [{"path": "package-lock.json", "content": "requests==1.0.1"}]}
        spec.pop("analysis_source", None)
        spec.pop("analysis_patch", None)
        localization = build_localization(spec)
        self.assertEqual(localization["status"], "UNASSESSED")
        self.assertIn("analysis_source", " ".join(localization["unresolved_reasons"]))

    def test_server_runtime_case_uses_dependency_source_and_upstream_patch(self):
        spec = _spec()
        dependency_patch = spec["patch"]["unified_diff"]
        server_patch = "--- a/package-lock.json\n+++ b/package-lock.json\n@@ -1 +1 @@\n-1.0.0\n+1.0.1\n"
        analysis_source = copy.deepcopy(spec["source"])
        spec["source"] = {
            "role": "server_runtime",
            "vulnerable": [{"path": "package-lock.json", "content": "1.0.0"}],
            "fixed": [{"path": "package-lock.json", "content": "1.0.1"}],
        }
        spec["patch"] = {"unified_diff": server_patch}
        spec["analysis_source"] = analysis_source
        spec["analysis_patch"] = {"unified_diff": dependency_patch}
        localization = build_localization(spec)
        self.assertEqual(localization["status"], "LOCALIZED", localization)
        self.assertTrue(localization["anchor_candidates"])


if __name__ == "__main__":
    unittest.main()
