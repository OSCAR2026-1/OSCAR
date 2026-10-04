import tempfile
import unittest
from pathlib import Path

from scripts.build_public_release import audit_files, _load_manifest, _selected_files


class PublicReleaseTests(unittest.TestCase):
    def test_manifest_selects_no_hidden_or_local_files(self):
        selected = _selected_files(_load_manifest())
        lowered = "\n".join(selected).lower()
        self.assertNotIn("hidden_gt", lowered)
        self.assertNotIn("vulveil_v1.tar.gz", lowered)
        self.assertFalse(audit_files(selected))

    def test_auditor_rejects_evaluator_only_json_keys(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "fixture.json"
            path.write_text('{"ground_truth_label":"POSITIVE"}\n', encoding="utf-8")
            # The release auditor is rooted at the repository, so exercise its
            # structured-key policy through the exported constant behavior.
            from scripts.build_public_release import _walk_json
            errors = []
            _walk_json({"ground_truth_label": "POSITIVE"}, str(path), errors)
        self.assertTrue(errors)


if __name__ == "__main__":
    unittest.main()
