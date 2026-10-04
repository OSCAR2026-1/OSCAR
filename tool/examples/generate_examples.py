"""Regenerate the label-free Stage 2 example models."""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path


OSCAR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(OSCAR))

from oscar.runtime.blind_runtime import load_json, run_blind_case  # noqa: E402


def generate(case_name: str, output_name: str) -> None:
    case_path = OSCAR / "tests" / "fixtures" / case_name
    spec = load_json(case_path)
    spec["_blind_case_base_dir"] = str(case_path.parent)
    with tempfile.TemporaryDirectory(prefix="vulveil-stage2-example-") as temporary:
        prediction = run_blind_case(spec, Path(temporary), base_dir=case_path.parent)
    (Path(__file__).parent / output_name).write_text(
        json.dumps(prediction["effect_model"], ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def main() -> int:
    generate("blind_case.json", "positive_effect_model.json")
    generate("blind_case_insufficient.json", "unassessed_effect_model.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
