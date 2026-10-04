import json
import os
from pathlib import Path


levels = [
    "L0_RAW_MCP_RESULT",
    "L1_NORMALIZED_TOOL_RESULT",
    "L2_HOST_PROCESSED_TOOL_RESULT",
    "L3_SESSION_TOOL_RESULT",
    "L4_MODEL_VISIBLE_OBSERVATION",
]
output = Path(os.environ["VULVEIL_OUTPUT_DIR"])
(output / "recorder.jsonl").write_text(
    "".join(json.dumps({"level": level, "content": "fixture"}) + "\n" for level in levels),
    encoding="utf-8",
)
