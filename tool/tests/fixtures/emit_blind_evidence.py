import json
import os
import hashlib
from pathlib import Path


levels = [
    "L0_RAW_MCP_RESULT",
    "L1_NORMALIZED_TOOL_RESULT",
    "L2_HOST_PROCESSED_TOOL_RESULT",
    "L3_SESSION_TOOL_RESULT",
    "L4_MODEL_VISIBLE_OBSERVATION",
]
side = os.environ.get("VULVEIL_CASE_SIDE", "patched")
mode = os.environ.get("VULVEIL_MODE", "effect")
counterfactual_role = os.environ.get("VULVEIL_COUNTERFACTUAL_ROLE", "")
tool_input = json.loads(os.environ.get("VULVEIL_TOOL_INPUT_JSON", "{}"))
tool_input_digest = hashlib.sha256(
    json.dumps(tool_input, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
).hexdigest() if counterfactual_role else None
rows = []
for level in levels:
    vulnerable = side == "vulnerable"
    effect_enabled = vulnerable and counterfactual_role not in {"safe", "field-only"}
    if mode == "drop" and effect_enabled and level == "L4_MODEL_VISIBLE_OBSERVATION":
        payload = {"tool_result": {"status": "filtered"}}
    elif mode == "echo":
        payload = {"tool_result": {"echo": "frozen"}}
    elif effect_enabled:
        payload = {"tool_result": {"derived_value": "fixture-derived"}}
    else:
        payload = {"tool_result": {"status": "safe"}}
    row = {"level": level, "content": payload, "anchor_reached": vulnerable, "tool_call_id": "fixture-call-1"}
    if level == "L0_RAW_MCP_RESULT":
        row["event"] = {
            "function": "fixture_package.execute",
            "location": "probe.py:5",
            "tool_call_id": "fixture-call-1",
            "return": payload,
        }
    if tool_input_digest:
        row["tool_input_digest"] = tool_input_digest
        row["counterfactual_role"] = counterfactual_role
    if level == "L4_MODEL_VISIBLE_OBSERVATION" and mode != "fake_l4":
        row["actual_next_model_request"] = True
        row["model_request"] = {
            "messages": [
                {
                    "role": "tool",
                    "tool_call_id": "fixture-call-1",
                    "content": payload,
                }
            ]
        }
    elif level == "L4_MODEL_VISIBLE_OBSERVATION":
        row["observation"] = payload
    rows.append(row)
output = Path(os.environ["VULVEIL_OUTPUT_DIR"])
(output / "blind_evidence.jsonl").write_text(
    "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows), encoding="utf-8"
)
