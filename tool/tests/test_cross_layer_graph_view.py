import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from oscar.runtime.blind_runtime import run_blind_case
from oscar.analysis.cross_layer_graph import (
    VIEW_SCHEMA_VERSION,
    build_cross_layer_graph,
    build_simplified_cross_layer_graph,
    validate_simplified_cross_layer_graph,
)
from oscar.analysis.effect_modeling import build_effect_model
from tests.test_cross_layer_graph import _python_spec, _rows


ROOT = Path(__file__).parent


class CrossLayerGraphViewTests(unittest.TestCase):
    def _positive_graph(self):
        fixture = ROOT / "fixtures" / "blind_case.json"
        spec = json.loads(fixture.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as temporary:
            run_root = Path(temporary) / "run"
            prediction = run_blind_case(spec, run_root, base_dir=fixture.parent)
            graph = json.loads((run_root / "cross_layer_graph.json").read_text(encoding="utf-8"))
        return prediction, graph

    def test_blind_runtime_emits_display_view_without_using_it_as_prediction_input(self):
        fixture = ROOT / "fixtures" / "blind_case.json"
        spec = json.loads(fixture.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as temporary:
            run_root = Path(temporary) / "run"
            prediction = run_blind_case(spec, run_root, base_dir=fixture.parent)
            view = json.loads((run_root / "cross_layer_graph_view.json").read_text(encoding="utf-8"))
        self.assertTrue(prediction["predicted_reachability"])
        self.assertEqual(view["source_graph_id"], prediction["cross_layer_graph"]["graph_id"])
        self.assertEqual(view["projection_validation"]["status"], "OK")

    def test_replacing_display_projection_cannot_change_prediction(self):
        fixture = ROOT / "fixtures" / "blind_case.json"
        spec = json.loads(fixture.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            baseline_root = Path(first) / "run"
            projected_root = Path(second) / "run"
            baseline = run_blind_case(spec, baseline_root, base_dir=fixture.parent)
            with patch("oscar.runtime.blind_runtime.build_simplified_cross_layer_graph", return_value={"sentinel": True}):
                projected = run_blind_case(spec, projected_root, base_dir=fixture.parent)
            baseline_graph = json.loads((baseline_root / "cross_layer_graph.json").read_text(encoding="utf-8"))
            projected_graph = json.loads((projected_root / "cross_layer_graph.json").read_text(encoding="utf-8"))
        self.assertEqual(
            projected_graph["stage4_effect_observation"],
            baseline_graph["stage4_effect_observation"],
        )
        for field in ("effect_path_status", "graph_validation"):
            self.assertEqual(
                projected_graph[field],
                baseline_graph[field],
                field,
            )
        for field in ("predicted_reachability", "witnessed_level", "run_status"):
            self.assertEqual(projected[field], baseline[field], field)

    def test_effect_centered_view_retains_complete_core_path_and_collapses_static_nodes(self):
        prediction, graph = self._positive_graph()
        prediction_snapshot = copy.deepcopy(prediction)
        original = json.dumps(graph, ensure_ascii=False, sort_keys=True)
        view = build_simplified_cross_layer_graph(graph)
        self.assertEqual(view["schema_version"], VIEW_SCHEMA_VERSION)
        self.assertEqual(view["projection_validation"]["status"], "OK", view["projection_validation"])
        self.assertEqual(view["status"], graph["status"])
        self.assertEqual(view["effect_path_status"], graph["effect_path_status"])
        self.assertEqual(view["stage4_effect_observation"], graph["stage4_effect_observation"])
        self.assertEqual(view["graph_validation"], graph["graph_validation"])
        self.assertEqual(json.dumps(graph, ensure_ascii=False, sort_keys=True), original)
        self.assertEqual(prediction, prediction_snapshot)
        self.assertTrue(prediction["predicted_reachability"])

        core_kinds = {
            "vulnerability_anchor", "effect_instance", "program_value", "control_state",
            "resource_event", "resource_state", "readback_value", "tool_result_field",
            "json_rpc_field", "host_normalized_field", "session_event",
            "exact_l4_content_block", "tool_call", "tool_handler", "agent_task",
        }
        self.assertTrue({node["kind"] for node in view["nodes"]}.issubset(core_kinds))
        collapsed_kinds = {node["kind"] for node in view["collapsed_nodes"]}
        self.assertTrue({"file", "function", "call_site", "parameter"}.issubset(collapsed_kinds))

        complete_ids = [
            effect_id for effect_id, path in view["effect_path_status"].items()
            if path.get("status") == "COMPLETE"
        ]
        self.assertTrue(complete_ids)
        effect_id = complete_ids[0]
        nodes = view["nodes"]
        edges = [
            edge for edge in view["edges"]
            if edge.get("projection_effect_id") == effect_id
            or effect_id in edge.get("effect_ids", [])
            or effect_id in edge.get("carrier_effect_ids", [])
        ]
        self.assertTrue(any(node["kind"] == "vulnerability_anchor" and effect_id in node["effect_ids"] for node in nodes))
        self.assertTrue(any(node["kind"] == "effect_instance" and effect_id in node["effect_ids"] for node in nodes))
        self.assertTrue(any(edge["kind"] == "PRODUCES" for edge in edges))
        self.assertTrue(any(edge["kind"] == "CARRIED_BY" for edge in edges))
        self.assertTrue(any(node["kind"] == "tool_result_field" and effect_id in node["effect_ids"] for node in nodes))
        self.assertTrue({node.get("boundary_level") for node in nodes if effect_id in node.get("effect_ids", [])}.issuperset({
            "RAW_TOOL_RESULT", "MCP_PROTOCOL_FIELD", "HOST_PROCESSED_RESULT", "SESSION_MESSAGE", "EXACT_L4_CONTENT",
        }))
        self.assertTrue(any(
            edge.get("boundary") == "L3_SESSION_TOOL_RESULT->L4_MODEL_VISIBLE_OBSERVATION"
            and edge["kind"] == "OBSERVE"
            and edge.get("exact_l4_observed")
            for edge in edges
        ))

    def test_resource_view_has_event_state_readback_result_l4_without_forcing_resource_nodes(self):
        spec = _python_spec()
        traces = _rows({"structuredContent": {"file_content": "secret"}}, {"structuredContent": {"status": "blocked"}})
        traces["vulnerable"][2]["event"] = {
            "operation": "write", "state_write": True, "resource_id": "fixture-resource",
            "function": "open", "location": "server.py:5",
            "before_state": {"exists": False}, "after_state": {"content": "secret"},
        }
        traces["vulnerable"][3]["event"] = {
            "operation": "read", "state_read": True, "resource_id": "fixture-resource",
            "function": "readback", "location": "server.py:5",
            "before_state": {"content": "secret"}, "after_state": {"content": "secret"},
            "return": {"content": "secret"},
        }
        model = build_effect_model(spec, traces)
        graph = build_cross_layer_graph(spec, model, traces)
        view = build_simplified_cross_layer_graph(graph)
        self.assertEqual(view["projection_validation"]["status"], "OK", view["projection_validation"])
        resource_ids = {
            effect_id for node in view["nodes"]
            if node["kind"] == "effect_instance" and node.get("effect_kind") == "RESOURCE_EFFECT"
            for effect_id in node.get("effect_ids", [])
        }
        self.assertTrue(resource_ids)
        complete_resource_ids = {
            effect_id for effect_id in resource_ids
            if view["effect_path_status"].get(effect_id, {}).get("status") == "COMPLETE"
        }
        self.assertTrue(complete_resource_ids)
        resource_id = next(iter(complete_resource_ids))
        resource_nodes = [node for node in view["nodes"] if resource_id in node.get("effect_ids", [])]
        self.assertTrue(any(node["kind"] == "resource_event" for node in resource_nodes))
        self.assertTrue(any(node["kind"] == "resource_state" for node in resource_nodes))
        self.assertTrue(any(node["kind"] == "readback_value" for node in resource_nodes))
        self.assertTrue(any(node["kind"] == "tool_result_field" for node in resource_nodes))
        resource_edges = [
            edge for edge in view["edges"]
            if edge.get("projection_effect_id") == resource_id
        ]
        self.assertTrue(any(edge["kind"] == "DERIVES_VALUE" for edge in resource_edges))
        self.assertTrue(any(edge["kind"] == "RETURNS" for edge in resource_edges))
        self.assertTrue(any(edge["kind"] in {"STATE_WRITE", "WRITES_RESOURCE", "STATE_READ", "READS_RESOURCE"} for edge in resource_edges))
        self.assertFalse(any(node["kind"] == "resource" for node in view["nodes"]))
        self.assertTrue(any(node["kind"] == "resource" for node in view["collapsed_nodes"]))

    def test_effect_instances_and_carrier_edges_are_not_merged(self):
        _, view_graph = self._positive_graph()
        view = build_simplified_cross_layer_graph(view_graph)
        effect_ids = [node["effect_ids"][0] for node in view["nodes"] if node["kind"] == "effect_instance" and node.get("effect_ids")]
        self.assertGreaterEqual(len(set(effect_ids)), 2)
        for effect_id in set(effect_ids):
            for node in view["nodes"]:
                if node.get("projection_effect_id") == effect_id and node["kind"] in {"program_value", "control_state", "resource_event", "resource_state", "readback_value"}:
                    self.assertEqual(node.get("effect_ids"), [effect_id])
            for edge in view["edges"]:
                if edge.get("projection_effect_id") == effect_id and edge["kind"] == "CARRIED_BY":
                    self.assertEqual(edge.get("effect_ids"), [effect_id])

    def test_interleaved_tool_calls_keep_independent_tool_and_l4_nodes(self):
        spec = _python_spec()
        base = _rows({"structuredContent": {"derived_value": "uid=0"}}, {"structuredContent": {"status": "blocked"}})
        traces = {"vulnerable": [], "fixed": []}
        for side in traces:
            calls = {"call-a": [], "call-b": []}
            for row in base[side]:
                for call_id, invocation_id in (("call-a", "inv-a"), ("call-b", "inv-b")):
                    item = copy.deepcopy(row)
                    item.update(
                        tool_call_id=call_id, invocation_id=invocation_id,
                        session_id=f"session-{call_id}", trace_id=f"trace:{side}:{call_id}",
                        span_id=f"span:{side}:{call_id}:{item['level']}",
                    )
                    calls[call_id].append(item)
            for index in range(5):
                traces[side].extend((calls["call-a"][index], calls["call-b"][index]))
        model = build_effect_model(spec, traces)
        graph = build_cross_layer_graph(spec, model, traces)
        view = build_simplified_cross_layer_graph(graph)
        tool_calls = [node for node in view["nodes"] if node["kind"] == "tool_call" and node.get("side") == "vulnerable"]
        l4_nodes = [node for node in view["nodes"] if node["kind"] == "exact_l4_content_block" and node.get("side") == "vulnerable"]
        self.assertEqual({node["invocation_identity"]["tool_call_id"] for node in tool_calls}, {"call-a", "call-b"})
        self.assertEqual({node["dynamic"]["call_key"] for node in l4_nodes}, {"tool_call_id:call-a", "tool_call_id:call-b"})
        self.assertEqual(len(l4_nodes), 2)
        self.assertEqual(view["projection_validation"]["status"], "OK", view["projection_validation"])

    def test_isolated_l4_edge_cannot_make_projection_complete(self):
        _, graph = self._positive_graph()
        isolated = copy.deepcopy(graph)
        isolated["edges"] = [
            edge for edge in isolated["edges"]
            if edge.get("boundary") == "L3_SESSION_TOOL_RESULT->L4_MODEL_VISIBLE_OBSERVATION"
        ]
        view = build_simplified_cross_layer_graph(isolated)
        self.assertNotEqual(view["status"], "COMPLETE")
        self.assertEqual(view["effect_path_status"], graph["effect_path_status"])
        self.assertEqual(view["projection_validation"]["status"], "ERROR")
        self.assertTrue(any("continuous effect path" in error or "production" in error for error in view["projection_validation"]["errors"]))

    def test_disconnected_boundary_edges_cannot_fake_a_continuous_path(self):
        _, graph = self._positive_graph()
        view = build_simplified_cross_layer_graph(graph)
        complete_effect = next(
            effect_id for effect_id, path in view["effect_path_status"].items()
            if path.get("status") == "COMPLETE"
        )
        boundary = "L1_NORMALIZED_TOOL_RESULT->L2_HOST_PROCESSED_TOOL_RESULT"
        target_edges = [
            edge for edge in view["edges"]
            if edge.get("projection_effect_id") == complete_effect
            and edge.get("boundary") == boundary
            and edge.get("side") == "vulnerable"
        ]
        replacement = next(node["node_id"] for node in view["nodes"] if node.get("kind") == "effect_instance")
        for target_edge in target_edges:
            target_edge["target"] = replacement
        errors = validate_simplified_cross_layer_graph(view, source_graph=graph)
        self.assertTrue(any("continuous effect path" in error for error in errors), errors)

    def test_projected_edges_keep_explicit_call_context_fields(self):
        _, graph = self._positive_graph()
        view = build_simplified_cross_layer_graph(graph)
        required = {
            "repetition", "tool_call_id", "invocation_id", "session_id",
            "trace_id", "span_id", "boundary", "evidence_refs",
        }
        for edge in view["edges"]:
            self.assertTrue(required.issubset(edge), edge)
        dynamic_edges = [edge for edge in view["edges"] if edge.get("repetition") is not None]
        self.assertTrue(dynamic_edges)
        self.assertTrue(any(edge.get("tool_call_id") == "fixture-call-1" for edge in dynamic_edges))

    def test_filter_transform_and_unassessed_states_survive_projection(self):
        spec = _python_spec()
        source = _rows({"structuredContent": {"derived_value": "uid=0"}}, {"structuredContent": {"status": "blocked"}})
        model = build_effect_model(spec, source)
        cases = []
        transformed = copy.deepcopy(source)
        for row in transformed["vulnerable"]:
            if row["level"] == "L4_MODEL_VISIBLE_OBSERVATION":
                row["content"] = {"structuredContent": {"renamed_value": "uid=0"}}
                row["model_request"]["messages"][0]["content"] = row["content"]
                fingerprint = hashlib.sha256(json.dumps("uid=0", separators=(",", ":")).encode()).hexdigest()
                row["transformation"] = {
                    "input": ["structuredContent.derived_value"], "output": ["structuredContent.renamed_value"],
                    "rule": "host-field-rename", "evidence_refs": ["trace:vulnerable:host-field-rename"],
                    "input_fingerprints": [fingerprint], "output_fingerprints": [fingerprint],
                }
        cases.append(transformed)
        filtered = copy.deepcopy(source)
        for row in filtered["vulnerable"]:
            if row["level"] in {"L3_SESSION_TOOL_RESULT", "L4_MODEL_VISIBLE_OBSERVATION"}:
                row["content"] = {"structuredContent": {"status": "filtered"}}
                row["filtering"] = {"field": "structuredContent.derived_value", "action": "drop"}
                if row["level"] == "L4_MODEL_VISIBLE_OBSERVATION":
                    row["model_request"]["messages"][0]["content"] = row["content"]
        cases.append(filtered)
        unassessed = copy.deepcopy(source)
        for row in unassessed["vulnerable"]:
            if row["level"] in {"L3_SESSION_TOOL_RESULT", "L4_MODEL_VISIBLE_OBSERVATION"}:
                row["content"] = {"structuredContent": {"status": "ordinary"}}
                if row["level"] == "L4_MODEL_VISIBLE_OBSERVATION":
                    row["model_request"]["messages"][0]["content"] = row["content"]
        cases.append(unassessed)
        graphs = [build_cross_layer_graph(spec, model, traces) for traces in cases]
        views = [build_simplified_cross_layer_graph(graph) for graph in graphs]
        self.assertTrue(any(edge["kind"] in {"TRANSFORMS", "OBSERVE"} and edge["status"] == "TRANSFORMED" for edge in views[0]["edges"]))
        self.assertTrue(any(edge["kind"] == "FILTERS" and edge["status"] == "DROPPED" for edge in views[1]["edges"]))
        self.assertTrue(any(edge["status"] == "UNASSESSED" for edge in views[2]["edges"]))
        for graph, view in zip(graphs, views):
            self.assertEqual(view["effect_path_status"], graph["effect_path_status"])
            self.assertEqual(view["graph_validation"], graph["graph_validation"])

    def test_view_validator_rejects_non_core_node_and_gt_content(self):
        _, graph = self._positive_graph()
        view = build_simplified_cross_layer_graph(graph)
        bad = copy.deepcopy(view)
        bad["nodes"].append({"node_id": "bad", "layer": "PROGRAM_SERVER", "kind": "function", "side": "vulnerable", "identity": "bad", "effect_ids": []})
        bad["vulnerability_component"]["leak"] = "ground_truth_label"
        errors = validate_simplified_cross_layer_graph(bad, source_graph=graph)
        self.assertTrue(any("non-core node" in error for error in errors))
        self.assertTrue(any("forbidden GT" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
