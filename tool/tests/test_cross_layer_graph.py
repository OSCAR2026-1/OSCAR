import copy
import hashlib
import json
import unittest

from oscar.analysis.cross_layer_graph import _continuous_effect_path, _field_values, _paths_equivalent, _scalar_digests, _typescript_static, build_cross_layer_graph, validate_cross_layer_graph
from oscar.analysis.effect_modeling import build_effect_model, inspect_l4_effect


def _rows(vulnerable, fixed, *, model_request=True):
    def side(value, side_name):
        rows = []
        for level in ("L0_RAW_MCP_RESULT", "L1_NORMALIZED_TOOL_RESULT", "L2_HOST_PROCESSED_TOOL_RESULT", "L3_SESSION_TOOL_RESULT", "L4_MODEL_VISIBLE_OBSERVATION"):
            row = {
                "level": level,
                "content": value,
                "repetition": 1,
                "trace_id": f"trace:{side_name}:1",
                "span_id": f"span:{side_name}:{level}",
                "operation": level,
            }
            if level == "L4_MODEL_VISIBLE_OBSERVATION" and model_request:
                row["model_request"] = {"messages": [{"role": "tool", "content": value}]}
                row["actual_next_model_request"] = True
            rows.append(row)
        return rows
    return {"vulnerable": side(vulnerable, "vulnerable"), "fixed": side(fixed, "fixed")}


def _python_spec():
    return {
        "schema_version": "vulveil-blind-case/v1",
        "identity": {"advisory": "CVE-GRAPH-0001", "package": "fixture", "vulnerable_version": "1.0", "fixed_version": "1.1"},
        "experiment_type": "COMMAND_OR_QUERY_INJECTION",
        "direct_runtime_dependency": {
            "dependency_name": "dangerlib",
            "dependency_purl": "pkg:pypi/dangerlib",
            "dependency_depth": 1,
            "dependency_scope": "runtime",
            "vulnerable_version": "1.0",
            "fixed_version": "1.1",
            "relation_status": "affected_exact_direct_runtime"
        },
        "server": {"repository": "fixture/server", "module": "fixture"},
        "tool": {"name": "probe"}, "tool_input": {"command": "id | whoami"},
        "source": {
            "vulnerable": [{"path": "server.py", "content": "import dangerlib\nclass Server:\n    @mcp.tool()\n    def probe(self, command):\n        return dangerlib.execute(command, shell=True)\n"}],
            "fixed": [{"path": "server.py", "content": "import dangerlib\nclass Server:\n    @mcp.tool()\n    def probe(self, command):\n        if '|' in command: raise ValueError('blocked')\n        return dangerlib.execute([command], shell=False)\n"}],
        },
        "patch": {"unified_diff": "--- a/server.py\n+++ b/server.py\n@@ -3,3 +3,4 @@\n     @mcp.tool()\n     def probe(self, command):\n+        if '|' in command: raise ValueError('blocked')\n         return dangerlib.execute(command, shell=True)\n"},
        "agent_task": "Call probe", "host_profile": {"model": "fixture"}, "environment": {},
    }


class CrossLayerGraphTests(unittest.TestCase):
    def test_scalar_root_has_a_stable_carrier_path(self):
        self.assertEqual(set(_scalar_digests("scalar")), {"$"})
        self.assertEqual(_field_values("scalar"), [("$", "scalar")])

    def test_json_path_normalization_handles_root_array_paths(self):
        self.assertTrue(_paths_equivalent("$[1].content[0].text", "[1].content[0].text"))

    def test_python_handler_dependency_return_to_tool_result(self):
        spec = _python_spec()
        traces = _rows({"structuredContent": {"derived_value": "uid=0"}}, {"structuredContent": {"status": "blocked"}})
        model = build_effect_model(spec, traces)
        self.assertEqual(model["status"], "GENERATED")
        self.assertTrue(all("effect_role" in item and "effect_realization" in item and "propagation" in item for item in model["effects"]))
        graph = build_cross_layer_graph(spec, model, traces)
        self.assertIn(graph["status"], {"COMPLETE", "PARTIAL"})
        self.assertTrue(any(node["kind"] == "function" and node.get("side") in {"vulnerable", "both"} for node in graph["nodes"]))
        self.assertTrue(any(edge["kind"] == "DATA" and "effect-value-1" in edge["effect_ids"] for edge in graph["edges"]))
        self.assertTrue(any(edge["kind"] == "OBSERVE" and edge["dynamic_provenance"] for edge in graph["edges"]))
        dependency_edges = [
            edge for edge in graph["edges"]
            if edge["kind"] == "CALL" and edge.get("field_mapping", {}).get("dependency_api_identity") == "dangerlib.execute"
        ]
        self.assertTrue(dependency_edges)
        self.assertTrue(all(edge["field_mapping"].get("caller_source_path") == "server.py" for edge in dependency_edges))
        self.assertTrue(all(edge["field_mapping"].get("caller_line") for edge in dependency_edges))
        self.assertTrue(all(edge["field_mapping"].get("dependency_purl") == "pkg:pypi/dangerlib" for edge in dependency_edges))
        self.assertFalse(validate_cross_layer_graph(graph, effect_model=model), graph["graph_validation"])

    def test_graph_effect_nodes_preserve_role_realization_and_carrier_projection(self):
        spec = _python_spec()
        traces = _rows({"structuredContent": {"derived_value": "uid=0"}}, {"structuredContent": {"status": "blocked"}})
        model = build_effect_model(spec, traces)
        graph = build_cross_layer_graph(spec, model, traces)
        effect_nodes = [node for node in graph["nodes"] if node["kind"] == "effect_instance"]
        self.assertTrue(effect_nodes)
        self.assertTrue(all(node.get("effect_role") in {"INTERMEDIATE", "TERMINAL", "BOTH"} for node in effect_nodes))
        self.assertTrue(all(isinstance(node.get("effect_realization"), dict) for node in effect_nodes))
        self.assertTrue(any(relation.get("provenance_status") for relation in graph["effect_relations"]))

    def test_graph_preserves_dropped_propagation_without_l4_visibility(self):
        spec = _python_spec()
        traces = _rows({"structuredContent": {"derived_value": "uid=0"}}, {"structuredContent": {"status": "blocked"}})
        for row in traces["vulnerable"]:
            if row["level"] == "L2_HOST_PROCESSED_TOOL_RESULT":
                row["filtering"] = {"field": "structuredContent.derived_value", "action": "drop"}
        model = build_effect_model(spec, traces)
        graph = build_cross_layer_graph(spec, model, traces)
        effect_nodes = [node for node in graph["nodes"] if node["kind"] == "effect_instance"]
        self.assertTrue(any(node.get("propagation", {}).get("host") == "DROPPED" for node in effect_nodes))
        self.assertTrue(all(node.get("propagation", {}).get("agent_observation") != "REACHED" for node in effect_nodes))

    def test_static_slice_excludes_unrelated_functions(self):
        spec = _python_spec()
        for side in ("vulnerable", "fixed"):
            spec["source"][side][0]["content"] += "\ndef unrelated_helper(secret):\n    return secret\n"
        traces = _rows({"structuredContent": {"derived_value": "uid=0"}}, {"structuredContent": {"status": "blocked"}})
        model = build_effect_model(_python_spec(), traces)
        graph = build_cross_layer_graph(spec, model, traces)
        self.assertFalse(any(node.get("source", {}).get("symbol") == "unrelated_helper" for node in graph["nodes"]))

    def test_typescript_tool_binding_and_return_serialization(self):
        spec = _python_spec()
        spec["tool"]["name"] = "probe"
        spec["source"] = {
            "vulnerable": [{"path": "server.ts", "content": "export const probe = async (command: string) => { return axios.get(command); };\nserver.tool('probe', schema, probe);"}],
            "fixed": [{"path": "server.ts", "content": "export const probe = async (command: string) => { if (command.includes('|')) throw Error('blocked'); return axios.get(command); };\nserver.tool('probe', schema, probe);"}],
        }
        spec["experiment_type"] = "SSRF_WITH_RESPONSE_OR_METADATA"
        spec["patch"] = {"unified_diff": "--- a/server.ts\n+++ b/server.ts\n@@ -1 +1 @@\n-export const probe = async (command: string) => { return axios.get(command); };\n+export const probe = async (command: string) => { if (command.includes('|')) throw Error('blocked'); return axios.get(command); };\n"}
        traces = _rows({"content": [{"type": "text", "text": "loopback"}], "structuredContent": {"response_metadata": "loopback"}}, {"content": [{"type": "text", "text": "blocked"}], "structuredContent": {"status": "blocked"}})
        model = build_effect_model(spec, traces)
        self.assertEqual(model["status"], "GENERATED")
        graph = build_cross_layer_graph(spec, model, traces)
        self.assertTrue(any(node["kind"] == "mcp_tool" and node.get("tool_name") == "probe" for node in graph["nodes"]))
        self.assertTrue(any(edge["kind"] == "BIND" and edge["static_provenance"] for edge in graph["edges"]))
        self.assertTrue(any(edge["kind"] in {"SERIALIZE", "DESERIALIZE"} for edge in graph["edges"]))
        self.assertTrue(any("$.content" in node.get("field_paths", []) for node in graph["nodes"]))
        self.assertTrue(any("$.structuredContent" in node.get("field_paths", []) for node in graph["nodes"]))
        self.assertTrue(any(edge.get("field_mapping", {}).get("source_jsonpaths") for edge in graph["edges"] if edge["dynamic_provenance"]))

    def test_typescript_inline_tool_handler_precedes_schema_calls(self):
        spec = _python_spec()
        spec["source"] = {
            "vulnerable": [{"path": "server.ts", "content": "server.tool('probe', { limit: z.number() }, async ({ limit }) => { return axios.get(String(limit)); });"}],
            "fixed": [{"path": "server.ts", "content": "server.tool('probe', { limit: z.number() }, async ({ limit }) => { return axios.get(String(limit)); });"}],
        }
        nodes, edges = {}, {}
        static = _typescript_static(spec, "vulnerable", nodes, edges, [])
        self.assertIn("probe", static["handlers"])
        self.assertTrue(static["returns"].get("probe"))
        self.assertFalse(any(edge.get("unresolved_reason") == "inline TypeScript handler symbol unresolved" for edge in edges.values()))

    def test_l4_requires_actual_model_request_and_validator_fails_closed(self):
        spec = _python_spec()
        traces = _rows({"structuredContent": {"derived_value": "uid=0"}}, {"structuredContent": {"status": "blocked"}}, model_request=False)
        model = build_effect_model(spec, traces)
        graph = build_cross_layer_graph(spec, model, traces)
        self.assertFalse(any(node["kind"] == "exact_l4_content_block" for node in graph["nodes"]))
        bad = copy.deepcopy(graph)
        bad["edges"].append({"edge_id": "duplicate", "source": "missing", "target": "missing", "kind": "OBSERVE", "side": "vulnerable", "field_mapping": {}, "effect_ids": [], "evidence_refs": [], "confidence": 1.0, "dynamic_provenance": True})
        self.assertTrue(validate_cross_layer_graph(bad, effect_model=model))

    def test_host_normalize_session_and_exact_l4_chain(self):
        spec = _python_spec()
        traces = _rows({"content": [{"type": "text", "text": "derived"}], "structuredContent": {"derived_value": "uid=0"}}, {"content": [{"type": "text", "text": "blocked"}], "structuredContent": {"status": "blocked"}})
        model = build_effect_model(spec, traces)
        graph = build_cross_layer_graph(spec, model, traces)
        kinds = {node["kind"] for node in graph["nodes"]}
        self.assertTrue({"json_rpc_field", "host_normalized_field", "session_event", "model_request_message", "exact_l4_content_block"}.issubset(kinds))
        dynamic_edges = [edge for edge in graph["edges"] if edge["dynamic_provenance"]]
        self.assertTrue({"DESERIALIZE", "TRANSFORM", "SERIALIZE", "OBSERVE"}.issubset({edge["kind"] for edge in dynamic_edges}))
        self.assertTrue(all(edge["field_mapping"].get("source_jsonpaths") or edge.get("unresolved_reason") for edge in dynamic_edges))

    def test_control_effect_branch_and_exception_are_attributed(self):
        spec = _python_spec()
        traces = _rows({"structuredContent": {"derived_value": "uid=0"}}, {"structuredContent": {"status": "blocked"}})
        traces["vulnerable"][2]["event"] = {"function": "subprocess.check_output", "location": "server.py:5", "arguments": {"command": "id | whoami"}, "return": {"stdout": "uid=0"}}
        traces["fixed"][2]["event"] = {"function": "probe", "location": "server.py:5", "error": {"type": "ValueError"}}
        model = build_effect_model(spec, traces)
        graph = build_cross_layer_graph(spec, model, traces)
        self.assertTrue(any(node["kind"] == "branch" for node in graph["nodes"]))
        self.assertTrue(any(edge["kind"] == "CONTROL" for edge in graph["edges"]))
        self.assertTrue(any(node["kind"] == "exception" and node["dynamically_observed"] for node in graph["nodes"]))

    def test_resource_effect_has_explicit_write_read_result_chain(self):
        spec = _python_spec()
        traces = _rows({"structuredContent": {"file_content": "secret"}}, {"structuredContent": {"status": "blocked"}})
        traces["vulnerable"][2]["event"] = {"operation": "write", "state_write": True, "resource_id": "fixture-resource", "function": "open", "location": "server.py:5"}
        traces["vulnerable"][3]["event"] = {"operation": "read", "state_read": True, "resource_id": "fixture-resource", "function": "readback", "return": {"content": "secret"}}
        model = build_effect_model(spec, traces)
        graph = build_cross_layer_graph(spec, model, traces)
        self.assertTrue(any(edge["kind"] == "STATE_WRITE" for edge in graph["edges"]))
        self.assertTrue(any(edge["kind"] == "STATE_READ" for edge in graph["edges"]))
        self.assertTrue(any(edge["kind"] == "STATE_READ" and edge.get("dynamic_provenance") and edge.get("field_mapping", {}).get("resource_id") for edge in graph["edges"]))
        self.assertTrue(any(edge["kind"] == "DATA" and "effect-value-1" in edge["effect_ids"] for edge in graph["edges"]))
        resource_edges = [edge for edge in graph["edges"] if edge["side"] == "vulnerable" and edge["kind"] in {"STATE_WRITE", "STATE_READ"}]
        self.assertTrue(resource_edges)
        write_ids = {effect_id for edge in resource_edges if edge["kind"] == "STATE_WRITE" for effect_id in edge["effect_ids"]}
        read_ids = {effect_id for edge in resource_edges if edge["kind"] == "STATE_READ" for effect_id in edge["effect_ids"]}
        self.assertEqual(len(write_ids), 1)
        self.assertEqual(len(read_ids), 1)
        self.assertTrue(write_ids.isdisjoint(read_ids))
        self.assertTrue(all(edge["field_mapping"].get("source_jsonpaths") and edge["field_mapping"].get("target_jsonpaths") for edge in resource_edges))
        self.assertTrue(all("effect-value-1" in edge["effect_ids"] for edge in graph["edges"] if edge["kind"] == "DATA" and edge.get("field_mapping", {}).get("target_paths")))

    def test_unrelated_resource_event_is_not_attributed_to_target_effect(self):
        spec = _python_spec()
        traces = _rows({"structuredContent": {"file_content": "secret"}}, {"structuredContent": {"status": "blocked"}})
        traces["vulnerable"][2]["event"] = {"operation": "read", "state_read": True, "resource_id": "target", "function": "read_target", "location": "server.py:5", "return": {"content": "secret"}}
        traces["vulnerable"][3]["event"] = {"operation": "read", "state_read": True, "resource_id": "unrelated", "function": "read_other", "location": "server.py:6", "return": {"content": "other"}}
        traces["fixed"][2]["event"] = {"operation": "blocked", "function": "probe", "location": "server.py:5", "error": {"type": "ValueError"}}
        model = build_effect_model(spec, traces)
        graph = build_cross_layer_graph(spec, model, traces)
        effects = [item for item in model["effects"] if item["effect_kind"] == "RESOURCE_EFFECT"]
        self.assertGreaterEqual(len(effects), 2)
        event_nodes = [node for node in graph["nodes"] if node["side"] == "vulnerable" and node["kind"] == "resource_event"]
        self.assertGreaterEqual(len(event_nodes), 2)
        for node in event_nodes:
            self.assertEqual(len(node["effect_ids"]), 1)
        self.assertTrue(validate_cross_layer_graph(graph, effect_model=model) == [], graph["graph_validation"])

    def test_explicit_field_transformation_is_preserved_per_effect(self):
        spec = _python_spec()
        traces = _rows({"structuredContent": {"derived_value": "uid=0"}}, {"structuredContent": {"status": "blocked"}})
        for row in traces["vulnerable"]:
            if row["level"] == "L4_MODEL_VISIBLE_OBSERVATION":
                row["content"] = {"structuredContent": {"renamed_value": "uid=0"}}
                row["model_request"]["messages"][0]["content"] = row["content"]
                row["transformation"] = {
                    "input": ["structuredContent.derived_value"],
                    "output": ["structuredContent.renamed_value"],
                    "rule": "host-field-rename",
                    "evidence_refs": ["trace:vulnerable:host-field-rename"],
                    "input_fingerprints": [hashlib.sha256(json.dumps("uid=0", ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()).hexdigest()],
                    "output_fingerprints": [hashlib.sha256(json.dumps("uid=0", ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()).hexdigest()],
                }
        model = build_effect_model(spec, _rows({"structuredContent": {"derived_value": "uid=0"}}, {"structuredContent": {"status": "blocked"}}))
        graph = build_cross_layer_graph(spec, model, traces)
        transformed = [edge for edge in graph["edges"] if edge.get("status") == "TRANSFORMED" and "effect-value-1" in edge.get("effect_ids", [])]
        self.assertTrue(transformed)
        self.assertTrue(all(edge.get("transformation", {}).get("rule") == "host-field-rename" for edge in transformed))
        self.assertFalse(validate_cross_layer_graph(graph, effect_model=model), graph["graph_validation"])

    def test_explicit_host_filter_is_dropped_and_attributed(self):
        spec = _python_spec()
        source_traces = _rows({"structuredContent": {"derived_value": "uid=0"}}, {"structuredContent": {"status": "blocked"}})
        model = build_effect_model(spec, source_traces)
        traces = copy.deepcopy(source_traces)
        for row in traces["vulnerable"]:
            if row["level"] in {"L3_SESSION_TOOL_RESULT", "L4_MODEL_VISIBLE_OBSERVATION"}:
                row["content"] = {"structuredContent": {"status": "filtered"}}
                row["filtering"] = {"field": "structuredContent.derived_value", "action": "drop"}
                if row["level"] == "L4_MODEL_VISIBLE_OBSERVATION":
                    row["model_request"]["messages"][0]["content"] = row["content"]
        graph = build_cross_layer_graph(spec, model, traces)
        filtered = [edge for edge in graph["edges"] if edge["kind"] == "FILTERS" and edge["status"] == "DROPPED"]
        self.assertTrue(filtered)
        self.assertTrue(any("effect-value-1" in edge["effect_ids"] for edge in filtered))
        self.assertFalse(validate_cross_layer_graph(graph, effect_model=model), graph["graph_validation"])

    def test_missing_filter_evidence_is_unassessed_not_filtered(self):
        spec = _python_spec()
        source_traces = _rows({"structuredContent": {"derived_value": "uid=0"}}, {"structuredContent": {"status": "blocked"}})
        model = build_effect_model(spec, source_traces)
        traces = copy.deepcopy(source_traces)
        for row in traces["vulnerable"]:
            if row["level"] in {"L3_SESSION_TOOL_RESULT", "L4_MODEL_VISIBLE_OBSERVATION"}:
                row["content"] = {"structuredContent": {"status": "ordinary"}}
                if row["level"] == "L4_MODEL_VISIBLE_OBSERVATION":
                    row["model_request"]["messages"][0]["content"] = row["content"]
        graph = build_cross_layer_graph(spec, model, traces)
        effect_edges = [edge for edge in graph["edges"] if "effect-value-1" in edge.get("effect_ids", []) and edge.get("dynamic_provenance")]
        self.assertTrue(any(edge["status"] == "UNASSESSED" for edge in effect_edges))
        self.assertFalse(any(edge["kind"] in {"FILTER", "FILTERS"} or edge["status"] == "DROPPED" for edge in effect_edges))
        self.assertNotEqual(graph["effect_path_status"]["effect-value-1"]["status"], "COMPLETE")
        self.assertFalse(validate_cross_layer_graph(graph, effect_model=model), graph["graph_validation"])

    def test_input_echo_does_not_create_effect_propagation(self):
        spec = _python_spec()
        traces = _rows({"command": "id | whoami"}, {"command": "id"})
        model = build_effect_model(spec, traces)
        self.assertEqual(model["status"], "UNASSESSED")
        graph = build_cross_layer_graph(spec, model, traces)
        self.assertEqual(graph["status"], "UNASSESSED")
        self.assertFalse(graph["edges"])

    def test_external_sink_without_tool_provenance_cannot_reach_l4(self):
        spec = _python_spec()
        traces = _rows({"external_state": "proxy-response"}, {"external_state": "none"})
        for side in traces.values():
            for row in side:
                if row["level"] in {"L2_HOST_PROCESSED_TOOL_RESULT", "L3_SESSION_TOOL_RESULT"}:
                    row["content"] = {"external_state": "proxy-response"}
                elif row["level"] == "L4_MODEL_VISIBLE_OBSERVATION":
                    row["content"] = {"observation": "ordinary completion"}
                    row.pop("model_request", None)
                    row.pop("tool_message", None)
                else:
                    row["content"] = {"external_state": "proxy-response"}
        model = build_effect_model(spec, traces)
        self.assertEqual(model["status"], "UNASSESSED")
        graph = build_cross_layer_graph(spec, model, traces)
        self.assertEqual(graph["status"], "UNASSESSED")
        self.assertFalse(any(node["kind"] == "exact_l4_content_block" for node in graph["nodes"]))

    def test_static_reachability_is_distinct_from_dynamic_observation(self):
        spec = _python_spec()
        traces = _rows({"structuredContent": {"derived_value": "uid=0"}}, {"structuredContent": {"status": "blocked"}}, model_request=False)
        model = build_effect_model(spec, traces)
        graph = build_cross_layer_graph(spec, model, traces)
        observation = graph["effect_observation"]["effect-value-1"]
        self.assertTrue(observation["statically_reachable"])
        self.assertTrue(observation["dynamically_observed"])
        self.assertFalse(observation["exact_l4_observed"])
        self.assertEqual(observation["observed_repetitions"], [1])

    def test_unlinked_l4_carrier_path_is_transport_only(self):
        spec = _python_spec()
        traces = _rows({"structuredContent": {"derived_value": "uid=0"}}, {"structuredContent": {"status": "blocked"}})
        traces["vulnerable"][-1]["content"] = {"structuredContent": {"derived_value": "unrelated"}}
        traces["vulnerable"][-1]["model_request"]["messages"][0]["content"] = traces["vulnerable"][-1]["content"]
        model = build_effect_model(spec, traces)
        graph = build_cross_layer_graph(spec, model, traces)
        observed = graph["effect_observation"]["effect-value-1"]["by_side"]["vulnerable"]
        self.assertTrue(observed["transport_observed"])
        self.assertTrue(observed["effect_carrier_observed"])
        self.assertFalse(observed["exact_l4_observed"])

    def test_same_repetition_interleaved_tool_calls_have_independent_nodes(self):
        spec = _python_spec()
        rows = {"vulnerable": [], "fixed": []}
        order = [
            ("L0_RAW_MCP_RESULT", "call-a", "a"),
            ("L0_RAW_MCP_RESULT", "call-b", "b"),
            ("L1_NORMALIZED_TOOL_RESULT", "call-b", "b"),
            ("L1_NORMALIZED_TOOL_RESULT", "call-a", "a"),
            ("L2_HOST_PROCESSED_TOOL_RESULT", "call-a", "a"),
            ("L2_HOST_PROCESSED_TOOL_RESULT", "call-b", "b"),
            ("L3_SESSION_TOOL_RESULT", "call-b", "b"),
            ("L3_SESSION_TOOL_RESULT", "call-a", "a"),
            ("L4_MODEL_VISIBLE_OBSERVATION", "call-a", "a"),
            ("L4_MODEL_VISIBLE_OBSERVATION", "call-b", "b"),
        ]
        for side in ("vulnerable", "fixed"):
            for level, call_id, value in order:
                payload = {"structuredContent": {"derived_value": "uid=0" if value == "a" else "other"}}
                row = {"level": level, "content": payload, "repetition": 1, "tool_call_id": call_id, "trace_id": "trace:shared:1", "span_id": f"span:{call_id}"}
                if level == "L4_MODEL_VISIBLE_OBSERVATION":
                    row["actual_next_model_request"] = True
                    row["model_request"] = {"messages": [{"role": "tool", "tool_call_id": call_id, "content": payload}]}
                rows[side].append(row)
        model = build_effect_model(spec, _rows({"structuredContent": {"derived_value": "uid=0"}}, {"status": "blocked"}))
        graph = build_cross_layer_graph(spec, model, rows)
        calls = [node for node in graph["nodes"] if node["side"] == "vulnerable" and node["kind"] == "tool_call"]
        l4 = [node for node in graph["nodes"] if node["side"] == "vulnerable" and node["kind"] == "exact_l4_content_block"]
        self.assertEqual(len(calls), 2)
        self.assertEqual(len(l4), 2)
        self.assertEqual({node["dynamic"]["call_key"] for node in l4}, {"tool_call_id:call-a", "tool_call_id:call-b"})
        self.assertFalse(any(edge.get("field_mapping", {}).get("call_key") == "tool_call_id:call-a" and edge.get("field_mapping", {}).get("call_key") == "tool_call_id:call-b" for edge in graph["edges"]))

    def test_same_trace_without_call_ids_is_split_or_unresolved(self):
        spec = _python_spec()
        rows = {"vulnerable": [], "fixed": []}
        for side in rows:
            for call_id, value in (("a", "uid=0"), ("b", "other")):
                for level in ("L0_RAW_MCP_RESULT", "L1_NORMALIZED_TOOL_RESULT", "L2_HOST_PROCESSED_TOOL_RESULT", "L3_SESSION_TOOL_RESULT"):
                    rows[side].append({
                        "level": level,
                        "content": {"structuredContent": {"derived_value": value}},
                        "repetition": 1,
                        "trace_id": "trace:shared:1",
                        "span_id": f"span:{call_id}:{level}",
                    })
                row = {
                    "level": "L4_MODEL_VISIBLE_OBSERVATION",
                    "content": {"structuredContent": {"derived_value": value}},
                    "repetition": 1,
                    "trace_id": "trace:shared:1",
                    "span_id": f"span:{call_id}:L4",
                    "actual_next_model_request": True,
                    "model_request": {"messages": [{"role": "tool", "content": {"structuredContent": {"derived_value": value}}}]},
                }
                rows[side].append(row)
        model = build_effect_model(spec, _rows({"structuredContent": {"derived_value": "uid=0"}}, {"status": "blocked"}))
        graph = build_cross_layer_graph(spec, model, rows)
        self.assertNotEqual(graph["status"], "COMPLETE")
        self.assertTrue(any("ambiguous" in str(item).lower() or "unresolved" in str(item).lower() for item in graph.get("diagnostic_unresolved_boundaries", [])))
        tool_calls = [node for node in graph["nodes"] if node.get("side") == "vulnerable" and node.get("kind") == "tool_call"]
        self.assertGreater(len(tool_calls), 1)

    def test_ambiguous_unqualified_tool_messages_remain_unresolved(self):
        spec = _python_spec()
        traces = _rows({"structuredContent": {"derived_value": "uid=0"}}, {"structuredContent": {"status": "blocked"}})
        traces["vulnerable"][-1]["model_request"]["messages"].append({"role": "tool", "content": traces["vulnerable"][-1]["content"]})
        model = build_effect_model(spec, traces)
        graph = build_cross_layer_graph(spec, model, traces)
        self.assertNotEqual(graph["effect_path_status"]["effect-value-1"]["status"], "COMPLETE")
        self.assertTrue(any("ambiguous" in str(item).lower() for item in graph["effect_path_status"]["effect-value-1"].get("breakpoints", [])) or any("ambiguous" in str(item).lower() for item in graph.get("diagnostic_unresolved_boundaries", [])))

    def test_l4_edge_without_intermediate_causal_boundary_is_not_complete(self):
        spec = _python_spec()
        complete = _rows({"structuredContent": {"derived_value": "uid=0"}}, {"structuredContent": {"status": "blocked"}})
        model = build_effect_model(spec, complete)
        broken = copy.deepcopy(complete)
        broken["vulnerable"] = [row for row in broken["vulnerable"] if row["level"] != "L1_NORMALIZED_TOOL_RESULT"]
        graph = build_cross_layer_graph(spec, model, broken)
        path = graph["effect_path_status"]["effect-value-1"]
        self.assertNotEqual(path["status"], "COMPLETE")
        self.assertIn("L0_RAW_MCP_RESULT->L1_NORMALIZED_TOOL_RESULT", path["missing_boundaries"])
        self.assertTrue(any("evidence edge is missing" in item for item in path["breakpoints"]))

    def test_fixed_side_complete_chain_cannot_complete_vulnerable_effect(self):
        spec = _python_spec()
        traces = _rows({"structuredContent": {"derived_value": "uid=0"}}, {"structuredContent": {"derived_value": "safe"}})
        model = build_effect_model(spec, traces)
        broken = copy.deepcopy(traces)
        broken["vulnerable"] = [row for row in broken["vulnerable"] if row["level"] != "L1_NORMALIZED_TOOL_RESULT"]
        graph = build_cross_layer_graph(spec, model, broken)
        path = graph["effect_path_status"]["effect-value-1"]
        self.assertNotEqual(path["status"], "COMPLETE")
        self.assertIn("L0_RAW_MCP_RESULT->L1_NORMALIZED_TOOL_RESULT", path["missing_boundaries"])

    def test_continuous_path_requires_anchor_and_carrier_edges(self):
        spec = _python_spec()
        traces = _rows({"structuredContent": {"derived_value": "uid=0"}}, {"structuredContent": {"status": "blocked"}})
        model = build_effect_model(spec, traces)
        graph = build_cross_layer_graph(spec, model, traces)
        nodes = {node["node_id"]: node for node in graph["nodes"]}
        edges = {edge["edge_id"]: edge for edge in graph["edges"] if not (edge["kind"] == "PRODUCES" and "effect-value-1" in edge.get("effect_ids", []))}
        stage4_effect = next(item for item in inspect_l4_effect(model, traces["vulnerable"])["effects"] if item["effect_id"] == "effect-value-1")
        result = _continuous_effect_path("effect-value-1", nodes, edges, stage4_effect)
        self.assertNotEqual(result["status"], "COMPLETE")
        self.assertIn("vulnerability anchor -> effect production", result["missing_boundaries"])

    def test_vulnerable_fixed_repair_cutpoint_is_recorded(self):
        spec = _python_spec()
        traces = _rows({"structuredContent": {"derived_value": "uid=0"}}, {"structuredContent": {"status": "blocked"}})
        model = build_effect_model(spec, traces)
        graph = build_cross_layer_graph(spec, model, traces)
        repair = graph["repair_alignment"]
        self.assertIn("predicate", repair)
        self.assertIn("cutpoint_edges", repair)
        self.assertIn("fixed_replacement_edges", repair)
        self.assertEqual(repair["status"], "SUPPORTED")

    def test_missing_stage2_model_is_unassessed(self):
        graph = build_cross_layer_graph(_python_spec(), {"schema_version": "vulveil-effect-model/v1", "status": "UNASSESSED", "effects": []}, {"vulnerable": [], "fixed": []})
        self.assertEqual(graph["status"], "UNASSESSED")
        self.assertEqual(graph["graph_validation"]["status"], "UNASSESSED")

    def test_legacy_v2_graph_is_rejected_with_migration_reason(self):
        spec = _python_spec()
        traces = _rows({"structuredContent": {"derived_value": "uid=0"}}, {"structuredContent": {"status": "blocked"}})
        model = build_effect_model(spec, traces)
        graph = build_cross_layer_graph(spec, model, traces)
        graph["schema_version"] = "vulveil-cross-layer-graph/v2"
        errors = validate_cross_layer_graph(graph, effect_model=model)
        self.assertTrue(any("legacy v2" in item and "incompatible" in item for item in errors))

    def test_unresolved_language_or_sdk_is_partial(self):
        spec = _python_spec()
        spec["source"] = {"vulnerable": [{"path": "server.java", "content": "class Server {}"}], "fixed": [{"path": "server.java", "content": "class Server {}"}]}
        traces = _rows({"derived_value": "uid=0"}, {"status": "blocked"})
        model = build_effect_model(_python_spec(), _rows({"structuredContent": {"derived_value": "uid=0"}}, {"structuredContent": {"status": "blocked"}}))
        graph = build_cross_layer_graph(spec, model, traces)
        self.assertIn(graph["status"], {"PARTIAL", "UNASSESSED"})
        self.assertTrue(graph["unresolved_boundaries"])

    def test_fixed_invalid_run_is_not_treated_as_patch_blocking(self):
        spec = _python_spec()
        traces = _rows({"structuredContent": {"derived_value": "uid=0"}}, {"structuredContent": {"status": "blocked"}})
        model = build_effect_model(spec, traces)
        graph = build_cross_layer_graph(spec, model, traces, vulnerable_results=[{"repetition": 1, "valid": True}], fixed_results=[{"repetition": 1, "valid": False, "timed_out": False}])
        self.assertEqual(graph["status"], "INVALID")
        self.assertEqual(graph["repair_alignment"]["status"], "UNRESOLVED")

    def test_validator_rejects_fake_l4_missing_evidence_and_gt_content(self):
        spec = _python_spec()
        traces = _rows({"structuredContent": {"derived_value": "uid=0"}}, {"structuredContent": {"status": "blocked"}})
        model = build_effect_model(spec, traces)
        graph = build_cross_layer_graph(spec, model, traces)
        fake = copy.deepcopy(graph)
        fake_id = "fake-l4"
        fake["nodes"].append({"node_id": fake_id, "layer": "AGENT_OBSERVATION", "kind": "exact_l4_content_block", "side": "vulnerable", "identity": fake_id, "effect_ids": [], "model_request": True, "dynamic": {"json_paths": ["$.text"]}})
        fake["edges"].append({"edge_id": "no-evidence", "source": fake_id, "target": fake_id, "kind": "OBSERVE", "side": "vulnerable", "field_mapping": {}, "effect_ids": [], "evidence_refs": [], "confidence": 1.0, "dynamic_provenance": False})
        fake["case_identity"]["leak"] = "GT-999"
        errors = validate_cross_layer_graph(fake, effect_model=model)
        self.assertTrue(any("L4" in error for error in errors))
        self.assertTrue(any("evidence" in error for error in errors))
        self.assertTrue(any("GT" in error for error in errors))

    def test_graph_validator_rejects_unknown_effect_relation_endpoint(self):
        spec = _python_spec()
        traces = _rows({"structuredContent": {"derived_value": "uid=0"}}, {"structuredContent": {"status": "blocked"}})
        model = build_effect_model(spec, traces)
        graph = build_cross_layer_graph(spec, model, traces)
        graph["effect_relations"].append({"from": "missing-effect", "to": "effect-value-1", "relation": "PRODUCES", "evidence_refs": ["test"]})
        self.assertTrue(any("unknown effect ID" in error for error in validate_cross_layer_graph(graph, effect_model=model)))


if __name__ == "__main__":
    unittest.main()
