import unittest
import difflib
from pathlib import Path
from tempfile import TemporaryDirectory

from oscar.analysis.component_path import discover_component_tool_paths, validate_component_tool_path
from oscar.workflows.stage2_readiness import assess_case


def _patch(path: str, old: str, new: str) -> str:
    return "".join(difflib.unified_diff(
        old.splitlines(keepends=True), new.splitlines(keepends=True),
        fromfile=f"a/{path}", tofile=f"b/{path}", lineterm="\n",
    ))


def _python_discovery(root: Path, *, component: str = "target-pkg", origin: str = "MCP_FRAMEWORK",
                      patch: str | None = None, analysis_root: Path | None = None,
                      analysis_patch: str | None = None, tool: str = "probe") -> dict:
    analysis_patch = analysis_patch or patch
    return discover_component_tool_paths(
        root, "server.py", tool, component, origin, patch=patch,
        analysis_root=analysis_root or root, analysis_patch=analysis_patch,
    )


class ComponentPathTests(unittest.TestCase):
    def test_python_direct_call_is_patch_anchored(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            old = "def call(value):\n    return value\n"
            new = "def call(value):\n    return str(value)\n"
            (root / "server.py").write_text("from target_pkg import call\n\n@server.tool('probe')\ndef probe(value):\n    return call(value)\n", encoding="utf-8")
            (root / "target.py").write_text(old, encoding="utf-8")
            result = _python_discovery(root, patch=_patch("target.py", old, new))
        self.assertEqual(result["status"], "RESOLVED")
        self.assertFalse(validate_component_tool_path(result, component_name="target-pkg", tool_name="probe"))

    def test_python_cross_file_call_is_patch_anchored(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            old = "def call(value):\n    return value\n"
            new = "def call(value):\n    return str(value)\n"
            (root / "server.py").write_text("from .helper import forward\n\n@server.tool('probe')\ndef probe(value):\n    return forward(value)\n", encoding="utf-8")
            (root / "helper.py").write_text("from target_pkg import call\n\ndef forward(value):\n    return call(value)\n", encoding="utf-8")
            (root / "target.py").write_text(old, encoding="utf-8")
            result = _python_discovery(root, patch=_patch("target.py", old, new))
        self.assertEqual(result["status"], "RESOLVED")

    def test_server_self_handler_reaches_server_patch_anchor(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            old = "def vulnerable_call(value):\n    return value\n"
            new = "def vulnerable_call(value):\n    return str(value)\n"
            (root / "server.py").write_text("from .vuln import vulnerable_call\n\n@server.tool('probe')\ndef probe(value):\n    return vulnerable_call(value)\n", encoding="utf-8")
            (root / "vuln.py").write_text(old, encoding="utf-8")
            result = _python_discovery(root, origin="MCP_SERVER_SELF", component="server", patch=_patch("vuln.py", old, new))
        self.assertEqual(result["status"], "RESOLVED")

    def test_comment_and_string_component_names_do_not_form_paths(self):
        for body in (
            "# target_pkg is mentioned here\n\n@server.tool('probe')\ndef probe(value):\n    return value\n",
            "value = 'target_pkg'\n\n@server.tool('probe')\ndef probe(value):\n    return value\n",
        ):
            with self.subTest(body=body), TemporaryDirectory() as temporary:
                root = Path(temporary)
                old = "def call(value):\n    return value\n"
                new = "def call(value):\n    return str(value)\n"
                (root / "server.py").write_text(body, encoding="utf-8")
                (root / "target.py").write_text(old, encoding="utf-8")
                result = _python_discovery(root, patch=_patch("target.py", old, new))
                self.assertNotEqual(result["status"], "RESOLVED")

    def test_unused_import_does_not_form_path(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            old = "def call(value):\n    return value\n"
            new = "def call(value):\n    return str(value)\n"
            (root / "server.py").write_text("from target_pkg import call\n\n@server.tool('probe')\ndef probe(value):\n    return value\n", encoding="utf-8")
            (root / "target.py").write_text(old, encoding="utf-8")
            result = _python_discovery(root, patch=_patch("target.py", old, new))
        self.assertNotEqual(result["status"], "RESOLVED")

    def test_non_target_tool_does_not_satisfy_selected_tool(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            old = "def call(value):\n    return value\n"
            new = "def call(value):\n    return str(value)\n"
            (root / "server.py").write_text("from target_pkg import call\n\n@server.tool('other')\ndef other(value):\n    return call(value)\n\n@server.tool('probe')\ndef probe(value):\n    return value\n", encoding="utf-8")
            (root / "target.py").write_text(old, encoding="utf-8")
            result = _python_discovery(root, patch=_patch("target.py", old, new), tool="probe")
        self.assertNotEqual(result["status"], "RESOLVED")

    def test_same_name_local_function_does_not_shadow_component_call(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            old = "def call(value):\n    return value\n"
            new = "def call(value):\n    return str(value)\n"
            (root / "server.py").write_text("from target_pkg import call\n\n@server.tool('probe')\ndef probe(value):\n    def call(value):\n        return value\n    return call(value)\n", encoding="utf-8")
            (root / "target.py").write_text(old, encoding="utf-8")
            result = _python_discovery(root, patch=_patch("target.py", old, new))
        self.assertNotEqual(result["status"], "RESOLVED")

    def test_broken_cross_file_call_chain_is_unresolved(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            old = "def call(value):\n    return value\n"
            new = "def call(value):\n    return str(value)\n"
            (root / "server.py").write_text("from .missing import forward\n\n@server.tool('probe')\ndef probe(value):\n    return forward(value)\n", encoding="utf-8")
            (root / "target.py").write_text(old, encoding="utf-8")
            result = _python_discovery(root, patch=_patch("target.py", old, new))
        self.assertNotEqual(result["status"], "RESOLVED")

    def test_component_api_without_patch_anchor_is_unresolved(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = "def call(value):\n    return value\n\ndef unrelated(value):\n    return value\n"
            changed = "def call(value):\n    return value\n\ndef unrelated(value):\n    return str(value)\n"
            (root / "server.py").write_text("from target_pkg import call\n\n@server.tool('probe')\ndef probe(value):\n    return call(value)\n", encoding="utf-8")
            (root / "target.py").write_text(source, encoding="utf-8")
            result = _python_discovery(root, patch=_patch("target.py", source, changed))
        self.assertNotEqual(result["status"], "RESOLVED")

    def test_javascript_direct_and_cross_file_calls_are_structured(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            old = "export function call(value) { return value; }\n"
            new = "export function call(value) { return String(value); }\n"
            (root / "server.js").write_text('import { call } from "target-pkg";\nconst server = {};\nserver.tool("probe", (value) => { return call(value); });\n', encoding="utf-8")
            (root / "target.js").write_text(old, encoding="utf-8")
            direct = discover_component_tool_paths(root, "server.js", "probe", "target-pkg", "MCP_FRAMEWORK", analysis_root=root, analysis_patch=_patch("target.js", old, new))
            self.assertEqual(direct["status"], "RESOLVED")
            (root / "server.js").write_text('import { forward } from "./helper.js";\nconst server = {};\nserver.tool("probe", (value) => { return forward(value); });\n', encoding="utf-8")
            (root / "helper.js").write_text('import { call } from "target-pkg";\nexport function forward(value) { return call(value); }\n', encoding="utf-8")
            cross_file = discover_component_tool_paths(root, "server.js", "probe", "target-pkg", "MCP_FRAMEWORK", analysis_root=root, analysis_patch=_patch("target.js", old, new))
        self.assertEqual(cross_file["status"], "RESOLVED")
        self.assertFalse(validate_component_tool_path(cross_file, component_name="target-pkg", tool_name="probe"))

    def test_typescript_direct_call_is_patch_anchored(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            old = "export function call(value: string) { return value; }\n"
            new = "export function call(value: string) { return String(value); }\n"
            (root / "server.ts").write_text(
                'import { call } from "target-pkg";\nconst server = {};\n'
                'server.tool("probe", (value: string) => { return call(value); });\n',
                encoding="utf-8",
            )
            (root / "target.ts").write_text(old, encoding="utf-8")
            result = discover_component_tool_paths(
                root, "server.ts", "probe", "target-pkg", "MCP_FRAMEWORK",
                analysis_root=root, analysis_patch=_patch("target.ts", old, new),
            )
        self.assertEqual(result["status"], "RESOLVED")
        self.assertFalse(validate_component_tool_path(result, component_name="target-pkg", tool_name="probe"))

    def test_readiness_rejects_forged_reaches_component_flag(self):
        try:
            from test_component_origins import _component_spec
        except ImportError:
            from .test_component_origins import _component_spec

        spec = _component_spec("MCP_FRAMEWORK")
        spec["tool"] = {"name": "probe", "configuration": {"transport": "stdio"}}
        spec["server"]["tool"] = "probe"
        spec["runner"]["counterfactual_input_mode"] = "env-json/v1"
        spec["onboarding"] = {"tool_path_discovery": {
            "schema_version": "vulveil-tool-discovery/v2", "status": "RESOLVED", "language": "python",
            "component_name": "fixture-package", "tools": [{
                "tool": "probe", "handler": "probe", "source_ref": "server.py:1", "reaches_component": True,
                "component_paths": [{"call_chain": ["probe", "call"], "source_refs": ["server.py:1"], "anchor_refs": ["sdk.py:1"]}],
            }], "graph": {"nodes": [{"node_id": "python:tool:probe"}, {"node_id": "python:server.py:probe"}], "edges": [{"kind": "REGISTER", "from": "python:tool:probe", "to": "python:server.py:probe", "tool": "probe"}]},
        }}
        readiness = assess_case(spec, "forged-path")
        self.assertEqual(readiness["checks"]["tool_to_component_path"]["status"], "UNRESOLVED")
        self.assertFalse(readiness["status"] == "READY")

    def test_path_validator_rejects_complete_graph_with_undeclared_anchor(self):
        discovery = {
            "schema_version": "vulveil-tool-discovery/v2",
            "language": "python",
            "component_name": "fixture-package",
            "anchor_candidates": [{"name": "call", "refs": ["sdk.py:2"]}],
            "tools": [{
                "tool": "probe", "handler": "probe", "source_ref": "server.py:1",
                "reaches_component": True,
                "component_paths": [{
                    "call_chain": ["probe", "fixture.call"],
                    "component_call": "fixture.call",
                    "source_refs": ["server.py:4"],
                    "anchor_refs": ["forged.py:99"],
                }],
            }],
            "graph": {
                "nodes": [
                    {"node_id": "python:tool:probe", "kind": "tool_registration", "tool": "probe"},
                    {"node_id": "python:server.py:probe", "kind": "function", "symbol": "probe"},
                    {"node_id": "python:component:fixture.call", "kind": "component_api", "component_name": "fixture-package", "source_refs": ["server.py:4"]},
                    {"node_id": "python:anchor:forged.py:99", "kind": "patch_anchor", "component_name": "fixture-package", "anchor_ref": "forged.py:99"},
                ],
                "edges": [
                    {"from": "python:tool:probe", "to": "python:server.py:probe", "kind": "REGISTER", "tool": "probe"},
                    {"from": "python:server.py:probe", "to": "python:component:fixture.call", "kind": "COMPONENT_CALL", "tool": "probe", "source_refs": ["server.py:4"]},
                    {"from": "python:component:fixture.call", "to": "python:anchor:forged.py:99", "kind": "PATCH_ANCHOR", "tool": "probe", "anchor_ref": "forged.py:99", "source_refs": ["server.py:4"]},
                ],
            },
        }
        errors = validate_component_tool_path(discovery, component_name="fixture-package", tool_name="probe")
        self.assertTrue(any("anchor_candidates" in error for error in errors), errors)


if __name__ == "__main__":
    unittest.main()
