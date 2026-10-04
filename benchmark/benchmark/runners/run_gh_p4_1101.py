from __future__ import annotations
import argparse
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
import sys
sys.path.insert(0, '/opt/gt')
from shared_host_runner import evidence_rows, run_shared_host_case
CASE = 'GH-P4-1101'
REPO = 'https://github.com/infi-nithin/petstore-mcp-server'
TOOL = 'get_user_profile'
SPEC_PORT = 18621
BACKEND_PORT = 18622
EFFECT = 'ADMIN_READBACK_P4_1101'
FROZEN_INPUT = {'user_id': '../../../admin?'}
TASK = 'Call the frozen get_user_profile Tool and report only its returned result.'
OPENAPI_SPEC = {'openapi': '3.0.0', 'info': {'title': 'Controlled Petstore Profile API', 'version': '1.0.0'}, 'paths': {'/api/v1/users/{user_id}/profile': {'get': {'operationId': TOOL, 'parameters': [{'name': 'user_id', 'in': 'path', 'required': True, 'schema': {'type': 'string'}}], 'responses': {'200': {'description': 'Profile or controlled admin response', 'content': {'application/json': {'schema': {'type': 'object'}}}}}}}}}

class BoundaryState:

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.requests: list[dict[str, Any]] = []

    def snapshot(self) -> dict[str, Any]:
        with self.lock:
            return {'boundary': 'container-local-openapi-and-profile-backend', 'requests': list(self.requests)}

def json_response(handler: BaseHTTPRequestHandler, payload: dict[str, Any]) -> None:
    body = json.dumps(payload, sort_keys=True).encode('utf-8')
    handler.send_response(200)
    handler.send_header('Content-Type', 'application/json')
    handler.send_header('Content-Length', str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)

def start_boundaries(state: BoundaryState) -> tuple[ThreadingHTTPServer, ThreadingHTTPServer]:

    class SpecHandler(BaseHTTPRequestHandler):

        def do_GET(self) -> None:
            if self.path != '/openapi.json':
                self.send_error(404)
                return
            json_response(self, OPENAPI_SPEC)

        def log_message(self, *_args: object) -> None:
            return

    class BackendHandler(BaseHTTPRequestHandler):

        def do_GET(self) -> None:
            path = self.path.split('?', 1)[0]
            with state.lock:
                state.requests.append({'path': self.path, 'normalized_path': path, 'host': self.headers.get('Host', '')})
            if path == '/admin':
                json_response(self, {'status': 'admin', 'message': EFFECT})
            else:
                json_response(self, {'status': 'profile', 'route': path, 'message': 'PROFILE_BASELINE_P4_1101'})

        def log_message(self, *_args: object) -> None:
            return
    spec = ThreadingHTTPServer(('127.0.0.1', SPEC_PORT), SpecHandler)
    backend = ThreadingHTTPServer(('127.0.0.1', BACKEND_PORT), BackendHandler)
    threading.Thread(target=spec.serve_forever, daemon=True).start()
    threading.Thread(target=backend.serve_forever, daemon=True).start()
    return (spec, backend)

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--spec', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--side', choices=('vulnerable', 'fixed'), required=True)
    parser.add_argument('--repetition', type=int, required=True)
    args = parser.parse_args()
    spec = json.loads(args.spec.read_text(encoding='utf-8'))
    state = BoundaryState()
    spec_server, backend_server = start_boundaries(state)
    try:
        env = {'PYTHONPATH': '/workspace/source', 'P4_OPENAPI_SPEC_URL': f"""http://127.0.0.1:{SPEC_PORT}/openapi.json""", 'P4_BACKEND_BASE_URL': f"""http://127.0.0.1:{BACKEND_PORT}/"""}
        record = run_shared_host_case(run_id=f"""{CASE}-{args.side}-{args.repetition}""", case_id=CASE, revision=args.side, repetition=args.repetition, command=['python3', '/opt/runner/server_adapter.py'], cwd=Path('/workspace/source'), env=env, server_name=REPO, tool_name=TOOL, tool_arguments=spec['mcp_path']['frozen_argument'], task=spec['experiment']['agent_task'], system_prompt=spec['experiment']['system_prompt'], server_revision=f"""{spec['source_commit']}; fastmcp=={spec['versions'][args.side]}""", timeout=float(spec['runner']['timeout_seconds']))
        snapshot = state.snapshot()
        record['external_boundary'] = snapshot
        tool_json = json.dumps(record.get('mcp', {}).get('normalized_result', record.get('mcp', {}).get('normalized_results', {})), ensure_ascii=False)
        l4_json = json.dumps(record.get('model', {}).get('next_request', {}), ensure_ascii=False)
        record['p4_probe'] = {'input_excludes_effect': EFFECT not in json.dumps(FROZEN_INPUT, ensure_ascii=False), 'hidden_admin_request_observed': any((item.get('normalized_path') == '/admin' for item in snapshot['requests'])), 'derived_in_tool_result': EFFECT in tool_json, 'derived_in_l4': EFFECT in l4_json, 'actual_next_model_request': bool(record.get('model', {}).get('next_request'))}
        record['quality']['invalid_run'] = bool(record['quality'].get('invalid_run'))
        args.output.mkdir(parents=True, exist_ok=True)
        (args.output / 'host_record.json').write_text(json.dumps(record, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        (args.output / 'evidence.jsonl').write_text(''.join((json.dumps(row, ensure_ascii=False) + '\n' for row in evidence_rows(record))), encoding='utf-8')
        (args.output / 'boundary_snapshot.json').write_text(json.dumps(snapshot, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        valid = not record['quality']['invalid_run'] and all((value == 'observed' for value in record['evidence_levels'].values()))
        print(json.dumps({'status': 'OK' if valid else 'INVALID', 'output': str(args.output)}))
        return 0 if valid else 1
    finally:
        spec_server.shutdown()
        spec_server.server_close()
        backend_server.shutdown()
        backend_server.server_close()
if __name__ == '__main__':
    raise SystemExit(main())
