from __future__ import annotations
import argparse
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from shared_host_runner import evidence_rows, run_shared_host_case
PROXY_SIGNAL = 'GH_P3_124_PROXY_RESPONSE_READBACK'
DIRECT_SIGNAL = 'GH_P3_124_DIRECT_RESPONSE_READBACK'
TARGET_PORT = 18131
PROXY_PORT = 18132

class Boundary:

    def __init__(self) -> None:
        self.requests: list[dict[str, Any]] = []
        boundary = self

        class TargetHandler(BaseHTTPRequestHandler):

            def do_GET(self) -> None:
                boundary.requests.append({'role': 'target', 'method': self.command, 'path': self.path, 'headers': dict(self.headers)})
                response = json.dumps([{'id': 1, 'name': DIRECT_SIGNAL, 'is4k': False, 'isDefault': True}], separators=(',', ':')).encode()
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(response)))
                self.end_headers()
                self.wfile.write(response)

            def log_message(self, *_args: object) -> None:
                return

        class ProxyHandler(BaseHTTPRequestHandler):

            def do_GET(self) -> None:
                boundary.requests.append({'role': 'proxy', 'method': self.command, 'path': self.path, 'headers': dict(self.headers)})
                response = json.dumps([{'id': 1, 'name': PROXY_SIGNAL, 'is4k': False, 'isDefault': True}], separators=(',', ':')).encode()
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(response)))
                self.end_headers()
                self.wfile.write(response)

            def log_message(self, *_args: object) -> None:
                return
        self.target = ThreadingHTTPServer(('127.0.0.1', TARGET_PORT), TargetHandler)
        self.proxy = ThreadingHTTPServer(('127.0.0.1', PROXY_PORT), ProxyHandler)
        self.threads = [threading.Thread(target=self.target.serve_forever, daemon=True), threading.Thread(target=self.proxy.serve_forever, daemon=True)]

    def start(self) -> None:
        for thread in self.threads:
            thread.start()

    def close(self) -> None:
        self.target.shutdown()
        self.proxy.shutdown()
        self.target.server_close()
        self.proxy.server_close()
        for thread in self.threads:
            thread.join(timeout=3)

    def snapshot(self) -> dict[str, Any]:
        return {'boundary': 'container-local-overseerr-target-and-http-proxy', 'target': f"""127.0.0.1:{TARGET_PORT}""", 'proxy': f"""127.0.0.1:{PROXY_PORT}""", 'requests': list(self.requests)}

def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')

def values(record: dict[str, Any]) -> dict[str, Any]:
    mcp = record.get('mcp', {})
    host = record.get('host', {})
    session = record.get('session', {})
    request = record.get('model', {}).get('next_request') or {}
    l4 = [message.get('content') for message in request.get('messages', []) if message.get('role') == 'tool']
    return {'L0_RAW_MCP_RESULT': mcp.get('raw_jsonrpc_response', mcp.get('raw_results')), 'L1_NORMALIZED_TOOL_RESULT': mcp.get('normalized_result', mcp.get('normalized_results')), 'L2_HOST_PROCESSED_TOOL_RESULT': host.get('tool_runtime_result'), 'L3_SESSION_TOOL_RESULT': session.get('tool_result', session.get('tool_results')), 'L4_MODEL_VISIBLE_OBSERVATION': l4}

def contains(value: Any, marker: str) -> bool:
    return marker in json.dumps(value, ensure_ascii=False, sort_keys=True)

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--spec', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--side', choices=('vulnerable', 'fixed'), required=True)
    parser.add_argument('--repetition', type=int, required=True)
    args = parser.parse_args()
    spec = json.loads(args.spec.read_text(encoding='utf-8'))
    boundary = Boundary()
    boundary.start()
    try:
        axios_version = '1.13.6' if args.side == 'vulnerable' else '1.15.0'
        source_root = Path(f"""/workspace/source-{args.side}""")
        env = {'SEERR_URL': f"""http://localhost.:{TARGET_PORT}""", 'SEERR_API_KEY': 'GH_P3_124_FROZEN_API_KEY_123456', 'HTTP_PROXY': f"""http://127.0.0.1:{PROXY_PORT}""", 'HTTPS_PROXY': f"""http://127.0.0.1:{PROXY_PORT}""", 'ALL_PROXY': '', 'NO_PROXY': 'localhost,127.0.0.1,::1', 'http_proxy': f"""http://127.0.0.1:{PROXY_PORT}""", 'https_proxy': f"""http://127.0.0.1:{PROXY_PORT}""", 'all_proxy': '', 'no_proxy': 'localhost,127.0.0.1,::1', 'PYTHONPATH': '/opt/gt', 'NODE_OPTIONS': '--no-warnings'}
        record = run_shared_host_case(run_id=f"""{spec['case_id']}-{args.side}-{args.repetition}""", case_id=spec['case_id'], revision=args.side, repetition=args.repetition, command=['node', str(source_root / 'build/index.js')], cwd=Path('/tmp'), env=env, server_name=spec['discovery']['repository_url'], tool_name=spec['mcp_path_review']['tool'], tool_arguments=spec['mcp_path_review']['tool_arguments'], task=spec['experiment']['agent_task'], system_prompt=spec['experiment']['system_prompt'], server_revision=f"""{spec['discovery']['repository_commit']}; axios=={axios_version}""", timeout=75)
        snapshot = boundary.snapshot()
        record['external_boundary'] = snapshot
        level_values = values(record)
        roles = [item.get('role') for item in snapshot['requests']]
        record['gh_p3_124_probe'] = {'effect_type': 'SSRF_WITH_RESPONSE_OR_METADATA', 'proxy_signal': PROXY_SIGNAL, 'direct_signal': DIRECT_SIGNAL, 'axios_version': axios_version, 'proxy_request_count': roles.count('proxy'), 'target_request_count': roles.count('target'), 'proxy_by_level': {level: contains(value, PROXY_SIGNAL) for level, value in level_values.items()}, 'direct_by_level': {level: contains(value, DIRECT_SIGNAL) for level, value in level_values.items()}, 'input_signal_absent': not any((marker in json.dumps(spec['mcp_path_review']['tool_arguments'], ensure_ascii=False) for marker in (PROXY_SIGNAL, DIRECT_SIGNAL)))}
        args.output.mkdir(parents=True, exist_ok=True)
        write_json(args.output / 'host_record.json', record)
        (args.output / 'evidence.jsonl').write_text(''.join((json.dumps(row, ensure_ascii=False) + '\n' for row in evidence_rows(record))), encoding='utf-8')
        write_json(args.output / 'boundary_snapshot.json', snapshot)
        valid = not record['quality']['invalid_run'] and all((value == 'observed' for value in record['evidence_levels'].values()))
        print(json.dumps({'status': 'OK' if valid else 'INVALID', 'output': str(args.output)}, ensure_ascii=False))
        return 0 if valid else 1
    finally:
        boundary.close()
if __name__ == '__main__':
    raise SystemExit(main())
