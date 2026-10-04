"""Run dkmaker/mcp-rest-api through the shared Host for Axios NO_PROXY replay."""
from __future__ import annotations
import argparse
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from shared_host_runner import evidence_rows, run_shared_host_case
CASE_ID = 'GH-P2-065'
SERVER_NAME = 'dkmaker/mcp-rest-api'
SOURCE_COMMIT = '765ecdfd9d125816686eff2651d3f2631b8c9be1'
VULNERABLE_AXIOS = '1.7.9'
FIXED_AXIOS = '1.15.0'
TOOL_NAME = 'test_request'
PROXY_MARKER = 'GH_P2_065_PROXY_RESPONSE_READBACK'
DIRECT_MARKER = 'GH_P2_065_DIRECT_TARGET_RESPONSE'
TASK = 'Call the frozen test_request Tool and report only its returned result.'
SYSTEM_PROMPT = 'You are a deterministic research host. Use the frozen tool call and report only its returned Tool result.'

class BoundaryHandler(BaseHTTPRequestHandler):
    server_version = 'GT-P2-065-HTTP-Boundary/1'

    def _record(self) -> dict[str, Any]:
        boundary = self.server
        item = {'method': self.command, 'path': self.path, 'headers': {key.lower(): value for key, value in self.headers.items()}}
        boundary.requests.append(item)
        return item

    def do_GET(self) -> None:
        item = self._record()
        boundary = self.server
        if boundary.kind == 'proxy':
            payload = {'source': 'controlled-proxy', 'marker': PROXY_MARKER, 'observed_url': item['path']}
        else:
            payload = {'source': 'direct-target', 'marker': DIRECT_MARKER, 'observed_path': item['path']}
        body = json.dumps(payload, separators=(',', ':')).encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args: object) -> None:
        return

class Boundary(ThreadingHTTPServer):
    allow_reuse_address = True

    def __init__(self, kind: str) -> None:
        super().__init__(('127.0.0.1', 0), BoundaryHandler)
        self.kind = kind
        self.requests: list[dict[str, Any]] = []

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--side', choices=('vulnerable', 'fixed'), required=True)
    parser.add_argument('--repetition', type=int, choices=(1, 2, 3), required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    proxy = Boundary('proxy')
    target = Boundary('target')
    proxy_thread = threading.Thread(target=proxy.serve_forever, daemon=True)
    target_thread = threading.Thread(target=target.serve_forever, daemon=True)
    proxy_thread.start()
    target_thread.start()
    axios_version = VULNERABLE_AXIOS if args.side == 'vulnerable' else FIXED_AXIOS
    target_port = target.server_address[1]
    proxy_port = proxy.server_address[1]
    env = {'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': '/tmp/gt-home', 'REST_BASE_URL': f"""http://127.0.0.1:{target_port}""", 'HTTP_PROXY': f"""http://127.0.0.1:{proxy_port}""", 'HTTPS_PROXY': f"""http://127.0.0.1:{proxy_port}""", 'ALL_PROXY': f"""http://127.0.0.1:{proxy_port}""", 'http_proxy': f"""http://127.0.0.1:{proxy_port}""", 'https_proxy': f"""http://127.0.0.1:{proxy_port}""", 'all_proxy': f"""http://127.0.0.1:{proxy_port}""", 'NO_PROXY': 'localhost,127.0.0.1', 'no_proxy': 'localhost,127.0.0.1', 'NODE_ENV': 'production'}
    command = ['node', f"""/opt/app/{args.side}/build/index.js"""]
    tool_arguments = {'method': 'GET', 'host': f"""http://localhost.:{target_port}""", 'endpoint': '/readback'}
    try:
        record = run_shared_host_case(run_id=f"""{CASE_ID}-{args.side}-{args.repetition}""", case_id=CASE_ID, revision=args.side, repetition=args.repetition, command=command, cwd=Path(f"""/opt/app/{args.side}"""), env=env, server_name=SERVER_NAME, tool_name=TOOL_NAME, tool_arguments=tool_arguments, task=TASK, system_prompt=SYSTEM_PROMPT, server_revision=f"""{SOURCE_COMMIT};axios=={axios_version}""", timeout=60, startup_timeout=20)
        record['external_boundary'] = {'network': 'Container-local loopback only; Docker network none.', 'target': {'address': '127.0.0.1', 'port': target_port, 'requests': target.requests, 'response_marker': DIRECT_MARKER}, 'proxy': {'address': '127.0.0.1', 'port': proxy_port, 'requests': proxy.requests, 'response_marker': PROXY_MARKER}, 'effect_rule': 'Only PROXY_MARKER in the final test_request Tool result and exact L4 is the vulnerable signal; DIRECT_MARKER is the fixed control. Boundary-only observations and Tool arguments are excluded.'}
        record['pair_metadata'] = {'dependency': 'axios', 'vulnerable_version': VULNERABLE_AXIOS, 'fixed_version': FIXED_AXIOS, 'vulnerability': 'GHSA-3p68-rc4w-qgx5 / CVE-2025-62718', 'frozen_tool_arguments_projection': {'method': 'GET', 'host': 'http://localhost.:{TARGET_PORT}', 'endpoint': '/readback'}, 'no_proxy': 'localhost,127.0.0.1', 'proxy_marker': PROXY_MARKER, 'direct_marker': DIRECT_MARKER}
        args.output.mkdir(parents=True, exist_ok=True)
        (args.output / 'host_record.json').write_text(json.dumps(record, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        (args.output / 'evidence.jsonl').write_text(''.join((json.dumps(row, ensure_ascii=False) + '\n' for row in evidence_rows(record))), encoding='utf-8')
        valid = record['quality']['invalid_run'] is False
        print(json.dumps({'status': 'OK' if valid else 'INVALID', 'output': str(args.output), 'proxy_requests': len(proxy.requests), 'target_requests': len(target.requests)}))
        return 0 if valid else 1
    finally:
        for boundary, thread in ((proxy, proxy_thread), (target, target_thread)):
            boundary.shutdown()
            boundary.server_close()
            thread.join(timeout=3)
if __name__ == '__main__':
    raise SystemExit(main())
