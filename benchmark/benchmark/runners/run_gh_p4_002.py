from __future__ import annotations
import argparse
import json
import os
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from shared_host_runner import evidence_rows, run_shared_host_case
LEVELS = ('L0_RAW_MCP_RESULT', 'L1_NORMALIZED_TOOL_RESULT', 'L2_HOST_PROCESSED_TOOL_RESULT', 'L3_SESSION_TOOL_RESULT', 'L4_MODEL_VISIBLE_OBSERVATION')
SECRET = 'GT_ENV_SECRET_93D7'

class HttpsBoundary:

    def __init__(self) -> None:
        self.requests: list[dict[str, Any]] = []
        boundary = self

        class Handler(BaseHTTPRequestHandler):

            def do_GET(self) -> None:
                boundary.requests.append({'method': self.command, 'path': self.path, 'headers': dict(self.headers)})
                body = b'controlled 404'
                self.send_response(404)
                self.send_header('Content-Type', 'text/plain')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args: object) -> None:
                return
        self.server = ThreadingHTTPServer(('0.0.0.0', 443), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain('/opt/gt/certs/github.crt', '/opt/gt/certs/github.key')
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def start(self) -> None:
        self.thread.start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)

    def snapshot(self) -> dict[str, Any]:
        return {'boundary': 'container-local-controlled-https-github-boundary', 'requests': list(self.requests)}

def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--spec', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--side', choices=('vulnerable', 'fixed'), required=True)
    parser.add_argument('--repetition', type=int, required=True)
    args = parser.parse_args()
    spec = json.loads(args.spec.read_text(encoding='utf-8'))
    boundary = HttpsBoundary()
    boundary.start()
    try:
        dep_root = '/opt/deps/vulnerable' if args.side == 'vulnerable' else '/opt/deps/fixed'
        env = {'PYTHONPATH': f"""{dep_root}:/workspace/source/src""", 'HOME': '/tmp/gt-home', 'XDG_CACHE_HOME': '/tmp/gt-cache', 'MCP_WORKSPACE_ROOT': '/tmp/gt-workspaces', 'GT_AGENT_SECRET': SECRET, 'GIT_SSL_NO_VERIFY': '1', 'PYTHONIOENCODING': 'utf-8'}
        command = ['python3', '-m', 'multi_repo_mcp.server']
        tool = spec['mcp_path_review']['tool_arguments']
        record = run_shared_host_case(run_id=f"""{spec['case_id']}-{args.side}-{args.repetition}""", case_id=spec['case_id'], revision=args.side, repetition=args.repetition, command=command, cwd=Path('/workspace/source'), env=env, server_name=spec['discovery']['repository_url'], tool_name=spec['mcp_path_review']['tool'], tool_arguments=tool, task=spec['experiment']['agent_task'], system_prompt='You are a deterministic research host. Use the frozen tool call and report only its returned Tool result.', server_revision=spec['discovery']['repository_commit'] + '; gitpython==' + spec['vulnerability']['vulnerable_version' if args.side == 'vulnerable' else 'fixed_version'], timeout=60)
        record['external_boundary'] = boundary.snapshot()
        record['gh_p4_probe'] = {'effect_signal': SECRET, 'boundary_request_count': len(boundary.requests), 'expanded_secret_in_boundary_path': any((SECRET in item.get('path', '') for item in boundary.requests)), 'expanded_secret_in_tool_result': SECRET in json.dumps(record.get('mcp', {}).get('normalized_result', {}), ensure_ascii=False), 'expanded_secret_in_l4': SECRET in json.dumps(record.get('model', {}).get('next_request', {}), ensure_ascii=False), 'input_token_excluded': SECRET not in json.dumps(tool, ensure_ascii=False)}
        args.output.mkdir(parents=True, exist_ok=True)
        write_json(args.output / 'host_record.json', record)
        (args.output / 'evidence.jsonl').write_text(''.join((json.dumps(row, ensure_ascii=False) + '\n' for row in evidence_rows(record))), encoding='utf-8')
        write_json(args.output / 'boundary_snapshot.json', boundary.snapshot())
        print(json.dumps({'status': 'OK' if not record['quality']['invalid_run'] else 'INVALID', 'output': str(args.output)}, ensure_ascii=False))
        return 0 if not record['quality']['invalid_run'] else 1
    finally:
        boundary.close()
if __name__ == '__main__':
    raise SystemExit(main())
