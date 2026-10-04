from __future__ import annotations
import argparse
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from shared_host_runner import evidence_rows, run_shared_host_case
CASE_ID = 'GH-P3-032-fetch-guard-requests-netrc'
SECRET = 'GT_P3_032_NETRC_SECRET_7F4A'
NETRC_MACHINE = 'trusted.internal'
TARGET_PORT = 18080

class ReadbackBoundary:

    def __init__(self) -> None:
        self.requests: list[dict[str, Any]] = []
        boundary = self

        class Handler(BaseHTTPRequestHandler):

            def do_GET(self) -> None:
                headers = dict(self.headers)
                boundary.requests.append({'method': self.command, 'path': self.path, 'headers': headers})
                if self.path == '/llms.txt':
                    body = b'not found'
                    self.send_response(404)
                    self.send_header('Content-Type', 'text/plain')
                else:
                    authorization = headers.get('Authorization', '')
                    body = f"""<html><head><title>controlled</title></head><body><article><h1>Controlled readback</h1><p>Authorization: {authorization}</p></article></body></html>""".encode('utf-8')
                    self.send_response(200)
                    self.send_header('Content-Type', 'text/html; charset=utf-8')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args: object) -> None:
                return
        self.server = ThreadingHTTPServer(('127.0.0.1', TARGET_PORT), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def start(self) -> None:
        self.thread.start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)

    def snapshot(self) -> dict[str, Any]:
        return {'boundary': 'container-local-http-netrc-readback', 'requests': list(self.requests)}

def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--spec', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--side', choices=('vulnerable', 'fixed'), required=True)
    parser.add_argument('--repetition', type=int, choices=(1, 2, 3), required=True)
    args = parser.parse_args()
    spec = json.loads(args.spec.read_text(encoding='utf-8'))
    boundary = ReadbackBoundary()
    boundary.start()
    netrc_path = Path('/tmp/gt-netrc')
    netrc_path.write_text(f"""machine {NETRC_MACHINE} login gt-user password {SECRET}\n""", encoding='utf-8')
    netrc_path.chmod(384)
    side_version = spec['direct_runtime_dependency']['vulnerable_version' if args.side == 'vulnerable' else 'fixed_version']
    env = {'PYTHONPATH': f"""/opt/side-deps/{args.side}:/opt/deps/common:/workspace/source:/opt/deps/fixed:/opt/gt""", 'HOME': '/tmp/gt-home', 'NETRC': str(netrc_path), 'NO_PROXY': '*', 'no_proxy': '*', 'HTTP_PROXY': '', 'HTTPS_PROXY': '', 'ALL_PROXY': '', 'PYTHONIOENCODING': 'utf-8'}
    try:
        record = run_shared_host_case(run_id=f"""{CASE_ID}-{args.side}-{args.repetition}""", case_id=CASE_ID, revision=args.side, repetition=args.repetition, command=['python3', '-m', 'fetch_guard.server'], cwd=Path('/workspace/source'), env=env, server_name=spec['discovery']['repository_url'], tool_name=spec['mcp_path_review']['tool'], tool_arguments=spec['mcp_path_review']['tool_arguments'], task=spec['experiment']['agent_task'], system_prompt='You are a deterministic research host. Use the frozen tool call and report only its returned Tool result.', server_revision=f"""{spec['discovery']['repository_commit']}; requests=={side_version}""", timeout=45)
        boundary_snapshot = boundary.snapshot()
        record['external_boundary'] = boundary_snapshot
        args.output.mkdir(parents=True, exist_ok=True)
        write_json(args.output / 'host_record.json', record)
        (args.output / 'evidence.jsonl').write_text(''.join((json.dumps(row, ensure_ascii=False) + '\n' for row in evidence_rows(record))), encoding='utf-8')
        write_json(args.output / 'boundary_snapshot.json', boundary_snapshot)
        valid = record['quality']['invalid_run'] is False and all((value == 'observed' for value in record['evidence_levels'].values()))
        print(json.dumps({'status': 'OK' if valid else 'INVALID', 'output': str(args.output)}, ensure_ascii=False))
        return 0 if valid else 1
    finally:
        boundary.close()
if __name__ == '__main__':
    raise SystemExit(main())
