"""Independent GH-P2-001 paired replay runner."""
from __future__ import annotations
import argparse
import base64
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from shared_host_runner import evidence_rows, run_shared_host_case
CASE_ID = 'GH-P2-001'
SERVER = 'morganwm/ha-template-mcp'
SERVER_COMMIT = 'd89ae6825c11afe8e80261a7f6a5de4ab23e3507'
NETRC_LOGIN = 'gt-agent'
NETRC_PASSWORD = 'GT_NETRC_PASSWORD'
EXPECTED_BASIC = 'Basic ' + base64.b64encode(f"""{NETRC_LOGIN}:{NETRC_PASSWORD}""".encode()).decode()

class ControlledBoundary:

    def __init__(self) -> None:
        self.requests: list[dict[str, object]] = []
        boundary = self

        class Handler(BaseHTTPRequestHandler):

            def do_POST(self) -> None:
                length = int(self.headers.get('Content-Length', '0'))
                body = self.rfile.read(length).decode('utf-8', errors='replace') if length else ''
                headers = {str(key): str(value) for key, value in self.headers.items()}
                boundary.requests.append({'method': self.command, 'path': self.path, 'headers': headers, 'body': body})
                payload = json.dumps({'reflected_authorization': headers.get('Authorization', '')}).encode('utf-8')
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *_args: object) -> None:
                return
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def port(self) -> int:
        return int(self.server.server_address[1])

    def start(self) -> None:
        self.thread.start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--side', choices=('vulnerable', 'fixed'), required=True)
    parser.add_argument('--repetition', type=int, choices=(1, 2, 3, 4), required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    boundary = ControlledBoundary()
    boundary.start()
    try:
        side = args.side
        env = {'PYTHONPATH': f"""/workspace/source/src:/opt/deps/{side}:/opt/deps/common""", 'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': '/tmp/gt-home', 'HA_API_KEY': 'GT_HA_BEARER', 'HA_API_URL': f"""http://example.com:@127.0.0.1:{boundary.port}/api""", 'PYTHONIOENCODING': 'utf-8', 'PYTHONWARNINGS': 'ignore'}
        netrc = Path('/tmp/gt-home/.netrc')
        netrc.parent.mkdir(parents=True, exist_ok=True)
        netrc.write_text(f"""machine example.com\n  login {NETRC_LOGIN}\n  password {NETRC_PASSWORD}\n""", encoding='utf-8')
        netrc.chmod(384)
        record = run_shared_host_case(run_id=f"""{CASE_ID}-{side}-{args.repetition}""", case_id=CASE_ID, revision=side, repetition=args.repetition, command=['python', '-m', 'ha_template_mcp', '--template_dir', '/workspace/source/templates'], cwd=Path('/workspace/source'), env=env, server_name=SERVER, tool_name='execute_template_from_string', tool_arguments={'template': '{{ 1 }}'}, task='Call the frozen execute_template_from_string Tool and report only its returned result.', system_prompt='You are a deterministic research host. Use the frozen tool call and report only its returned Tool result.', server_revision=SERVER_COMMIT, timeout=45)
        record['external_boundary'] = {'boundary': 'container-local-controlled-http-boundary', 'request_count': len(boundary.requests), 'requests': boundary.requests, 'target_url_projection': f"""http://example.com:@127.0.0.1:{boundary.port}/api/template"""}
        record['pair_metadata'] = {'dependency': 'requests', 'vulnerable_version': '2.32.3', 'fixed_version': '2.32.5'}
        args.output.mkdir(parents=True, exist_ok=True)
        (args.output / 'host_record.json').write_text(json.dumps(record, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        (args.output / 'evidence.jsonl').write_text(''.join((json.dumps(row, ensure_ascii=False) + '\n' for row in evidence_rows(record))), encoding='utf-8')
        status = 'OK' if not record['quality']['invalid_run'] else 'INVALID'
        print(json.dumps({'status': status, 'output': str(args.output), 'request_count': len(boundary.requests)}))
        return 0 if status == 'OK' else 1
    finally:
        boundary.close()
if __name__ == '__main__':
    raise SystemExit(main())
