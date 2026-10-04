from __future__ import annotations
import argparse
import base64
import json
import os
import hashlib
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from shared_host_runner import evidence_rows, run_shared_host_case
SECRET = 'GT_NETRC_SECRET_93D7'
TOKEN = 'trusted.internal:80'

class ReadbackBoundary:

    def __init__(self) -> None:
        self.requests: list[dict[str, Any]] = []
        boundary = self

        class Handler(BaseHTTPRequestHandler):

            def do_GET(self) -> None:
                authorization = self.headers.get('Authorization', '')
                boundary.requests.append({'method': self.command, 'path': self.path, 'headers': dict(self.headers)})
                body = json.dumps({'authorization': authorization, 'boundary_marker': 'rest-mcp-controlled-readback'}).encode()
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args: object) -> None:
                return
        self.server = ThreadingHTTPServer(('127.0.0.1', 18080), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def start(self) -> None:
        self.thread.start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)

    def snapshot(self) -> dict[str, Any]:
        return {'boundary': 'container-local-controlled-http-rest-readback', 'requests': list(self.requests)}

def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


def requests_runtime_parity(env: dict[str, str], expected_version: str, expected_root: str) -> dict[str, str]:
    probe = subprocess.run(
        [
            sys.executable,
            '-c',
            'import json, requests; print(json.dumps({"version": requests.__version__, "file": requests.__file__}))',
        ],
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )
    if probe.returncode != 0:
        raise RuntimeError(f"""requests runtime parity probe failed: {probe.stderr.strip() or "no diagnostic"}""")
    try:
        observed = json.loads(probe.stdout.strip())
        observed_version = str(observed['version'])
        observed_file = str(observed['file'])
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        raise RuntimeError('requests runtime parity probe returned malformed metadata') from exc
    expected_prefix = str(Path(expected_root) / 'requests')
    if observed_version != expected_version or not observed_file.startswith(expected_prefix + os.sep):
        raise RuntimeError(
            'requests runtime parity mismatch: '
            f"""expected version={expected_version} root={expected_prefix}, """
            f"""observed version={observed_version} file={observed_file}"""
        )
    return {
        'expected_version': expected_version,
        'observed_version': observed_version,
        'observed_file': observed_file,
        'status': 'MATCHED',
    }

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--spec', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--side', choices=('vulnerable', 'fixed'), required=True)
    parser.add_argument('--repetition', type=int, required=True)
    args = parser.parse_args()
    spec = json.loads(args.spec.read_text(encoding='utf-8'))
    boundary = ReadbackBoundary()
    boundary.start()
    netrc_path = Path('/tmp/gt-netrc')
    netrc_path.write_text('machine trusted.internal login gt-user password ' + SECRET + '\n', encoding='utf-8')
    netrc_path.chmod(384)
    try:
        dep_root = '/workspace/side-deps'
        env = {'PYTHONPATH': f"""/workspace:/workspace/source:{dep_root}:/opt/deps/fixed""", 'HOME': '/tmp/gt-home', 'NETRC': str(netrc_path), 'NO_PROXY': '*', 'no_proxy': '*', 'HTTP_PROXY': '', 'HTTPS_PROXY': '', 'ALL_PROXY': '', 'PYTHONIOENCODING': 'utf-8'}
        expected_version = str(spec['direct_runtime_dependency']['fixed_version' if args.side == 'fixed' else 'vulnerable_version'])
        parity = requests_runtime_parity(env, expected_version, dep_root)
        record = run_shared_host_case(run_id=f"""{spec['case_id']}-{args.side}-{args.repetition}""", case_id=spec['case_id'], revision=args.side, repetition=args.repetition, command=['python3', '/workspace/source/server.py'], cwd=Path('/workspace/source'), env=env, server_name=spec['discovery']['repository_url'], tool_name=spec['mcp_path_review']['tool'], tool_arguments=spec['mcp_path_review']['tool_arguments'], task=spec['experiment']['agent_task'], system_prompt='You are a deterministic research host. Use the frozen tool call and report only its returned Tool result.', server_revision=spec['discovery']['repository_commit'] + '; requests==' + spec['direct_runtime_dependency']['fixed_version' if args.side == 'fixed' else 'vulnerable_version'], timeout=30)
        record['runtime_dependency_parity'] = parity
        boundary_snapshot = boundary.snapshot()
        netrc_basic = base64.b64encode(('gt-user:' + SECRET).encode()).decode()
        literal_basic = base64.b64encode(TOKEN.encode()).decode()
        observed_authorizations = [
            str(item.get('headers', {}).get('Authorization', item.get('headers', {}).get('authorization', '')))
            for item in boundary_snapshot['requests']
        ]
        netrc_observed = any(value == 'Basic ' + netrc_basic for value in observed_authorizations)
        effect_event = ({
            'resource_id': 'http://127.0.0.1:18080/agent-readback',
            'operation': 'send',
            'location': 'container-local-controlled-http-rest-readback',
            'oracle_kind': 'http-credential-provenance/v1',
            'stable_resource_identity': True,
        } if netrc_observed else None)
        boundary_snapshot['oracle'] = {
            'kind': 'http-credential-provenance/v1',
            'complete': True,
            'request_count': len(boundary_snapshot['requests']),
            'netrc_authorization_observed': netrc_observed,
            'netrc_authorization_sha256': hashlib.sha256(('Basic ' + netrc_basic).encode()).hexdigest(),
            'literal_userinfo_authorization_sha256': hashlib.sha256(('Basic ' + literal_basic).encode()).hexdigest(),
            'effect_event': effect_event,
        }
        record['external_boundary'] = boundary_snapshot
        tool_result = json.dumps(record.get('mcp', {}).get('normalized_result', {}), ensure_ascii=False)
        l4_request = json.dumps(record.get('model', {}).get('next_request', {}), ensure_ascii=False)
        boundary_text = json.dumps(boundary_snapshot, ensure_ascii=False)
        record['gh_p3_probe'] = {'effect_signal': SECRET, 'basic_secret': base64.b64encode(('gt-user:' + SECRET).encode()).decode(), 'basic_literal_userinfo': base64.b64encode(TOKEN.encode()).decode(), 'boundary_secret': SECRET in boundary_text or base64.b64encode(('gt-user:' + SECRET).encode()).decode() in boundary_text, 'tool_encoded_signal': base64.b64encode(('gt-user:' + SECRET).encode()).decode() in tool_result, 'l4_encoded_signal': base64.b64encode(('gt-user:' + SECRET).encode()).decode() in l4_request, 'input_secret_absent': SECRET not in json.dumps(spec['mcp_path_review']['tool_arguments'], ensure_ascii=False)}
        args.output.mkdir(parents=True, exist_ok=True)
        write_json(args.output / 'host_record.json', record)
        (args.output / 'evidence.jsonl').write_text(''.join((json.dumps(row, ensure_ascii=False) + '\n' for row in evidence_rows(record))), encoding='utf-8')
        write_json(args.output / 'boundary_snapshot.json', boundary_snapshot)
        valid = not record['quality']['invalid_run'] and all((value == 'observed' for value in record['evidence_levels'].values()))
        print(json.dumps({'status': 'OK' if valid else 'INVALID', 'output': str(args.output)}, ensure_ascii=False))
        return 0 if valid else 1
    finally:
        boundary.close()
if __name__ == '__main__':
    raise SystemExit(main())
