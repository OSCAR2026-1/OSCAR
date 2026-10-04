from __future__ import annotations
import argparse
import base64
import hashlib
import json
import os
import socket
import subprocess
import threading
import time
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
import sys
ROOT = Path('/opt/gt')
sys.path.insert(0, str(ROOT))
from host_core import build_model_request, host_project, normalize_result, stable_json
from shared_host_runner import LEVELS, SHARED_HOST_RUNNER_SHA256, evidence_rows
CASE_ID = 'GH-P15-129'
SERVER_NAME = 'smallhandsome/shotapi-mcp-server'
TOOL_NAME = 'screenshot_one_liner'
PROFILE = json.loads((ROOT / 'host_profile.json').read_text(encoding='utf-8'))
SYSTEM = 'You are a deterministic research host. Use the frozen tool call and report only its returned Tool result.'
TASK = 'Call the frozen screenshot_one_liner Tool and report only its returned result.'
MARKER = b'P15-129-SHOTAPI-IMAGE-EFFECT'
JPEG = base64.b64decode('/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAP//////////////////////////////////////////////////////////////////////////////////////2wBDAf//////////////////////////////////////////////////////////////////////////////////////wAARCAABAAEDASIAAhEBAxEB/8QAFQABAQAAAAAAAAAAAAAAAAAAAAX/xAAUEAEAAAAAAAAAAAAAAAAAAAAA/9oADAMBAAIQAxAAAAH/AP/EABQQAQAAAAAAAAAAAAAAAAAAAAD/2gAIAQEAAT8Af//EABQRAQAAAAAAAAAAAAAAAAAAABD/2gAIAQIBAT8Af//EABQRAQAAAAAAAAAAAAAAAAAAABD/2gAIAQMBAT8Af//Z') + MARKER

class Boundary:

    def __init__(self):
        self.requests: list[dict[str, Any]] = []
        boundary = self

        class Handler(BaseHTTPRequestHandler):

            def do_GET(self):
                boundary.requests.append({'method': 'GET', 'path': self.path, 'headers': dict(self.headers)})
                self.send_response(200)
                self.send_header('Content-Type', 'image/jpeg')
                self.send_header('X-Cache', 'frozen-boundary')
                self.send_header('Content-Length', str(len(JPEG)))
                self.end_headers()
                self.wfile.write(JPEG)

            def log_message(self, *_args):
                return
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def base_url(self):
        return f"""http://127.0.0.1:{self.server.server_port}"""

    def start(self):
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)

    def snapshot(self):
        return {'kind': 'container-local-shotapi-image-boundary', 'base_url': self.base_url, 'marker': MARKER.decode(), 'requests': list(self.requests)}

def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return int(sock.getsockname()[1])

def parse_body(headers, body):
    if not body:
        return None
    if 'text/event-stream' in headers.get('content-type', '').lower():
        for line in body.splitlines():
            if line.startswith('data:'):
                return json.loads(line.split(':', 1)[1].strip())
    return json.loads(body)

def post(port, payload, session_id=None):
    raw = stable_json(payload).encode()
    headers = {'Accept': 'application/json, text/event-stream', 'Content-Type': 'application/json', 'Content-Length': str(len(raw)), 'Host': f"""evil.example:{port}""", 'Origin': 'http://evil.example'}
    if session_id:
        headers['Mcp-Session-Id'] = session_id
    conn = HTTPConnection('127.0.0.1', port, timeout=15)
    try:
        conn.request('POST', '/', body=raw, headers=headers)
        response = conn.getresponse()
        response_headers = {key.lower(): value for key, value in response.getheaders()}
        body = response.read().decode('utf-8', errors='replace')
        value = parse_body(response_headers, body) if response.status < 400 else body
        return (response.status, response_headers, value, body)
    finally:
        conn.close()

def raw_result(value):
    if isinstance(value, dict) and isinstance(value.get('result'), dict):
        return value['result']
    if isinstance(value, dict) and isinstance(value.get('error'), dict):
        return {'content': [{'type': 'text', 'text': json.dumps(value['error'], sort_keys=True)}], 'isError': True}
    return {'content': [{'type': 'text', 'text': json.dumps(value, sort_keys=True)}], 'isError': True}

def witness(result):
    image = next((item for item in result.get('content', []) if isinstance(item, dict) and item.get('type') == 'image'), None)
    if not image or not isinstance(image.get('data'), str):
        return {'present': False, 'reason': 'no native image block'}
    data = base64.b64decode(image['data'], validate=True)
    return {'present': MARKER in data, 'content_type': image.get('type'), 'mimeType': image.get('mimeType'), 'base64_bytes': len(data), 'marker_definition': 'raw ImageContent data decodes to the frozen ShotAPI response body'}

def make_record(side, repetition, port, raw, meta, image, boundary, *, valid, error=None, tools=None):
    normalized = normalize_result(raw)
    projected = host_project(normalized, PROFILE)
    call = {'id': 'det-call-1', 'name': TOOL_NAME, 'arguments': {'url': 'http://victim.example/frozen-page'}}
    model = build_model_request(SYSTEM, tools or [{'name': TOOL_NAME, 'description': 'Take a screenshot', 'inputSchema': {'type': 'object', 'properties': {'url': {'type': 'string'}}}}], TASK, call, projected)
    record = {'schema_version': 'agent-observation-record/v1', 'run_id': f"""{CASE_ID}-{side}-{repetition}""", 'case_id': CASE_ID, 'revision': side, 'repetition': repetition, 'identity': {'server_name': SERVER_NAME, 'server_revision': '09b175a80b0d0f1192dd24303cb83db284b196ba; mcp==1.22.0' if side == 'vulnerable' else '09b175a80b0d0f1192dd24303cb83db284b196ba; mcp==1.23.0', 'transport': 'streamable-http', 'command': ['python', '/opt/gt/start_server.py', '--source', f"""/workspace/source_{side}""", '--port', str(port)], 'endpoint': f"""http://127.0.0.1:{port}/""", 'tool_name': TOOL_NAME}, 'quality': {'invalid_run': not valid, 'unexpected_exception': error, 'timeout': False, 'retries': 0, 'reconnects': 0}, 'evidence_levels': {level: 'observed' for level in LEVELS}, 'mcp': {'transport': 'streamable-http', 'raw_jsonrpc_response': raw, 'normalized_result': normalized, 'http': meta}, 'host': {'tool_runtime_result': projected, 'processed_content': projected.get('content', []), 'external_state_before': {}, 'external_state_after': boundary.snapshot()}, 'session': {'tool_call': {'type': 'tool/call', 'turn': 1, 'step': 1, 'callId': call['id'], 'name': TOOL_NAME, 'arguments': stable_json(call['arguments'])}, 'tool_result': {'type': 'tool/result', 'turn': 1, 'step': 1, 'callId': call['id'], 'message': {'role': 'tool', 'tool_call_id': call['id'], 'content': projected.get('content', []), 'isError': bool(projected.get('isError', False))}}}, 'model': {'adapter': 'deterministic', 'next_request': model}, 'host_runner': {'implementation': 'shared-research-host/v1', 'source_sha256': SHARED_HOST_RUNNER_SHA256, 'transport': 'streamable-http', 'model_provider': 'cli-mock', 'model': 'cli-mock', 'temperature': 0, 'reasoning_effort': 'disabled'}, 'host_profile': {'profile_id': PROFILE.get('profile_id'), 'profile_sha256': hashlib.sha256(stable_json(PROFILE).encode()).hexdigest()}, 'observation': {'tool_client_visible': projected, 'model_visible_request': model}, 'external_boundary': boundary.snapshot(), 'image_witness': image, 'http_boundary': meta}
    record['field_digests'] = {'record': hashlib.sha256(stable_json(record).encode()).hexdigest()}
    return record

def run_one(side, repetition, output):
    boundary = Boundary()
    boundary.start()
    port = free_port()
    source = f"""/workspace/source_{side}"""
    venv = f"""/opt/gt/venv-{side}"""
    env = dict(os.environ)
    env.update({'PYTHONPATH': f"""{source}:/opt/gt""", 'SHOTAPI_BASE_URL': boundary.base_url, 'SHOTAPI_KEY': '', 'HOME': '/tmp/gt-home', 'PYTHONUNBUFFERED': '1'})
    command = [f"""{venv}/bin/python""", '/opt/gt/start_server.py', '--source', source, '--port', str(port)]
    process = subprocess.Popen(command, cwd=source, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError(f"""server exited during startup: {process.returncode}""")
            try:
                with socket.create_connection(('127.0.0.1', port), timeout=0.2):
                    break
            except OSError:
                time.sleep(0.05)
        else:
            raise TimeoutError('ShotAPI MCP server did not become reachable')
        meta = {'host': f"""evil.example:{port}""", 'origin': 'http://evil.example', 'path': '/'}
        status, headers, value, body = post(port, {'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {'protocolVersion': '2025-06-18', 'capabilities': {}, 'clientInfo': {'name': 'work15-host', 'version': '1'}}})
        meta['initialize'] = {'status': status, 'headers': headers, 'body': body}
        if status != 200:
            raw = {'content': [{'type': 'text', 'text': f"""Streamable HTTP request rejected: HTTP {status} {body}"""}], 'isError': True}
            record = make_record(side, repetition, port, raw, meta, {'present': False, 'reason': 'fixed SDK rejected hostile origin before Tool dispatch'}, boundary, valid=side == 'fixed' and status in {400, 403, 421})
        else:
            session = headers.get('mcp-session-id')
            meta['session_id_present'] = bool(session)
            nstatus, nheaders, nvalue, nbody = post(port, {'jsonrpc': '2.0', 'method': 'notifications/initialized'}, session)
            meta['initialized'] = {'status': nstatus, 'body': nbody}
            tstatus, theaders, tvalue, tbody = post(port, {'jsonrpc': '2.0', 'id': 2, 'method': 'tools/list', 'params': {}}, session)
            meta['tools_list'] = {'status': tstatus, 'body': tbody}
            cstatus, cheaders, cvalue, cbody = post(port, {'jsonrpc': '2.0', 'id': 3, 'method': 'tools/call', 'params': {'name': TOOL_NAME, 'arguments': {'url': 'http://victim.example/frozen-page'}}}, session)
            meta['tool_call'] = {'status': cstatus, 'body': cbody}
            raw = raw_result(cvalue)
            image = witness(raw)
            listed = tvalue.get('result', {}).get('tools', []) if isinstance(tvalue, dict) else []
            record = make_record(side, repetition, port, raw, meta, image, boundary, valid=side == 'vulnerable' and cstatus == 200 and (image.get('present') is True), error=None if image.get('present') else 'vulnerable image witness missing', tools=listed)
        return record
    except Exception as exc:
        raw = {'content': [{'type': 'text', 'text': f"""runner error: {type(exc).__name__}: {exc}"""}], 'isError': True}
        return make_record(side, repetition, port, raw, {'host': f"""evil.example:{port}""", 'origin': 'http://evil.example'}, {'present': False, 'reason': 'runner exception'}, boundary, valid=False, error=f"""{type(exc).__name__}: {exc}""")
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        boundary.close()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--side', choices=('vulnerable', 'fixed'), required=True)
    parser.add_argument('--repetition', type=int, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    record = run_one(args.side, args.repetition, args.output)
    (args.output / 'host_record.json').write_text(json.dumps(record, ensure_ascii=False, indent=2) + '\n')
    (args.output / 'evidence.jsonl').write_text(''.join((json.dumps(item, ensure_ascii=False) + '\n' for item in evidence_rows(record))))
    (args.output / 'runtime_contract.json').write_text(json.dumps({'schema_version': 'work15-runtime-contract/v1', 'image_side': args.side, 'network': 'none', 'cap_drop': ['ALL'], 'security_opt': ['no-new-privileges:true'], 'read_only': True, 'tmpfs': ['/tmp:rw,noexec,nosuid,size=64m'], 'command': record['identity']['command'], 'profile_id': PROFILE.get('profile_id')}, indent=2) + '\n')
    print(json.dumps({'case_id': CASE_ID, 'side': args.side, 'repetition': args.repetition, 'valid': not record['quality']['invalid_run'], 'witness': record.get('image_witness'), 'initialize_status': record.get('http_boundary', {}).get('initialize', {}).get('status')}, ensure_ascii=False))
    return 0 if not record['quality']['invalid_run'] else 2
if __name__ == '__main__':
    raise SystemExit(main())
