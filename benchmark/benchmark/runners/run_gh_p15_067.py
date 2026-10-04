from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import os
import socket
import subprocess
import sys
import time
from http.client import HTTPConnection
from pathlib import Path
from typing import Any

ROOT = Path('/opt/gt')
sys.path.insert(0, str(ROOT))
from host_core import build_model_request, host_project, normalize_result, stable_json
from shared_host_runner import LEVELS, SHARED_HOST_RUNNER_SHA256, evidence_rows

CASE_ID = 'GH-P15-067'
SERVER_NAME = 'Lakr233/iphone-mcp'
TOOL_NAME = 'iphone_interface_snapshot'
PROFILE = json.loads((ROOT / 'host_profile.json').read_text(encoding='utf-8'))
SYSTEM = 'You are a deterministic research host. Use the frozen tool call and report only its returned Tool result.'
TASK = 'Call the frozen iphone_interface_snapshot Tool and report only its returned result.'


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return int(sock.getsockname()[1])


def parse_body(headers: dict[str, str], body: str) -> Any:
    if not body:
        return None
    if 'text/event-stream' in headers.get('content-type', '').lower():
        for line in body.splitlines():
            if line.startswith('data:'):
                return json.loads(line.split(':', 1)[1].strip())
    return json.loads(body)


def post(port: int, payload: dict[str, Any], session_id: str | None = None) -> tuple[int, dict[str, str], Any, str]:
    raw = stable_json(payload).encode('utf-8')
    headers = {'Accept': 'application/json, text/event-stream', 'Content-Type': 'application/json', 'Content-Length': str(len(raw)), 'Host': f"""evil.example:{port}""", 'Origin': 'http://evil.example'}
    if session_id:
        headers['Mcp-Session-Id'] = session_id
    connection = HTTPConnection('127.0.0.1', port, timeout=15)
    try:
        connection.request('POST', '/mcp', body=raw, headers=headers)
        response = connection.getresponse()
        response_headers = {key.lower(): value for key, value in response.getheaders()}
        body = response.read().decode('utf-8', errors='replace')
        value = parse_body(response_headers, body) if response.status < 400 else body
        return response.status, response_headers, value, body
    finally:
        connection.close()


def raw_result_from_response(value: Any) -> dict[str, Any]:
    if isinstance(value, dict) and isinstance(value.get('result'), dict):
        return value['result']
    if isinstance(value, dict) and isinstance(value.get('error'), dict):
        return {'content': [{'type': 'text', 'text': json.dumps(value['error'], ensure_ascii=False, sort_keys=True)}], 'isError': True}
    return {'content': [{'type': 'text', 'text': json.dumps(value, ensure_ascii=False, sort_keys=True)}], 'isError': True}


def image_witness(result: dict[str, Any]) -> dict[str, Any]:
    content = result.get('content', [])
    image = next((item for item in content if isinstance(item, dict) and item.get('type') == 'image'), None)
    if not image or not isinstance(image.get('data'), str):
        return {'present': False, 'reason': 'no native image block'}
    try:
        data = base64.b64decode(image['data'], validate=True)
        from PIL import Image
        decoded = Image.open(io.BytesIO(data)).convert('RGB')
        pixel = decoded.getpixel((80, 48))
        marker = pixel[0] > 170 and pixel[1] < 150 and pixel[2] < 100
        return {'present': bool(marker), 'content_type': image.get('type'), 'mimeType': image.get('mimeType'), 'base64_bytes': len(data), 'decoded_size': list(decoded.size), 'marker_pixel': list(pixel), 'marker_definition': 'decoded screenshot pixel (80,48) is the frozen iPhone boundary color'}
    except Exception as exc:  # noqa: BLE001
        return {'present': False, 'reason': f"""image decode failed: {type(exc).__name__}: {exc}"""}


def make_record(side: str, repetition: int, port: int, raw: dict[str, Any], http_meta: dict[str, Any], witness: dict[str, Any], *, valid: bool, error: str | None = None, tools: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    normalized = normalize_result(raw)
    projected = host_project(normalized, PROFILE)
    call = {'id': 'det-call-1', 'name': TOOL_NAME, 'arguments': {}}
    model = build_model_request(SYSTEM, tools or [{'name': TOOL_NAME, 'description': 'Get screenshot + page source', 'inputSchema': {'type': 'object', 'properties': {}}}], TASK, call, projected)
    record = {
        'schema_version': 'agent-observation-record/v1', 'run_id': f"""{CASE_ID}-{side}-{repetition}""", 'case_id': CASE_ID, 'revision': side, 'repetition': repetition,
        'identity': {'server_name': SERVER_NAME, 'server_revision': '3508de0230eeca39e2b4f61fd316cbc7f021187c; mcp==1.22.0' if side == 'vulnerable' else '3508de0230eeca39e2b4f61fd316cbc7f021187c; mcp==1.23.0', 'transport': 'streamable-http', 'command': ['python', '/opt/gt/start_server.py', '--source', f"""/workspace/source_{side}""", '--venv', f"""/opt/gt/venv-{side}""", '--port', str(port)], 'endpoint': f"""http://127.0.0.1:{port}/mcp""", 'tool_name': TOOL_NAME},
        'quality': {'invalid_run': not valid, 'unexpected_exception': error, 'timeout': False, 'retries': 0, 'reconnects': 0}, 'evidence_levels': {level: 'observed' for level in LEVELS},
        'mcp': {'transport': 'streamable-http', 'raw_jsonrpc_response': raw, 'normalized_result': normalized, 'http': http_meta},
        'host': {'tool_runtime_result': projected, 'processed_content': projected.get('content', []), 'external_state_before': {}, 'external_state_after': {'iphone_boundary': 'frozen screenshot fixture'}},
        'session': {'tool_call': {'type': 'tool/call', 'turn': 1, 'step': 1, 'callId': call['id'], 'name': TOOL_NAME, 'arguments': '{}'}, 'tool_result': {'type': 'tool/result', 'turn': 1, 'step': 1, 'callId': call['id'], 'message': {'role': 'tool', 'tool_call_id': call['id'], 'content': projected.get('content', []), 'isError': bool(projected.get('isError', False))}}},
        'model': {'adapter': 'deterministic', 'next_request': model},
        'host_runner': {'implementation': 'shared-research-host/v1', 'source_sha256': SHARED_HOST_RUNNER_SHA256, 'transport': 'streamable-http', 'model_provider': 'cli-mock', 'model': 'cli-mock', 'temperature': 0, 'reasoning_effort': 'disabled'},
        'host_profile': {'profile_id': PROFILE.get('profile_id'), 'profile_sha256': hashlib.sha256(stable_json(PROFILE).encode('utf-8')).hexdigest()},
        'observation': {'tool_client_visible': projected, 'model_visible_request': model},
        'external_boundary': {'kind': 'container-local-frozen-iphone-screen-fixture', 'marker': 'P15-067 frozen pixel pattern', 'witness': witness}, 'image_witness': witness, 'http_boundary': http_meta,
    }
    record['field_digests'] = {'record': hashlib.sha256(stable_json(record).encode('utf-8')).hexdigest()}
    return record


def run_one(side: str, repetition: int, output: Path) -> dict[str, Any]:
    port = free_port()
    source = f"""/workspace/source_{side}"""
    venv = f"""/opt/gt/venv-{side}"""
    env = dict(os.environ)
    env.update({'PYTHONPATH': f"""{source}:/opt/gt""", 'HOME': '/tmp/gt-home', 'PYTHONUNBUFFERED': '1'})
    command = [f"""{venv}/bin/python""", '/opt/gt/start_server.py', '--source', source, '--venv', venv, '--port', str(port)]
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
            raise TimeoutError('Streamable HTTP server did not become reachable')
        http_meta: dict[str, Any] = {'host': f"""evil.example:{port}""", 'origin': 'http://evil.example', 'path': '/mcp'}
        init_payload = {'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {'protocolVersion': '2025-06-18', 'capabilities': {}, 'clientInfo': {'name': 'work15-host', 'version': '1'}}}
        init_status, init_headers, init_value, init_body = post(port, init_payload)
        http_meta['initialize'] = {'status': init_status, 'headers': init_headers, 'body': init_body}
        if init_status != 200:
            raw = {'content': [{'type': 'text', 'text': f"""Streamable HTTP request rejected: HTTP {init_status} {init_body}"""}], 'isError': True}
            record = make_record(side, repetition, port, raw, http_meta, {'present': False, 'reason': 'fixed SDK rejected hostile origin before Tool dispatch'}, valid=(side == 'fixed' and init_status in {400, 403, 421}), error=None)
        else:
            session_id = init_headers.get('mcp-session-id')
            http_meta['session_id_present'] = bool(session_id)
            notify_status, notify_headers, notify_value, notify_body = post(port, {'jsonrpc': '2.0', 'method': 'notifications/initialized'}, session_id)
            http_meta['initialized'] = {'status': notify_status, 'headers': notify_headers, 'body': notify_body}
            tools_status, tools_headers, tools_value, tools_body = post(port, {'jsonrpc': '2.0', 'id': 2, 'method': 'tools/list', 'params': {}}, session_id)
            http_meta['tools_list'] = {'status': tools_status, 'headers': tools_headers, 'body': tools_body}
            tool_status, tool_headers, tool_value, tool_body = post(port, {'jsonrpc': '2.0', 'id': 3, 'method': 'tools/call', 'params': {'name': TOOL_NAME, 'arguments': {}}}, session_id)
            http_meta['tool_call'] = {'status': tool_status, 'headers': tool_headers, 'body': tool_body}
            raw = raw_result_from_response(tool_value)
            witness = image_witness(raw)
            listed = tools_value.get('result', {}).get('tools', []) if isinstance(tools_value, dict) else []
            record = make_record(side, repetition, port, raw, http_meta, witness, valid=(side == 'vulnerable' and tool_status == 200 and witness.get('present') is True), error=None if witness.get('present') else 'vulnerable screenshot witness missing', tools=listed)
        return record
    except Exception as exc:  # noqa: BLE001
        raw = {'content': [{'type': 'text', 'text': f"""runner error: {type(exc).__name__}: {exc}"""}], 'isError': True}
        return make_record(side, repetition, port, raw, {'host': f"""evil.example:{port}""", 'origin': 'http://evil.example'}, {'present': False, 'reason': 'runner exception'}, valid=False, error=f"""{type(exc).__name__}: {exc}""")
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--side', choices=('vulnerable', 'fixed'), required=True)
    parser.add_argument('--repetition', type=int, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    record = run_one(args.side, args.repetition, args.output)
    (args.output / 'host_record.json').write_text(json.dumps(record, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    (args.output / 'evidence.jsonl').write_text(''.join(json.dumps(item, ensure_ascii=False) + '\n' for item in evidence_rows(record)), encoding='utf-8')
    (args.output / 'runtime_contract.json').write_text(json.dumps({'schema_version': 'work15-runtime-contract/v1', 'image_side': args.side, 'network': 'none', 'cap_drop': ['ALL'], 'security_opt': ['no-new-privileges:true'], 'read_only': True, 'tmpfs': ['/tmp:rw,noexec,nosuid,size=64m'], 'command': record['identity']['command'], 'profile_id': PROFILE.get('profile_id')}, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'case_id': CASE_ID, 'side': args.side, 'repetition': args.repetition, 'valid': not record['quality']['invalid_run'], 'witness': record.get('image_witness'), 'initialize_status': record.get('http_boundary', {}).get('initialize', {}).get('status')}, ensure_ascii=False))
    return 0 if not record['quality']['invalid_run'] else 2


if __name__ == '__main__':
    raise SystemExit(main())
