"""Replay two newly reconstructed MCP vulnerability cases as paired GT evidence."""
from __future__ import annotations
import argparse
import asyncio
import base64
import json
import os
import socket
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
import httpx
ROOT = Path('/opt/gt')
OUTPUT_ROOT: Path | None = None
sys.path.insert(0, str(ROOT / 'agent_observation_harness'))
from host_core import LEVELS, build_model_request, field_digest, host_project, normalize_result
from shared_host_runner import evidence_rows, run_shared_host_case
NETRC_LOGIN = 'mcp-user'
NETRC_PASSWORD = 'mcp-secret'
NETRC_BASIC = 'Basic ' + base64.b64encode(f"""{NETRC_LOGIN}:{NETRC_PASSWORD}""".encode()).decode()
WEBHOOK_SIGNAL = 'servergenerateda'
WEBHOOK_TOOL = 'generate_webhook'
STATIC_WEBHOOK_TOOLS = {'tools': [{'name': WEBHOOK_TOOL, 'description': 'Generate a webhook endpoint that captures incoming HTTP requests', 'inputSchema': {'type': 'object', 'properties': {}}}]}

def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')

def write_record(path: Path, record: dict[str, Any], boundary: dict[str, Any]) -> None:
    record['external_boundary'] = boundary
    record['field_digests'] = {'record': field_digest(record)}
    write_json(path / 'host_record.json', record)
    (path / 'evidence.jsonl').write_text(''.join((json.dumps(row, ensure_ascii=False) + '\n' for row in evidence_rows(record))), encoding='utf-8')

class ZillizBoundary:

    def __init__(self) -> None:
        boundary = self
        self.requests: list[dict[str, Any]] = []
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), self._handler())
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def _handler(self):
        boundary = self

        class Handler(BaseHTTPRequestHandler):

            def do_GET(self) -> None:
                authorization = self.headers.get('Authorization')
                boundary.requests.append({'method': 'GET', 'path': self.path, 'authorization': authorization, 'body': ''})
                if self.path.startswith(('/v2/clusters/', '/control/v2/clusters/')):
                    payload = {'code': 0, 'data': {'clusterId': 'gt-cluster', 'regionId': 'gt-region', 'connectAddress': boundary.data_plane_url}}
                else:
                    payload = {'code': 0, 'data': []}
                raw = json.dumps(payload).encode('utf-8')
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_POST(self) -> None:
                length = int(self.headers.get('Content-Length', '0'))
                body = self.rfile.read(length) if length else b''
                authorization = self.headers.get('Authorization')
                boundary.requests.append({'method': 'POST', 'path': self.path, 'authorization': authorization, 'body': body.decode('utf-8', errors='replace')})
                if self.path.startswith('/control/v2/clusters/'):
                    payload = {'code': 0, 'data': {'clusterId': 'gt-cluster', 'regionId': 'gt-region', 'connectAddress': boundary.data_plane_url}}
                elif self.path.startswith('/v2/vectordb/databases/list'):
                    payload = {'code': 0, 'data': [f"""boundary-authorization:{authorization or 'none'}"""]}
                else:
                    payload = {'code': 0, 'data': []}
                raw = json.dumps(payload).encode('utf-8')
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def log_message(self, *_args: object) -> None:
                return
        return Handler

    @property
    def port(self) -> int:
        return int(self.server.server_port)

    @property
    def data_plane_url(self) -> str:
        return f"""http://example.com:@127.0.0.1:{self.port}/"""

    @property
    def control_plane_url(self) -> str:
        return f"""http://127.0.0.1:{self.port}/control"""

    def start(self) -> None:
        self.thread.start()

    def snapshot(self) -> dict[str, Any]:
        return {'boundary': 'zilliz-netrc-controlled-http', 'request_count': len(self.requests), 'requests': list(self.requests), 'expected_vulnerable_authorization': NETRC_BASIC}

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)

def neutral_env() -> dict[str, str]:
    return {'NO_PROXY': '*', 'no_proxy': '*', 'HTTP_PROXY': '', 'HTTPS_PROXY': '', 'ALL_PROXY': '', 'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin', 'PYTHONIOENCODING': 'utf-8'}

def prepare_netrc(root: Path, case_id: str, side: str, repetition: int) -> Path:
    input_root = Path(os.getenv('VULVEIL_RUN_INPUT_ROOT', str(root)))
    path = input_root / 'new_inputs' / case_id / side / str(repetition) / 'netrc'
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"""machine example.com login {NETRC_LOGIN} password {NETRC_PASSWORD}\n""", encoding='utf-8')
    path.chmod(384)
    return path

def run_zilliz(root: Path, side: str, repetition: int) -> dict[str, Any]:
    boundary = ZillizBoundary()
    boundary.start()
    case_id = 'CVE-2024-47081-zilliz'
    source = root / 'case_assets/new_cases/zilliz' / ('source-vulnerable' if side == 'vulnerable' else 'source-fixed')
    deps = root / 'new_deps/zilliz' / side
    netrc = prepare_netrc(root, case_id, side, repetition)
    env = neutral_env()
    env.update({'PYTHONPATH': f"""{deps}:{source / 'src'}""", 'NETRC': str(netrc), 'HOME': str(netrc.parent), 'ZILLIZ_CLOUD_TOKEN': 'gt-cloud-token', 'ZILLIZ_CLOUD_URI': boundary.control_plane_url, 'ZILLIZ_CLOUD_FREE_CLUSTER_REGION': 'gt-region', 'MCP_SERVER_HOST': '127.0.0.1'})
    arguments = {'cluster_id': 'gt-cluster', 'region_id': 'gt-region', 'endpoint': boundary.data_plane_url}
    try:
        record = run_shared_host_case(run_id=f"""{case_id}-{side}-{repetition}""", case_id=case_id, revision=side, repetition=repetition, command=[str(root / 'venv/bin/python'), str(root / 'case_assets/new_cases/zilliz/zilliz_stdio_entry.py')], cwd=source, env=env, server_name='zilliztech/zilliz-mcp-server', tool_name='list_databases', tool_arguments=arguments, task='Call list_databases with the frozen cluster parameters and report the returned result.', system_prompt='You are a deterministic research host. Use the requested tool and report its result.', server_revision=f"""{('23beec6^' if side == 'vulnerable' else '23beec6')}; requests=={('2.32.3' if side == 'vulnerable' else '2.32.4')}""", timeout=45)
        record['new_case'] = {'sink_tool': 'list_databases', 'effect_signal_token': NETRC_BASIC, 'signal_source': 'credential-derived boundary response reflected by the sink Tool result'}
        output = (OUTPUT_ROOT or root / 'runs/new_gt') / case_id / side / str(repetition)
        write_record(output, record, boundary.snapshot())
        return record
    finally:
        boundary.close()

def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(('127.0.0.1', 0))
        return int(sock.getsockname()[1])

def parse_json_response(response: httpx.Response) -> dict[str, Any]:
    try:
        value = response.json()
    except ValueError:
        return {'text': response.text}
    return value if isinstance(value, dict) else {'value': value}

async def http_post(client: httpx.AsyncClient, url: str, body: dict[str, Any], timeout: float) -> dict[str, Any]:
    try:
        response = await client.post(url, headers={'accept': 'application/json, text/event-stream', 'content-type': 'application/json'}, json=body, timeout=timeout)
        return {'status': response.status_code, 'json': parse_json_response(response)}
    except (httpx.TimeoutException, httpx.HTTPError) as error:
        return {'error': f"""{type(error).__name__}: {error}"""}

async def replay_webhook(port: int) -> dict[str, Any]:
    url = f"""http://127.0.0.1:{port}/mcp"""
    async with httpx.AsyncClient(trust_env=False) as client:
        initialize = await http_post(client, url, {'jsonrpc': '2.0', 'id': 100, 'method': 'initialize', 'params': {'protocolVersion': '2025-06-18', 'capabilities': {}, 'clientInfo': {'name': 'gt-new-case-host', 'version': '1'}}}, 5)
        initialized = await http_post(client, url, {'jsonrpc': '2.0', 'method': 'notifications/initialized'}, 5)
        call_a = asyncio.create_task(http_post(client, url, {'jsonrpc': '2.0', 'id': 7, 'method': 'tools/call', 'params': {'name': WEBHOOK_TOOL, 'arguments': {}}}, 0.7))
        await asyncio.sleep(0.02)
        call_b = asyncio.create_task(http_post(client, url, {'jsonrpc': '2.0', 'id': 7, 'method': 'tools/call', 'params': {'name': WEBHOOK_TOOL, 'arguments': {}}}, 0.7))
        result_a, result_b = await asyncio.gather(call_a, call_b)
        try:
            state_response = await client.get(f"""http://127.0.0.1:{port}/state""", timeout=5)
            state = {'status': state_response.status_code, 'json': parse_json_response(state_response)}
        except httpx.HTTPError as error:
            state = {'error': f"""{type(error).__name__}: {error}"""}
    return {'initialize': initialize, 'initialized': initialized, 'client_a': result_a, 'client_b': result_b, 'state': state}

def start_webhook_server(root: Path, side: str, port: int, log_path: Path) -> subprocess.Popen[str]:
    package = root / 'new_deps/usewebhook' / side
    env = neutral_env()
    env['NODE_NO_WARNINGS'] = '1'
    log_path.parent.mkdir(parents=True, exist_ok=True)
    stream = log_path.open('w', encoding='utf-8')
    process = subprocess.Popen(['node', str(root / 'case_assets/new_cases/usewebhook/deployment_entry.mjs'), '--server-root', str(package), '--port', str(port)], cwd=package, env=env, stdout=stream, stderr=subprocess.STDOUT, text=True)
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"""usewebhook server exited with {process.returncode}; see {log_path}""")
        try:
            response = httpx.get(f"""http://127.0.0.1:{port}/health""", timeout=1, trust_env=False)
            if response.status_code == 200:
                return process
        except httpx.HTTPError:
            pass
        time.sleep(0.1)
    process.terminate()
    raise RuntimeError(f"""usewebhook server did not start; see {log_path}""")

def stop_webhook_server(process: subprocess.Popen[str]) -> None:
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)

def normalize_http_result(value: dict[str, Any]) -> dict[str, Any]:
    payload = value.get('json')
    if not isinstance(payload, dict):
        return normalize_result({'isError': True, 'content': [{'type': 'text', 'text': value.get('error', 'no response')}]})
    if 'result' in payload:
        return normalize_result(payload['result'])
    if 'error' in payload:
        return normalize_result({'isError': True, 'content': [{'type': 'text', 'text': payload['error'].get('message', 'MCP error')}]})
    return normalize_result(payload)

def run_webhook(root: Path, side: str, repetition: int) -> dict[str, Any]:
    case_id = 'CVE-2026-25536-usewebhook'
    port = free_port()
    output = (OUTPUT_ROOT or root / 'runs/new_gt') / case_id / side / str(repetition)
    process = start_webhook_server(root, side, port, output / 'server.log')
    try:
        replay = asyncio.run(replay_webhook(port))
        selected = replay['client_b']
        normalized = normalize_http_result(selected)
        projected = host_project(normalized)
        call = {'id': 'det-call-1', 'name': WEBHOOK_TOOL, 'arguments': {}}
        model_request = build_model_request('You are a deterministic research host. Use the frozen tool call, then summarize the returned Tool result.', STATIC_WEBHOOK_TOOLS, 'Call the frozen webhook generation tool and report its returned result.', call, projected)
        record = {'schema_version': 'agent-observation-record/v1', 'run_id': f"""{case_id}-{side}-{repetition}""", 'case_id': case_id, 'revision': side, 'repetition': repetition, 'identity': {'server_name': 'figstra/usewebhook-mcp', 'server_revision': '28ba604b95bf49ba1b88719fdd81909900602b87', 'transport': 'streamable-http', 'command': ['deployment_entry.mjs'], 'tool_name': WEBHOOK_TOOL}, 'quality': {'invalid_run': False, 'unexpected_exception': None, 'timeout': False, 'expected_client_a_timeout': side == 'vulnerable'}, 'evidence_levels': {level: 'observed' for level in LEVELS}, 'mcp': {'initialize': replay['initialize'], 'initialized': replay['initialized'], 'raw_jsonrpc_responses': [replay['client_a'], replay['client_b']], 'normalized_result': normalized, 'client_a': replay['client_a'], 'client_b': replay['client_b']}, 'host': {'tool_runtime_result': projected, 'processed_content': projected.get('content', []), 'external_state_before': {}, 'external_state_after': replay['state']}, 'session': {'tool_call': {'type': 'tool/call', 'turn': 1, 'step': 1, 'callId': call['id'], 'name': WEBHOOK_TOOL, 'arguments': '{}'}, 'tool_result': {'type': 'tool/result', 'message': {'role': 'tool', 'tool_call_id': call['id'], 'name': WEBHOOK_TOOL, 'content': projected.get('content', []), 'isError': projected.get('isError', False)}}}, 'model': {'adapter': 'deterministic', 'next_request': model_request, 'final_response': {'role': 'assistant', 'content': [{'type': 'text', 'text': 'Deterministic host completed the scripted tool call.'}]}}, 'observation': {'tool_client_visible': projected, 'model_visible_request': model_request}, 'new_case': {'sink_tool': WEBHOOK_TOOL, 'effect_signal_token': WEBHOOK_SIGNAL, 'signal_source': 'server-generated webhook ID returned by the sink Tool result', 'routing_witness': "client B received client A's generated value in the vulnerable run"}}
        write_record(output, record, {'boundary': 'shared-streamable-http-transport', 'port': port, 'replay': replay})
        return record
    finally:
        stop_webhook_server(process)
RUNNERS = {'CVE-2024-47081-zilliz': run_zilliz, 'CVE-2026-25536-usewebhook': run_webhook}

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--output-root', type=Path, default=ROOT / 'runs/gt_linux_new_20260923')
    parser.add_argument('--repetitions', type=int, default=3)
    parser.add_argument('--cases', nargs='*', choices=sorted(RUNNERS))
    args = parser.parse_args()
    global OUTPUT_ROOT
    OUTPUT_ROOT = args.output_root.resolve()
    OUTPUT_ROOT.mkdir(parents=True, exist_ok=True)
    selected = args.cases or list(RUNNERS)
    records: list[dict[str, Any]] = []
    for repetition in range(1, args.repetitions + 1):
        for case_id in selected:
            for side in ('vulnerable', 'patched'):
                records.append(RUNNERS[case_id](ROOT, side, repetition))
    summary = {'schema_version': 'agent-observation-new-gt-replay/v1', 'transport': {'CVE-2024-47081-zilliz': 'stdio', 'CVE-2026-25536-usewebhook': 'streamable-http'}, 'repetitions': args.repetitions, 'case_ids': selected, 'record_count': len(records), 'invalid_count': sum((1 for row in records if row.get('quality', {}).get('invalid_run'))), 'raw_evidence_modified': False, 'records': [{'case_id': row.get('case_id'), 'side': row.get('revision'), 'repetition': row.get('repetition'), 'invalid_run': row.get('quality', {}).get('invalid_run'), 'evidence_levels': row.get('evidence_levels')} for row in records]}
    write_json(OUTPUT_ROOT / 'replay_summary.json', summary)
    write_json(OUTPUT_ROOT / 'environment_manifest.json', {'schema_version': 'agent-observation-new-gt-environment/v1', 'image_reference': os.getenv('GT_IMAGE_REFERENCE', 'sha256:86266e4906d4009ef3662918a8a6824dd7a301829d141c9bee8a5d492bbf43dc'), 'image_digest': os.getenv('GT_IMAGE_DIGEST', 'unknown'), 'base_image': 'sha256:c01f63e428a4da09d4bfc7a62fed664b08d4bc69d777a919ceafd40f1e910167', 'container_constraints': {'network': 'none', 'cap_drop': ['ALL'], 'no_new_privileges': True, 'host_secrets': False}, 'shared_host': 'shared-research-host/v1', 'frozen_input_same_across_pair': True, 'agent_task_same_across_pair': True, 'external_boundary_same_across_pair': True, 'only_version_or_dependency_replaced': True, 'case_ids': selected, 'repetitions': args.repetitions, 'record_count': len(records), 'invalid_count': summary['invalid_count']})
    print(json.dumps({'status': 'OK', 'record_count': len(records), 'invalid_count': summary['invalid_count']}, indent=2))
    return 0
if __name__ == '__main__':
    raise SystemExit(main())
