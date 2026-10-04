"""Replay Axios NO_PROXY paired cases on a shared Linux Host."""
from __future__ import annotations
import argparse
import asyncio
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
CASES = {'CVE-2025-62718-webhook': {'transport': 'stdio'}, 'CVE-2025-62718-openapi': {'transport': 'stdio'}, 'CVE-2025-62718-websnatch': {'transport': 'streamable-http'}, 'CVE-2025-62718-websnatch-control': {'transport': 'streamable-http'}, 'CVE-2025-62718-markdown': {'transport': 'stdio'}, 'CVE-2025-62718-qpd-image': {'transport': 'stdio'}, 'CVE-2025-62718-sun-image': {'transport': 'stdio'}, 'CVE-2025-62718-avr-search': {'transport': 'stdio'}, 'CVE-2025-62718-avr-list': {'transport': 'stdio'}, 'CVE-2025-62718-avr-page': {'transport': 'stdio'}}
WEBHOOK_MARKER = 'GT_PROXY_WEBHOOK_RESPONSE'
OPENAPI_MARKER = 'GT_PROXY_OPENAPI_RESPONSE'
MARKDOWN_MARKER = 'GT_PROXY_MARKDOWN_RESPONSE'
QPD_MARKER = 'GT_PROXY_QPD_RESPONSE'
SUN_MARKER = 'GT_PROXY_SUN_AUTHOR'
WEB_SNATCH_PROXY_CONTENT_TYPE = 'application/json'
AVR_MARKERS = {'search': 'GT_PROXY_AVR_SEARCH', 'list': 'GT_PROXY_AVR_LIST', 'page': 'GT_PROXY_AVR_PAGE'}

def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')

def write_record(path: Path, record: dict[str, Any], boundary: dict[str, Any]) -> None:
    record['external_boundary'] = boundary
    record['field_digests'] = {'record': field_digest(record)}
    write_json(path / 'host_record.json', record)
    (path / 'evidence.jsonl').write_text(''.join((json.dumps(row, ensure_ascii=False) + '\n' for row in evidence_rows(record))), encoding='utf-8')

class ProxyBoundary:

    def __init__(self, mode: str, control: bool=False) -> None:
        self.mode = mode
        self.control = control
        self.proxy_requests: list[dict[str, Any]] = []
        self.target_requests: list[dict[str, Any]] = []
        boundary = self

        class ProxyHandler(BaseHTTPRequestHandler):

            def _record(self) -> None:
                boundary.proxy_requests.append({'method': self.command, 'path': self.path, 'headers': dict(self.headers)})

            def do_HEAD(self) -> None:
                self._record()
                self.send_response(200)
                self.send_header('Content-Type', 'application/json' if boundary.mode == 'websnatch' else 'application/json')
                self.send_header('Content-Length', str(len(boundary.body(self.path))))
                self.end_headers()

            def do_GET(self) -> None:
                self._record()
                raw, content_type = boundary.proxy_payload(self.path)
                self.send_response(200)
                self.send_header('Content-Type', content_type)
                self.send_header('Content-Length', str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_POST(self) -> None:
                self._record()
                length = int(self.headers.get('Content-Length', '0'))
                if length:
                    self.rfile.read(length)
                raw, content_type = boundary.proxy_payload(self.path)
                self.send_response(200)
                self.send_header('Content-Type', content_type)
                self.send_header('Content-Length', str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def log_message(self, *_args: object) -> None:
                return

        class TargetHandler(BaseHTTPRequestHandler):

            def _record(self) -> None:
                boundary.target_requests.append({'method': self.command, 'path': self.path, 'headers': dict(self.headers)})

            def do_HEAD(self) -> None:
                self._record()
                raw, content_type = boundary.target_payload(self.path)
                self.send_response(200)
                self.send_header('Content-Type', content_type)
                self.send_header('Content-Length', str(len(raw)))
                self.end_headers()

            def do_GET(self) -> None:
                self._record()
                raw, content_type = boundary.target_payload(self.path)
                self.send_response(200)
                self.send_header('Content-Type', content_type)
                self.send_header('Content-Length', str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_POST(self) -> None:
                self._record()
                length = int(self.headers.get('Content-Length', '0'))
                if length:
                    self.rfile.read(length)
                raw, content_type = boundary.target_payload()
                self.send_response(200)
                self.send_header('Content-Type', content_type)
                self.send_header('Content-Length', str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def log_message(self, *_args: object) -> None:
                return
        self.proxy = ThreadingHTTPServer(('127.0.0.1', 0), ProxyHandler)
        self.target = ThreadingHTTPServer(('127.0.0.1', 0), TargetHandler)
        self.proxy_thread = threading.Thread(target=self.proxy.serve_forever, daemon=True)
        self.target_thread = threading.Thread(target=self.target.serve_forever, daemon=True)

    def body(self, request_path: str='/') -> bytes:
        if self.mode == 'openapi':
            return json.dumps({'openapi': '3.0.0', 'info': {'title': OPENAPI_MARKER, 'version': '1'}, 'paths': {}}).encode('utf-8')
        if self.mode == 'webhook':
            return json.dumps({'marker': WEBHOOK_MARKER}).encode('utf-8')
        if self.mode == 'markdown':
            return MARKDOWN_MARKER.encode('utf-8')
        if self.mode == 'qpd-image':
            return QPD_MARKER.encode('utf-8')
        if self.mode == 'sun-image':
            if request_path.split('?', 1)[0].endswith('/search/photos'):
                return json.dumps({'results': [{'urls': {'regular': self.proxy_url() + '/image.jpg'}, 'alt_description': 'proxy', 'user': {'name': SUN_MARKER, 'links': {'html': 'http://proxy.invalid'}}, 'links': {'download_location': 'http://proxy.invalid/download'}}]}).encode('utf-8')
            return b'GT_PROXY_SUN_IMAGE'
        if self.mode.startswith('avr-'):
            marker = self.mode.removeprefix('avr-')
            if marker == 'search':
                return json.dumps({'data': {'pages': {'search': {'results': [{'id': '1', 'title': AVR_MARKERS[marker], 'description': 'controlled', 'path': 'gt', 'locale': 'en'}], 'totalHits': 1}}}}).encode('utf-8')
            if marker == 'list':
                return json.dumps({'data': {'pages': {'list': [{'id': 1, 'title': AVR_MARKERS[marker], 'description': 'controlled', 'path': 'gt', 'locale': 'en', 'contentType': 'markdown', 'isPublished': True, 'isPrivate': False, 'createdAt': '2026-09-23T00:00:00.000Z', 'updatedAt': '2026-09-23T00:00:00.000Z', 'tags': [{'title': 'gt'}]}]}}}).encode('utf-8')
            return json.dumps({'data': {'pages': {'singleByPath': {'id': 1, 'title': AVR_MARKERS[marker], 'description': 'controlled', 'path': 'gt-page', 'locale': 'en', 'content': AVR_MARKERS[marker] + '_CONTENT', 'contentType': 'markdown', 'isPublished': True, 'isPrivate': False, 'createdAt': '2026-09-23T00:00:00.000Z', 'updatedAt': '2026-09-23T00:00:00.000Z', 'tags': [{'id': 1, 'title': 'gt'}], 'authorId': 1, 'authorName': 'controlled', 'authorEmail': 'gt@example.invalid'}}}}).encode('utf-8')
        return b'GT_PROXY_FILE_CONTENT'

    def proxy_payload(self, request_path: str='/') -> tuple[bytes, str]:
        if self.mode == 'openapi':
            return (self.body(), 'application/json')
        if self.mode == 'webhook':
            return (self.body(), 'application/json')
        if self.mode == 'sun-image' and (not request_path.split('?', 1)[0].endswith('/search/photos')):
            return (self.body(request_path), 'image/jpeg')
        if self.mode == 'sun-image':
            return (self.body(request_path), 'application/json')
        if self.mode.startswith('avr-'):
            return (self.body(request_path), 'application/json')
        return (self.body(), 'application/json')

    def target_payload(self, request_path: str='/') -> tuple[bytes, str]:
        if self.mode == 'openapi':
            return (json.dumps({'openapi': '3.0.0', 'info': {'title': 'GT_DIRECT_TARGET', 'version': '1'}, 'paths': {}}).encode('utf-8'), 'application/json')
        if self.mode == 'webhook':
            return (json.dumps({'marker': 'GT_DIRECT_TARGET'}).encode('utf-8'), 'application/json')
        if self.mode == 'markdown':
            return (b'GT_DIRECT_MARKDOWN_RESPONSE', 'text/markdown')
        if self.mode == 'qpd-image':
            return (b'GT_DIRECT_QPD_RESPONSE', 'image/jpeg')
        if self.mode == 'sun-image':
            if not request_path.split('?', 1)[0].endswith('/search/photos'):
                return (b'GT_DIRECT_SUN_IMAGE', 'image/jpeg')
            return (json.dumps({'results': [{'urls': {'regular': self.target_url(normalized=True) + '/image.jpg'}, 'alt_description': 'direct', 'user': {'name': 'GT_DIRECT_SUN_AUTHOR', 'links': {'html': 'http://direct.invalid'}}, 'links': {'download_location': 'http://direct.invalid/download'}}]}).encode('utf-8'), 'application/json')
        if self.mode.startswith('avr-'):
            marker = self.mode.removeprefix('avr-')
            if marker == 'search':
                return (json.dumps({'data': {'pages': {'search': {'results': [{'id': '1', 'title': 'GT_DIRECT_AVR_SEARCH', 'description': 'direct', 'path': 'direct', 'locale': 'en'}], 'totalHits': 1}}}}).encode('utf-8'), 'application/json')
            if marker == 'list':
                return (json.dumps({'data': {'pages': {'list': [{'id': 1, 'title': 'GT_DIRECT_AVR_LIST', 'description': 'direct', 'path': 'direct', 'locale': 'en', 'contentType': 'markdown', 'isPublished': True, 'isPrivate': False, 'createdAt': '2026-09-23T00:00:00.000Z', 'updatedAt': '2026-09-23T00:00:00.000Z', 'tags': [{'title': 'direct'}]}]}}}).encode('utf-8'), 'application/json')
            return (json.dumps({'data': {'pages': {'singleByPath': {'id': 1, 'title': 'GT_DIRECT_AVR_PAGE', 'description': 'direct', 'path': 'gt-page', 'locale': 'en', 'content': 'GT_DIRECT_AVR_PAGE_CONTENT', 'contentType': 'markdown', 'isPublished': True, 'isPrivate': False, 'createdAt': '2026-09-23T00:00:00.000Z', 'updatedAt': '2026-09-23T00:00:00.000Z', 'tags': [{'id': 1, 'title': 'direct'}], 'authorId': 1, 'authorName': 'direct', 'authorEmail': 'direct@example.invalid'}}}}).encode('utf-8'), 'application/json')
        return (b'GT_DIRECT_FILE_CONTENT', 'text/plain')

    @property
    def proxy_port(self) -> int:
        return int(self.proxy.server_port)

    @property
    def target_port(self) -> int:
        return int(self.target.server_port)

    def start(self) -> None:
        self.proxy_thread.start()
        self.target_thread.start()

    def target_url(self, normalized: bool=False) -> str:
        host = '127.0.0.1' if normalized else 'localhost.'
        return f"""http://{host}:{self.target_port}/gt-probe"""

    def proxy_url(self) -> str:
        return f"""http://127.0.0.1:{self.proxy_port}"""

    def snapshot(self) -> dict[str, Any]:
        return {'boundary': 'axios-no-proxy-normalization-controlled-proxy-and-target', 'mode': self.mode, 'proxy_request_count': len(self.proxy_requests), 'target_request_count': len(self.target_requests), 'proxy_requests': list(self.proxy_requests), 'target_requests': list(self.target_requests), 'proxy_marker': WEBHOOK_MARKER if self.mode == 'webhook' else OPENAPI_MARKER if self.mode == 'openapi' else MARKDOWN_MARKER if self.mode == 'markdown' else QPD_MARKER if self.mode == 'qpd-image' else SUN_MARKER if self.mode == 'sun-image' else AVR_MARKERS.get(self.mode.removeprefix('avr-'), WEB_SNATCH_PROXY_CONTENT_TYPE) if self.mode.startswith('avr-') else WEB_SNATCH_PROXY_CONTENT_TYPE, 'proxy_hit': bool(self.proxy_requests), 'target_hit': bool(self.target_requests)}

    def close(self) -> None:
        self.proxy.shutdown()
        self.target.shutdown()
        self.proxy.server_close()
        self.target.server_close()
        self.proxy_thread.join(timeout=3)
        self.target_thread.join(timeout=3)

def neutral_env(boundary: ProxyBoundary, *, use_proxy: bool=True) -> dict[str, str]:
    return {'NO_PROXY': 'localhost,127.0.0.1', 'no_proxy': 'localhost,127.0.0.1', 'HTTP_PROXY': boundary.proxy_url() if use_proxy else '', 'HTTPS_PROXY': boundary.proxy_url() if use_proxy else '', 'ALL_PROXY': '', 'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin', 'NODE_NO_WARNINGS': '1'}

def case_output(case_id: str, side: str, repetition: int) -> Path:
    return (OUTPUT_ROOT or ROOT / 'runs/gt_linux_proxy_20260923') / case_id / side / str(repetition)

def run_stdio_proxy_case(root: Path, case_id: str, side: str, repetition: int) -> dict[str, Any]:
    if case_id.endswith('webhook'):
        mode = 'webhook'
    elif case_id.endswith('openapi'):
        mode = 'openapi'
    elif case_id.endswith('markdown'):
        mode = 'markdown'
    elif case_id.endswith('qpd-image'):
        mode = 'qpd-image'
    elif case_id.endswith('sun-image'):
        mode = 'sun-image'
    elif case_id.endswith('avr-search'):
        mode = 'avr-search'
    elif case_id.endswith('avr-list'):
        mode = 'avr-list'
    else:
        mode = 'avr-page'
    boundary = ProxyBoundary(mode)
    boundary.start()
    target = boundary.target_url()
    if mode == 'webhook':
        source = root / 'proxy_cases/webhook' / side
        command = ['node', str(source / 'dist/index.js')]
        env = neutral_env(boundary)
        tool = 'send_webhook'
        args = {'url': target, 'method': 'GET', 'parameters': {'frozen': 'gt'}}
        server = 'rafabarbosa/webhook_mcp'
        revision = f"""source@4ca7c43; axios=={('1.9.0' if side == 'vulnerable' else '1.15.0')}"""
        task = 'Call send_webhook with the frozen URL and report the returned response.'
        token = WEBHOOK_MARKER
    elif mode == 'openapi':
        source = root / 'case_assets/expanded_cases/openapi_directory' / side
        command = ['node', str(source / 'dist/index.js')]
        env = neutral_env(boundary)
        env.update({'DISABLE_CACHE': 'true', 'PRIMARY_API_BASE_URL': boundary.target_url(normalized=True), 'SECONDARY_API_BASE_URL': boundary.target_url(normalized=True)})
        tool = 'get_openapi_spec'
        args = {'url': target}
        server = 'rawveg/openapi-directory-mcp'
        revision = f"""source@7d439005; axios=={('1.13.1' if side == 'vulnerable' else '1.16.0')}"""
        task = 'Call get_openapi_spec with the frozen URL and report the returned specification.'
        token = OPENAPI_MARKER
    elif mode == 'markdown':
        source = root / 'case_assets/expanded_cases/markdown_downloader' / side
        command = ['node', str(source / 'build/index.js')]
        env = neutral_env(boundary)
        env['MARKDOWN_JINA_BASE_URL'] = target
        tool = 'download_markdown'
        args = {'url': 'gt-page', 'subdirectory': 'gt'}
        server = 'dazeb/markdown-downloader'
        revision = f"""source@candidate-frozen; axios=={('1.9.0' if side == 'vulnerable' else '1.16.0')}"""
        task = 'Call download_markdown with the frozen page identifier and report the returned result.'
        token = MARKDOWN_MARKER
    elif mode == 'qpd-image':
        source = root / 'case_assets/expanded_cases/qpd_image_downloader' / side
        command = ['node', str(source / 'build/index.js')]
        env = neutral_env(boundary)
        tool = 'download_image'
        args = {'url': target, 'outputPath': '/tmp/gt-qpd/image.jpg'}
        server = 'qpd-v/mcp-image-downloader'
        revision = f"""source@candidate-frozen; axios=={('1.7.9' if side == 'vulnerable' else '1.16.0')}"""
        task = 'Call download_image with the frozen URL and report the returned result.'
        token = QPD_MARKER
    elif mode == 'sun-image':
        source = root / 'case_assets/expanded_cases/sun_image_downloader' / side
        command = ['node', str(source / 'projection_entry.js')]
        env = neutral_env(boundary)
        env.update({'UNSPLASH_ACCESS_KEY': 'gt-key', 'UNSPLASH_API_BASE_URL': target})
        tool = 'downloadProjectImage'
        args = {'query': 'gt-sun', 'saveDir': '/tmp/gt-sun', 'filename': 'gt-sun'}
        server = 'SunFei123456/mcp-image-downloader'
        revision = f"""source@candidate-frozen; axios=={('1.11.0' if side == 'vulnerable' else '1.16.0')}"""
        task = 'Call downloadProjectImage with the frozen query and report the returned metadata.'
        token = SUN_MARKER
    else:
        source = root / 'proxy_cases/avr' / side
        command = ['node', str(source / 'dist/index.js')]
        env = neutral_env(boundary)
        env.update({'WIKI_JS_BASE_URL': target, 'WIKI_JS_API_KEY': 'gt-api-key', 'LOG_LEVEL': 'error'})
        avr_kind = mode.removeprefix('avr-')
        if avr_kind == 'search':
            tool = 'search_wiki_pages'
            args = {'query': 'gt-search', 'page': 1, 'limit': 10}
            task = 'Call search_wiki_pages with the frozen query and report the returned pages.'
            token = AVR_MARKERS[avr_kind]
        elif avr_kind == 'list':
            tool = 'list_wiki_pages'
            args = {'page': 1, 'limit': 10}
            task = 'Call list_wiki_pages with the frozen pagination and report the returned pages.'
            token = AVR_MARKERS[avr_kind]
        else:
            tool = 'get_wiki_page'
            args = {'pageId': 'gt-page'}
            task = 'Call get_wiki_page with the frozen page path and report the returned page.'
            token = AVR_MARKERS[avr_kind]
        server = 'agentvoiceresponse/avr-docs-mcp'
        revision = f"""source@839bc61eaab1529db5ae2abec49110e4559daf4c; projection=linux-stdio; axios=={('1.12.2' if side == 'vulnerable' else '1.15.0')}"""
    try:
        record = run_shared_host_case(run_id=f"""{case_id}-{side}-{repetition}""", case_id=case_id, revision=side, repetition=repetition, command=command, cwd=source, env=env, server_name=server, tool_name=tool, tool_arguments=args, task=task, system_prompt='You are a deterministic research host. Use the requested tool and report its result.', server_revision=revision, timeout=45)
        record['new_case'] = {'sink_tool': tool, 'effect_signal_token': token, 'signal_source': 'controlled proxy response returned by the declared sink Tool', 'proxy_response_is_not_an_effect_unless_present_in_sink_result': mode in {'markdown', 'qpd-image'}}
        write_record(case_output(case_id, side, repetition), record, boundary.snapshot())
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
        for line in response.text.splitlines():
            if not line.startswith('data:'):
                continue
            try:
                value = json.loads(line[5:].strip())
            except ValueError:
                continue
            return value if isinstance(value, dict) else {'value': value}
        return {'text': response.text}
    return value if isinstance(value, dict) else {'value': value}

async def post_mcp(client: httpx.AsyncClient, url: str, body: dict[str, Any], session_id: str | None=None) -> tuple[dict[str, Any], str | None]:
    headers = {'accept': 'application/json, text/event-stream', 'content-type': 'application/json'}
    if session_id:
        headers['mcp-session-id'] = session_id
    try:
        response = await client.post(url, headers=headers, json=body, timeout=10)
        return ({'status': response.status_code, 'json': parse_json_response(response), 'headers': dict(response.headers)}, response.headers.get('mcp-session-id') or session_id)
    except (httpx.TimeoutException, httpx.HTTPError) as error:
        return ({'error': f"""{type(error).__name__}: {error}"""}, session_id)

def start_websnatch(root: Path, side: str, boundary: ProxyBoundary, log_path: Path, use_proxy: bool) -> subprocess.Popen[str]:
    source = root / 'proxy_cases/websnatch' / side
    env = neutral_env(boundary, use_proxy=use_proxy)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    stream = log_path.open('w', encoding='utf-8')
    process = subprocess.Popen(['node', str(source / 'index.js')], cwd=source, env=env, stdout=stream, stderr=subprocess.STDOUT, text=True)
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"""websnatch exited with {process.returncode}; see {log_path}""")
        try:
            with socket.create_connection(('127.0.0.1', 3000), timeout=0.5):
                return process
        except OSError:
            time.sleep(0.1)
    process.terminate()
    raise RuntimeError(f"""websnatch did not start; see {log_path}""")

def stop_process(process: subprocess.Popen[str]) -> None:
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

async def replay_websnatch(boundary: ProxyBoundary, control: bool) -> dict[str, Any]:
    url = 'http://127.0.0.1:3000/mcp'
    target = boundary.target_url(normalized=control)
    async with httpx.AsyncClient(trust_env=False) as client:
        initialize, session_id = await post_mcp(client, url, {'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {'protocolVersion': '2025-06-18', 'capabilities': {}, 'clientInfo': {'name': 'gt-proxy-host', 'version': '1'}}})
        initialized, session_id = await post_mcp(client, url, {'jsonrpc': '2.0', 'method': 'notifications/initialized'}, session_id)
        call, session_id = await post_mcp(client, url, {'jsonrpc': '2.0', 'id': 2, 'method': 'tools/call', 'params': {'name': 'downloadFromWeb', 'arguments': {'url': target, 'fileName': 'gt-probe'}}}, session_id)
    return {'initialize': initialize, 'initialized': initialized, 'call': call, 'session_id': session_id, 'target_url': target}

def run_websnatch(root: Path, side: str, repetition: int, control: bool) -> dict[str, Any]:
    case_id = 'CVE-2025-62718-websnatch-control' if control else 'CVE-2025-62718-websnatch'
    boundary = ProxyBoundary('websnatch', control=control)
    boundary.start()
    output = case_output(case_id, side, repetition)
    process = start_websnatch(root, side, boundary, output / 'server.log', use_proxy=True)
    try:
        replay = asyncio.run(replay_websnatch(boundary, control))
        normalized = normalize_http_result(replay['call'])
        projected = host_project(normalized)
        call = {'id': 'det-call-1', 'name': 'downloadFromWeb', 'arguments': {'url': replay['target_url'], 'fileName': 'gt-probe'}}
        tools = [{'name': 'downloadFromWeb', 'description': 'Download any file from a given URL', 'inputSchema': {'type': 'object', 'properties': {'url': {'type': 'string'}, 'fileName': {'type': 'string'}}, 'required': ['url']}}]
        request = build_model_request('You are a deterministic research host. Use the requested tool and report its result.', tools, 'Call downloadFromWeb with the frozen URL and report its returned result.', call, projected)
        record = {'schema_version': 'agent-observation-record/v1', 'run_id': f"""{case_id}-{side}-{repetition}""", 'case_id': case_id, 'revision': side, 'repetition': repetition, 'identity': {'server_name': 'EivorRrz/WebSnatch-A-lightning-fast-MCP-powered-Downloader', 'server_revision': f"""source@592ae79; axios=={('1.9.0' if side == 'vulnerable' else '1.15.0')}""", 'transport': 'streamable-http', 'command': ['node', 'index.js'], 'tool_name': 'downloadFromWeb'}, 'quality': {'invalid_run': False, 'unexpected_exception': None, 'timeout': False, 'retries': 0, 'reconnects': 0}, 'evidence_levels': {level: 'observed' for level in LEVELS}, 'mcp': {'initialize': replay['initialize'], 'initialized': replay['initialized'], 'raw_jsonrpc_responses': [replay['call']], 'normalized_result': normalized, 'http_response': replay['call']}, 'host': {'tool_runtime_result': projected, 'processed_content': projected.get('content', []), 'external_state_before': {}, 'external_state_after': {}}, 'session': {'tool_call': {'type': 'tool/call', 'turn': 1, 'step': 1, 'callId': call['id'], 'name': call['name'], 'arguments': json.dumps(call['arguments'], sort_keys=True)}, 'tool_result': {'type': 'tool/result', 'message': {'role': 'tool', 'tool_call_id': call['id'], 'name': call['name'], 'content': projected.get('content', []), 'isError': projected.get('isError', False)}}}, 'model': {'adapter': 'deterministic', 'next_request': request, 'final_response': {'role': 'assistant', 'content': [{'type': 'text', 'text': 'Deterministic host completed the scripted tool call.'}]}}, 'observation': {'tool_client_visible': projected, 'model_visible_request': request}, 'new_case': {'sink_tool': 'downloadFromWeb', 'effect_signal_token': WEB_SNATCH_PROXY_CONTENT_TYPE, 'signal_source': 'proxy-controlled response Content-Type returned as sink metadata', 'control_input': control}}
        write_record(output, record, boundary.snapshot())
        return record
    finally:
        stop_process(process)
        boundary.close()
RUNNERS = {'CVE-2025-62718-webhook': lambda root, side, repetition: run_stdio_proxy_case(root, 'CVE-2025-62718-webhook', side, repetition), 'CVE-2025-62718-openapi': lambda root, side, repetition: run_stdio_proxy_case(root, 'CVE-2025-62718-openapi', side, repetition), 'CVE-2025-62718-websnatch': lambda root, side, repetition: run_websnatch(root, side, repetition, False), 'CVE-2025-62718-websnatch-control': lambda root, side, repetition: run_websnatch(root, side, repetition, True), 'CVE-2025-62718-markdown': lambda root, side, repetition: run_stdio_proxy_case(root, 'CVE-2025-62718-markdown', side, repetition), 'CVE-2025-62718-qpd-image': lambda root, side, repetition: run_stdio_proxy_case(root, 'CVE-2025-62718-qpd-image', side, repetition), 'CVE-2025-62718-sun-image': lambda root, side, repetition: run_stdio_proxy_case(root, 'CVE-2025-62718-sun-image', side, repetition), 'CVE-2025-62718-avr-search': lambda root, side, repetition: run_stdio_proxy_case(root, 'CVE-2025-62718-avr-search', side, repetition), 'CVE-2025-62718-avr-list': lambda root, side, repetition: run_stdio_proxy_case(root, 'CVE-2025-62718-avr-list', side, repetition), 'CVE-2025-62718-avr-page': lambda root, side, repetition: run_stdio_proxy_case(root, 'CVE-2025-62718-avr-page', side, repetition)}

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--output-root', type=Path, default=ROOT / 'runs/gt_linux_proxy_20260923')
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
    summary = {'schema_version': 'agent-observation-proxy-gt-replay/v1', 'transport': {case_id: CASES[case_id]['transport'] for case_id in selected}, 'repetitions': args.repetitions, 'case_ids': selected, 'record_count': len(records), 'invalid_count': sum((1 for row in records if row.get('quality', {}).get('invalid_run'))), 'raw_evidence_modified': False, 'records': [{'case_id': row.get('case_id'), 'side': row.get('revision'), 'repetition': row.get('repetition'), 'invalid_run': row.get('quality', {}).get('invalid_run'), 'evidence_levels': row.get('evidence_levels')} for row in records]}
    write_json(OUTPUT_ROOT / 'replay_summary.json', summary)
    write_json(OUTPUT_ROOT / 'environment_manifest.json', {'schema_version': 'agent-observation-proxy-gt-environment/v1', 'image_reference': os.getenv('GT_IMAGE_REFERENCE', 'sha256:5d250f71758f13405365c34492add0dad9964c4e56137274e8ddeb0e8a4cb044'), 'image_digest': os.getenv('GT_IMAGE_DIGEST', 'unknown'), 'base_image': 'sha256:24adea2f2959f25a65396ebca8525e730be4d1bd8a286871daacdf60a9c68d45', 'container_constraints': {'network': 'none', 'cap_drop': ['ALL'], 'no_new_privileges': True, 'host_secrets': False, 'extra_hosts': {'localhost.': '127.0.0.1'}}, 'shared_host': 'shared-research-host/v1', 'frozen_input_same_across_pair': True, 'agent_task_same_across_pair': True, 'external_boundary_same_across_pair': True, 'only_version_or_dependency_replaced': True, 'case_ids': selected, 'repetitions': args.repetitions, 'record_count': len(records), 'invalid_count': summary['invalid_count']})
    print(json.dumps({'status': 'OK', 'record_count': len(records), 'invalid_count': summary['invalid_count']}, indent=2))
    return 0
if __name__ == '__main__':
    raise SystemExit(main())
