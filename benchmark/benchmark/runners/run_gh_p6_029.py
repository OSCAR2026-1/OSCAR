from __future__ import annotations
import argparse
import json
import ssl
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from shared_host_runner import evidence_rows, run_shared_host_case
PROXY_SIGNAL = 'GT_P6_029_PROXY_WEREAD_BOOK'
DIRECT_SIGNAL = 'GT_P6_029_DIRECT_WEREAD_BOOK'
PROXY_COOKIE = 'GT_P6_029_PROXY_COOKIE'
DIRECT_COOKIE = 'GT_P6_029_DIRECT_COOKIE'

class WereadBoundary:

    def __init__(self, cert: Path, key: Path) -> None:
        self.proxy_requests: list[dict[str, Any]] = []
        self.cookie_target_requests: list[dict[str, Any]] = []
        self.weread_requests: list[dict[str, Any]] = []
        boundary = self

        class Handler(BaseHTTPRequestHandler):

            def _record(self, role: str) -> None:
                row = {'role': role, 'method': self.command, 'path': self.path, 'headers': dict(self.headers)}
                if role == 'proxy':
                    boundary.proxy_requests.append(row)
                elif role == 'cookie_target':
                    boundary.cookie_target_requests.append(row)
                else:
                    boundary.weread_requests.append(row)

            def _send_json(self, payload: dict[str, Any], role: str) -> None:
                self._record(role)
                body = json.dumps(payload, ensure_ascii=False).encode('utf-8')
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self) -> None:
                length = int(self.headers.get('Content-Length', '0'))
                if length:
                    self.rfile.read(length)
                if self.server.role == 'proxy':
                    self._send_json({'cookie_data': {'weread.qq.com': [{'name': 'wr_probe', 'value': PROXY_COOKIE}]}}, 'proxy')
                else:
                    self._send_json({'cookie_data': {'weread.qq.com': [{'name': 'wr_probe', 'value': DIRECT_COOKIE}]}}, 'cookie_target')

            def do_GET(self) -> None:
                cookie = self.headers.get('Cookie', '')
                marker = PROXY_SIGNAL if PROXY_COOKIE in cookie else DIRECT_SIGNAL
                if self.server.role != 'weread':
                    self._send_json({'cookie_data': {'weread.qq.com': [{'name': 'wr_probe', 'value': DIRECT_COOKIE}]}}, 'cookie_target')
                    return
                self._send_json({'bookProgress': [], 'books': [{'bookId': 'fixture-book', 'title': marker, 'author': 'fixture-author', 'translator': '', 'categories': [], 'finishReading': 0, 'paid': 0}], 'archive': []} if self.path.split('?', 1)[0].endswith('/shelf/sync') else {'books': []}, 'weread')

            def log_message(self, *_args: object) -> None:
                return
        self.proxy = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.proxy.role = 'proxy'
        self.cookie_target = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.cookie_target.role = 'cookie_target'
        self.weread = HTTPServer(('127.0.0.1', 443), Handler)
        self.weread.role = 'weread'
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=cert, keyfile=key)
        self.weread.socket = context.wrap_socket(self.weread.socket, server_side=True)
        self.threads = [threading.Thread(target=self.proxy.serve_forever, daemon=True), threading.Thread(target=self.cookie_target.serve_forever, daemon=True), threading.Thread(target=self.weread.serve_forever, daemon=True)]

    def start(self) -> None:
        for thread in self.threads:
            thread.start()

    def close(self) -> None:
        for server in (self.proxy, self.cookie_target, self.weread):
            server.shutdown()
            server.server_close()
        for thread in self.threads:
            thread.join(timeout=3)

    def snapshot(self) -> dict[str, Any]:
        return {'boundary': 'container-local-cookiecloud-proxy-direct-target-and-weread-target', 'proxy_port': self.proxy.server_port, 'cookie_target_port': self.cookie_target.server_port, 'weread_port': 443, 'proxy_requests': list(self.proxy_requests), 'cookie_target_requests': list(self.cookie_target_requests), 'weread_requests': list(self.weread_requests), 'proxy_hit': bool(self.proxy_requests), 'cookie_target_hit': bool(self.cookie_target_requests), 'weread_target_hit': bool(self.weread_requests), 'proxy_signal': PROXY_SIGNAL, 'direct_signal': DIRECT_SIGNAL}

def text_content(value: Any) -> str:
    if not isinstance(value, list):
        return ''
    return '\n'.join((item['text'] for item in value if isinstance(item, dict) and isinstance(item.get('text'), str)))

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--spec', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--side', choices=('vulnerable', 'fixed'), required=True)
    parser.add_argument('--repetition', type=int, required=True)
    args = parser.parse_args()
    spec = json.loads(args.spec.read_text(encoding='utf-8'))
    boundary = WereadBoundary(Path('/opt/gt/weread.crt'), Path('/opt/gt/weread.key'))
    boundary.start()
    try:
        app_root = f"""/opt/app/{args.side}"""
        cc_url = f"""http://localhost.:{boundary.cookie_target.server_port}"""
        env = {'HOME': '/tmp/gt-home', 'CC_URL': cc_url, 'CC_ID': 'frozen-id', 'CC_PASSWORD': 'frozen-password', 'NO_PROXY': 'localhost,127.0.0.1,::1', 'no_proxy': 'localhost,127.0.0.1,::1', 'HTTP_PROXY': f"""http://127.0.0.1:{boundary.proxy.server_port}""", 'http_proxy': f"""http://127.0.0.1:{boundary.proxy.server_port}""", 'HTTPS_PROXY': '', 'https_proxy': '', 'ALL_PROXY': '', 'all_proxy': '', 'NODE_TLS_REJECT_UNAUTHORIZED': '0', 'NODE_OPTIONS': '--require=/opt/gt-tools/node_stdio_quiet.cjs'}
        record = run_shared_host_case(run_id=f"""{spec['case_id']}-{args.side}-{args.repetition}""", case_id=spec['case_id'], revision=args.side, repetition=args.repetition, command=['node', f"""{app_root}/build/index.js"""], cwd=Path(app_root), env=env, server_name=spec['repository_url'], tool_name=spec['mcp_path']['tool'], tool_arguments=spec['experiment']['tool_arguments'], task=spec['experiment']['agent_task'], system_prompt='You are a deterministic research host. Use the frozen tool call and report only its returned Tool result.', server_revision=f"""{spec['source_commit']}; axios=={spec['versions'][args.side]}""", timeout=float(spec['runner']['timeout_seconds']))
        boundary_snapshot = boundary.snapshot()
        record['external_boundary'] = boundary_snapshot
        normalized = record.get('mcp', {}).get('normalized_result', {})
        tool_text = text_content(normalized.get('content', [])) if isinstance(normalized, dict) else ''
        next_request = record.get('model', {}).get('next_request', {})
        l4_text = json.dumps(next_request, ensure_ascii=False)
        record['p6_probe'] = {'input_cc_url': cc_url, 'input_excludes_proxy_signal': PROXY_SIGNAL not in cc_url, 'proxy_hit': boundary_snapshot['proxy_hit'], 'cookie_target_hit': boundary_snapshot['cookie_target_hit'], 'weread_target_hit': boundary_snapshot['weread_target_hit'], 'proxy_signal_in_tool_result': PROXY_SIGNAL in tool_text, 'proxy_signal_in_l4': PROXY_SIGNAL in l4_text, 'direct_signal_in_tool_result': DIRECT_SIGNAL in tool_text, 'direct_signal_in_l4': DIRECT_SIGNAL in l4_text, 'l4_is_actual_next_model_request': bool(next_request)}
        args.output.mkdir(parents=True, exist_ok=True)
        (args.output / 'host_record.json').write_text(json.dumps(record, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        (args.output / 'evidence.jsonl').write_text(''.join((json.dumps(row, ensure_ascii=False) + '\n' for row in evidence_rows(record))), encoding='utf-8')
        (args.output / 'boundary_snapshot.json').write_text(json.dumps(boundary_snapshot, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        valid = not record['quality']['invalid_run']
        print(json.dumps({'status': 'OK' if valid else 'INVALID', 'output': str(args.output)}))
        return 0 if valid else 1
    finally:
        boundary.close()
if __name__ == '__main__':
    raise SystemExit(main())
