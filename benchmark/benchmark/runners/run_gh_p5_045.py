from __future__ import annotations
import argparse
import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from shared_host_runner import evidence_rows, run_shared_host_case
PROXY_SIGNAL = 'GH_P5_045_PROXY_FEED_READBACK'
DIRECT_SIGNAL = 'GH_P5_045_DIRECT_FEED_READBACK'
TARGET_PORT = 18081
PROXY_PORT = 18082

def rss_body(title: str) -> bytes:
    return f"""<?xml version="1.0" encoding="UTF-8"?><rss version="2.0"><channel><title>GH-P5-045 controlled feed</title><item><title>{title}</title><link>http://[::1]:{TARGET_PORT}/item</link><description>controlled paired replay</description></item></channel></rss>""".encode()

class Boundary:

    def __init__(self) -> None:
        self.requests: list[dict[str, Any]] = []
        boundary = self

        class TargetHandler(BaseHTTPRequestHandler):

            def do_GET(self) -> None:
                boundary.requests.append({'role': 'target', 'method': self.command, 'path': self.path, 'headers': dict(self.headers)})
                body = rss_body(DIRECT_SIGNAL)
                self.send_response(200)
                self.send_header('Content-Type', 'application/rss+xml')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args: object) -> None:
                return

        class ProxyHandler(BaseHTTPRequestHandler):

            def do_GET(self) -> None:
                boundary.requests.append({'role': 'proxy', 'method': self.command, 'path': self.path, 'headers': dict(self.headers)})
                body = rss_body(PROXY_SIGNAL)
                self.send_response(200)
                self.send_header('Content-Type', 'application/rss+xml')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args: object) -> None:
                return
        target_server = type('IPv6TargetServer', (ThreadingHTTPServer,), {'address_family': socket.AF_INET6})
        self.target = target_server(('::1', TARGET_PORT), TargetHandler)
        self.proxy = ThreadingHTTPServer(('127.0.0.1', PROXY_PORT), ProxyHandler)
        self.threads = [threading.Thread(target=self.target.serve_forever, daemon=True), threading.Thread(target=self.proxy.serve_forever, daemon=True)]

    def start(self) -> None:
        for thread in self.threads:
            thread.start()

    def close(self) -> None:
        self.target.shutdown()
        self.proxy.shutdown()
        self.target.server_close()
        self.proxy.server_close()
        for thread in self.threads:
            thread.join(timeout=3)

    def snapshot(self) -> dict[str, Any]:
        return {'boundary': 'container-local-ipv6-loopback-target-and-http-proxy-rss', 'target': f"""[::1]:{TARGET_PORT}""", 'proxy': f"""127.0.0.1:{PROXY_PORT}""", 'requests': list(self.requests)}

def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')

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
        side_root = '/opt/deps/vulnerable' if args.side == 'vulnerable' else '/opt/deps/fixed'
        axios_version = '1.14.0' if args.side == 'vulnerable' else '1.15.0'
        env = {'NODE_PATH': f"""{side_root}/node_modules""", 'HTTP_PROXY': f"""http://127.0.0.1:{PROXY_PORT}""", 'HTTPS_PROXY': f"""http://127.0.0.1:{PROXY_PORT}""", 'ALL_PROXY': '', 'NO_PROXY': 'localhost,127.0.0.1,::1', 'http_proxy': f"""http://127.0.0.1:{PROXY_PORT}""", 'https_proxy': f"""http://127.0.0.1:{PROXY_PORT}""", 'all_proxy': '', 'no_proxy': 'localhost,127.0.0.1,::1', 'PYTHONPATH': '/opt/gt', 'NODE_OPTIONS': ''}
        record = run_shared_host_case(run_id=f"""{spec['case_id']}-{args.side}-{args.repetition}""", case_id=spec['case_id'], revision=args.side, repetition=args.repetition, command=['node', f"""/opt/server/{args.side}/build/index.js"""], cwd=Path(f"""/opt/server/{args.side}"""), env=env, server_name=spec['discovery']['repository_url'], tool_name=spec['mcp_path_review']['tool'], tool_arguments=spec['mcp_path_review']['tool_arguments'], task=spec['experiment']['agent_task'], system_prompt='You are a deterministic research host. Use the frozen tool call and report only its returned result.', server_revision=f"""{spec['discovery']['repository_commit']}; axios=={axios_version}""", timeout=float(spec['runner']['timeout_seconds']))
        snapshot = boundary.snapshot()
        record['external_boundary'] = snapshot
        serialized = json.dumps(record, ensure_ascii=False)
        l4 = json.dumps(record.get('model', {}).get('next_request', {}), ensure_ascii=False)
        record['gh_p5_045_probe'] = {'proxy_signal': PROXY_SIGNAL, 'direct_signal': DIRECT_SIGNAL, 'axios_version': axios_version, 'proxy_request_count': sum((item.get('role') == 'proxy' for item in snapshot['requests'])), 'target_request_count': sum((item.get('role') == 'target' for item in snapshot['requests'])), 'proxy_signal_in_tool_and_l4': PROXY_SIGNAL in serialized and PROXY_SIGNAL in l4, 'direct_signal_in_tool_and_l4': DIRECT_SIGNAL in serialized and DIRECT_SIGNAL in l4, 'input_signal_absent': PROXY_SIGNAL not in json.dumps(spec['mcp_path_review']['tool_arguments'], ensure_ascii=False)}
        write_json(args.output / 'host_record.json', record)
        (args.output / 'evidence.jsonl').write_text(''.join((json.dumps(row, ensure_ascii=False) + '\n' for row in evidence_rows(record))), encoding='utf-8')
        write_json(args.output / 'boundary_snapshot.json', snapshot)
        valid = not record['quality']['invalid_run'] and all((value == 'observed' for value in record['evidence_levels'].values()))
        print(json.dumps({'status': 'OK' if valid else 'INVALID', 'output': str(args.output)}, ensure_ascii=False))
        return 0 if valid else 1
    finally:
        boundary.close()
if __name__ == '__main__':
    raise SystemExit(main())
