from __future__ import annotations
import argparse
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from shared_host_runner import evidence_rows, run_shared_host_case
PROXY_SIGNAL = 'GT_P4_029_PROXY_RAW_TEXT'
DIRECT_SIGNAL = 'GT_P4_029_DIRECT_RAW_TEXT'

class Boundary:

    def __init__(self) -> None:
        self.proxy_requests: list[dict[str, Any]] = []
        self.target_requests: list[dict[str, Any]] = []
        boundary = self

        class Handler(BaseHTTPRequestHandler):

            def _serve(self, role: str) -> None:
                item = {'role': role, 'method': self.command, 'path': self.path, 'headers': dict(self.headers)}
                (boundary.proxy_requests if role == 'proxy' else boundary.target_requests).append(item)
                marker = PROXY_SIGNAL if role == 'proxy' else DIRECT_SIGNAL
                body = f"""{marker}\ncontrolled {role} response\n""".encode('utf-8')
                self.send_response(200)
                self.send_header('Content-Type', 'text/plain')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self) -> None:
                self._serve('proxy' if self.server is boundary.proxy else 'target')

            def log_message(self, *_args: object) -> None:
                return
        self.proxy = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.target = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.proxy_thread = threading.Thread(target=self.proxy.serve_forever, daemon=True)
        self.target_thread = threading.Thread(target=self.target.serve_forever, daemon=True)

    def start(self) -> None:
        self.proxy_thread.start()
        self.target_thread.start()

    def close(self) -> None:
        for server in (self.proxy, self.target):
            server.shutdown()
            server.server_close()
        self.proxy_thread.join(timeout=3)
        self.target_thread.join(timeout=3)

    def snapshot(self) -> dict[str, Any]:
        return {'boundary': 'container-local-controlled-raw-text-proxy-and-target', 'proxy_port': self.proxy.server_port, 'target_port': self.target.server_port, 'proxy_requests': list(self.proxy_requests), 'target_requests': list(self.target_requests), 'proxy_hit': bool(self.proxy_requests), 'target_hit': bool(self.target_requests), 'proxy_signal': PROXY_SIGNAL, 'direct_signal': DIRECT_SIGNAL}

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
    boundary = Boundary()
    boundary.start()
    try:
        url = f"""http://localhost.:{boundary.target.server_port}/agent-readback"""
        app_root = f"""/opt/app/{args.side}"""
        env = {'HOME': '/tmp/gt-home', 'XDG_CACHE_HOME': '/tmp/gt-cache', 'NODE_OPTIONS': '--require=/opt/gt-tools/node_stdio_quiet.cjs', 'NO_PROXY': 'localhost,127.0.0.1,::1', 'no_proxy': 'localhost,127.0.0.1,::1', 'HTTP_PROXY': f"""http://127.0.0.1:{boundary.proxy.server_port}""", 'http_proxy': f"""http://127.0.0.1:{boundary.proxy.server_port}""", 'HTTPS_PROXY': '', 'https_proxy': '', 'ALL_PROXY': '', 'all_proxy': ''}
        record = run_shared_host_case(run_id=f"""{spec['case_id']}-{args.side}-{args.repetition}""", case_id=spec['case_id'], revision=args.side, repetition=args.repetition, command=['node', f"""{app_root}/build/index.js"""], cwd=Path(app_root), env=env, server_name=spec['repository_url'], tool_name=spec['mcp_path']['tool'], tool_arguments={'url': url}, task=spec['experiment']['agent_task'], system_prompt='You are a deterministic research host. Use the frozen tool call and report only its returned Tool result.', server_revision=f"""{spec['source_commit']}; axios=={spec['versions'][args.side]}""", timeout=float(spec['runner']['timeout_seconds']))
        snapshot = boundary.snapshot()
        record['external_boundary'] = snapshot
        normalized = record.get('mcp', {}).get('normalized_result', {})
        tool_text = text_content(normalized.get('content', [])) if isinstance(normalized, dict) else ''
        next_request = record.get('model', {}).get('next_request', {})
        l4_text = json.dumps(next_request, ensure_ascii=False)
        record['p4_probe'] = {'input_url': url, 'input_excludes_proxy_signal': PROXY_SIGNAL not in url, 'proxy_hit': snapshot['proxy_hit'], 'target_hit': snapshot['target_hit'], 'proxy_signal_in_tool_result': PROXY_SIGNAL in tool_text, 'proxy_signal_in_l4': PROXY_SIGNAL in l4_text, 'direct_signal_in_tool_result': DIRECT_SIGNAL in tool_text, 'direct_signal_in_l4': DIRECT_SIGNAL in l4_text, 'l4_is_actual_next_model_request': bool(next_request)}
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
