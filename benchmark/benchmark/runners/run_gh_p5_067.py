from __future__ import annotations

import argparse
import base64
import json
import select
import socket
import socketserver
import ssl
import subprocess
import threading
from pathlib import Path
from typing import Any

from shared_host_runner import evidence_rows, run_shared_host_case


EFFECT_SIGNAL = "GH_P5_067_PROXY_AUTH_READBACK"
PROXY_AUTH = "Basic " + base64.b64encode(b"P5_067_PROXY_USER:P5_067_PROXY_SECRET").decode("ascii")
CASE_ID = "GH-P5-067"
REPOSITORY = "https://github.com/unclevicky/mcp-server-fetchplus"
SOURCE_COMMIT = "7affe5a27de9f320d39d37446e006e70e31f6894"
TOOL = "fetch_url"
VERSIONS = {"vulnerable": "2.30.0", "fixed": "2.31.0"}
AGENT_TASK = "Call the frozen fetch_url Tool and report only its returned result."


def read_headers(data: bytes) -> tuple[str, dict[str, str]]:
    head = data.split(b"\r\n\r\n", 1)[0].decode("iso-8859-1", errors="replace")
    lines = head.split("\r\n")
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip().lower()] = value.strip()
    return (lines[0] if lines else "", headers)


def recv_headers(sock: socket.socket) -> bytes:
    data = b""
    while b"\r\n\r\n" not in data and len(data) < 65536:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data


class Boundary:
    def __init__(self) -> None:
        self.proxy_requests: list[dict[str, Any]] = []
        self.origin_requests: list[dict[str, Any]] = []
        self.lock = threading.Lock()
        self.cert_dir = Path("/tmp/gh-p5-067-cert")
        self.cert_dir.mkdir(parents=True, exist_ok=True)
        self.cert = self.cert_dir / "origin.crt"
        self.key = self.cert_dir / "origin.key"
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-keyout", str(self.key), "-out", str(self.cert), "-days", "1",
                "-subj", "/CN=destination.example",
                "-addext", "subjectAltName=DNS:destination.example",
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        self.origin_server = socketserver.ThreadingTCPServer(("0.0.0.0", 0), self._origin_handler())
        self.origin_server.daemon_threads = True
        self.origin_port = self.origin_server.server_address[1]
        self.proxy_server = socketserver.ThreadingTCPServer(("0.0.0.0", 0), self._proxy_handler())
        self.proxy_server.daemon_threads = True
        self.proxy_port = self.proxy_server.server_address[1]
        self.origin_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.origin_context.load_cert_chain(certfile=str(self.cert), keyfile=str(self.key))
        self.threads: list[threading.Thread] = []

    def _origin_handler(self) -> type[socketserver.BaseRequestHandler]:
        boundary = self

        class OriginHandler(socketserver.BaseRequestHandler):
            def handle(self) -> None:
                try:
                    tls = boundary.origin_context.wrap_socket(self.request, server_side=True)
                    with tls:
                        data = recv_headers(tls)
                        request_line, headers = read_headers(data)
                        with boundary.lock:
                            boundary.origin_requests.append({"request_line": request_line, "headers": headers})
                        auth = headers.get("proxy-authorization", "")
                        body = (
                            "<html><head><title>" + EFFECT_SIGNAL + "=" + (auth or "NONE")
                            + "</title></head><body><p>Controlled HTTPS origin.</p></body></html>"
                        ).encode("utf-8")
                        response = (
                            b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n"
                            + f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode("ascii")
                            + body
                        )
                        tls.sendall(response)
                except (ConnectionError, OSError, ssl.SSLError):
                    return

        return OriginHandler

    def _proxy_handler(self) -> type[socketserver.BaseRequestHandler]:
        boundary = self

        class ProxyHandler(socketserver.BaseRequestHandler):
            def handle(self) -> None:
                try:
                    data = recv_headers(self.request)
                    request_line, headers = read_headers(data)
                    with boundary.lock:
                        boundary.proxy_requests.append({"request_line": request_line, "headers": headers})
                    if request_line.startswith("CONNECT "):
                        upstream = socket.create_connection(("127.0.0.1", boundary.origin_port), timeout=10)
                        try:
                            self.request.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                            boundary.relay(self.request, upstream)
                        finally:
                            upstream.close()
                        return
                    location = f"https://destination.example:{boundary.origin_port}/final"
                    response = (
                        "HTTP/1.1 302 Found\r\n"
                        f"Location: {location}\r\n"
                        "Content-Length: 0\r\nConnection: close\r\n\r\n"
                    ).encode("ascii")
                    self.request.sendall(response)
                except (ConnectionError, OSError, ssl.SSLError):
                    return

        return ProxyHandler

    @staticmethod
    def relay(left: socket.socket, right: socket.socket) -> None:
        left.settimeout(10)
        right.settimeout(10)
        while True:
            readable, _, _ = select.select([left, right], [], [], 10)
            if not readable:
                return
            for source in readable:
                data = source.recv(65536)
                if not data:
                    return
                (right if source is left else left).sendall(data)

    def start(self) -> None:
        for server in (self.origin_server, self.proxy_server):
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            self.threads.append(thread)

    def close(self) -> None:
        for server in (self.proxy_server, self.origin_server):
            server.shutdown()
            server.server_close()
        for thread in self.threads:
            thread.join(timeout=3)

    def snapshot(self) -> dict[str, Any]:
        return {
            "boundary": "container-local-authenticated-http-proxy-to-https-origin-gh-p5-067",
            "proxy_port": self.proxy_port,
            "origin_port": self.origin_port,
            "proxy_requests": list(self.proxy_requests),
            "origin_requests": list(self.origin_requests),
        }


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--side", choices=("vulnerable", "fixed"), required=True)
    parser.add_argument("--repetition", type=int, required=True)
    args = parser.parse_args()
    boundary = Boundary()
    boundary.start()
    try:
        dep_root = f"/opt/deps/proxy_{args.side}"
        proxy_url = f"http://P5_067_PROXY_USER:P5_067_PROXY_SECRET@proxy.example:{boundary.proxy_port}"
        env = {
            "PYTHONPATH": f"{dep_root}:/opt/deps/mcp_legacy:/opt/deps/fetchplus:/opt/deps/common:/workspace/source/src:/opt/gt",
            "HTTP_PROXY": proxy_url,
            "http_proxy": proxy_url,
            "HTTPS_PROXY": proxy_url,
            "https_proxy": proxy_url,
            "ALL_PROXY": "",
            "all_proxy": "",
            "NO_PROXY": "",
            "no_proxy": "",
            "REQUESTS_CA_BUNDLE": str(boundary.cert),
            "PYTHONIOENCODING": "utf-8",
        }
        tool_args = {"url": "http://start.example/start"}
        record = run_shared_host_case(
            run_id=f"{CASE_ID}-{args.side}-{args.repetition}",
            case_id=CASE_ID,
            revision=args.side,
            repetition=args.repetition,
            command=["/bin/sh", "-c", "cd /tmp && exec python3 -m mcp_server_fetchplus.server"],
            cwd=Path("/tmp"),
            env=env,
            server_name=REPOSITORY,
            tool_name=TOOL,
            tool_arguments=tool_args,
            task=AGENT_TASK,
            system_prompt="You are a deterministic research host. Use the frozen tool call and report only its returned result.",
            server_revision=f"{SOURCE_COMMIT}; requests=={VERSIONS[args.side]}",
            timeout=60,
        )
        snapshot = boundary.snapshot()
        origin_leaks_proxy_auth = any(
            bool((item.get('headers') or {}).get('proxy-authorization'))
            for item in boundary.origin_requests
        )
        snapshot['oracle'] = {
            'kind': 'http-proxy-credential-provenance/v1',
            'complete': True,
            'origin_request_count': len(boundary.origin_requests),
            'proxy_authorization_at_origin': origin_leaks_proxy_auth,
            'effect_event': ({
                'resource_id': 'https-origin:destination.example/final',
                'operation': 'send',
                'location': 'container-local-https-origin',
                'oracle_kind': 'http-proxy-credential-provenance/v1',
                'stable_resource_identity': True,
            } if origin_leaks_proxy_auth else None),
        }
        record["external_boundary"] = snapshot
        record["runtime_dependency"] = {"name": "requests", "version": VERSIONS[args.side], "import_root": dep_root}
        write_json(args.output / "host_record.json", record)
        (args.output / "evidence.jsonl").write_text("".join(json.dumps(row, ensure_ascii=False) + "\n" for row in evidence_rows(record)), encoding="utf-8")
        write_json(args.output / "boundary_snapshot.json", snapshot)
        valid = not record["quality"]["invalid_run"] and all(value == "observed" for value in record["evidence_levels"].values())
        print(json.dumps({"status": "OK" if valid else "INVALID", "output": str(args.output)}, ensure_ascii=False))
        return 0 if valid else 1
    finally:
        boundary.close()


if __name__ == "__main__":
    raise SystemExit(main())
