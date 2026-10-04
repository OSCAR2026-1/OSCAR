"""Label-free adapters for the two Linux stdio cases with legacy batch runners."""

from __future__ import annotations

import http.server
import json
import shutil
import socketserver
import threading
from pathlib import Path
from typing import Any

from shared_host_runner import evidence_rows, run_shared_host_case

ROOT = Path("/opt/gt")
OUTPUT_ROOT: Path | None = None


def _write(root: Path, case_id: str, side: str, repetition: int, record: dict[str, Any]) -> None:
    output = (OUTPUT_ROOT or root / "runs" / "selected") / case_id / side / str(repetition)
    output.mkdir(parents=True, exist_ok=True)
    (output / "host_record.json").write_text(
        json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (output / "evidence.jsonl").write_text(
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in evidence_rows(record)),
        encoding="utf-8",
    )


def run_mobile(root: Path, side: str, repetition: int) -> dict[str, Any]:
    package_source = root / "mobile" / ("vulnerable" if side == "vulnerable" else "patched")
    # Keep the package writable while placing ../escape.png outside the server's
    # current directory and outside the OS temp root.  This preserves the
    # fixed server's output-path boundary under the read-only public image.
    runtime_root = (OUTPUT_ROOT or Path("/tmp/vulveil-mobile-output")) / "_mobile_runtime"
    shutil.rmtree(runtime_root, ignore_errors=True)
    package = runtime_root / ("vulnerable" if side == "vulnerable" else "patched")
    runtime_root.mkdir(parents=True, exist_ok=True)
    shutil.copytree(package_source, package, symlinks=True)
    escape = runtime_root / "escape.png"
    escape.unlink(missing_ok=True)
    fake_mobile = root / "fake-mobile"
    env = {
        "MOBILECLI_PATH": str(fake_mobile / "mobilecli"),
        "ANDROID_HOME": str(fake_mobile),
        "PATH": f"{fake_mobile}:{fake_mobile / 'platform-tools'}:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "NO_PROXY": "*", "HTTP_PROXY": "", "HTTPS_PROXY": "", "ALL_PROXY": "",
    }
    record = run_shared_host_case(
        run_id=f"CVE-2026-33989-{side}-{repetition}", case_id="CVE-2026-33989",
        revision=side, repetition=repetition, command=["node", "lib/index.js"], cwd=package,
        env=env, server_name="mobile-next-mobile-mcp", tool_name="mobile_save_screenshot",
        tool_arguments={"device": "fake-device", "saveTo": "../escape.png"},
        task="Use the frozen tool call sequence and report the Tool result.",
        system_prompt="You are a deterministic research host. Use the frozen tool call and report only its returned result.",
        server_revision="0.0.48" if side == "vulnerable" else "0.0.49", timeout=60,
    )
    record["external_boundary"] = {
        "boundary": "container-local-filesystem", "escape_exists": escape.exists(),
        "escape_size": escape.stat().st_size if escape.exists() else None,
    }
    _write(root, "CVE-2026-33989", side, repetition, record)
    shutil.rmtree(runtime_root, ignore_errors=True)
    return record


class _UnixRedirectBoundary:
    def __init__(self, repetition: int) -> None:
        self.redirect_hits = 0
        self.socket_hits = 0
        self.socket_path = Path(f"/tmp/vulveil-broken-link-{repetition}.sock")
        self.socket_path.unlink(missing_ok=True)
        boundary = self

        class UnixHandler(socketserver.StreamRequestHandler):
            def handle(self) -> None:
                while True:
                    line = self.rfile.readline()
                    if not line or line in (b"\r\n", b"\n"):
                        break
                boundary.socket_hits += 1
                self.wfile.write(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nX-Boundary: unix\r\n\r\n")

        class RedirectHandler(http.server.BaseHTTPRequestHandler):
            def do_HEAD(self) -> None:
                boundary.redirect_hits += 1
                self.send_response(302)
                self.send_header("Location", f"http://unix:{boundary.socket_path}:/probe")
                self.end_headers()

            def log_message(self, *_args: object) -> None:
                return

        self.unix_server = socketserver.ThreadingUnixStreamServer(str(self.socket_path), UnixHandler)
        self.redirect_server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), RedirectHandler)
        self.threads = [
            threading.Thread(target=self.unix_server.serve_forever, daemon=True),
            threading.Thread(target=self.redirect_server.serve_forever, daemon=True),
        ]

    def start(self) -> None:
        for thread in self.threads:
            thread.start()

    def close(self) -> None:
        self.redirect_server.shutdown()
        self.unix_server.shutdown()
        self.redirect_server.server_close()
        self.unix_server.server_close()
        for thread in self.threads:
            thread.join(timeout=3)
        self.socket_path.unlink(missing_ok=True)


def run_broken_link(root: Path, side: str, repetition: int) -> dict[str, Any]:
    boundary = _UnixRedirectBoundary(repetition)
    boundary.start()
    try:
        package_side = "vulnerable" if side == "vulnerable" else "patched"
        env = {
            "BROKEN_LINK_PACKAGE_ROOT": str(root / "case_assets/broken_link_case/upstream" / package_side),
            "NODE_OPTIONS": "", "NO_PROXY": "*", "HTTP_PROXY": "", "HTTPS_PROXY": "", "ALL_PROXY": "",
        }
        record = run_shared_host_case(
            run_id=f"CVE-2022-33987-{side}-{repetition}", case_id="CVE-2022-33987",
            revision=side, repetition=repetition, command=["node", "stdio_entry.mjs"],
            cwd=root / "case_assets/broken_link_case", env=env,
            server_name="davinoishi-mcp-broken-link-checker", tool_name="check_url",
            tool_arguments={"url": f"http://127.0.0.1:{boundary.redirect_server.server_port}/redirect", "timeout": 2000, "followRedirects": True, "maxRedirects": 5},
            task="Use the frozen tool call sequence and report the Tool result.",
            system_prompt="You are a deterministic research host. Use the frozen tool call and report only its returned result.",
            server_revision="got==10.7.0" if side == "vulnerable" else "got==11.8.5", timeout=60,
        )
        record["external_boundary"] = {
            "boundary": "controlled-unix-socket-redirect", "redirect_hits": boundary.redirect_hits,
            "unix_socket_hits": boundary.socket_hits, "socket_path": str(boundary.socket_path),
        }
        _write(root, "CVE-2022-33987", side, repetition, record)
        return record
    finally:
        boundary.close()


RUNNERS = {"CVE-2022-33987": run_broken_link, "CVE-2026-33989": run_mobile}
