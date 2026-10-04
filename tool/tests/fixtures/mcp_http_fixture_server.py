"""Loopback MCP fixture implementing Streamable HTTP and legacy SSE."""

from __future__ import annotations

import argparse
import json
import queue
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit


RESPONSES: queue.Queue[dict] = queue.Queue()


def dispatch(message: dict) -> dict | None:
    request_id = message.get("id")
    method = message.get("method")
    if request_id is None:
        return None
    if method == "initialize":
        result = {"protocolVersion": message.get("params", {}).get("protocolVersion"), "capabilities": {},
                  "serverInfo": {"name": "http-fixture", "version": "1"}}
    elif method == "tools/list":
        result = {"tools": [{"name": "probe", "description": "HTTP fixture", "inputSchema": {
            "type": "object", "properties": {"value": {"type": "string"}}, "additionalProperties": False}}]}
    elif method == "tools/call":
        value = message.get("params", {}).get("arguments", {}).get("value", "none")
        result = {"content": [{"type": "text", "text": f"http-result:{value}"}],
                  "structuredContent": {"transport_value": value}}
    else:
        return {"jsonrpc": "2.0", "id": request_id, "error": {"code": -32601, "message": "method not found"}}
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:  # noqa: N802
        if self.server.mode != "sse" or urlsplit(self.path).path != "/sse":
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        endpoint = ("http://127.0.0.1:9/messages?session_id=fixture-session"
                    if self.server.fault == "cross-origin" else "/messages?session_id=fixture-session")
        self.wfile.write(f"event: endpoint\ndata: {endpoint}\n\n".encode())
        self.wfile.flush()
        while True:
            message = RESPONSES.get()
            raw = json.dumps(message, separators=(",", ":")).encode("utf-8")
            self.wfile.write(b"event: message\ndata: " + raw + b"\n\n")
            self.wfile.flush()

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        message = json.loads(self.rfile.read(length) if length else b"{}")
        result = dispatch(message)
        if result is not None and self.server.fault == "wrong-id":
            result["id"] = "nonmatching-id"
        path = urlsplit(self.path).path
        if self.server.mode == "streamable" and path == "/mcp":
            if message.get("method") != "initialize" and self.headers.get("Mcp-Session-Id") != "fixture-session":
                self.send_error(400, "missing session")
                return
            if result is None:
                self.send_response(202)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            raw = json.dumps(result, separators=(",", ":")).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            if message.get("method") == "initialize" and self.server.fault != "missing-session":
                self.send_header("Mcp-Session-Id", "fixture-session")
            elif message.get("method") != "initialize" and self.server.fault == "session-drift":
                self.send_header("Mcp-Session-Id", "drifted-session")
            self.end_headers()
            self.wfile.write(raw)
            return
        if self.server.mode == "sse" and path == "/messages" and parse_qs(urlsplit(self.path).query).get("session_id") == ["fixture-session"]:
            if result is not None:
                RESPONSES.put(result)
            self.send_response(202)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.send_error(404)

    def log_message(self, *_args: object) -> None:
        return


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("streamable", "sse"), required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--fault", choices=("none", "missing-session", "session-drift", "cross-origin", "wrong-id"), default="none")
    args = parser.parse_args()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    server.mode = args.mode
    server.fault = args.fault
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
