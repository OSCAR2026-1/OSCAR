"""Minimal loopback-only MCP Streamable HTTP and legacy SSE clients."""

from __future__ import annotations

import json
import os
import socket
import subprocess
import threading
import time
from http.client import HTTPConnection, HTTPResponse
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlsplit


LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}


def _validate_endpoint(endpoint: str) -> tuple[str, int, str]:
    parsed = urlsplit(endpoint)
    if parsed.scheme != "http" or parsed.hostname not in LOOPBACK_HOSTS or parsed.port is None:
        raise ValueError("HTTP MCP endpoint must be an explicit loopback http URL with port")
    return parsed.hostname, parsed.port, parsed.path or "/"


def _sse_event(response: HTTPResponse, expected: str, timeout: float) -> str:
    event: dict[str, list[str]] = {}
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        line = response.fp.readline() if response.fp else b""
        if not line:
            break
        text = line.decode("utf-8", errors="replace").rstrip("\r\n")
        if text.startswith(":"):
            continue
        if not text:
            if event.get("event", ["message"])[-1] == expected and event.get("data"):
                return "\n".join(event["data"])
            event = {}
        elif ":" in text:
            field, value = text.split(":", 1)
            event.setdefault(field, []).append(value.lstrip())
    raise TimeoutError(f"SSE {expected} event was not received")


def _json_response(response: HTTPResponse, timeout: float) -> tuple[Any, str]:
    content_type = response.getheader("Content-Type", "").lower()
    if "text/event-stream" in content_type:
        data = _sse_event(response, "message", timeout)
        return json.loads(data), data
    raw = response.read().decode("utf-8", errors="replace")
    if not raw:
        return None, raw
    return json.loads(raw), raw


class ManagedHttpMcpClient:
    transport = "streamable-http"
    protocol_version = "2025-06-18"

    def __init__(self, command: list[str], cwd: Path, env: dict[str, str], endpoint: str,
                 headers: dict[str, str] | None = None, timeout: float = 30.0,
                 startup_timeout: float = 20.0, stateless: bool = False) -> None:
        self.command, self.cwd, self.env = command, cwd, env
        self.endpoint, self.headers = endpoint, dict(headers or {})
        self.timeout, self.startup_timeout, self.stateless = timeout, startup_timeout, stateless
        self.host, self.port, self.path = _validate_endpoint(endpoint)
        self.proc: subprocess.Popen[str] | None = None
        self.next_id = 1
        self.session_id: str | None = None
        self.wire: list[dict[str, Any]] = []
        self.stderr: list[str] = []
        self.stdout: list[str] = []
        self.reader_threads: list[threading.Thread] = []

    def __enter__(self) -> "ManagedHttpMcpClient":
        try:
            if self.command:
                environment = os.environ.copy()
                environment.update(self.env)
                self.proc = subprocess.Popen(self.command, cwd=self.cwd, env=environment,
                                             stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                             text=True, encoding="utf-8", errors="replace")
                self.reader_threads = [
                    threading.Thread(target=self._drain, args=(self.proc.stdout, self.stdout), daemon=True),
                    threading.Thread(target=self._drain, args=(self.proc.stderr, self.stderr), daemon=True),
                ]
                for thread in self.reader_threads:
                    thread.start()
            self._wait_until_reachable()
            return self
        except Exception:
            self.__exit__()
            raise

    def __exit__(self, *_: object) -> None:
        if self.proc is not None:
            if self.proc.poll() is None:
                self.proc.terminate()
                try:
                    self.proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    self.proc.kill()
                    self.proc.wait(timeout=3)
            for thread in self.reader_threads:
                thread.join(timeout=2)
            for stream in (self.proc.stdout, self.proc.stderr):
                if stream is not None and not stream.closed:
                    stream.close()

    @staticmethod
    def _drain(stream: Any, target: list[str]) -> None:
        if stream is not None:
            target.extend(stream)

    def _wait_until_reachable(self) -> None:
        deadline = time.monotonic() + self.startup_timeout
        while time.monotonic() < deadline:
            if self.proc is not None and self.proc.poll() is not None:
                raise RuntimeError(f"HTTP MCP server exited during startup: {self.proc.returncode}")
            try:
                with socket.create_connection((self.host, self.port), timeout=0.25):
                    return
            except OSError:
                time.sleep(0.05)
        raise TimeoutError("HTTP MCP server did not become reachable")

    def _post(self, message: dict[str, Any]) -> tuple[int, dict[str, str], Any, str]:
        raw = json.dumps(message, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        headers = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json",
                   "Content-Length": str(len(raw)), **self.headers}
        if self.session_id:
            headers["Mcp-Session-Id"] = self.session_id
        connection = HTTPConnection(self.host, self.port, timeout=self.timeout)
        try:
            connection.request("POST", self.path, body=raw, headers=headers)
            response = connection.getresponse()
            response_headers = {key.lower(): value for key, value in response.getheaders()}
            value, response_raw = _json_response(response, self.timeout)
            response_session = response_headers.get("mcp-session-id")
            if response_session:
                if self.session_id is not None and response_session != self.session_id:
                    raise RuntimeError("Streamable HTTP session ID drifted")
                self.session_id = response_session
            self.wire.append({"direction": "request", "message": message, "transport": self.transport})
            self.wire.append({"direction": "response", "message": value, "transport": self.transport,
                              "http_status": response.status, "headers": response_headers, "raw_body": response_raw})
            return response.status, response_headers, value, response_raw
        finally:
            connection.close()

    def request(self, method: str, params: dict[str, Any] | None = None, *, allow_error: bool = False) -> Any:
        request_id = self.next_id
        self.next_id += 1
        message: dict[str, Any] = {"jsonrpc": "2.0", "id": request_id, "method": method}
        if params is not None:
            message["params"] = params
        status, _headers, value, _raw = self._post(message)
        if status != 200 or not isinstance(value, dict) or value.get("id") != request_id:
            raise RuntimeError(f"invalid Streamable HTTP response for {method}: HTTP {status}")
        if method == "initialize" and not self.session_id and not self.stateless:
            raise RuntimeError("Streamable HTTP initialize response omitted the session ID")
        if "error" in value:
            if allow_error:
                return {"__jsonrpc_error__": value["error"]}
            raise RuntimeError(json.dumps(value["error"], ensure_ascii=False))
        return value.get("result")

    def notify(self, method: str) -> None:
        status, _headers, value, _raw = self._post({"jsonrpc": "2.0", "method": method})
        if status not in {200, 202, 204} or (status in {202, 204} and value is not None):
            raise RuntimeError(f"invalid Streamable HTTP notification response: HTTP {status}")


class LegacySseMcpClient(ManagedHttpMcpClient):
    transport = "sse"
    protocol_version = "2024-11-05"

    def __enter__(self) -> "LegacySseMcpClient":
        try:
            super().__enter__()
            self.sse_connection = HTTPConnection(self.host, self.port, timeout=self.timeout)
            headers = {"Accept": "text/event-stream", **self.headers}
            self.sse_connection.request("GET", self.path, headers=headers)
            self.sse_response = self.sse_connection.getresponse()
            if self.sse_response.status != 200:
                body = self.sse_response.read().decode("utf-8", errors="replace")
                raise RuntimeError(f"legacy SSE endpoint rejected connection: HTTP {self.sse_response.status}: {body}")
            endpoint = urljoin(self.endpoint, _sse_event(self.sse_response, "endpoint", self.timeout))
            host, port, path = _validate_endpoint(endpoint)
            if (host, port) != (self.host, self.port):
                raise ValueError("legacy SSE message endpoint crosses origin")
            self.message_path = path + (("?" + urlsplit(endpoint).query) if urlsplit(endpoint).query else "")
            return self
        except Exception:
            self.__exit__()
            raise

    def __exit__(self, *args: object) -> None:
        response = getattr(self, "sse_response", None)
        connection = getattr(self, "sse_connection", None)
        if response is not None:
            response.close()
        if connection is not None:
            connection.close()
        super().__exit__(*args)

    def _post_message(self, message: dict[str, Any]) -> int:
        raw = json.dumps(message, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        headers = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json",
                   "Content-Length": str(len(raw)), **self.headers}
        connection = HTTPConnection(self.host, self.port, timeout=self.timeout)
        try:
            connection.request("POST", self.message_path, body=raw, headers=headers)
            response = connection.getresponse()
            body = response.read().decode("utf-8", errors="replace")
            self.wire.append({"direction": "request", "message": message, "transport": self.transport})
            self.wire.append({"direction": "ack", "transport": self.transport, "http_status": response.status, "raw_body": body})
            if response.status not in {200, 202, 204}:
                raise RuntimeError(f"legacy SSE message POST failed: HTTP {response.status}")
            return response.status
        finally:
            connection.close()

    def request(self, method: str, params: dict[str, Any] | None = None, *, allow_error: bool = False) -> Any:
        request_id = self.next_id
        self.next_id += 1
        message: dict[str, Any] = {"jsonrpc": "2.0", "id": request_id, "method": method}
        if params is not None:
            message["params"] = params
        self._post_message(message)
        value = json.loads(_sse_event(self.sse_response, "message", self.timeout))
        self.wire.append({"direction": "response", "message": value, "transport": self.transport})
        if not isinstance(value, dict) or value.get("id") != request_id:
            raise RuntimeError(f"invalid legacy SSE response for {method}")
        if "error" in value:
            if allow_error:
                return {"__jsonrpc_error__": value["error"]}
            raise RuntimeError(json.dumps(value["error"], ensure_ascii=False))
        return value.get("result")

    def notify(self, method: str) -> None:
        self._post_message({"jsonrpc": "2.0", "method": method})
