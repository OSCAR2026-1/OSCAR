#!/usr/bin/env python3
from __future__ import annotations

import argparse
from email.headerregistry import Address
import json
import re
import socketserver
import ssl
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any

sys.path.insert(0, "/opt/gt/runtime")
from shared_host_runner import evidence_rows, run_shared_host_case


PROJECTS = {
    "GH-P10-024": {
        "command": lambda side: ["node", f"/opt/server/{side}/index.js"],
        "cwd": lambda side: Path(f"/opt/server/{side}"),
        "env": {"GOOGLE_EMAIL": "fixture-user@gmail.com", "GOOGLE_APP_PASSWORD": "fixture-app-password", "NODE_TLS_REJECT_UNAUTHORIZED": "0"},
        "tls": True,
        "port": 465,
    },
    "GH-P10-025": {
        "command": lambda side: [f"/opt/server/{side}/node_modules/.bin/tsx", f"/opt/server/{side}/src/server/index.ts"],
        "cwd": lambda side: Path(f"/opt/server/{side}"),
        "env": {"EMAIL_USER": "fixture-user@gmail.com", "EMAIL_PASS": "fixture-app-password", "NODE_TLS_REJECT_UNAUTHORIZED": "0"},
        "tls": True,
        "port": 465,
    },
    "GH-P10-028": {
        "command": lambda side: ["node", f"/opt/server/{side}/build/index.js"],
        "cwd": lambda side: Path(f"/opt/server/{side}"),
        "env": {"PROTONMAIL_HOST": "127.0.0.1", "PROTONMAIL_PORT": "2525", "PROTONMAIL_SECURE": "false", "PROTONMAIL_USERNAME": "sender@internal.domain", "PROTONMAIL_PASSWORD": "fixture-pass"},
        "tls": False,
        "port": 2525,
    },
}


class CaptureState:
    def __init__(self, policy: str) -> None:
        self.policy = policy
        self.lock = threading.Lock()
        self.commands: list[str] = []
        self.recipients: list[str] = []
        self.accepted_messages = 0


class SMTPHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        state: CaptureState = self.server.capture_state
        self.wfile.write(b"220 smtp.gmail.com ESMTP rq1-extension-boundary\r\n")
        self.wfile.flush()
        in_data = False
        auth_stage = 0
        while True:
            raw = self.rfile.readline(65536)
            if not raw:
                return
            line = raw.decode("utf-8", "replace").rstrip("\r\n")
            with state.lock:
                state.commands.append(line)
            if in_data:
                if line == ".":
                    in_data = False
                    with state.lock:
                        state.accepted_messages += 1
                    self.wfile.write(b"250 2.0.0 queued RQ1-EXTENSION\r\n")
                    self.wfile.flush()
                continue
            upper = line.upper()
            if auth_stage:
                if auth_stage == 1:
                    auth_stage = 2
                    self.wfile.write(b"334 UGFzc3dvcmQ6\r\n")
                else:
                    auth_stage = 0
                    self.wfile.write(b"235 2.7.0 authenticated\r\n")
            elif upper.startswith("EHLO") or upper.startswith("HELO"):
                self.wfile.write(b"250-smtp.gmail.com\r\n250-AUTH PLAIN LOGIN\r\n250 SIZE 10000000\r\n")
            elif upper.startswith("AUTH LOGIN") and len(line.split()) < 3:
                auth_stage = 1
                self.wfile.write(b"334 VXNlcm5hbWU6\r\n")
            elif upper.startswith("AUTH"):
                self.wfile.write(b"235 2.7.0 authenticated\r\n")
            elif upper.startswith("MAIL FROM"):
                self.wfile.write(b"250 2.1.0 sender accepted\r\n")
            elif upper.startswith("RCPT TO"):
                value = line.split(":", 1)[1].strip() if ":" in line else ""
                match = re.search(r"<([^>]*)>", value)
                recipient = match.group(1) if match else value
                with state.lock:
                    state.recipients.append(recipient)
                if state.policy == "reject":
                    self.wfile.write(b"550 5.1.1 recipient rejected by controlled boundary\r\n")
                else:
                    self.wfile.write(b"250 2.1.5 recipient accepted\r\n")
            elif upper == "DATA":
                in_data = True
                self.wfile.write(b"354 end with <CR><LF>.<CR><LF>\r\n")
            elif upper == "RSET":
                self.wfile.write(b"250 2.0.0 reset\r\n")
            elif upper == "QUIT":
                self.wfile.write(b"221 2.0.0 closing\r\n")
                self.wfile.flush()
                return
            else:
                self.wfile.write(b"250 2.0.0 ok\r\n")
            self.wfile.flush()


class SMTPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address: tuple[str, int], state: CaptureState, context: ssl.SSLContext | None) -> None:
        self.capture_state = state
        self.context = context
        super().__init__(address, SMTPHandler)

    def get_request(self):
        request, client_address = super().get_request()
        if self.context:
            request = self.context.wrap_socket(request, server_side=True)
        return request, client_address


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def make_context() -> ssl.SSLContext:
    key = Path("/tmp/smtp-key.pem")
    cert = Path("/tmp/smtp-cert.pem")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(cert), "-subj", "/CN=smtp.gmail.com", "-days", "1"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=cert, keyfile=key)
    return context


def requested_recipients(tool_input: dict[str, Any]) -> list[str]:
    value = tool_input.get("to", tool_input.get("recipient", []))
    values = value if isinstance(value, list) else [value]
    return [str(item) for item in values if item not in (None, "")]


def normalize_recipient(value: str) -> str | None:
    try:
        return Address(addr_spec=value).addr_spec.lower()
    except Exception:
        return None


def boundary_evidence_row(boundary: dict[str, Any], tool_input: dict[str, Any], *, valid: bool) -> dict[str, Any]:
    requested = requested_recipients(tool_input)
    normalized_requested = sorted({item for value in requested if (item := normalize_recipient(value))})
    actual = sorted({str(value).lower() for value in boundary.get("rcpt_to", []) if value})
    delivered = boundary.get("accepted_messages", 0) > 0
    unintended = sorted(value for value in actual if delivered and value not in normalized_requested)
    event = None
    if unintended:
        event = {
            "resource_id": unintended[0],
            "operation": "deliver",
            "location": "container-local-smtp",
            "oracle_kind": "smtp-delivery-projection/v1",
            "stable_resource_identity": True,
            "before_state": {"requested_recipients": requested, "normalized_recipients": normalized_requested},
            "after_state": {"actual_recipients": actual, "accepted_messages": boundary.get("accepted_messages", 0)},
        }
    return {
        "level": "SERVER_OR_EXTERNAL_EFFECT",
        "anchor_reached": valid,
        "event": event,
        "oracle": {
            "kind": "smtp-delivery-projection/v1",
            "complete": True,
            "requested_recipients": requested,
            "normalized_requested_recipients": normalized_requested,
            "actual_recipients": actual,
            "accepted_messages": boundary.get("accepted_messages", 0),
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--spec", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--side", choices=("vulnerable", "fixed"), required=True)
    parser.add_argument("--repetition", type=int, choices=(1, 2, 3), required=True)
    args = parser.parse_args()
    spec = json.loads(args.spec.read_text(encoding="utf-8"))
    config = PROJECTS[spec["base_case"]]
    state = CaptureState(spec["boundary"]["recipient_policy"])
    smtp = SMTPServer(("0.0.0.0" if config["tls"] else "127.0.0.1", config["port"]), state, make_context() if config["tls"] else None)
    thread = threading.Thread(target=smtp.serve_forever, daemon=True)
    thread.start()
    try:
        record = run_shared_host_case(
            run_id=f"{spec['case_id']}-{args.side}-{args.repetition}",
            case_id=spec["case_id"], revision=args.side, repetition=args.repetition,
            command=config["command"](args.side), cwd=config["cwd"](args.side), env=config["env"],
            server_name=spec["identity"]["repository"], tool_name="send_email",
            tool_arguments=spec["tool"]["input"], task=spec["agent_task"], system_prompt=spec["system_prompt"],
            server_revision=f"{spec['identity']['repository_commit']};nodemailer=={spec['versions'][args.side]}", timeout=45.0,
        )
    finally:
        smtp.shutdown()
        smtp.server_close()
        thread.join(timeout=5)
    with state.lock:
        boundary = {
            "kind": "container-local-smtp",
            "recipient_policy": state.policy,
            "rcpt_to": list(state.recipients),
            "accepted_messages": state.accepted_messages,
            "command_count": len(state.commands),
            "network": "none",
        }
    record["external_boundary"] = boundary
    record["host"]["external_state_after"] = boundary
    valid = record.get("quality", {}).get("invalid_run") is False and all(value == "observed" for value in record.get("evidence_levels", {}).values())
    rows = evidence_rows(record)
    rows.append(boundary_evidence_row(boundary, spec["tool"]["input"], valid=valid))
    write_json(args.output / "host_record.json", record)
    (args.output / "evidence.jsonl").write_text("".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows), encoding="utf-8")
    write_json(args.output / "boundary_snapshot.json", boundary)
    print(json.dumps({"status": "OK" if valid else "INVALID", "case_id": spec["case_id"], "side": args.side, "repetition": args.repetition, "boundary": boundary}))
    return 0 if valid else 1


if __name__ == "__main__":
    raise SystemExit(main())
