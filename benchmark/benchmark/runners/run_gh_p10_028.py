from __future__ import annotations
import argparse
import json
import re
import socketserver
import sys
import threading
from pathlib import Path
from typing import Any
sys.path.insert(0, '/opt/gt')
from shared_host_runner import evidence_rows, run_shared_host_case
CASE_ID = 'GH-P10-028'
COMMIT = 'fdca87e7a0615c21a2b7a4b411e39c93399ab7ec'
REPOSITORY = 'https://github.com/amotivv/protonmail-mcp'
TOOL = 'send_email'
UNEXPECTED_RCPT = 'xclow3n@gmail.com'
RFC_RCPT = '"xclow3n@gmail.com x"@internal.domain'

class CaptureState:

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.commands: list[str] = []
        self.recipients: list[str] = []
        self.accepted_messages = 0

class SMTPHandler(socketserver.StreamRequestHandler):

    def handle(self) -> None:
        state: CaptureState = self.server.capture_state
        self.wfile.write(b'220 gt-boundary ESMTP\r\n')
        self.wfile.flush()
        in_data = False
        while True:
            raw = self.rfile.readline(65536)
            if not raw:
                return
            line = raw.decode('utf-8', 'replace').rstrip('\r\n')
            with state.lock:
                state.commands.append(line)
            if in_data:
                if line == '.':
                    in_data = False
                    with state.lock:
                        state.accepted_messages += 1
                    self.wfile.write(b'250 2.0.0 queued GT-BOUNDARY\r\n')
                    self.wfile.flush()
                continue
            upper = line.upper()
            if upper.startswith('EHLO') or upper.startswith('HELO'):
                self.wfile.write(b'250-gt-boundary\r\n250-AUTH PLAIN LOGIN\r\n250 SIZE 10000000\r\n')
            elif upper.startswith('AUTH'):
                self.wfile.write(b'235 2.7.0 authenticated\r\n')
            elif upper.startswith('MAIL FROM'):
                self.wfile.write(b'250 2.1.0 sender accepted\r\n')
            elif upper.startswith('RCPT TO'):
                value = line.split(':', 1)[1].strip() if ':' in line else ''
                match = re.search('<([^>]*)>', value)
                recipient = match.group(1) if match else value
                with state.lock:
                    state.recipients.append(recipient)
                self.wfile.write(b'250 2.1.5 recipient accepted\r\n')
            elif upper == 'DATA':
                in_data = True
                self.wfile.write(b'354 end with <CR><LF>.<CR><LF>\r\n')
            elif upper == 'RSET':
                self.wfile.write(b'250 2.0.0 reset\r\n')
            elif upper == 'QUIT':
                self.wfile.write(b'221 2.0.0 closing\r\n')
                self.wfile.flush()
                return
            else:
                self.wfile.write(b'250 2.0.0 ok\r\n')
            self.wfile.flush()

class SMTPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address: tuple[str, int], state: CaptureState) -> None:
        self.capture_state = state
        super().__init__(address, SMTPHandler)

def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')

def boundary_snapshot(state: CaptureState) -> dict[str, Any]:
    with state.lock:
        recipients = list(state.recipients)
        commands = list(state.commands)
        accepted = state.accepted_messages
    return {'boundary': 'container-local-smtp-envelope', 'smtp_host': '127.0.0.1', 'smtp_port': 2525, 'rcpt_to': recipients, 'accepted_messages': accepted, 'command_count': len(commands), 'unexpected_rcpt_observed': UNEXPECTED_RCPT in recipients, 'rfc_quoted_rcpt_observed': RFC_RCPT in recipients, 'network': 'none', 'secret_value_excluded': True}

def tool_content_text(record: dict[str, Any]) -> str:
    normalized = record.get('mcp', {}).get('normalized_result', {})
    content = normalized.get('content', []) if isinstance(normalized, dict) else []
    return '\n'.join((str(item.get('text', '')) for item in content if isinstance(item, dict)))

def l4_tool_content_text(record: dict[str, Any]) -> str:
    request = record.get('model', {}).get('next_request') or {}
    return '\n'.join((str(item.get('text', '')) for message in request.get('messages', []) if isinstance(message, dict) and message.get('role') == 'tool' and isinstance(message.get('content'), list) for item in message['content'] if isinstance(item, dict)))

def returned_recipient(text: str) -> str | None:
    match = re.fullmatch('Email sent successfully to (.+)\\.', text.strip(), re.DOTALL)
    return match.group(1) if match else None

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--spec', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--side', choices=('vulnerable', 'fixed'), required=True)
    parser.add_argument('--repetition', type=int, required=True)
    args = parser.parse_args()
    spec = json.loads(args.spec.read_text(encoding='utf-8'))
    state = CaptureState()
    smtp = SMTPServer(('127.0.0.1', 2525), state)
    thread = threading.Thread(target=smtp.serve_forever, daemon=True)
    thread.start()
    try:
        server_root = Path(f"""/opt/server/{args.side}""")
        record = run_shared_host_case(run_id=f"""{CASE_ID}-{args.side}-{args.repetition}""", case_id=CASE_ID, revision=args.side, repetition=args.repetition, command=['node', str(server_root / 'build/index.js')], cwd=server_root, env={'PROTONMAIL_HOST': '127.0.0.1', 'PROTONMAIL_PORT': '2525', 'PROTONMAIL_SECURE': 'false', 'PROTONMAIL_USERNAME': 'sender@internal.domain', 'PROTONMAIL_PASSWORD': 'fixture-pass'}, server_name=REPOSITORY, tool_name=TOOL, tool_arguments=spec['experiment']['frozen_input'], task=spec['experiment']['agent_task'], system_prompt=spec['experiment']['system_prompt'], server_revision=f"""{COMMIT}; nodemailer=={spec['versions'][args.side]}""", timeout=float(spec['runner']['timeout_seconds']))
    finally:
        smtp.shutdown()
        smtp.server_close()
        thread.join(timeout=5)
    boundary = boundary_snapshot(state)
    record['external_boundary'] = boundary
    record['host']['external_state_after'] = boundary
    tool_text = tool_content_text(record)
    l4_text = l4_tool_content_text(record)
    tool_recipient = returned_recipient(tool_text)
    l4_recipient = returned_recipient(l4_text)
    record['gt_probe'] = {'vulnerability': 'GHSA-mm7p-fcc7-pg87/CVE-2025-13033', 'resolved_dependency_version': spec['versions'][args.side], 'boundary_effect_rule': 'vulnerable iff SMTP RCPT TO is exactly xclow3n@gmail.com; fixed control is the RFC quoted recipient', 'boundary_effect_observed': boundary['unexpected_rcpt_observed'], 'rfc_control_observed': boundary['rfc_quoted_rcpt_observed'], 'returned_recipient_in_tool_result': tool_recipient, 'returned_recipient_in_exact_l4_tool_message': l4_recipient, 'effect_in_tool_result': tool_recipient == UNEXPECTED_RCPT, 'effect_in_exact_l4_tool_message': l4_recipient == UNEXPECTED_RCPT, 'input_is_not_effect': True, 'effect_dropped_before_tool': boundary['unexpected_rcpt_observed'] and UNEXPECTED_RCPT not in tool_text}
    write_json(args.output / 'host_record.json', record)
    (args.output / 'evidence.jsonl').write_text(''.join((json.dumps(row, ensure_ascii=False) + '\n' for row in evidence_rows(record))), encoding='utf-8')
    write_json(args.output / 'boundary_snapshot.json', boundary)
    valid = record.get('quality', {}).get('invalid_run') is False and all((value == 'observed' for value in record.get('evidence_levels', {}).values()))
    print(json.dumps({'status': 'OK' if valid else 'INVALID', 'output': str(args.output), 'boundary': boundary}, ensure_ascii=False))
    return 0 if valid else 1
if __name__ == '__main__':
    raise SystemExit(main())
