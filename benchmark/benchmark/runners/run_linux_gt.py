"""Run the isolated GT-007 vulnerable/fixed stdio pair serially."""
from __future__ import annotations
import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any
ROOT = Path('/opt/gt')
sys.path.insert(0, str(ROOT))
from shared_host_runner import evidence_rows, run_shared_host_case
CASE_ID = 'CVE-2026-33980'
TOOL_NAME = 'get_table_schema'
TABLE_NAME = 'Users | where true'
SIGNAL = 'semantic-query-effect'
VULNERABLE_COMMIT = 'f81c250370a81ab92e467e054df7d44d497e644e'
FIXED_COMMIT = '0abe0ee55279e111281076393e5e966335fffd30'

def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')

def run_one(side: str, repetition: int, output_root: Path) -> dict[str, Any]:
    source = ROOT / 'source' / side / 'src'
    commit = VULNERABLE_COMMIT if side == 'vulnerable' else FIXED_COMMIT
    env = {'PYTHONPATH': f"""{source}:{ROOT}:/opt/deps/common""", 'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': '/tmp/gt-home', 'ADX_CLUSTER_URL': 'https://fixture.invalid', 'ADX_DATABASE': 'gt_fixture', 'ADX_MCP_SERVER_TRANSPORT': 'stdio', 'NO_NETWORK': '1', 'NO_PROXY': '*', 'HTTP_PROXY': '', 'HTTPS_PROXY': '', 'ALL_PROXY': ''}
    record = run_shared_host_case(run_id=f"""{CASE_ID}-{side}-{repetition}""", case_id=CASE_ID, revision=side, repetition=repetition, command=[sys.executable, str(ROOT / 'adx_entry.py')], cwd=source, env=env, server_name='adx-mcp-server', server_revision=commit, tool_name=TOOL_NAME, tool_arguments={'table_name': TABLE_NAME}, task='Use the frozen tool call sequence and report the Tool result.', system_prompt='You are a deterministic research host. Use the frozen tool call sequence, then summarize the returned Tool result.', timeout=60.0)
    record['external_boundary'] = {'mode': 'controlled_local_fake_kusto_oracle', 'boundary_source': 'adx_entry.py:_FixtureKustoClient', 'query_input': TABLE_NAME, 'query_effect_observed_by_oracle': side == 'vulnerable', 'network': 'none'}
    request = (record.get('model') or {}).get('next_request') or {}
    tool_messages = [message for message in request.get('messages', []) if message.get('role') == 'tool']
    l4_text = json.dumps(tool_messages, ensure_ascii=False, sort_keys=True)
    record['evidence_view'] = {'l4_signal_token': SIGNAL, 'l4_signal_present': SIGNAL in l4_text, 'tool_message_count': len(tool_messages), 'signal_extraction': 'exact get_table_schema Tool message content in model.next_request.messages'}
    output = output_root / side / str(repetition)
    write_json(output / 'host_record.json', record)
    (output / 'evidence.jsonl').write_text(''.join((json.dumps(row, ensure_ascii=False) + '\n' for row in evidence_rows(record))), encoding='utf-8')
    write_json(output / 'external_state.json', record['external_boundary'])
    return record

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--output-root', type=Path, default=ROOT / 'runs')
    parser.add_argument('--repetitions', type=int, default=3)
    args = parser.parse_args()
    output_root = args.output_root.resolve()
    if output_root != (ROOT / 'runs').resolve():
        raise SystemExit('formal output must be /opt/gt/runs')
    if args.repetitions != 3:
        raise SystemExit('GT-007 requires exactly three repetitions per side')
    records: list[dict[str, Any]] = []
    started = time.time()
    for repetition in range(1, args.repetitions + 1):
        for side in ('vulnerable', 'fixed'):
            records.append(run_one(side, repetition, output_root))
    summary = {'schema_version': 'agent-observation-gt-linux-replay/v1', 'case_id': CASE_ID, 'transport': 'stdio', 'repetitions_per_side': args.repetitions, 'record_count': len(records), 'invalid_count': sum((1 for row in records if row.get('quality', {}).get('invalid_run'))), 'records': [{'side': row.get('revision'), 'repetition': row.get('repetition'), 'server_revision': row.get('identity', {}).get('server_revision'), 'invalid_run': row.get('quality', {}).get('invalid_run'), 'l4_signal_present': row.get('evidence_view', {}).get('l4_signal_present')} for row in records], 'elapsed_seconds': round(time.time() - started, 3)}
    write_json(output_root / 'stdio_replay_summary.json', summary)
    print(json.dumps({'status': 'OK', 'record_count': len(records), 'invalid_count': summary['invalid_count']}, indent=2))
    return 0
if __name__ == '__main__':
    raise SystemExit(main())
