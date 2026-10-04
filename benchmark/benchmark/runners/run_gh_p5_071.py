from __future__ import annotations
import base64
import hashlib
import json
import argparse
from pathlib import Path
from typing import Any
from shared_host_runner import evidence_rows, run_shared_host_case
CASE_ID = 'GH-P5-071'
SECRET_VALUE = 'ORCHARD_P5_071_PRIVATE_BYTES'
FIXTURE_PATH = '/opt/fixture/GH-P5-071-controlled.docx'

def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--spec', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--side', choices=('vulnerable', 'fixed'), required=True)
    parser.add_argument('--repetition', type=int, required=True)
    args = parser.parse_args()
    spec = json.loads(args.spec.read_text(encoding='utf-8'))
    secret_path = Path('/tmp/GH_P5_071_SECRET.txt')
    secret_path.write_text(SECRET_VALUE, encoding='utf-8')
    signal_b64 = base64.b64encode(SECRET_VALUE.encode()).decode()
    command = ['node', f"""/opt/server/{args.side}/dist/esm/index.js"""]
    record = run_shared_host_case(run_id=f"""{CASE_ID}-{args.side}-{args.repetition}""", case_id=CASE_ID, revision=args.side, repetition=args.repetition, command=command, cwd=Path(f"""/opt/server/{args.side}"""), env={'NODE_ENV': 'test'}, server_name=spec['discovery']['repository_url'], tool_name=spec['mcp_path_review']['tool'], tool_arguments=spec['experiment']['frozen_input'], task=spec['experiment']['agent_task'], system_prompt=spec['experiment']['system_prompt'], server_revision=f"""{spec['discovery']['repository_commit']}; mammoth=={spec['versions'][args.side]}""", timeout=float(spec['runner']['timeout_seconds']))
    normalized = record.get('mcp', {}).get('normalized_result', {})
    normalized_text = json.dumps(normalized, ensure_ascii=False)
    next_request = record.get('model', {}).get('next_request', {})
    l4_text = json.dumps(next_request, ensure_ascii=False)
    secret_readback = signal_b64 in normalized_text
    record['external_boundary'] = {
        'boundary': 'container-local-runtime-secret-file-and-frozen-docx',
        'secret_path': str(secret_path),
        'secret_sha256': hashlib.sha256(SECRET_VALUE.encode()).hexdigest(),
        'secret_value_excluded': True,
        'fixture_path': FIXTURE_PATH,
        'fixture_sha256': hashlib.sha256(Path(FIXTURE_PATH).read_bytes()).hexdigest(),
        'network': 'none',
        'oracle': {
            'kind': 'filesystem-content-projection/v1',
            'complete': True,
            'resource_exists': True,
            'readback_present': secret_readback,
            'effect_event': ({
                'resource_id': 'container-local-filesystem:/tmp/GH_P5_071_SECRET.txt',
                'operation': 'read',
                'location': 'container-local-filesystem',
                'oracle_kind': 'filesystem-content-projection/v1',
                'stable_resource_identity': True,
            } if secret_readback else None),
        },
    }
    record['gh_p5_071_probe'] = {'mammoth_version': spec['versions'][args.side], 'effect_signal': 'runtime-secret-base64-in-markdown-data-uri', 'effect_signal_base64': signal_b64, 'input_effect_absent': SECRET_VALUE not in json.dumps(spec['experiment']['frozen_input'], ensure_ascii=False), 'signal_in_tool_result': signal_b64 in normalized_text, 'signal_in_exact_l4': signal_b64 in l4_text, 'l4_is_actual_next_model_request': bool(next_request), 'ordinary_path_not_counted': True}
    write_json(args.output / 'host_record.json', record)
    (args.output / 'evidence.jsonl').write_text(''.join((json.dumps(row, ensure_ascii=False) + '\n' for row in evidence_rows(record))), encoding='utf-8')
    write_json(args.output / 'boundary_snapshot.json', record['external_boundary'])
    valid = not record['quality']['invalid_run'] and all((value == 'observed' for value in record['evidence_levels'].values()))
    print(json.dumps({'status': 'OK' if valid else 'INVALID', 'output': str(args.output)}, ensure_ascii=False))
    return 0 if valid else 1
if __name__ == '__main__':
    raise SystemExit(main())
