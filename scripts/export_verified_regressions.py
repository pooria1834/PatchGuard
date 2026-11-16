"""Export only verified minimized fixture data from a read-only CI verifier.

The untrusted binary never runs in this (host-side, contents:read) process.
Archived bytes are rechecked with the trusted config and compared against
promotion results; output is a bounded, canonical data-only handoff.
"""

import argparse
import json
import re
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from patchguard.config import ConfigError, ROOT, load_config, workspace_path
from patchguard.promotion import inspect_archive

ID = re.compile(r'generated-[0-9a-f]{12}-[0-9a-f]{12}-(?:base|candidate)-(?:release|checked)(?:-a[0-9a-f]{10})?\Z')


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--config', required=True)
    p.add_argument('--archive', required=True)
    p.add_argument('--plan', required=True)
    p.add_argument('--out', required=True)
    p.add_argument('--run-id', required=True)
    p.add_argument('--run-attempt', required=True)
    args = p.parse_args(argv)
    if not args.run_id.isdecimal() or not args.run_attempt.isdecimal():
        p.error('invalid triggering run')
    config = load_config(args.config)
    archive = workspace_path(args.archive, 'archive', within=ROOT / 'artifacts')
    plan = json.loads(Path(args.plan).read_text(encoding='utf8'))
    if plan.get('schema') != 'patchguard-regression-pr-preparation/1' or plan.get('reviewed_dir') != config['regression']['reviewed']:
        raise ConfigError('promotion plan does not match trusted configuration')
    case_ids = plan.get('added')
    if (not isinstance(case_ids, list) or len(case_ids) > 500
        or len(set(case_ids)) != len(case_ids)
        or any(not isinstance(name, str) or not ID.fullmatch(name) for name in case_ids)):
        raise ConfigError('promotion plan has malformed case ids')
    out = Path(args.out)
    if out.exists() and any(out.iterdir()):
        raise ConfigError('verified handoff directory must start empty')
    reviewed = out / 'reviewed'
    reviewed.mkdir(parents=True)
    rows = []
    for case_id in sorted(case_ids):
        case, _ = inspect_archive(archive, config, case_id)
        data, expected = case['input'], case['expected_stdout']
        digest = __import__('hashlib').sha256(data).hexdigest()
        row = dict(id=case_id, kind=case['kind'], input=digest[:12] + '.bin',
                   expected_exit=case['expected_exit'], expected_stdout=case_id+'.out',
                   input_sha256=digest, preserved_signature=case['preserved_signature'],
                   witness_role=case['witness_role'], witness_mode=case['witness_mode'])
        if 'args' in case:
            row['args'] = case['args']
        for name, content in [(row['input'], data), (row['expected_stdout'], expected)]:
            path = reviewed / name
            if path.exists() and path.read_bytes() != content:
                raise ConfigError('fixture filename collision')
            path.write_bytes(content)
        rows.append(row)
    (reviewed / 'manifest.yaml').write_text(yaml.safe_dump(rows, sort_keys=False), encoding='utf8')
    handoff = dict(schema='patchguard-verified-regressions/1', source_run_id=args.run_id,
                   source_run_attempt=args.run_attempt, reviewed_dir=config['regression']['reviewed'],
                   added=[case['id'] for case in rows],
                   rejected=plan.get('rejected', []))
    (out / 'plan.json').write_text(json.dumps(handoff, indent=2) + '\n', encoding='utf8')
    print(f'Exported {len(rows)} verified nonduplicate minimized cases from run {args.run_id}')
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (ConfigError, ValueError, OSError, TypeError, KeyError) as exc:
        print(f'Verified regression export blocked: {exc}', file=sys.stderr)
        raise SystemExit(30)
