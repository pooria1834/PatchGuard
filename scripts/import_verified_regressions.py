"""Import a data-only verified handoff in the privileged publisher job.

No target binary, oracle, or code from a PR is executed here. Reject path
traversal, symlinks, extra handoff members, hash mismatches and duplicates.
"""

import argparse
import json
import re
import sys
from hashlib import sha256
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from patchguard.config import (ConfigError, ROOT, UniqueKeyLoader, load_cases,
                               load_yaml, validate_case_args, workspace_path)
from patchguard.report import generate_case

ID = re.compile(r'generated-([0-9a-f]{12})-([0-9a-f]{12})-(?:base|candidate)-(?:release|checked)(?:-a[0-9a-f]{10})?\Z')
HEX = re.compile(r'[0-9a-f]{64}\Z')


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--config', required=True)
    p.add_argument('--handoff', required=True)
    p.add_argument('--report-dir', default='artifacts/patchguard')
    p.add_argument('--source-run-id', required=True)
    p.add_argument('--source-run-attempt', required=True)
    args = p.parse_args(argv)
    trusted = load_yaml(workspace_path(args.config, 'trusted configuration'))
    if not isinstance(trusted, dict) or not all(key in trusted for key in ('target', 'regression', 'run', 'corpus')):
        raise ConfigError('invalid trusted configuration')
    run = trusted['run']
    reviewed = trusted['regression'].get('reviewed', f"tests/regression/reviewed/{trusted['target']['name']}")
    destination = workspace_path(reviewed, 'regression.reviewed', within=ROOT / 'tests/regression/reviewed')
    report = workspace_path(args.report_dir, 'report dir', within=ROOT / 'artifacts')
    handoff = Path(args.handoff).resolve()
    if not handoff.is_dir() or handoff.is_symlink():
        raise ConfigError('handoff directory must be an ordinary directory')
    if (handoff / 'plan.json').is_symlink() or (handoff / 'reviewed').is_symlink():
        raise ConfigError('symlink in handoff')
    plan = json.loads((handoff / 'plan.json').read_text(encoding='utf8'))
    if (plan.get('schema') != 'patchguard-verified-regressions/1'
        or plan.get('source_run_id') != args.source_run_id
        or plan.get('source_run_attempt') != args.source_run_attempt
        or plan.get('reviewed_dir') != reviewed):
        raise ConfigError('handoff does not match trusted run/config')
    ids = plan.get('added')
    if (not isinstance(ids, list) or len(ids) > 500 or len(set(ids)) != len(ids)
        or any(not isinstance(name, str) or not ID.fullmatch(name) for name in ids)):
        raise ConfigError('handoff case identifiers are malformed')
    manifest = handoff / 'reviewed' / 'manifest.yaml'
    if manifest.is_symlink() or not manifest.is_file():
        raise ConfigError('missing verified manifest')
    rows = yaml.load(manifest.read_text(encoding='utf8'), Loader=UniqueKeyLoader)
    if not isinstance(rows, list) or len(rows) != len(ids) or {r.get('id') for r in rows if isinstance(r, dict)} != set(ids):
        raise ConfigError('verified manifest does not match handoff plan')
    allowed = {'plan.json', 'reviewed', 'reviewed/manifest.yaml'}
    cases = []
    for row in rows:
        if not isinstance(row, dict):
            raise ConfigError('verified manifest row must be a mapping')
        required = {'id', 'kind', 'input', 'expected_exit', 'expected_stdout', 'input_sha256',
                    'preserved_signature', 'witness_role', 'witness_mode'}
        if not required <= row.keys() or row.keys() - required - {'args'}:
            raise ConfigError('unapproved manifest fields')
        case_id = row['id']
        if not ID.fullmatch(case_id) or row['kind'] not in ('valid', 'invalid', 'boundary', 'regression'):
            raise ConfigError('malformed case identity/kind')
        if (row['witness_role'] not in ('base', 'candidate')
            or row['witness_mode'] not in ('release', 'checked')):
            raise ConfigError('invalid witness role/mode')
        if (not isinstance(row['input_sha256'], str) or not HEX.fullmatch(row['input_sha256'])
            or not isinstance(row['preserved_signature'], str) or not HEX.fullmatch(row['preserved_signature'])
            or not case_id.startswith('generated-' + row['input_sha256'][:12] + '-'
                                       + row['preserved_signature'][:12] + '-')):
            raise ConfigError('case identity does not match hashes')
        if 'args' in row:
            argv = validate_case_args(row['args'], run['method'], 'case.args')
        else:
            argv = validate_case_args(run.get('args', []), run['method'], 'run.args')
        if '-a' in case_id:
            if 'args' not in row or not case_id.endswith('-a' + sha256(json.dumps(argv, ensure_ascii=True).encode()).hexdigest()[:10]):
                raise ConfigError('argv hash mismatch')
        if (row['input'] != row['input_sha256'][:12] + '.bin'
            or row['expected_stdout'] != case_id + '.out'
            or type(row['expected_exit']) is not int or not 0 <= row['expected_exit'] <= 255):
            raise ConfigError('invalid fixture filenames or expected exit')
        for name in (row['input'], row['expected_stdout']):
            allowed.add('reviewed/' + name)
        data_file = handoff / 'reviewed' / row['input']
        stdout_file = handoff / 'reviewed' / row['expected_stdout']
        if any(f.is_symlink() or not f.is_file() for f in (data_file, stdout_file)):
            raise ConfigError('fixture must be a regular file')
        data = data_file.read_bytes()
        expected = stdout_file.read_bytes()
        if (len(data) > run['max_input_bytes'] or len(expected) > run['output_limit_bytes']
            or sha256(data).hexdigest() != row['input_sha256']):
            raise ConfigError('fixture hash/length mismatch')
        cases.append((row, data, expected, tuple(argv)))
    seen_files = {p.relative_to(handoff).as_posix() for p in handoff.rglob('*')}
    if any(p.is_symlink() for p in handoff.rglob('*')) or seen_files != allowed:
        raise ConfigError('unexpected or symlinked files in the verified handoff')
    # No code in the handoff is executed; only trusted current-main fixtures
    # determine whether a new case is already covered.
    original = load_cases(workspace_path(trusted['corpus']['path'], 'corpus.path'),
                          run['max_input_bytes'], run['output_limit_bytes'], run=run)
    prior = load_cases(destination / 'manifest.yaml', run['max_input_bytes'],
                       run['output_limit_bytes'], optional=True, run=run)
    seen = {(sha256(c['input']).hexdigest(), tuple(c.get('args', run.get('args', []))))
            for c in original + prior}
    added = []
    for row, data, expected, argv in cases:
        key = sha256(data).hexdigest(), argv
        if key in seen:
            continue
        result = generate_case(destination, dict(kind=row['kind']), data, row['preserved_signature'],
                               expected_exit=row['expected_exit'], expected_stdout=expected,
                               witness_role=row['witness_role'], witness_mode=row['witness_mode'],
                               args=row.get('args'), case_id=row['id'])
        if not result['deduplicated']:
            added.append(row['id'])
        seen.add(key)
    report.mkdir(parents=True, exist_ok=True)
    (report / 'regression-pr-preparation.json').write_text(json.dumps({
        'schema': 'patchguard-regression-pr-preparation/1',
        'reviewed_dir': reviewed, 'added': added, 'already_present': sorted(set(ids) - set(added)),
        'rejected': []}, indent=2) + '\n', encoding='utf8')
    print(f'Imported {len(added)} new verified fixtures; {len(ids)-len(added)} already covered')
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (ConfigError, ValueError, OSError, TypeError, KeyError, yaml.YAMLError) as exc:
        print('Verified import blocked: ' + str(exc), file=sys.stderr)
        raise SystemExit(30)
