"""Focused regression tests for CLI argv, automated PR evidence and summaries."""

import json
import os
import subprocess
import sys
from hashlib import sha256
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

import pytest
import yaml

from patchguard.analyze import signature
from patchguard.config import ConfigError, oracle_argv, validate_case_args
from patchguard.promotion import inspect_archive
from patchguard.report import _summary


ROOT = Path(__file__).resolve().parents[1]


def test_individual_args_are_validated_and_not_treated_as_shell_script():
    assert validate_case_args(['-f', '{input_file}'], 'file', 'x') == ['-f', '{input_file}']
    assert validate_case_args(['-s'], 'stdin', 'x') == ['-s']
    jq_filter = '{value: .items[0], ok: true} | .value'
    assert validate_case_args(['-r', jq_filter], 'stdin', 'x') == ['-r', jq_filter]
    assert oracle_argv({'command':['python3', 'oracle.py', '{case_args}']}, ['-f','filter.jq']) == ['python3','oracle.py','-f','filter.jq']
    with pytest.raises(ConfigError, match='requires'):
        validate_case_args(['-s'], 'file', 'x')
    with pytest.raises(ConfigError, match='unsupported placeholder'):
        validate_case_args(['{input_file}'], 'stdin', 'x')


def test_execute_case_uses_its_own_args_and_generated_hashes(tmp_path):
    workspace = tmp_path
    (workspace / 'artifacts').mkdir()
    (workspace / 'cases').mkdir()
    (workspace / 'cases' / 'a.bin').write_bytes(b'hi')
    (workspace / 'cases' / 'b.bin').write_bytes(b'hi')
    (workspace / 'cases' / 'expect.out').write_bytes(b'')
    records = [dict(id='case-a', kind='valid', input='a.bin', expected_exit=0,
                    expected_stdout='expect.out', args=['-n']),
               dict(id='case-b', kind='valid', input='b.bin', expected_exit=0,
                    expected_stdout='expect.out', args=['-n', '--help'])]
    (workspace / 'cases' / 'manifest.yaml').write_text(yaml.safe_dump(records), encoding='utf-8')
    snippet = r'''
import json
from pathlib import Path
from patchguard.config import ROOT, load_cases
from patchguard.run import run_case
from patchguard.report import generate_case
settings = dict(method='stdin', args=['DEFAULT'], timeout_seconds=5,
                output_limit_bytes=40000, env={})
cases = load_cases(ROOT/'cases'/'manifest.yaml', 1000, 40000, run=settings)
build = dict(path='echo', sha256='0'*64, flags=[])
a = run_case(build, cases[0], settings, ROOT/'artifacts'/'a')
b = run_case(build, cases[1], settings, ROOT/'artifacts'/'b')
# Stored data is exactly the original per-case argv (no global fallback).
print(json.dumps(dict(a=a['argv'], b=b['argv'],
                      stdout=(ROOT/a['stdout']['path']).read_bytes().decode())))
g1 = generate_case(ROOT/'artifacts'/'generated', cases[0], b'hi', 'a'*64,
                   witness_role='base', witness_mode='release', args=['-n'], identity_args=['-n'])
g2 = generate_case(ROOT/'artifacts'/'generated', cases[1], b'hi', 'a'*64,
                   witness_role='base', witness_mode='release', args=['-n','--help'],
                   identity_args=['-n','--help'])
assert g1['id'] != g2['id']
assert generate_case(ROOT/'artifacts'/'generated', cases[0], b'hi', 'a'*64,
                     witness_role='base', witness_mode='release', args=['-n'],
                     identity_args=['-n'])['deduplicated']
'''
    (workspace / 'echo').symlink_to('/bin/echo')
    env = dict(os.environ, PATCHGUARD_WORKSPACE=str(workspace), PYTHONPATH=str(ROOT))
    result = subprocess.run([sys.executable, '-c', snippet], cwd=workspace, env=env,
                            capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    reported = json.loads(result.stdout)
    assert reported['a'][-1] == '-n'
    assert reported['b'][-2:] == ['-n', '--help']
    assert 'DEFAULT' not in reported['a'] and 'DEFAULT' not in reported['b']


def test_archive_accepts_candidate_and_validates_case_args(tmp_path):
    data, expected = b'case', b'OK\n'
    result = dict(mismatch_kind='stdout_mismatch', expected_stdout_hex=expected.hex(),
                  actual_stdout_hex=b'BAD\n'.hex(), expected_exit=0, actual_exit=0,
                  state='normal', stdout=dict(truncated=False), stderr=dict(truncated=False))
    token = signature(result)
    digest = sha256(data).hexdigest()
    case_id = f'generated-{digest[:12]}-{token[:12]}-candidate-checked'
    generated = 'tests/regression/generated/target'
    manifest = f'{generated}/manifest.yaml'
    member = f'artifacts/ci/cases/{token}-candidate-checked-original/minimized.bin'
    case_args = ['-s']
    rows = [dict(id=case_id, kind='valid', input=digest[:12]+'.bin',
                 expected_exit=0, expected_stdout=case_id+'.out',
                 input_sha256=digest, preserved_signature=token,
                 witness_role='candidate', witness_mode='checked', args=case_args)]
    history = [{'signature': token, 'path': f'artifacts/ci/attempt-{i}.json'} for i in range(1, 4)]
    archive_report = dict(schema='patchguard-safelab/1', run={'directory':'artifacts/ci', 'id':'ci'},
                          config={'resolved':{'target':{'name':'target'},
                                              'regression':{'dir':generated},
                                              'corpus':{'path':'tests/fixtures/a.yaml'}}},
                          sources={'candidate': {'digest':'b'*64}},
                          replay=[dict(role='candidate', mode='checked', stable=True,
                                       generated={'id':case_id, 'manifest':manifest},
                                       signature=token, minimized=member,
                                       minimized_sha256=digest, minimized_expected_exit=0,
                                       minimized_expected_stdout=expected.hex(),
                                       args=case_args, history=history)])
    config = {'target':{'name':'target'}, 'regression':{'dir':generated},
              'corpus':{'path':'tests/fixtures/a.yaml'},
              'run':{'method':'stdin', 'args':[],'max_input_bytes':100,'output_limit_bytes':100}}
    path = tmp_path/'evidence.zip'
    with ZipFile(path, 'w', ZIP_DEFLATED) as out:
        out.writestr('artifacts/ci/report.json', json.dumps(archive_report))
        out.writestr(manifest, yaml.safe_dump(rows))
        out.writestr(f'{generated}/{digest[:12]}.bin', data)
        out.writestr(f'{generated}/{case_id}.out', expected)
        out.writestr(member, data)
        for attempt in history:
            out.writestr(attempt['path'], json.dumps(result))
    case, metadata = inspect_archive(path, config, case_id)
    assert case['witness_role'] == 'candidate'
    assert case['args'] == ['-s']
    assert metadata['source_digest'] == 'b'*64
    assert metadata['args_explicit'] is True
    # Archive tampering is rejected, not blindly imported.
    with ZipFile(path, 'a') as out:
        out.writestr('artifacts/ci/attempt-1.json', '{}')
    with pytest.raises(ConfigError, match='duplicate archive member'):
        inspect_archive(path, config, case_id)


def test_summary_has_stack_and_hardening_with_exact_zip_members():
    def meta(value):
        return dict(hardening={k:dict(status=v) for k,v in value.items()},
                    tools={'readelf':{'process':{'stdout':{'path':'artifacts/ci/binary-info/readelf/stdout.bin'}}}})
    secure = dict(nx='enabled', pie='enabled', relro='full', stack_canary='present')
    weaker = dict(nx='enabled', pie='disabled', relro='partial', stack_canary='not_observed')
    run = dict(case_id='bad', role='candidate', mode='checked', diagnostic={
        'mechanism':'ASan', 'kind':'heap-buffer-overflow',
        'location': {'path':'source.c', 'line':42},
        'frames':[{'function':'read_record', 'path':'source.c', 'line':42},
                  {'function':'main', 'path':'main.c', 'line':9}]},
        state='signal', returncode=-6, signal='SIGABRT', timed_out=False,
        stdout={'path':'artifacts/ci/runs/candidate/checked/bad/stdout.bin'},
        stderr={'path':'artifacts/ci/runs/candidate/checked/bad/stderr.bin'},
        record='artifacts/ci/runs/candidate/checked/bad/result.json')
    report = dict(run={'directory':'artifacts/ci'}, exit_code=10,
                  result='INCOMPLETE_CORRECTION', exit_reason='fault still reproduces',
                  config={'resolved':{'target':{'name':'demo'},
                                      'regression':{'dir':'tests/regression/generated/demo',
                                                    'reviewed':'tests/regression/reviewed/demo'}}},
                  cases=[{}], executions=[run], observations={}, checks={},
                  binary_metadata={'base-release':meta(secure), 'candidate-release':meta(weaker),
                                   'base-checked':meta(secure),'candidate-checked':meta(weaker)},
                  hardening_warnings=[dict(protection='pie', before={'status':'enabled'},
                                          after={'status':'disabled'})],
                  replay=[dict(case_id='bad', role='candidate', mode='checked', stable=True,
                               path='artifacts/ci/cases/S-candidate-checked-bad/manifest.json',
                               minimized='artifacts/ci/cases/S-candidate-checked-bad/minimized.bin')])
    output = _summary(report)
    for marker in ('#0 read_record', '#1 main', '⚠ Hardening downgrade',
                   'RELRO', 'Stack Canary', 'technical-evidence.zip',
                   'artifacts/ci/runs/candidate/checked/bad/stderr.bin',
                   'artifacts/ci/cases/S-candidate-checked-bad/manifest.json',
                   'tests/regression/generated/demo/manifest.yaml'):
        assert marker in output


def test_host_dry_run_proposes_only_reviewed_files(tmp_path):
    subprocess.run(['git','init','-q',str(tmp_path)], check=True)
    (tmp_path/'README').write_text('demo')
    subprocess.run(['git','-C',str(tmp_path), 'add','README'], check=True)
    subprocess.run(['git','-C',str(tmp_path),'-c','user.name=T','-c','user.email=t@example.com',
                    'commit','-qm','initial'],check=True)
    reviewed = tmp_path/'tests/regression/reviewed/target'
    reviewed.mkdir(parents=True)
    (reviewed/'manifest.yaml').write_text('[]\n')
    (reviewed/'.manifest.lock').write_bytes(b'')
    gate = tmp_path/'artifacts/gate'
    gate.mkdir(parents=True)
    (gate/'regression-pr-preparation.json').write_text(json.dumps({
        'schema':'patchguard-regression-pr-preparation/1',
        'reviewed_dir':'tests/regression/reviewed/target',
        'added':['generated-new-case'], 'already_present':[], 'rejected':[]})+'\n')
    env = dict(os.environ, GITHUB_WORKSPACE=str(tmp_path))
    result = subprocess.run([sys.executable, str(ROOT/'scripts/create_regression_pr.py'),
                             '--report-dir','artifacts/gate','--dry-run'],
                            env=env, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert 'DRY RUN: proposal commit:' in result.stdout
    assert not (gate/'regression-pr.json').exists()
