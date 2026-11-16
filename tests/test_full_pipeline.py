"""Full local CI smoke: two CLI modes, four C builds, minimization and one PR proposal."""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

TOOL = Path(__file__).resolve().parents[1]


@pytest.mark.integration
def test_four_builds_and_single_auto_regression_proposal(tmp_path):
    if not all(shutil.which(tool) for tool in ('gcc', 'git', 'readelf', 'file')):
        pytest.skip('C build and ELF tools are required for this integration test')
    for side in ('base', 'patched'):
        directory = tmp_path / 'src' / side
        directory.mkdir(parents=True)
        (directory / 'app.c').write_text(r'''#include <stdio.h>
#include <string.h>
int main(int argc, char **argv) {
    if (argc != 2) return 3;
    char data[1024] = {0};
    if (!fgets(data, sizeof(data), stdin)) return 3;
    if (strstr(data, "bad")) { puts("''' + ('BAD' if side == 'base' else 'ERR') + r'''"); return 0; }
    puts(strcmp(argv[1], "-f") == 0 ? "FOK" : "SOK");
    return 0;
}
''')
    fixture = tmp_path / 'tests' / 'fixtures' / 'target'
    fixture.mkdir(parents=True)
    (fixture / 'valid.bin').write_bytes(b'hello\n')
    (fixture / 'invalid.bin').write_bytes(b'bad' + b'X'*13 + b'\n')
    (fixture / 'valid.out').write_bytes(b'FOK\n')
    (fixture / 'invalid.out').write_bytes(b'ERR\n')
    (fixture / 'cases.yaml').write_text(yaml.safe_dump([
        dict(id='valid', kind='valid', input='valid.bin', expected_exit=0,
             expected_stdout='valid.out', args=['-f']),
        dict(id='invalid', kind='invalid', input='invalid.bin', expected_exit=0,
             expected_stdout='invalid.out', args=['-s']),
    ], sort_keys=False))
    (tmp_path/'oracle.py').write_text('''import sys
content = sys.stdin.buffer.read()
mode = sys.argv[1]
sys.stdout.buffer.write(b"ERR\\n" if b"bad" in content else
                        b"FOK\\n" if mode == "-f" else b"SOK\\n")
''')
    base_flags = ['-O0', '-g', '-fstack-protector-all', '-fPIE', '-pie', '-Wl,-z,relro,-z,now']
    config = dict(target=dict(name='smoke'),
                  sources=dict(base='src/base', patched='src/patched'),
                  build=dict(command=['gcc', '{flags}', '{sources}', '-o', '{output}'],
                             sources=['{source_dir}/app.c'],
                             flags=dict(release=base_flags, checked=base_flags + ['-fsanitize=undefined']),
                             output='app'),
                  run=dict(method='stdin', args=['-s'], timeout_seconds=3,
                           max_input_bytes=1024, output_limit_bytes=4096, env={}),
                  corpus=dict(path='tests/fixtures/target/cases.yaml'),
                  regression=dict(dir='tests/regression/generated/smoke'),
                  oracle=dict(command=['python3', 'oracle.py', '{case_args}'], timeout_seconds=2))
    (tmp_path/'config.yaml').write_text(yaml.safe_dump(config, sort_keys=False))
    (tmp_path/'artifacts').mkdir()
    subprocess.run(['git', 'init', '-q', str(tmp_path)], check=True)
    subprocess.run(['git', '-C', str(tmp_path), 'add', 'config.yaml', 'src', 'tests/fixtures', 'oracle.py'], check=True)
    subprocess.run(['git','-C',str(tmp_path),'-c','user.name=Test','-c','user.email=t@example.com',
                    'commit','-qm','baseline'], check=True)
    env = dict(os.environ, PATCHGUARD_WORKSPACE=str(tmp_path), PYTHONPATH=str(TOOL))
    def command(*args):
        return subprocess.run([sys.executable, *args], cwd=tmp_path, env=env,
                              capture_output=True, text=True, timeout=90)
    evaluation = command('-m', 'patchguard', 'validate', '--config', 'config.yaml',
                         '--report-dir', 'artifacts/ci')
    assert evaluation.returncode == 0, evaluation.stderr
    folder = tmp_path/'artifacts/ci'
    report = json.loads((folder/'report.json').read_text())
    assert len(report['builds']) == 4 and len(report['executions']) == 8
    assert all(row['argv'][-1] == ('-f' if row['case_id']=='valid' else '-s')
               for row in report['executions'])
    assert report['config']['resolved']['regression']['reviewed'] == 'tests/regression/reviewed/smoke'
    assert all(stage['status'] == 'passed' for stage in report['stages'])
    summary = (folder/'summary.md').read_text()
    assert 'Binary hardening' in summary and 'Exact layout' in summary
    assert 'artifacts/ci/cases/' in summary
    packed = command(str(TOOL/'scripts/package_ci_evidence.py'), '--report-dir', 'artifacts/ci')
    assert packed.returncode == 0, packed.stderr
    staged = command(str(TOOL/'scripts/batch_promote.py'), '--config', 'config.yaml',
                     '--report-dir', 'artifacts/ci')
    assert staged.returncode == 0, staged.stderr
    plan = json.loads((folder/'regression-pr-preparation.json').read_text())
    assert len(plan['added']) == 1
    assert len(plan['redundant_build_modes']) == 1
    assert not plan['rejected']
    dry_run = subprocess.run([sys.executable, str(TOOL/'scripts/create_regression_pr.py'),
                              '--report-dir', 'artifacts/ci', '--dry-run'], cwd=tmp_path,
                             env=dict(env, GITHUB_WORKSPACE=str(tmp_path)),
                             capture_output=True, text=True, timeout=20)
    assert dry_run.returncode == 0, dry_run.stderr
    assert 'DRY RUN' in dry_run.stdout
    # A second promotion must propose nothing new.
    repeated = command(str(TOOL/'scripts/batch_promote.py'), '--config', 'config.yaml',
                       '--report-dir', 'artifacts/ci')
    assert repeated.returncode == 0, repeated.stderr
    assert not json.loads((folder/'regression-pr-preparation.json').read_text())['added']
    assert (folder/'summary.md').read_text().count('## Automated regression PR preparation') == 1
