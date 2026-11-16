"""Exercise exact source rehydration from an immutable PR merge Git ref."""

import json
import os
import subprocess
import sys
from hashlib import sha256
from pathlib import Path
from zipfile import ZipFile

from patchguard.source import tree_digest

TOOL = Path(__file__).resolve().parents[1]


def git(root, *args):
    return subprocess.run(['git', '-C', str(root), *args], check=True,
                          text=True, capture_output=True).stdout.strip()


def test_workflow_run_exact_git_sources(tmp_path):
    root = tmp_path / 'repo'
    root.mkdir()
    origin = tmp_path / 'origin.git'
    subprocess.run(['git', 'init', '--bare', '-q', str(origin)], check=True)
    subprocess.run(['git', 'init', '-q', '-b', 'main', str(root)], check=True)
    git(root, 'remote', 'add', 'origin', str(origin))
    git(root, 'config', 'user.name', 'tester')
    git(root, 'config', 'user.email', 'test@example.com')
    (root/'src').mkdir()
    (root/'src'/'record_parser.c').write_bytes(b'int old_code = 1;\n')
    (root/'.patchguard').mkdir()
    (root/'.patchguard'/'config.yaml').write_text('sources:\n  base: .patchguard/base/src\n  patched: src\n')
    git(root, 'add', '.'); git(root, 'commit', '-qm', 'initial')
    base = git(root, 'rev-parse', 'HEAD')
    git(root, 'checkout', '-qb', 'feature')
    (root/'src'/'record_parser.c').write_bytes(b'int patched_code = 2;\n')
    git(root, 'add', '.'); git(root, 'commit', '-qm', 'patch')
    head = git(root, 'rev-parse', 'HEAD')
    git(root, 'checkout', '-q', 'main')
    git(root, 'checkout', '-qb', 'simulated-merge')
    git(root, 'merge', '--no-ff', '-qm', 'merge preview', 'feature')
    merge = git(root, 'rev-parse', 'HEAD')
    git(root, 'push', 'origin', f'{merge}:refs/pull/9/merge')
    git(root, 'checkout', '-q', 'main')
    base_bytes = b'int old_code = 1;\n'
    changed_bytes = b'int patched_code = 2;\n'
    digest = lambda data: tree_digest({'record_parser.c': sha256(data).hexdigest()})
    archive = root/'artifacts'/'patchguard'/'technical-evidence.zip'
    archive.parent.mkdir(parents=True)
    with ZipFile(archive, 'w') as zf:
        zf.writestr('artifacts/patchguard/report.json', json.dumps({
            'sources': {'base': {'digest': digest(base_bytes)},
                        'candidate': {'revision': merge, 'digest': digest(changed_bytes)}}}))
    env = dict(os.environ, PATCHGUARD_WORKSPACE=str(root), PYTHONPATH=str(TOOL))
    command = [sys.executable, str(TOOL/'scripts/workflow_run_sources.py'),
               '--config', '.patchguard/config.yaml',
               '--archive', 'artifacts/patchguard/technical-evidence.zip',
               '--pr-number', '9', '--expected-head-sha', head]
    good = subprocess.run(command, cwd=root, env=env, text=True, capture_output=True)
    assert good.returncode == 0, good.stderr
    assert (root/'.patchguard/base/src/record_parser.c').read_bytes() == base_bytes
    assert (root/'src/record_parser.c').read_bytes() == changed_bytes
    bad = subprocess.run(command[:-1] + [base], cwd=root, env=env, text=True, capture_output=True)
    assert bad.returncode == 30


def test_both_record_parser_workflows_have_correct_events_and_permissions():
    import yaml
    primary = yaml.load((TOOL/'examples/record-parser/patchguard.yml').read_text(), Loader=yaml.BaseLoader)
    subscriber = yaml.load((TOOL/'examples/record-parser/patchguard-regression-pr.yml').read_text(), Loader=yaml.BaseLoader)
    assert 'pull_request' in primary['on']
    assert primary['permissions']['contents'] == 'read'
    assert subscriber['on']['workflow_run']['workflows'] == ['PatchGuard']
    assert subscriber['jobs']['verify'].get('permissions', subscriber['permissions'])['contents'] == 'read'
    assert subscriber['jobs']['publish']['permissions']['contents'] == 'write'
    assert subscriber['jobs']['publish']['permissions']['pull-requests'] == 'write'
