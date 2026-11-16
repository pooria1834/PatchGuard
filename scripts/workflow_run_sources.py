"""Reconstruct exact PR-merge sources for unprivileged workflow_run verification.

Only use in a contents:read job, on a checkout of the trusted default branch.
The downloaded CI evidence is untrusted and must match the GitHub PR merge
commit and source tree hashes before any witness replay is attempted.
"""

import argparse
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path, PurePosixPath
from zipfile import ZipFile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from patchguard.config import ROOT, load_yaml, workspace_path, ConfigError
from patchguard.source import inventory, tree_digest

SHA = re.compile(r'[0-9a-f]{40}\Z')


def git(*argv: str) -> bytes:
    return subprocess.run(['git', '-c', 'core.hooksPath=/dev/null',
                           '-c', 'core.fsmonitor=false', '-C', str(ROOT), *argv],
                          check=True, capture_output=True).stdout


def checked_rel(value: str, label: str) -> Path:
    if not isinstance(value, str) or not value or value == '.' or '\\' in value:
        raise ConfigError(f'{label}: invalid source path')
    parts = PurePosixPath(value).parts
    if (PurePosixPath(value).is_absolute() or '..' in parts or not parts
        or any(part in ('.git', 'artifacts', 'tests', '__pycache__') for part in parts)):
        raise ConfigError(f'{label}: unsafe source path')
    return Path(value)


def materialize(revision: str, tracked_dir: Path, destination: Path) -> None:
    """Write regular Git blobs only: reject symlinks, submodules and escapes."""
    if destination.exists():
        if destination.is_symlink() or not destination.is_dir():
            raise ConfigError('source destination must be a real directory')
        shutil.rmtree(destination)
    destination.mkdir(parents=True)
    prefix = tracked_dir.as_posix().rstrip('/') + '/'
    raw = git('ls-tree', '-r', '-z', revision, '--', tracked_dir.as_posix())
    count = 0
    for entry in raw.split(b'\0'):
        if not entry:
            continue
        header, filename = entry.split(b'\t', 1)
        mode, kind, blob = header.decode('ascii').split()
        name = filename.decode('utf-8', 'surrogateescape')
        if not name.startswith(prefix) or mode not in ('100644', '100755') or kind != 'blob':
            raise ConfigError(f'unsupported Git source entry: {name!r} ({mode})')
        rel = Path(name[len(prefix):])
        if any(part in ('', '.', '..', '.git') for part in rel.parts):
            raise ConfigError(f'unsafe Git path: {name!r}')
        size = int(git('cat-file', '-s', blob).decode().strip())
        if size > 32 * 1024 * 1024 or count >= 20000:
            raise ConfigError('source snapshot exceeds safe size/count limit')
        data = git('cat-file', 'blob', blob)
        if len(data) != size:
            raise ConfigError(f'Git blob length mismatch: {name}')
        target = destination / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        if mode == '100755':
            target.chmod(0o755)
        count += 1
    if not count:
        raise ConfigError(f'no tracked source files at {tracked_dir}')


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--config', required=True)
    p.add_argument('--archive', required=True)
    p.add_argument('--pr-number', type=int, required=True)
    p.add_argument('--expected-head-sha', required=True)
    p.add_argument('--report-dir', default='artifacts/patchguard')
    args = p.parse_args(argv)
    if args.pr_number < 1 or not SHA.fullmatch(args.expected_head_sha):
        p.error('invalid PR number/head SHA')
    config = load_yaml(workspace_path(args.config, 'trusted config'))
    if not isinstance(config, dict) or not isinstance(config.get('sources'), dict):
        p.error('invalid trusted config')
    source = config['sources']
    base_dir = checked_rel(source['base'], 'sources.base')
    candidate_dir = checked_rel(source['patched'], 'sources.patched')
    if base_dir == candidate_dir or base_dir in candidate_dir.parents or candidate_dir in base_dir.parents:
        p.error('overlapping source roots are not supported by workflow_run snapshots')
    archive = workspace_path(args.archive, 'archive', within=ROOT / 'artifacts')
    report_path = args.report_dir.rstrip('/') + '/report.json'
    with ZipFile(archive) as zf:
        matching = [i for i in zf.infolist() if i.filename == report_path]
        if len(matching) != 1 or matching[0].file_size > 16 * 1024 * 1024:
            raise ConfigError('missing or oversized evidence report')
        report = json.loads(zf.read(matching[0]))
    revision = report.get('sources', {}).get('candidate', {}).get('revision')
    if not isinstance(revision, str) or not SHA.fullmatch(revision):
        raise ConfigError('CI report lacks an exact candidate Git commit')
    # This is intentionally fetched from the canonical origin and is NOT taken
    # from an arbitrary ref or URL in the untrusted artifact.
    git('fetch', '--no-tags', 'origin', f'refs/pull/{args.pr_number}/merge')
    merge = git('rev-parse', 'FETCH_HEAD').decode().strip()
    parent2 = git('rev-parse', merge + '^2').decode().strip()
    parent1 = git('rev-parse', merge + '^1').decode().strip()
    if revision != merge or args.expected_head_sha not in (merge, parent2):
        raise ConfigError('PR merge changed since the source Action run; rerun PatchGuard on the current PR')
    # Both source snapshots come from the same tracked source subtree of their
    # respective revisions (e.g. record-parser `src`).
    materialize(parent1, candidate_dir, ROOT / base_dir)
    materialize(merge, candidate_dir, ROOT / candidate_dir)
    for role, folder in [('base', ROOT / base_dir), ('candidate', ROOT / candidate_dir)]:
        expected_digest = report.get('sources', {}).get(role, {}).get('digest')
        actual = tree_digest(inventory(folder))
        if actual != expected_digest:
            raise ConfigError(f'{role} Git source digest differs from original PatchGuard CI evidence')
    print(f'Verified exact PR #{args.pr_number}: base {parent1}, merge {merge}; both source digests match')
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (ConfigError, ValueError, KeyError, OSError, subprocess.CalledProcessError, json.JSONDecodeError) as exc:
        print(f'workflow_run source verification blocked: {exc}', file=sys.stderr)
        raise SystemExit(30)
