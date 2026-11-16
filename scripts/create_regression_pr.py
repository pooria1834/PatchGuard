"""Create one GitHub pull request containing all prepared regression fixtures.

This host-only program never executes the target, the independent oracle, or
untrusted fixture bytes. It must NOT run with an untrusted PR's write token.
"""

import argparse
import base64
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path


def git(directory: Path, *arguments: str, env: dict | None = None) -> str:
    # Keep the write token out of all git child processes except the explicit
    # HTTPS authentication header passed solely to the final push. Disable
    # repository hooks/fsmonitor, which must never run in this trusted stage.
    clean_env = dict(os.environ if env is None else env)
    clean_env.pop('PG_GITHUB_TOKEN', None)
    clean_env.pop('GITHUB_TOKEN', None)
    completed = subprocess.run(['git', '-c', 'core.hooksPath=/dev/null',
                                '-c', 'core.fsmonitor=false', '-C', str(directory),
                                *arguments], env=clean_env,
                               check=True, text=True, capture_output=True)
    return completed.stdout.strip()


def api(url: str, token: str, payload: dict) -> dict:
    request = urllib.request.Request(url, data=json.dumps(payload).encode('utf-8'),
                                     method='POST', headers={'Authorization': 'Bearer ' + token,
                                     'Accept': 'application/vnd.github+json',
                                     'X-GitHub-Api-Version': '2022-11-28',
                                     'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.load(response)
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f'GitHub PR API returned HTTP {exc.code}: '
                           + exc.read(2000).decode('utf-8', 'replace')) from exc


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report-dir', required=True)
    parser.add_argument('--dry-run', action='store_true', help='Make a local commit only; do not push or open a PR')
    args = parser.parse_args(argv)
    root = Path(os.environ.get('GITHUB_WORKSPACE', '.')).resolve()
    folder = (root / args.report_dir).resolve()
    if not folder.is_relative_to(root / 'artifacts'):
        parser.error('report directory must be inside artifacts/')
    plan_path = folder / 'regression-pr-preparation.json'
    if not plan_path.is_file():
        print('No verified regression PR plan was produced; skipping.')
        return 0
    plan = json.loads(plan_path.read_text(encoding='utf-8'))
    case_ids = plan.get('added') or []
    def note(message: str):
        summary = folder / 'summary.md'
        if summary.is_file():
            old = summary.read_text(encoding='utf-8')
            marker = '<!-- patchguard-auto-pr-status -->'
            if marker in old:
                old = old[:old.index(marker)].rstrip()
            summary.write_text(old + '\n\n' + marker + '\n- **Automated PR status:** '
                               + message + '\n', encoding='utf-8')
    if not case_ids:
        print('No new regression cases; no PR needed.')
        note('not needed; no new unique minimized witnesses.')
        return 0
    if plan.get('schema') != 'patchguard-regression-pr-preparation/1':
        parser.error('invalid preparation schema')
    reviewed = plan.get('reviewed_dir')
    if (not isinstance(reviewed, str) or not re.fullmatch(r'tests/regression/reviewed(?:/[a-zA-Z0-9_./-]+)?', reviewed)
        or '..' in Path(reviewed).parts):
        parser.error('invalid reviewed directory')
    source = (root / reviewed).resolve()
    if not source.is_relative_to(root / 'tests/regression/reviewed') or not source.is_dir():
        parser.error('reviewed directory is missing or unsafe')
    if any(path.is_symlink() for path in source.rglob('*')):
        parser.error('reviewed suite must not contain symlinks')
    # Never expose a write-capable GitHub token to the network-disabled Docker
    # process that ran the untrusted target or to third-party pull requests.
    event = os.environ.get('GITHUB_EVENT_NAME', '')
    default = os.environ.get('PG_DEFAULT_BRANCH', '')
    current_ref = os.environ.get('GITHUB_REF', '')
    repository = os.environ.get('GITHUB_REPOSITORY', '')
    token = os.environ.get('PG_GITHUB_TOKEN', '')
    if not args.dry_run and (event not in ('push', 'workflow_dispatch')
                             or not default or current_ref != 'refs/heads/' + default):
        print('Automatic PR skipped: only trusted default-branch pushes/dispatches may create a write PR.')
        note('skipped on untrusted/non-default-branch event; review the evidence artifact.')
        return 0
    if not args.dry_run and (not token or not re.fullmatch(r'[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+', repository)):
        print('Automatic PR skipped: GitHub token/repository is unavailable.')
        note('skipped; GitHub token or repository permission is missing.')
        return 0
    number = os.environ.get('GITHUB_RUN_ID', 'local')
    attempt = os.environ.get('GITHUB_RUN_ATTEMPT', '1')
    if not re.fullmatch(r'[0-9]+', number) or not re.fullmatch(r'[0-9]+', attempt):
        if not args.dry_run:
            parser.error('invalid GitHub run number')
        number, attempt = '0', '1'
    branch = f'patchguard/regressions-{number}-{attempt}'
    result_path = folder / 'regression-pr.json'
    with tempfile.TemporaryDirectory(prefix='patchguard-pr-') as temporary:
        worktree = Path(temporary) / 'checkout'
        git(root, 'worktree', 'add', '--detach', str(worktree), 'HEAD')
        try:
            destination = worktree / reviewed
            destination.mkdir(parents=True, exist_ok=True)
            # Only the validated reviewed corpus is copied and committed. No
            # build artifact, ZIP, or arbitrary workspace change enters the PR.
            shutil.copytree(source, destination, dirs_exist_ok=True,
                            ignore=shutil.ignore_patterns(".manifest.lock", ".manifest.pending"))
            git(worktree, 'add', '-A', '--', reviewed)
            if not git(worktree, 'diff', '--cached', '--name-only', '--', reviewed):
                print('Tracked regression corpus is unchanged; no PR needed.')
                note('not needed; there is no tracked corpus change.')
                return 0
            git(worktree, '-c', 'user.name=patchguard[bot]',
                '-c', 'user.email=41898282+github-actions[bot]@users.noreply.github.com',
                'commit', '-m', f'Add {len(case_ids)} verified PatchGuard regression case(s)')
            if args.dry_run:
                print('DRY RUN: proposal commit:', git(worktree, 'rev-parse', 'HEAD'))
                note('locally verified (dry run); no GitHub PR created.')
                return 0
            auth = base64.b64encode(f'x-access-token:{token}'.encode()).decode('ascii')
            env = dict(os.environ, GIT_TERMINAL_PROMPT='0', GIT_CONFIG_COUNT='1',
                       GIT_CONFIG_KEY_0='http.https://github.com/.extraheader',
                       GIT_CONFIG_VALUE_0='AUTHORIZATION: basic ' + auth)
            # Use the repository as a fixed origin; no untrusted remote URL.
            git(worktree, 'push', f'https://github.com/{repository}.git',
                f'HEAD:refs/heads/{branch}', env=env)
            body = ('PatchGuard automatically generated **' + str(len(case_ids))
                    + '** stable, minimized regression case(s). This PR is **not auto-merged**.\n\n'
                    + 'Every included case was validated against the recorded 3x replay signatures '
                    + 'and an independent oracle (or a byte-identical trusted fixture). '
                    + 'Review the inputs, expected behavior, and CI logs before merging.\n\n'
                    + 'Witnesses (`base` and/or `candidate`):\n'
                    + '\n'.join('- `' + item + '`' for item in case_ids)
                    + '\n\nSource CI run: ' + os.environ.get('GITHUB_SERVER_URL', 'https://github.com')
                    + '/' + repository + '/actions/runs/' + number + '\n')
            response = api(f'https://api.github.com/repos/{repository}/pulls', token,
                           dict(title=f'PatchGuard: add {len(case_ids)} minimized regression case(s)',
                                head=branch, base=default, body=body, draft=True))
            url = response.get('html_url')
            if not isinstance(url, str) or not url.startswith('https://github.com/'):
                raise RuntimeError('GitHub did not return a verified PR link')
            result_path.write_text(json.dumps(dict(branch=branch, url=url, cases=case_ids), indent=2) + '\n')
            print('Created reviewable draft regression PR:', url)
            note(f'draft PR: {url} ({len(case_ids)} new minimized case(s); '
                 'review and approval required).')
            return 0
        finally:
            git(root, 'worktree', 'remove', '--force', str(worktree))


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError, RuntimeError, urllib.error.URLError) as exc:
        print('Automatic regression PR failed: ' + str(exc), file=sys.stderr)
        raise SystemExit(30)
