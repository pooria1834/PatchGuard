"""Safely prepare ALL new stable regression witnesses for one review PR.

Run inside the same network-disabled PatchGuard container as validation. The
archive is treated as untrusted. A PR is created separately on the host,
without putting a GitHub token near the target binaries or the oracle.
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from patchguard.config import ConfigError, ROOT, load_cases, load_config, workspace_path
from patchguard.promotion import promote_archive
from patchguard.report import write_json
from hashlib import sha256


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True)
    parser.add_argument('--report-dir', required=True)
    args = parser.parse_args(argv)
    try:
        folder = workspace_path(args.report_dir, 'report directory', within=ROOT / 'artifacts')
        report = json.loads((folder / 'report.json').read_text(encoding='utf-8'))
        config = load_config(args.config)
        reviewed = config['regression'].get('reviewed')
        if not reviewed:
            raise ConfigError('regression.reviewed is required for automatic PR proposals')
        archive = folder / 'technical-evidence.zip'
        if not archive.is_file():
            raise ConfigError('technical-evidence.zip is unavailable; no PR can be prepared')
        limits = (config['run']['max_input_bytes'], config['run']['output_limit_bytes'])
        run_settings = config['run']
        # The original corpus is always rerun; carrying the exact same input
        # and argv into reviewed/ would NOT add a new regression test.
        original = load_cases(workspace_path(config['corpus']['path'], 'corpus.path'),
                              *limits, run=run_settings)
        reviewed_path = workspace_path(reviewed, 'regression.reviewed')
        reviewed_cases = load_cases(reviewed_path / 'manifest.yaml', *limits,
                                    optional=True, run=run_settings)
        def args_key(row):
            return tuple(row.get('args', run_settings.get('args', [])))
        existing_inputs = {(sha256(row['input']).hexdigest(), args_key(row)) for row in original}
        existing_signatures = {(sha256(row['input']).hexdigest(), args_key(row),
                                row.get('preserved_signature'), row.get('witness_role'))
                               for row in reviewed_cases}
        # Same minimized bytes + behavior + argv + side need only ONE test,
        # because each reviewed case is already run in BOTH build modes.
        # Prefer Checked if it has a sanitizer traceback; otherwise Release.
        selected = {}
        skipped_modes, already_covered = [], []
        for bundle in report.get('replay', []):
            generated = bundle.get('generated') or {}
            case_id = generated.get('id')
            if not (bundle.get('stable') is True and isinstance(case_id, str)
                    and case_id.startswith('generated-')
                    and bundle.get('role') in ('base', 'candidate')
                    and bundle.get('mode') in ('release', 'checked')):
                continue
            digest = bundle.get('minimized_sha256')
            argv = args_key(bundle)
            source_key = (digest, argv)
            confirmed_key = (digest, argv, bundle.get('signature'), bundle.get('role'))
            if source_key in existing_inputs or confirmed_key in existing_signatures:
                already_covered.append(case_id)
                continue
            identity = (bundle.get('role'), bundle.get('signature'), digest, argv,
                        bundle.get('minimized_expected_exit'), bundle.get('minimized_expected_stdout'))
            original_witness = selected.get(identity)
            def quality(item):
                diagnostic = item.get('diagnostic') or {}
                return (1 if diagnostic.get('mechanism') in ('ASan', 'UBSan') else 0,
                        1 if item.get('mode') == 'release' else 0)
            if original_witness is None:
                selected[identity] = bundle
            elif quality(bundle) > quality(original_witness):
                skipped_modes.append(original_witness['generated']['id'])
                selected[identity] = bundle
            else:
                skipped_modes.append(case_id)
        entries = {row['generated']['id']: row for row in selected.values()}
        added, existing, rejected = [], [], []
        for case_id in sorted(entries):
            try:
                # Recheck archived original/minimized bytes, sha256, role/mode,
                # three identical replay signatures, and independent oracle.
                # The three Base/Candidate replays have already happened in CI;
                # avoid rebuilding the target once per candidate.
                result = promote_archive(args.config, str(archive), case_id, verify_base=False)
                (existing if result.get('deduplicated') else added).append(case_id)
            except (ConfigError, ValueError, OSError, KeyError, TypeError) as exc:
                rejected.append(dict(id=case_id, reason=str(exc)))
        outcome = dict(schema='patchguard-regression-pr-preparation/1', reviewed_dir=reviewed,
                       candidates=len(entries), added=added,
                       already_present=existing + already_covered,
                       redundant_build_modes=skipped_modes, rejected=rejected)
        write_json(folder / 'regression-pr-preparation.json', outcome)
        summary = folder / 'summary.md'
        if summary.is_file():
            opening = '<!-- patchguard-auto-pr-preparation:start -->'
            closing = '<!-- patchguard-auto-pr-preparation:end -->'
            original = summary.read_text(encoding='utf-8')
            if opening in original and closing in original:
                left = original.index(opening)
                right = original.index(closing, left) + len(closing)
                original = original[:left].rstrip() + original[right:]
            proposal = ('\n\n' + opening + '\n## Automated regression PR preparation\n\n'
                        f'- Verified unique minimized witnesses: **{len(added)} newly proposed**.\n'
                        f'- Already in the corpus: {len(existing) + len(already_covered)}; '
                        f'equivalent build-mode witnesses skipped: {len(skipped_modes)}; '
                        f'validation rejects: {len(rejected)}.\n'
                        f'- Preparation details (separate CI artifact member): '
                        f'`{(folder / "regression-pr-preparation.json").relative_to(ROOT)}`.\n'
                        '- The draft PR is created only with write permission on trusted '
                        'default-branch runs; it is **never merged automatically**.\n')
            if rejected:
                proposal += ('- **⚠ Some witnesses were rejected:** inspect the preparation JSON '
                             'for exact reasons.\n')
            summary.write_text(original.rstrip() + proposal + closing + '\n', encoding='utf-8')
        print(f'PR preparation: {len(added)} new, {len(existing) + len(already_covered)} preexisting, '
              f'{len(skipped_modes)} equivalent build-mode duplicates, {len(rejected)} rejected')
        for item in rejected:
            print(f"Rejected {item['id']}: {item['reason']}", file=sys.stderr)
        return 0 if not rejected else 40
    except (ConfigError, ValueError, OSError, KeyError, TypeError) as exc:
        print(f'PR preparation blocked: {exc}', file=sys.stderr)
        return 30


if __name__ == '__main__':
    raise SystemExit(main())
