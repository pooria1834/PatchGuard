"""Write the available run evidence on early exit."""

import json
from datetime import datetime, timezone
from pathlib import Path
from time import monotonic

from .config import ROOT, workspace_path

from .classify import NAMES
SCOPE = "Conclusions apply only to the configured target versions, recorded cases, and toolchain settings."


def write_json(path: Path, data: dict) -> None:
    """Persist deterministic JSON without following an escaping path."""
    workspace_path(path, "JSON output").write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_partial_report(
    directory: Path, *, command: str, config: str | None, resolved: dict | None,
    started_at: str, started: float, stage: str, code: int, reason: str, evidence: dict | None = None,
) -> None:
    """Record an early exit with no fabricated target executions."""
    result = NAMES[code]
    report = {
        "schema": "patchguard-safelab/1",
        "run": {
            "id": directory.name,
            "command": command,
            "directory": directory.relative_to(ROOT).as_posix(),
            "started_at": started_at,
            "finished_at": datetime.now(timezone.utc).isoformat(),
            "duration_seconds": monotonic() - started,
        },
        "scope": SCOPE,
        "config": {"path": config, "resolved": resolved},
        "stages": [{"name": stage, "status": "failed" if code == 30 else "not run", "reason": reason}],
        "tests_started": False,
        "exit_code": code,
        "exit_reason": reason,
        "result": result,
    }
    report.update(evidence or {})
    write_json(workspace_path(directory / "report.json", "report.json", within=directory), report)
    # Human-readable decision is intentionally small; machine evidence stays in JSON.
    workspace_path(directory / "summary.md", "summary.md", within=directory).write_text(
        _summary(report), encoding="utf-8",
    )
    _write_evidence_index(directory, report)
    write_json(directory / "verdict.json", _verdict(report))


def generate_case(directory: Path, case: dict, data: bytes, signature: str,
                  *, expected_exit: int | None = None, expected_stdout: bytes | None = None,
                  witness_role: str | None = None, witness_mode: str | None = None,
                  args: list[str] | None = None,
                  identity_args: list[str] | None = None, case_id: str | None = None) -> dict:
    """Persist a deterministic regression observation without replacing manual fixtures."""
    from hashlib import sha256
    import fcntl

    import yaml

    from .config import ROOT, load_yaml

    if expected_exit is None:
        expected_exit = case["expected_exit"]
    if expected_stdout is None:
        expected_stdout = case["expected_stdout"]
    directory.mkdir(parents=True, exist_ok=True)
    manifest = workspace_path(directory / "manifest.yaml", "generated manifest", within=directory)
    digest = sha256(data).hexdigest()
    generated_id = f"generated-{digest[:12]}-{signature[:12]}"
    if witness_role is not None and witness_mode is not None:
        generated_id += f"-{witness_role}-{witness_mode}"
    if identity_args is not None:
        # Same bytes and fault can arise under different CLI flags. They
        # must not collide with one another or older global-args fixtures.
        argv_digest = sha256(json.dumps(identity_args, ensure_ascii=True).encode()).hexdigest()[:10]
        generated_id += f"-a{argv_digest}"
    case_id = case_id or generated_id
    row = dict(id=case_id, kind=case["kind"], input=f"{digest[:12]}.bin",
               expected_exit=expected_exit, expected_stdout=f"{case_id}.out",
               preserved_signature=signature, input_sha256=digest)
    if witness_role is not None and witness_mode is not None:
        row.update(witness_role=witness_role, witness_mode=witness_mode)
    if args is not None:
        row["args"] = list(args)
    with workspace_path(directory / ".manifest.lock", "generated lock", within=directory).open("ab") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        rows = load_yaml(manifest) if manifest.exists() else []
        if not isinstance(rows, list) or any(not isinstance(entry, dict) for entry in rows):
            raise ValueError("invalid generated manifest")
        existing = next((entry for entry in rows if entry.get("id") == case_id), None)
        if existing is not None and existing != row:
            raise ValueError(f"generated case ID collision: {case_id}")
        for field, content in (("input", data), ("expected_stdout", expected_stdout)):
            path = workspace_path(directory / row[field], field, within=directory)
            if path.exists():
                if path.read_bytes() != content:
                    raise ValueError(f"generated fixture would overwrite {path}")
            else:
                with path.open("xb") as stream:
                    stream.write(content)
        if existing is None:
            rows.append(row)
            rows.sort(key=lambda entry: entry["id"])
            temporary = workspace_path(directory / ".manifest.pending", "generated update", within=directory)
            temporary.write_text(yaml.safe_dump(rows, sort_keys=False))
            temporary.replace(manifest)
    return dict(manifest=manifest.relative_to(ROOT).as_posix(), id=case_id, deduplicated=existing is not None)


def evidence_complete(report: dict) -> bool:
    """Verify core run evidence exists before emitting an acceptance result."""
    required = ("sources", "diff", "toolchain", "builds", "cases", "executions", "replay", "binary_metadata")
    if not all(key in report for key in required) or len(report["builds"]) != 4 or not report["cases"]:
        return False
    if len(report["executions"]) != len(report["cases"]) * 4:
        return False
    return all((ROOT / path).is_file() for path in _evidence_paths(report))


def _evidence_paths(report: dict) -> list[str]:
    paths = [report["diff"]["path"]] if report.get("diff") else []
    for case in report["cases"]:
        paths.extend(case[key] for key in ("input_path", "expected_stdout_path"))
    for row in report["executions"]:
        paths.extend((row["record"], row["stdout"]["path"], row["stderr"]["path"]))
        if row["staged"]:
            paths.append(row["staged"])
    for build in report["builds"]:
        if build["path"]:
            paths.append(build["path"])
        for stream in ("stdout", "stderr"):
            paths.append(build["process"][stream]["path"])
    for bundle in report.get("replay", []):
        paths.extend(bundle[key] for key in ("path", "original", "minimized") if key in bundle)
        paths.extend(entry["path"] for entry in bundle["history"])
        if "generated" in bundle:
            paths.append(bundle["generated"]["manifest"])
    processes = list(report.get("toolchain", {}).values())
    for metadata in report.get("binary_metadata", {}).values():
        processes.extend(tool["process"] for tool in metadata["tools"].values())
    for process in processes:
        paths.extend(process[stream]["path"] for stream in ("stdout", "stderr"))
    return paths


def _verdict(report: dict) -> dict:
    """A stable, compact CI interface independent of the full raw schema."""
    observations = report.get("observations") or {}
    findings = report.get("runtime_findings") or []
    stable_findings = [row for row in findings if row.get("stable") and row.get("status") in ("Incomplete Fix", "New Issue")]
    regressions = observations.get("regressions") or []
    failures = [dict(name=name, reason=item.get("reason")) for name, item in (report.get("checks") or {}).items()
                if item.get("status") == "failed"]
    return dict(schema="patchguard-verdict/1", exit_code=report["exit_code"], result=report["result"],
                reason=report["exit_reason"], target=(report.get("config", {}).get("resolved") or {}).get("target", {}).get("name"),
                run_directory=report["run"]["directory"],
                security=report.get("security_state", "inconclusive"),
                functionality=report.get("functional_state", "inconclusive"),
                completeness=report.get("completeness", "incomplete"),
                case_count=len(report.get("cases") or []),
                execution_count=len(report.get("executions") or []),
                runtime_issues=[dict(case_id=row["case_id"], mode=row["mode"], status=row["status"],
                                     kind=(row.get("after") or {}).get("kind"),
                                     association=(row.get("correlation") or {}).get("label", "unknown"))
                                for row in stable_findings],
                functional_regressions=regressions, failed_checks=failures)


def _short(items: list[str], limit: int = 6) -> str:
    """Print a bounded list in the human summary."""
    if not items:
        return "none"
    visible = ", ".join(f"`{item}`" for item in items[:limit])
    return visible + (f" … (+{len(items) - limit} more)" if len(items) > limit else "")


def _execution_state(row: dict) -> str:
    diagnostic = row.get('diagnostic') or {}
    if diagnostic:
        return f"{diagnostic.get('mechanism', 'fault')}/{diagnostic.get('kind', 'unknown')}"
    if row.get('state') not in (None, 'normal'):
        return f"{row.get('state')}/{row.get('signal') or row.get('returncode')}"
    if row.get('match') is False:
        return f"mismatch/{row.get('mismatch_kind', '?')}"
    return 'OK'


def _clean_cell(value: object) -> str:
    return str(value).replace('|', '/').replace('`', "'").replace('\n', ' ')


def _detailed_sections(report: dict) -> list[str]:
    """Show actionable human evidence and the exact internal ZIP paths."""
    prefix = report['run']['directory']
    lines = ['', '## Binary hardening · all four builds', '',
             '| Build | NX | PIE | RELRO | Stack Canary | Exact evidence path INSIDE ZIP |',
             '| --- | --- | --- | --- | --- | --- |']
    info = report.get('binary_metadata') or {}
    for role in ('base', 'candidate'):
        for mode in ('release', 'checked'):
            key = f'{role}-{mode}'
            metadata = info.get(key) or {}
            protections = metadata.get('hardening') or {}
            values = [str((protections.get(name) or {}).get('status', 'not checked'))
                      for name in ('nx', 'pie', 'relro', 'stack_canary')]
            probe = ((metadata.get('tools') or {}).get('readelf') or {}).get('process') or {}
            evidence = (probe.get('stdout') or {}).get('path', 'unavailable')
            lines.append(f"| `{key}` | " + ' | '.join(values) + f' | `{evidence}` |')
    base = (info.get('base-release') or {}).get('hardening') or {}
    candidate = (info.get('candidate-release') or {}).get('hardening') or {}
    if base and candidate:
        lines.extend(['', '**Release Base → Candidate:** ' + '; '.join(
            f"{name}: {base[name]['status']} → {candidate[name]['status']}"
            for name in ('nx', 'pie', 'relro', 'stack_canary')) + '.'])
        warnings = report.get('hardening_warnings') or []
        lines.append('**' + ('⚠ Hardening downgrade: ' + '; '.join(
            f"{row['protection']} ({row['before']['status']} → {row['after']['status']})"
            for row in warnings) if warnings else 'No Release hardening downgrade observed.') + '**')
    else:
        lines.extend(['', '**⚠ Hardening comparison unavailable:** binary metadata was not completed.'])
    runtime = report.get('runtime_findings') or []
    observations = report.get('observations') or {}
    categories = ('Fixed', 'Incomplete Fix', 'New Issue', 'Inconclusive')
    lines.extend(['', '## Patch-to-finding correlation and independent contract states', '',
                  '- **Runtime findings:** ' + ', '.join(
                      f'{name}: {sum(row.get("status") == name for row in runtime)}' for name in categories) + '.',
                  '- **Functional regression cases:** ' +
                  str(len(observations.get('regressions') or [])) +
                  '; **contract mismatches remaining:** ' + str(len(observations.get('remaining') or [])) +
                  '; **new contract issues:** ' + str(len(observations.get('new_issues') or [])) + '.',
                  '- The patch correlation can be `direct`, `indirect`, or `unknown`; it is '
                  'supporting evidence, **not proof that the patch caused a fault**.', '',
                  '| Case | Mode | Status | Changed-code relationship | Fault site |',
                  '| --- | --- | --- | --- | --- |'])
    for finding in runtime[:20]:
        location = ((finding.get('after') or finding.get('before') or {}).get('location') or {})
        site = f"{location.get('path')}:{location.get('line')}" if location else 'not symbolized'
        lines.append(f"| `{_clean_cell(finding.get('case_id'))}` | `{finding.get('mode')}` | "
                     f"{_clean_cell(finding.get('status', 'Inconclusive'))} | "
                     f"`{(finding.get('correlation') or {}).get('label', 'unknown')}` | "
                     f"`{_clean_cell(site)}` |")
    if not runtime:
        lines.append('| *(none observed)* | – | – | – | – |')
    if len(runtime) > 20:
        lines.append(f"{len(runtime)-20} more mappings in `{prefix}/report.json` → `runtime_findings`.")
    lines.extend(['', '## All-case outcome at a glance', '',
                  '| Test case | Base Release | Candidate Release | Base Checked | Candidate Checked |',
                  '| --- | --- | --- | --- | --- |'])
    all_records = report.get('executions') or []
    grouped = {}
    for row in all_records:
        grouped.setdefault(row.get('case_id'), {})[(row.get('role'), row.get('mode'))] = row
    for case_id, variants in sorted(grouped.items())[:20]:
        states = [_clean_cell(_execution_state(variants[(role, mode)]))
                  if (role, mode) in variants else 'not run'
                  for role, mode in (('base', 'release'), ('candidate', 'release'),
                                     ('base', 'checked'), ('candidate', 'checked'))]
        lines.append(f"| `{_clean_cell(case_id)}` | " + ' | '.join(states) + ' |')
    if not grouped:
        lines.append('| *(no executions)* | – | – | – | – |')
    if len(grouped) > 20:
        lines.append(f'\n{len(grouped)-20} additional cases: `{prefix}/report.json` → `executions`.')
    abnormal = [row for row in all_records if row.get('diagnostic')
                or row.get('state') not in (None, 'normal') or row.get('match') is False]
    lines.extend(['', f'## Crash details and readable stack traces ({len(abnormal)} abnormal runs)', ''])
    if not abnormal:
        lines.append('No unexpected exit, sanitizer finding or output mismatch was observed.')
    for row in abnormal[:12]:
        diagnostic = row.get('diagnostic') or {}
        stdout = (row.get('stdout') or {}).get('path', 'unavailable')
        stderr = (row.get('stderr') or {}).get('path', 'unavailable')
        record = row.get('record', 'unavailable')
        lines.extend(['', f"### `{_clean_cell(row.get('case_id'))}` · {row.get('role')}/{row.get('mode')}", '',
                      f"- **Error type / detection:** `{_clean_cell(_execution_state(row))}` / "
                      f"`{diagnostic.get('mechanism', 'process/contract')}`.",
                      f"- **Termination:** `{row.get('state')}`; exit code `{row.get('returncode')}`; "
                      f"signal `{row.get('signal') or 'none'}`; timeout `{row.get('timed_out', False)}`.",
                      f'- **Inside ZIP:** execution `{record}`, stderr `{stderr}`, stdout `{stdout}`.'])
        location = diagnostic.get('location') or {}
        if location:
            lines.append(f"- **Reported site:** `{_clean_cell(location.get('path'))}:{location.get('line', '?')}`.")
        frames = diagnostic.get('frames') or []
        if frames:
            lines.extend(['- **Stack trace (top frame first):**', '', '```text'])
            for index, frame in enumerate(frames[:8]):
                function = str(frame.get('function', '?')).replace('```', "''")[:160]
                path = str(frame.get('path', '?')).replace('```', "''")[:200]
                lines.append(f"#{index} {function}  —  {path}:{frame.get('line', '?')}")
            lines.extend(['```', ''])
            if len(frames) > 8:
                lines.append(f"{len(frames)-8} further frames: inspect the exact stderr file above.")
        elif diagnostic or row.get('state') not in (None, 'normal'):
            lines.append('- **Stack trace:** unavailable in recorded stderr; see stderr above. '
                         'No invented backtrace is shown.')
        else:
            lines.append('- **Stack trace:** not applicable (independent functional oracle mismatch).')
        finding = next((item for item in report.get('runtime_findings', [])
                        if item.get('case_id') == row.get('case_id') and item.get('mode') == row.get('mode')), None)
        if finding:
            lines.append(f"- **Patch association:** `{(finding.get('correlation') or {}).get('label', 'unknown')}`; "
                         f"full evidence: `{prefix}/report.json` → `runtime_findings`.")
    if len(abnormal) > 12:
        lines.append(f"{len(abnormal)-12} more abnormal runs: `{prefix}/report.json` → `executions` "
                     '(each item contains exact `record` and stderr paths).')
    bundles = report.get('replay') or []
    lines.extend(['', '## Three-attempt reproducers and minimized tests', '',
                  '| Case | Witness | Stable after 3 repeats? | Bundle manifest INSIDE ZIP | Minimized input INSIDE ZIP |',
                  '| --- | --- | --- | --- | --- |'])
    for bundle in bundles[:20]:
        lines.append(f"| `{_clean_cell(bundle.get('case_id'))}` | "
                     f"`{bundle.get('role')}/{bundle.get('mode')}` | "
                     f"{'yes' if bundle.get('stable') else 'NO / flaky'} | "
                     f"`{bundle.get('path')}` | `{bundle.get('minimized', 'unavailable')}` |")
    if not bundles:
        lines.append('| *(none)* | – | – | – | – |')
    if len(bundles) > 20:
        lines.append(f"{len(bundles)-20} additional reproducers: `{prefix}/report.json` → `replay`.")
    resolved = (report.get('config') or {}).get('resolved') or {}
    regression = resolved.get('regression') or {}
    lines.extend(['', '## Exact layout of `technical-evidence.zip`', '',
                  f'- **ZIP saved by Action:** `{prefix}/technical-evidence.zip`.',
                  f'- **Full structured verdict:** `{prefix}/report.json` (INSIDE ZIP).',
                  f'- **Source patch:** `{prefix}/diff/source.patch` (INSIDE ZIP).',
                  f'- **Runs:** `{prefix}/runs/<base|candidate>/<release|checked>/<case-id>/result.json` '
                  'with neighboring `stdout.bin` and `stderr.bin` (INSIDE ZIP).',
                  f'- **Replay bundles:** `{prefix}/cases/<signature>-<role>-<mode>-<case-id>/manifest.json` '
                  '(INSIDE ZIP); each manifest gives `history` (three precise attempts), '
                  '`original`, `minimized`, toolchain, binary SHA-256 and runtime environment.',
                  f'- **Minimizer decision log:** `{prefix}/cases/<signature>-<role>-<mode>-<case-id>/'
                  'minimization-trace.json` (when minimization was performed).',
                  f'- **ELF hardening proofs:** `{prefix}/binary-info/<build-name>/readelf/stdout.bin` '
                  'and `symbols/stdout.bin` (INSIDE ZIP).',
                  f'- **Build commands and metadata:** `{prefix}/report.json` → `builds`; '
                  f'compiler logs: `{prefix}/builds/` (INSIDE ZIP).',
                  f'- **Patch-to-finding mapping:** `{prefix}/report.json` → `runtime_findings` and `correlation`.',
                  f'- **New generated fixture manifest:** `{regression.get("dir", "not configured")}/manifest.yaml` '
                  '(INSIDE ZIP, if generated).',
                  f'- **After PR approval, tracked regression suite:** '
                  f'`{regression.get("reviewed", "not configured")}/manifest.yaml`.',
                  '', '**Important:** paths above are ZIP member names relative to the repository root. '
                  '`summary.md` is intentionally published outside the ZIP in the Action artifact.'])
    return lines


def _summary(report: dict) -> str:
    """One-screen CI report; raw logs are NEVER expanded in this file."""
    verdict = _verdict(report)
    code = verdict["exit_code"]
    label = {0: "PASS — patch accepted within tested scope", 10: "BLOCK — vulnerability remains or new security issue",
             20: "BLOCK — functional regression", 30: "BLOCK — build/config/tool error",
             40: "BLOCK — insufficient evidence"}.get(code, "BLOCK — unknown result")
    observations = report.get("observations") or {}
    if code == 0:
        reason = "A Base fault was reproduced; no matching fault or contract regression was confirmed on Candidate within the configured corpus."
    elif code == 10:
        reason = "The Candidate still triggers a confirmed security fault or a previously observed vulnerability remains."
    elif code == 20:
        reason = ("A valid input that passed on Base fails on Candidate: "
                  + _short(observations.get("regressions") or [], 4))
    elif code == 40:
        reason = "The validation cannot safely accept the patch because mandatory evidence is missing, unstable or ambiguous."
    else:
        reason = report["exit_reason"]
    lines = ["# PatchGuard · patch review", "", f"**{label}** (exit `{code}` / `{verdict['result']}`)", "",
             f"**Target:** `{verdict['target'] or 'not configured'}` · "
             f"**Cases:** {verdict['case_count']} · **Runs:** {verdict['execution_count']}",
             f"**Security:** {verdict['security']} · **Functionality:** {verdict['functionality']} · "
             f"**Evidence:** {verdict['completeness']}", "", "## Why?", "", reason, ""]
    remaining = (report.get("observations") or {}).get("remaining", [])
    fixed = (report.get("observations") or {}).get("fixed", [])
    lines.extend(["## Cases to inspect", "", f"- Fixed in tested scope: {_short(fixed)}",
                  f"- Remaining contract mismatches: {_short(remaining)}",
                  f"- Functional regressions: {_short(verdict['functional_regressions'])}"])
    if verdict["runtime_issues"]:
        from collections import defaultdict
        from os.path import relpath

        # Show root-cause-like groups rather than one line per triggering input.
        # Grouping is purely a presentation convenience, not causal proof.
        grouped = defaultdict(list)
        for finding in report.get("runtime_findings") or []:
            if not (finding.get("stable") and finding.get("status") in ("Incomplete Fix", "New Issue")):
                continue
            diag = finding.get("after") or {}
            location = diag.get("location") or {}
            group = (finding["status"], diag.get("mechanism"), diag.get("kind"),
                     location.get("path"), location.get("line"), finding["mode"],
                     (finding.get("correlation") or {}).get("label", "unknown"))
            grouped[group].append(finding)
        lines.append(f"- Confirmed runtime issue groups: {len(grouped)} (see `verdict.json` for every affected case)")
        report_dir = ROOT / report["run"]["directory"]
        for group, items in list(grouped.items())[:4]:
            status, mechanism, kind, source_path, line, mode, association = group
            location = f" at `{source_path}:{line}`" if source_path else ""
            examples = list(dict.fromkeys(item["case_id"] for item in items))
            lines.append(f"  - **{status}:** {mechanism or 'runtime'} {kind or 'fault'}{location} ({mode}); "
                         f"diff association: {association}; cases: {_short(examples, 4)}")
            example = items[0]
            links = []
            if record := example.get("candidate_record"):
                links.append(f"[execution]({relpath(ROOT / record, report_dir)})")
            bundle = next((row for row in report.get("replay", []) if row.get("case_id") == example["case_id"]
                           and row.get("role") == "candidate" and row.get("mode") == example["mode"]), None)
            if bundle:
                links.append(f"[replay]({relpath(ROOT / bundle['path'], report_dir)})")
            if links:
                lines.append("    - Example evidence: " + " · ".join(links))
        if len(grouped) > 4:
            lines.append(f"  - … (+{len(grouped) - 4} additional groups in `report.json`)")
    else:
        lines.append("- Confirmed runtime issues on candidate: none recorded")
    if verdict["failed_checks"]:
        lines.extend(["", "## Checks requiring attention", ""])
        for check in verdict["failed_checks"][:6]:
            lines.append(f"- `{check['name']}`: {check['reason'] or 'failed'}")
        if len(verdict["failed_checks"]) > 6:
            lines.append(f"- … (+{len(verdict['failed_checks']) - 6} more in `verdict.json`)")
    warnings = report.get("hardening_warnings") or []
    if warnings:
        lines.extend(["", "## Hardening warnings", ""])
        lines.extend(f"- {item['protection']}: {item['before']['status']} → {item['after']['status']}" for item in warnings[:6])
    lines.extend(_detailed_sections(report))
    lines.extend(["", "## Where to look", "", "- [Evidence guide](evidence-index.md) — which folder contains each kind of log",
                  "- [Compact machine verdict](verdict.json) · [Complete analysis](report.json)",
                  "- `runs/` — executed commands, stdout/stderr and process records",
                  "- `cases/` — reproducible failures, repeat attempts, minimized input",
                  "- `diff/source.patch` — actual source changes; `builds/` — compiler output",
                  "- `technical-evidence.zip` — optional packaged deep evidence (created by the packaging step)",
                  "", f"> {SCOPE}", ""])
    return "\n".join(lines)


def _write_evidence_index(directory: Path, report: dict) -> None:
    """Group file paths without repeating thousands of paths in the summary."""
    from collections import defaultdict
    from os.path import relpath

    groups = defaultdict(list)
    # Report is written before this index, so all referenced paths are now known.
    try:
        paths = _evidence_paths(report)
    except (KeyError, TypeError):
        paths = []  # An early failed stage legitimately has incomplete evidence.
    for path in sorted(set(paths)):
        item = ROOT / path
        if not item.is_relative_to(directory):
            group = "external-regressions"
        else:
            parts = item.relative_to(directory).parts
            group = parts[0] if len(parts) > 1 else "top-level"
        groups[group].append(relpath(item, directory))
    descriptions = {
        "runs": "Original Base/Candidate Release/Checked executions and raw stdout/stderr",
        "cases": "Three replays, minimization trials and reproducible input bundles",
        "builds": "Compiler logs, commands, executables and hashes",
        "binary-info": "ELF security protection evidence and tool output",
        "diff": "Unified source diff and Git diff logs",
        "provenance": "Source and compiler revision information",
        "external-regressions": "Generated regression fixtures stored outside this run directory",
    }
    data = dict(schema="patchguard-evidence-index/1", run_directory=report["run"]["directory"],
                groups={name: dict(description=descriptions.get(name, "Other runtime evidence"),
                                   files=items, count=len(items)) for name, items in sorted(groups.items())})
    write_json(directory / "evidence-index.json", data)
    lines = ["# Where are the PatchGuard logs?", "", "Start with [summary.md](summary.md) for the verdict.",
             "This index is for technical investigation. Full individual paths are in [evidence-index.json](evidence-index.json).", "",
             "| Folder | Contents | Referenced files |", "|---|---|---:|"]
    for name, details in data["groups"].items():
        lines.append(f"| `{name}/` | {details['description']} | {details['count']} |")
    lines.extend(["", "Most process stdout/stderr is stored as `.bin` because it can contain binary data.",
                  "Start with a failing case ID from [verdict.json](verdict.json).", "",
                  "For full details see [report.json](report.json), then `runs/<role>/<mode>/<case>/result.json` ",
                  "and `cases/<signature>-<role>-<mode>-<case>/manifest.json` where available.", ""])
    (directory / "evidence-index.md").write_text("\n".join(lines), encoding="utf-8")
