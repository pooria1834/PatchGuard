# PatchGuard — dynamic security-patch validation

PatchGuard executes four corresponding builds (Base/Candidate × Release/Checked), checks independent functional oracles and runtime faults, minimizes stable witnesses, and creates a human-readable `summary.md` plus JSON and zipped evidence.

## 1. Different command-line arguments for each case

`run.args` is a **default argv list**, not a mandatory value for every case. Add an `args` list to an individual case in its YAML corpus or reviewed/generated manifest to **replace** that default for that case. Empty `args: []` is allowed for `stdin` delivery. Arguments are lists of individual argv elements, **not shell commands**.

```yaml
# In config.yaml, common defaults:
run:
  method: stdin
  args: ['-s']
  timeout_seconds: 5
  max_input_bytes: 4096
  output_limit_bytes: 8192
  env: {}
```

```yaml
# In tests/fixtures/my_target/cases.yaml:
- id: simple-mode
  kind: valid
  input: inputs/simple.bin
  expected_exit: 0
  expected_stdout: expected/simple.out
  args: ['-s']

- id: file-style-flag
  kind: valid
  input: inputs/another.bin
  expected_exit: 0
  expected_stdout: expected/another.out
  args: ['-f']
```

The input delivery method is shared for a run, but argv flags vary per case. With `method: file`, the selected list **must contain** `{input_file}` (e.g. `args: ['-f', '{input_file}']`); with `method: argv`, it **must contain** `{input_arg}` (e.g. `args: ['-s', '{input_arg}']`). `stdin` cases need no placeholder. The same effective argv is retained for Base/Candidate and Release/Checked, replay/minimization, and the promoted regression case. If the independent reference oracle must know the selected CLI flags, set `oracle.command: ['python3', 'oracle.py', '{case_args}']` in the target config. That placeholder is expanded into separate argv elements (without shell evaluation). For an oracle whose contract depends only on stdin bytes, the placeholder is optional. Test IDs, invocation signatures and independent-oracle comparisons distinguish cases that use identical input bytes under different argv lists.

## 2. Automatic review PR for every *verified new* minimized witness

**Two separate GitHub workflows are required.** The first runs C/C++ targets on
`pull_request` with **read-only permissions**, creates the technical evidence ZIP
and uploads it even when PatchGuard exits 10 or 20. The validation action never
pushes to GitHub, never receives a write token, and never opens a PR itself.

A second trusted, default-branch `workflow_run` workflow starts after the first
workflow **completes** (success or failure). It works in **two jobs**:

1. **verify** (`contents: read`): downloads the triggering run's artifact,
   checks that the exact PR merge commit and BOTH source-tree digests still
   match the CI report, and reconstructs Base/Candidate source files from Git
   blobs. It runs PatchGuard's `batch_promote.py --verify-witness` in a
   network-disabled Docker container without a GitHub write credential. Each
   candidate's same fault signature must reproduce three more times; archive
   records, hashes, independent-oracle results and duplicates are checked. It
   exports only canonical, verified fixture data, not arbitrary files from the
   PR, to a new job artifact.
2. **publish** (`contents: write`, `pull-requests: write`): runs **trusted pinned
   PatchGuard tooling** from the default branch, downloads the verified fixture
   data, validates filenames, hashes, argv, ids and tracked-corpus duplicates,
   and imports **only** new `.bin`, `.out`, and `manifest.yaml` fixtures into
   `tests/regression/reviewed/<target>`. It creates **one new branch from `main`**
   and **one draft PR against `main`**, without merging. Neither binaries nor
   oracles from PR branches are executed in this privileged job.

The workflow processes minimized security findings (**Fixed**, **Incomplete
Fix**, **New Issue**) and functional regressions, provided the same fault is
stable and independently validated. It does not open PRs for unverified or
already-covered inputs (same bytes and per-case argv). Review and merge is a
human decision. The original failing patch PR is never merged automatically.

**Important deployment:** copy both workflows from
[`examples/record-parser/`](examples/record-parser/) to the `record-parser`
repository under `.github/workflows/`. Pin **both** PatchGuard references to
**the same new Git commit SHA**. The workflow_run subscriber must be committed
on the default branch **before** opening/re-running a feature PR. The initial
workflow's name must remain `PatchGuard` because the second subscribes to it.

This sample auto-promotion is limited to **same-repository PR branches**, not
forks; fork artifact uploads cannot trigger the write stage. Stale PR merge
refs are intentionally rejected: rerun the original workflow if the PR or
base branch moved. The `workflow_run` job logs explain any rejection. GitHub
requires repository setting **Settings → Actions → General → Allow GitHub
Actions to create and approve pull requests**. The publisher must have
`contents:write` and `pull-requests:write`. `actions/checkout` must always use
`persist-credentials: false` before executing untrusted targets.

GitHub's built-in `GITHUB_TOKEN` usually does not trigger a fresh `pull_request`
CI run when its bot creates a PR. Maintainers can review the draft manually;
the regression cases run automatically on future independently-triggered CI.
Concurrent outstanding draft PRs may overlap; the import step deduplicates
against `main` and the original corpus but cannot deduplicate against another
**unmerged** draft branch.

`auto-regression-pr` and `github-token` on the validation Action are deprecated
for inline publication; do not pass a GitHub write token to that Action. For
local use, `scripts/promote_regression.py` still supports manual imports.

## 3. One-stop summary and exact ZIP-relative evidence locations

`<report-dir>/summary.md` now includes:

- The verdict, security/functional states, failed checks, and a compact Base/Candidate/Release/Checked matrix.
- A **four-build ELF hardening table** for NX, PIE, RELRO and Stack Canary. It explicitly highlights Base Release → Candidate Release downgrades; unknown or incomplete evidence is shown rather than guessed.
- For abnormal executions, the observed error mechanism/type, exit code, signal, timeout state, source location, **symbolized stack frames if actually recorded**, and explicit stderr/stdout/JSON member paths. When no stack is available, it says so.
- Stable three-repeat bundles, minimized inputs, a source diff, correlation result locations, a handoff notice for the separate regression PR workflow, and the **exact names inside the downloaded technical-evidence ZIP**.

The technical evidence archive is generated at `<report-dir>/technical-evidence.zip`. Every member is **relative to the target repository root**, for example:

```text
artifacts/patchguard/report.json
artifacts/patchguard/diff/source.patch
artifacts/patchguard/runs/candidate/checked/<case-id>/result.json
artifacts/patchguard/runs/candidate/checked/<case-id>/stderr.bin
artifacts/patchguard/cases/<signature>-<role>-<mode>-<case-id>/manifest.json
artifacts/patchguard/cases/<signature>-<role>-<mode>-<case-id>/minimized.bin
tests/regression/generated/<target>/manifest.yaml
```

Bundle manifest names are generated from actual fault signatures; **copy the populated paths from `summary.md`**, not the angle-bracket examples. The summary, compact verdict, and PR status files are uploaded *outside* the ZIP by the example workflow; `report.json` is also included inside it.

## Usage and verification

See [`examples/record-parser/patchguard.yml`](examples/record-parser/patchguard.yml) and [`examples/record-parser/patchguard-regression-pr.yml`](examples/record-parser/patchguard-regression-pr.yml) for complete two-workflow deployment. The first must upload artifacts with `if: always()` so that failed evaluations still preserve evidence.

To run locally inside a **configured target workspace**:

```bash
PATCHGUARD_WORKSPACE="$PWD" PYTHONPATH=/path/to/PatchGuard \
  python3 -m patchguard validate --config config.yaml --report-dir artifacts/patchguard

PATCHGUARD_WORKSPACE="$PWD" python3 /path/to/PatchGuard/scripts/package_ci_evidence.py \
  --report-dir artifacts/patchguard

PATCHGUARD_WORKSPACE="$PWD" PYTHONPATH=/path/to/PatchGuard \
  python3 /path/to/PatchGuard/scripts/batch_promote.py \
    --config config.yaml --report-dir artifacts/patchguard
```

For focused checks in the tool checkout: `mkdir -p artifacts && PYTHONPATH=. pytest -q`.

**Limitations:** The supplied source ZIP contains the PatchGuard engine/scripts but **no target checkouts, target configs, or complete acceptance fixtures**. Its built-in tests can be run directly, but the full `verify-all` matrix requires the target project assets. The actual GitHub PR endpoint cannot be exercised without repository write access; tests cover artifact verification, Git ref reconstruction, import/deduplication, and local git dry runs. The Docker-isolated GitHub workflow itself must be verified in the target repository.
