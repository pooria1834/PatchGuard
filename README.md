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

## 2. Automatically propose one pull request with minimized regressions

Configure `regression.dir: tests/regression/generated/<target>` in the target YAML. `regression.reviewed` is optional and defaults to `tests/regression/reviewed/<target.name>`; set it explicitly to customize the tracked destination. On every successful or failed evaluation with stable witnesses, the Action:

1. Repeats each candidate failure three times and minimizes only when the **same fault signature** survives and a trusted independent expected outcome exists.
2. Saves original input, minimized input, exact argv, source/binary hashes, and replay evidence, including Base and Candidate findings.
3. Revalidates each archived witness, its three replay JSON records, and its independent oracle inside a **network-disabled Docker container**.
4. Excludes inputs already exercised by the original corpus; excludes equivalent reviewed cases; collapses equivalent Release/Checked witnesses that will be executed by the same future test anyway.
5. Copies **only** the generated reviewed-suite fixtures to a new git worktree, pushes a single branch, and opens **one draft PR for that workflow run**. **No automatic merge occurs.** Future runs include the reviewed cases after a maintainer merges the PR.

For safety, the workflow mounts checkout Git metadata read-only inside the untrusted containers and disables Git hooks in the trusted host-side PR process. The PR is automatically created **only on trusted pushes to the repository's default branch or workflow_dispatch on that branch**. On untrusted/fork pull requests, artifacts are generated but no write-token operations run. This is intentional: the target executable and its oracle are untrusted code and must not receive credentials. Each run uses its own draft PR branch; if multiple runs are queued before reviewing the first PR, review/close redundant proposals before merging them. Distinct cases are deduplicated *within each PR and against the currently tracked corpus*.

GitHub requirements: `contents: write` and `pull-requests: write` permissions in the calling workflow; `actions/checkout` with **`persist-credentials: false`** (the Action injects its token only for the trusted host-side push); and repository setting **Allow GitHub Actions to create and approve pull requests** enabled. If that setting or token permissions are missing, the Action cannot open a PR; see its log. GitHub's standard `GITHUB_TOKEN` may not trigger PR workflows when the bot opens the PR; the tests run normally after merge, and a separately configured bot PAT may be used if CI on the draft PR is needed.

You can disable automatic proposals with `auto-regression-pr: 'false'`. A local promotion is still possible with `scripts/promote_regression.py`; it is no longer required for the standard CI flow.

## 3. One-stop summary and exact ZIP-relative evidence locations

`<report-dir>/summary.md` now includes:

- The verdict, security/functional states, failed checks, and a compact Base/Candidate/Release/Checked matrix.
- A **four-build ELF hardening table** for NX, PIE, RELRO and Stack Canary. It explicitly highlights Base Release → Candidate Release downgrades; unknown or incomplete evidence is shown rather than guessed.
- For abnormal executions, the observed error mechanism/type, exit code, signal, timeout state, source location, **symbolized stack frames if actually recorded**, and explicit stderr/stdout/JSON member paths. When no stack is available, it says so.
- Stable three-repeat bundles, minimized inputs, a source diff, correlation result locations, an autogenerated regression PR status, and the **exact names inside the downloaded technical-evidence ZIP**.

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

See [`examples/consumer-workflow.yml`](examples/consumer-workflow.yml) for a reusable GitHub Actions example; replace the action repository/tag and target configuration. The workflow must upload artifacts using `if: always()` so that failed evaluations still preserve evidence.

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

**Limitations:** The supplied source ZIP contains the PatchGuard engine/scripts but **no target checkouts, target configs, or complete acceptance fixtures**. Its built-in tests can be run directly, but the full `verify-all` matrix requires the target project assets. The GitHub PR creation endpoint cannot be exercised without access to an actual repository and appropriately scoped permissions; the provided tests cover proposal generation and a no-network local git dry run.
