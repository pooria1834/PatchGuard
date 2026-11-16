# Deploying verified regression pull requests in record-parser

1. Commit/push the complete updated PatchGuard repository, then copy its **new**
   Git commit SHA (`git rev-parse HEAD`). The commit must already exist on GitHub.
2. In **record-parser** on `main`, copy `patchguard.yml` and
   `patchguard-regression-pr.yml` from this directory into `.github/workflows/`.
   Replace the `__PATCHGUARD_SHA__` placeholder **three times** (once in the
   first file, twice in the second) using the exact pushed PatchGuard SHA.
3. Do not change `.patchguard/config.yaml` for the current record-parser setup:
   the existing `sources.base`, `sources.patched`, `corpus`, `regression` and
   `oracle` configuration is compatible. Keep the source preparation in the
   first workflow: it builds `.patchguard/base/src/` from the baseline Git
   revision while the candidate is the PR checkout's `src/`.
4. In **record-parser** GitHub Settings → Actions → General, enable
   **Allow GitHub Actions to create and approve pull requests**. The validator
   needs only `contents:read`; only the follow-up `publish` job uses
   `contents:write` and `pull-requests:write`.
5. Commit both workflow files to **main before** (re)triggering a branch PR.
   Push a new commit to an existing feature branch (an empty commit is okay)
   or reopen its pull request to trigger validation and its follow-up.
6. In Actions, inspect the original **PatchGuard** check and the separate
   **PatchGuard regression PR** workflow, even when the first check failed.
   A Draft PR is opened against `main` for newly verified unique witnesses.
   Review and merge the regression PR yourself. The failing patch PR remains
   separate and blocked.

Details and limitations are in the root PatchGuard `README.md`. Fork PRs are
not automatically promoted. Re-run the original test if the PR merge ref moved
since evidence creation; immutable source digest checking deliberately fails
closed in that case. If GitHub Actions PR creation is disabled, the `publish`
job will fail with the REST API rejection and must be retried after enabling it.
