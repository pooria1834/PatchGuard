#!/usr/bin/env bash
# Reusable composite Action gate; target repository is always /work in Docker.
set -Eeuo pipefail
: "${GITHUB_WORKSPACE:?GitHub workspace is required}"
: "${GITHUB_ACTION_PATH:?Composite action checkout path is required}"
: "${PG_CONFIG:?Target config is required}"
PG_REPORT_DIR="${PG_REPORT_DIR:-artifacts/patchguard}"
# Avoid a path outside the workspace when preparing the local summary.
if [[ ! "$PG_REPORT_DIR" =~ ^artifacts/[a-zA-Z0-9_./-]+$ || "$PG_REPORT_DIR" == *'..'* ]]; then
  echo "Invalid report directory: $PG_REPORT_DIR (must be inside artifacts/)" >&2
  exit 30
fi
report="$GITHUB_WORKSPACE/$PG_REPORT_DIR"
mkdir -p "$report"
# The untrusted target runs inside a container with /work mounted. Never
# expose a checkout token through .git/config (checkout's default credential
# persistence). GitHub push later uses the explicit host-only token instead.
if git -C "$GITHUB_WORKSPACE" rev-parse --git-dir > /dev/null 2>&1; then
  if git -C "$GITHUB_WORKSPACE" config --local --get-regexp \
      '^(http\..*\.extraheader|credential\.helper)$' > /dev/null 2>&1; then
    echo 'Unsafe Git checkout: set actions/checkout with persist-credentials: false.' >&2
    printf '# PatchGuard CI setup blocked\n\nThe checkout exposes Git credentials to target binaries. Set `actions/checkout` `persist-credentials: false`.\n' > "$report/summary.md"
    exit 30
  fi
  remote_url="$(git -C "$GITHUB_WORKSPACE" config --local --get remote.origin.url || true)"
  if [[ "$remote_url" =~ ^https?://[^/]*@ ]]; then
    echo 'Unsafe origin URL: credentials are embedded in the checkout remote URL.' >&2
    printf '# PatchGuard CI setup blocked\n\nRemove credentials from `remote.origin.url` before running untrusted target code.\n' > "$report/summary.md"
    exit 30
  fi
fi
# The evaluated program can write its checkout files, but it must NOT be
# allowed to rewrite git metadata (hooks, config, refs). Host-side git later
# uses a write token to propose a review PR. Overlay .git read-only in BOTH
# untrusted containers; the normal checkout has a .git directory.
git_metadata_mount=()
if [[ -d "$GITHUB_WORKSPACE/.git" && ! -L "$GITHUB_WORKSPACE/.git" ]]; then
  git_metadata_mount=(--mount "type=bind,source=$GITHUB_WORKSPACE/.git,target=/work/.git,readonly")
elif [[ -e "$GITHUB_WORKSPACE/.git" || -L "$GITHUB_WORKSPACE/.git" ]]; then
  echo 'Cannot isolate .git safely: expected an ordinary checkout .git directory.' >&2
  printf '# PatchGuard CI setup blocked\n\nGit metadata must be an ordinary directory to prevent untrusted targets from modifying credentials or hooks.\n' > "$report/summary.md"
  exit 30
fi
image="patchguard-gate:${GITHUB_RUN_ID:-local}"
if ! docker build -t "$image" "$GITHUB_ACTION_PATH" > "$report/ci-image-build.log" 2>&1; then
  echo 'PatchGuard container build failed. See ci-image-build.log' >&2
  tail -n 20 "$report/ci-image-build.log" >&2
  printf '# PatchGuard CI setup failed\n\nSee `ci-image-build.log` in the report directory.\n' > "$report/summary.md"
  exit 30
fi
command=(python3 -m patchguard validate --config "$PG_CONFIG" --report-dir "$PG_REPORT_DIR")
if [[ -n "${PG_PATCHED:-}" ]]; then
  command+=(--patched "$PG_PATCHED")
fi
# The candidate code is untrusted: cap resources, deny network, and drop privileges.
set +e
docker run --rm \
  --network none --read-only --cap-drop ALL --security-opt no-new-privileges \
  --memory 2g --memory-swap 2g --cpus 2 --pids-limit 256 \
  --tmpfs /tmp:rw,nosuid,noexec,size=256m \
  --user "$(id -u):$(id -g)" \
  -e HOME=/tmp -e PATCHGUARD_WORKSPACE=/work -e PYTHONPATH=/tool \
  -e PATCHGUARD_BASE_REVISION="${PATCHGUARD_BASE_REVISION:-}" \
  -v "$GITHUB_WORKSPACE:/work" "${git_metadata_mount[@]}" -v "$GITHUB_ACTION_PATH:/tool:ro" -w /work \
  "$image" "${command[@]}"
code=$?
set -e
# Evidence upload is done by a separate workflow step with 'if: always()'.
if [[ -f "$report/report.json" ]]; then
  PATCHGUARD_WORKSPACE="$GITHUB_WORKSPACE" \
    python3 "$GITHUB_ACTION_PATH/scripts/github_annotations.py" --report-dir "$PG_REPORT_DIR" || true
  PATCHGUARD_WORKSPACE="$GITHUB_WORKSPACE" \
    python3 "$GITHUB_ACTION_PATH/scripts/regression_candidates.py" \
    --report-dir "$PG_REPORT_DIR" || echo 'WARNING: candidate index failed' >&2
  PATCHGUARD_WORKSPACE="$GITHUB_WORKSPACE" \
    python3 "$GITHUB_ACTION_PATH/scripts/package_ci_evidence.py" \
    --report-dir "$PG_REPORT_DIR" || echo 'WARNING: technical evidence packaging failed' >&2
fi
# The trusted host NEVER hands the GitHub write token to the evaluation
# container. A separate, network-denied container validates and stages all
# unique stable witnesses; host-side git then proposes one draft PR.
if [[ "${PG_AUTO_REGRESSION_PR:-true}" == "true" && -f "$report/technical-evidence.zip" ]]; then
  if docker run --rm \
    --network none --read-only --cap-drop ALL --security-opt no-new-privileges \
    --memory 2g --memory-swap 2g --cpus 2 --pids-limit 256 \
    --tmpfs /tmp:rw,nosuid,noexec,size=256m \
    --user "$(id -u):$(id -g)" \
    -e HOME=/tmp -e PATCHGUARD_WORKSPACE=/work -e PYTHONPATH=/tool \
    -v "$GITHUB_WORKSPACE:/work" "${git_metadata_mount[@]}" -v "$GITHUB_ACTION_PATH:/tool:ro" -w /work \
    "$image" python3 /tool/scripts/batch_promote.py \
      --config "$PG_CONFIG" --report-dir "$PG_REPORT_DIR"; then
    echo 'Regression witnesses verified for PR proposal.'
  else
    echo 'WARNING: at least one generated witness could not be auto-promoted; inspect regression-pr-preparation.json.' >&2
  fi
  # This step uses only stdlib, git and GitHub REST. It never executes the
  # target, replays arbitrary code, or publishes a PR without user review.
  python3 "$GITHUB_ACTION_PATH/scripts/create_regression_pr.py" \
    --report-dir "$PG_REPORT_DIR" || echo 'WARNING: could not create a GitHub regression PR' >&2
fi
if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  if [[ -f "$report/summary.md" ]]; then
    cat "$report/summary.md" >> "$GITHUB_STEP_SUMMARY"
    if [[ -f "$report/regression-candidates.md" ]]; then
      printf '\n---\n' >> "$GITHUB_STEP_SUMMARY"
      cat "$report/regression-candidates.md" >> "$GITHUB_STEP_SUMMARY"
    fi
    printf '\n> Detailed relative links work after downloading the `patchguard-pr-evidence` artifact.\n' >> "$GITHUB_STEP_SUMMARY"
  else
    printf '# PatchGuard did not finish\n\nExit `%s`. Check CI logs.\n' "$code" >> "$GITHUB_STEP_SUMMARY"
  fi
fi
if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  printf 'exit_code=%s\nreport_dir=%s\n' "$code" "$PG_REPORT_DIR" >> "$GITHUB_OUTPUT"
fi
exit "$code"
