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
  -v "$GITHUB_WORKSPACE:/work" -v "$GITHUB_ACTION_PATH:/tool:ro" -w /work \
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
