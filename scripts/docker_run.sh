#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${PATCHGUARD_IMAGE:-patchguard-safelab:dev}"
if [[ $# -lt 1 ]]; then
  echo "usage: $0 COMMAND [ARG ...]" >&2
  exit 2
fi
exec docker run --rm \
  --network none \
  --memory 2g --memory-swap 2g --cpus 2 --pids-limit 256 \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=256m \
  --user 1000:1000 \
  -e HOME=/tmp \
  -v "${ROOT}:/work" -w /work \
  "${IMAGE}" "$@"
