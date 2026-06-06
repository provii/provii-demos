#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Provii
#
# Cross-repo fixture drift check ().
#
# The canonical-message golden vectors live in three places:
#
# - provii-verifier/tests/fixtures/canonical_message_vectors.json
# - provii-issuer/tests/fixtures/canonical_message_vectors.json
# - provii-demos/demo-web-provii-agegate/test/docs/canonical_message_vectors.json
#
# All three files MUST be byte-identical. They lock the wire contract for
# the HMAC signing message used by every provii-verifier caller. A divergence
# means at least one service has lost its end of the contract and HMAC
# verification will silently fail at runtime.
#
# This script computes a SHA-256 over each file and exits non-zero if any
# of the three differs. Run it from the parent directory of all three
# repos (i.e. `~/Desktop/Provii` on a developer laptop, or whatever the
# CI runner uses).
#
# Usage:
# ./scripts/check-canonical-fixtures.sh # default paths
# PROVII_ROOT=/some/path ./scripts/check-canonical-fixtures.sh
#
# Exit codes:
# 0 all three files have the same SHA-256
# 1 one or more files diverge (or are missing)
# 2 a path could not be resolved (PROVII_ROOT misconfigured)

set -euo pipefail

# Resolve the parent directory holding all three repos. Default: walk up
# from this script's location two levels (provii-demos/scripts/ -> provii-
# demo -> ~/Desktop/Provii).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROVII_ROOT="${PROVII_ROOT:-$(cd "${SCRIPT_DIR}/../.." && pwd)}"

VERIFIER_FIXTURE="${PROVII_ROOT}/provii-verifier/tests/fixtures/canonical_message_vectors.json"
ISSUER_FIXTURE="${PROVII_ROOT}/provii-issuer/tests/fixtures/canonical_message_vectors.json"
DEMO_FIXTURE="${PROVII_ROOT}/provii-demos/demo-web-provii-agegate/test/docs/canonical_message_vectors.json"

missing=0
for f in "${VERIFIER_FIXTURE}" "${ISSUER_FIXTURE}" "${DEMO_FIXTURE}"; do
  if [[ ! -f "${f}" ]]; then
    printf 'missing: %s\n' "${f}" >&2
    missing=1
  fi
done
if [[ "${missing}" -ne 0 ]]; then
  printf '\nOne or more fixture files were not found under PROVII_ROOT=%s.\n' "${PROVII_ROOT}" >&2
  printf 'Set PROVII_ROOT to the directory containing provii-verifier/, provii-issuer/,\n' >&2
  printf 'and provii-demos/ (typically ~/Desktop/Provii).\n' >&2
  exit 2
fi

# Pick whatever shasum binary is on PATH. macOS, Linux, BSDs all ship one.
if command -v sha256sum >/dev/null 2>&1; then
  HASHER="sha256sum"
elif command -v shasum >/dev/null 2>&1; then
  HASHER="shasum -a 256"
else
  printf 'neither sha256sum nor shasum is on PATH; cannot compute hashes\n' >&2
  exit 2
fi

verifier_hash="$(${HASHER} "${VERIFIER_FIXTURE}" | awk '{print $1}')"
issuer_hash="$(${HASHER} "${ISSUER_FIXTURE}" | awk '{print $1}')"
demo_hash="$(${HASHER} "${DEMO_FIXTURE}" | awk '{print $1}')"

printf '  provii-verifier : %s\n' "${verifier_hash}"
printf '  provii-issuer   : %s\n' "${issuer_hash}"
printf '  provii-demos  : %s\n' "${demo_hash}"

if [[ "${verifier_hash}" == "${issuer_hash}" && "${issuer_hash}" == "${demo_hash}" ]]; then
  printf '\nAll three canonical-message fixture files are byte-identical.\n'
  exit 0
fi

printf '\nFIXTURE DRIFT DETECTED.\n' >&2
printf 'The three copies of canonical_message_vectors.json must stay in lock-step\n' >&2
printf 'or the wire contract for HMAC signing breaks across services. Re-sync from\n' >&2
printf 'the canonical source (the one most-recently edited and reviewed) using\n' >&2
printf '`cp` and re-run this script.\n' >&2
exit 1
