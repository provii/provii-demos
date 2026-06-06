#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Provii
#
# Point this worktree's git at the tracked `.githooks/` directory.
# Safe to re-run. Run once per clone and once per linked worktree.

set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "${repo_root}"

current="$(git config --get core.hooksPath || true)"
if [[ "${current}" == ".githooks" ]]; then
  printf 'core.hooksPath already set to .githooks; nothing to do.\n'
  exit 0
fi

git config core.hooksPath .githooks
printf 'core.hooksPath set to .githooks\n'
printf 'pre-commit hook will now enforce worktree isolation .\n'
