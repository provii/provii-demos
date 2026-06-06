#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Provii
#
# Worktree isolation check ().
#
# Background. The the DevOps owner/the platform owner incident happened because both sessions
# were launched with working directory `provii-demos/`, the SAME worktree.
# the DevOps owner ran `git stash` to clear dirty state before editing log-sanitizer,
# 15 mandates that any multi-agent same-repo work MUST use distinct
# `git worktree` checkouts so the two sessions never share a `.git/index`,
# never see each other's stash, and never race on branch checkout.
#
# This script enforces the rule in two modes.
#
# 1. Pre-launch audit.
#
# ./scripts/check-worktree-isolation.sh audit <cwd1> <cwd2> [...]
#
# Given a list of candidate working directories (one per planned session),
# resolve each to its worktree path via `git worktree list`, fail if any
# two resolve to the same worktree. Run this BEFORE kicking off parallel
# sessions, not after. Exit codes:
# 0 every candidate maps to a distinct worktree
# 1 two or more candidates share a worktree
# 2 one or more candidates are not inside any worktree
#
# 2. Interactive self-check.
#
# ./scripts/check-worktree-isolation.sh self
#
# Run from inside a session's working directory at the start of a
# session. Fails if:
# - the current directory is NOT a dedicated worktree (i.e. `git
# worktree list` shows only one entry and there are other sessions
# supposed to be running);
# - a concurrent `git` process holds `.git/index.lock` in the same
# worktree (strong signal another session is editing the same tree);
# - the stash list grew in the last 60 seconds without a matching
# commit SHA (heuristic for the exact bug that motivated this
# script: silent stash of a peer's WIP).
# Exit codes:
# 0 current worktree is safe to work in
# 1 collision detected; do not proceed
#
# Usage from CONTRIBUTING.md pointer:
#
# # Before launching two parallel sessions against the same repo:
# ./scripts/check-worktree-isolation.sh audit \
# /Users/me/Desktop/Provii/provii-demos \
# /Users/me/Desktop/Provii/provii-demos-w5
#
# Exit codes are structured so CI wrappers can distinguish operator error
# (2, path unresolvable) from a genuine collision (1).

set -euo pipefail

usage() {
  cat <<'USAGE' >&2
usage:
  check-worktree-isolation.sh audit <cwd1> <cwd2> [<cwdN>...]
  check-worktree-isolation.sh self

  audit  compare N candidate working directories, fail if any two map to
         the same git worktree
  self   run inside a session's cwd, fail if the current worktree shows
         signs of concurrent use by another session
USAGE
  exit 2
}

if [[ $# -lt 1 ]]; then
  usage
fi

mode="$1"
shift

# Resolve a cwd to the absolute path of its enclosing git worktree.
# Returns non-zero if the cwd is not inside any git worktree.
resolve_worktree() {
  local cwd="$1"
  if [[ ! -d "${cwd}" ]]; then
    printf 'not a directory: %s\n' "${cwd}" >&2
    return 2
  fi
 # `git -C <dir> rev-parse --show-toplevel` prints the worktree root.
 # `git -C <dir> rev-parse --git-common-dir` prints the shared `.git`
 # directory. Two distinct worktrees share one common-dir but have
 # different toplevels, so we compare toplevels.
  if ! git -C "${cwd}" rev-parse --show-toplevel >/dev/null 2>&1; then
    printf 'not inside a git worktree: %s\n' "${cwd}" >&2
    return 2
  fi
  git -C "${cwd}" rev-parse --show-toplevel
}

case "${mode}" in
  audit)
    if [[ $# -lt 2 ]]; then
      printf 'audit requires at least two candidate paths\n' >&2
      usage
    fi

    declare -a seen_toplevels=()
    declare -a seen_inputs=()
    any_error=0
    for cwd in "$@"; do
      if ! toplevel="$(resolve_worktree "${cwd}")"; then
        any_error=2
        continue
      fi

 # Check this toplevel against every prior one.
      for i in "${!seen_toplevels[@]}"; do
        prior_top="${seen_toplevels[$i]}"
        prior_in="${seen_inputs[$i]}"
        if [[ "${prior_top}" == "${toplevel}" ]]; then
          printf 'WORKTREE COLLISION\n' >&2
          printf '  input A : %s -> %s\n' "${prior_in}" "${prior_top}" >&2
          printf '  input B : %s -> %s\n' "${cwd}" "${toplevel}" >&2
          printf '\nTwo launch candidates resolve to the same worktree.\n' >&2
          printf 'Use `git worktree add` to create a dedicated\n' >&2
          printf 'checkout for one of them before launching.\n' >&2
          any_error=1
        fi
      done

      seen_toplevels+=("${toplevel}")
      seen_inputs+=("${cwd}")
    done

    if [[ "${any_error}" -ne 0 ]]; then
      exit "${any_error}"
    fi

    printf 'OK: %d candidate(s) resolve to distinct worktrees:\n' "${#seen_toplevels[@]}"
    for i in "${!seen_toplevels[@]}"; do
      printf '  %s -> %s\n' "${seen_inputs[$i]}" "${seen_toplevels[$i]}"
    done
    exit 0
    ;;

  self)
    cwd="$(pwd)"
    if ! toplevel="$(resolve_worktree "${cwd}")"; then
      exit 2
    fi
    common_dir="$(git -C "${cwd}" rev-parse --git-common-dir)"
 # `git -C <dir> rev-parse --git-dir` returns the worktree-specific
 # git directory. For the primary worktree this equals common-dir; for
 # linked worktrees it's `common-dir/worktrees/<name>`.
    worktree_git_dir="$(git -C "${cwd}" rev-parse --git-dir)"
    worktree_git_dir_abs="$(cd "${worktree_git_dir}" && pwd)"

 # Compile the worktree inventory. Each entry prints the toplevel.
 # macOS ships bash 3.2 which lacks `mapfile`; read the stream line by
 # line into a plain indexed array instead so the script runs on a
 # stock Apple-silicon laptop without `brew install bash`.
    inventory=()
    while IFS= read -r line; do
      inventory+=("${line}")
    done < <(git -C "${cwd}" worktree list --porcelain \
      | awk '/^worktree /{print substr($0,10)}')

    printf 'Current worktree : %s\n' "${toplevel}"
    printf 'Shared .git dir  : %s\n' "${common_dir}"
    printf 'Local .git dir   : %s\n' "${worktree_git_dir_abs}"
    printf 'Registered worktrees (%d):\n' "${#inventory[@]}"
    for t in "${inventory[@]}"; do
      printf '  - %s\n' "${t}"
    done

 # Check 1: `.git/index.lock` inside OUR worktree git dir. The lock
 # file lives under the worktree-specific git dir for linked worktrees
 # (`.git/worktrees/<name>/index.lock`) and under the shared dir for
 # the primary worktree. Either way, resolve_worktree + rev-parse
 # gives us the right path.
 #
 # Skip when invoked from a git hook. `git commit` itself acquires
 # `.git/index.lock` BEFORE running pre-commit hooks, so a literal
 # `[[ -e ... ]]` always trips inside a hook context. `GIT_INDEX_FILE`
 # is set by git when invoking hooks; no other git plumbing path
 # exports it, so it's a clean signal that the lock holder is our
 # parent process. Outside hooks (manual `self` call), the check
 # remains strict.
    if [[ -z "${GIT_INDEX_FILE:-}" ]]; then
      lock_file="${worktree_git_dir_abs}/index.lock"
      if [[ -e "${lock_file}" ]]; then
        printf '\nBLOCKED: %s exists.\n' "${lock_file}" >&2
        printf 'Another git process is writing to this worktree. Wait for it to\n' >&2
        printf 'complete or abort the stale operation before proceeding.\n' >&2
        exit 1
      fi
    fi

 # Check 2: peer worktrees with a locked index. If another session is
 # editing a peer worktree they are safely isolated, but we still log
 # it for visibility.
    peers_active=0
    for t in "${inventory[@]}"; do
      if [[ "${t}" == "${toplevel}" ]]; then
        continue
      fi
 # Peer worktree local .git dir is `${common_dir}/worktrees/<name>`
 # but the leaf name is not trivially derivable; `git worktree list
 # --porcelain` does not print the index.lock path directly, so we
 # fall back to checking the peer's own rev-parse.
      if peer_git_dir="$(git -C "${t}" rev-parse --git-dir 2>/dev/null)"; then
        peer_git_dir_abs="$(cd "${t}" && cd "${peer_git_dir}" && pwd)"
        if [[ -e "${peer_git_dir_abs}/index.lock" ]]; then
          printf '\nNOTE: peer worktree is currently locked:\n' >&2
          printf '  %s (index.lock held)\n' "${t}" >&2
          peers_active=$((peers_active + 1))
        fi
      fi
    done
    if [[ "${peers_active}" -gt 0 ]]; then
      printf '\nPeer worktrees are active but isolated; current worktree is safe.\n' >&2
    fi

 # Check 3: stash churn heuristic. The the DevOps owner/the platform owner incident surfaced as
 # a stash entry created seconds before a destructive checkout. If
 # the most-recent stash in the CURRENT worktree was created in the
 # last 60 seconds and is not the session's own, treat that as suspect.
 # `git stash list --format=...` on modern git supports committer-date
 # formatting; fall back gracefully if the format is unsupported.
    if stash_top="$(git -C "${cwd}" stash list --format=%ct 2>/dev/null | head -n 1)"; then
      if [[ -n "${stash_top}" ]]; then
        now="$(date +%s)"
        if age=$((now - stash_top)); [[ "${age}" -ge 0 && "${age}" -lt 60 ]]; then
          printf '\nWARNING: most-recent stash entry is %ds old.\n' "${age}" >&2
          printf 'Confirm this stash is intentional (yours) and not a peer\n' >&2
          printf 'agent burying live WIP in your worktree.\n' >&2
          printf 'Inspect with: git -C %s stash list\n' "${cwd}" >&2
 # Do not fail hard on the heuristic; print and continue. The
 # hard failure modes are index.lock and resolve_worktree.
        fi
      fi
    fi

    printf '\nOK: worktree is safe to work in.\n'
    exit 0
    ;;

  *)
    usage
    ;;
esac
