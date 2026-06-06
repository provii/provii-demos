#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Provii
#
# : Agent-launcher-side lock under `.git/provii-agent.lock`.
#
# Background. A review flagged that
# `scripts/check-worktree-isolation.sh` () and the pre-commit hook
# on `.githooks/pre-commit` catch collisions at check time and commit
# time, but nothing stops a second session from quietly opening edits in
# the same worktree between those gates. Damage (stash, branch switch,
# staged-index conflict) can happen inside that window.
#
# This script is the second defensive layer. It is called at the start
# and end of a parallel edit session and holds a per-worktree lock
# file that names the session (pid + cwd + toplevel + timestamp) who owns
# the worktree. A second session that tries to acquire a held lock is
# refused with the holder's identity printed to stderr. Combined with
# the pre-commit hook, the failure surface narrows to a deliberate
# stomp (`--no-verify` plus ignoring this script's output).
#
# Design notes.
#
# - Lock file location. `.git/provii-agent.lock` sits next to
# `.git/index.lock`. For a primary worktree this is the shared
# `.git` directory; for a linked worktree it is
# `.git/worktrees/<name>/provii-agent.lock`. Using
# `git rev-parse --git-dir` gives us the correct directory in both
# cases, so the lock stays scoped to a single worktree and parallel
# sessions on DIFFERENT worktrees do not collide.
#
# - Stale-lock expiry. If the recorded pid is no longer alive we treat
# the lock as abandoned and overwrite it. The old holder almost
# certainly crashed, was killed, or the operator closed the
# terminal. We do NOT use a timeout; long-running sessions are
# legitimate, pid-liveness is the right signal.
#
# - Atomicity. `acquire` opens the lock with `set -o noclobber` then
# writes the four required fields. If the open fails, we fall back
# to stale-lock inspection and retry exactly once. This avoids the
# TOCTOU race of "stat then open".
#
# - Release. `release` only removes the lock if the recorded pid
# matches the caller's pid AND the recorded toplevel matches the
# argument. Prevents one session from clearing another's lock by
# accident.
#
# Usage.
#
# # At the start of an edit session:
# ./scripts/agent-launch-lock.sh acquire "$(git rev-parse --show-toplevel)"
#
# # At the end (or in a trap on EXIT):
# ./scripts/agent-launch-lock.sh release "$(git rev-parse --show-toplevel)"
#
# # Inspect state without acquiring:
# ./scripts/agent-launch-lock.sh status "$(git rev-parse --show-toplevel)"
#
# Exit codes.
# 0 acquired / released / status printed
# 1 lock held by a live session; refuse
# 2 operator error (bad path, missing git dir, argument count)

set -euo pipefail

usage() {
  cat <<'USAGE' >&2
usage:
  agent-launch-lock.sh acquire <toplevel>
  agent-launch-lock.sh release <toplevel>
  agent-launch-lock.sh status  <toplevel>

Operates on `.git/provii-agent.lock` (or
`.git/worktrees/<name>/provii-agent.lock` for linked worktrees) under
the repository rooted at <toplevel>.
USAGE
  exit 2
}

if [[ $# -ne 2 ]]; then
  usage
fi

mode="$1"
toplevel="$2"

if [[ ! -d "${toplevel}" ]]; then
  printf 'agent-launch-lock: not a directory: %s\n' "${toplevel}" >&2
  exit 2
fi

# Resolve the worktree-specific git dir. For a primary worktree this is
# `<toplevel>/.git`; for a linked worktree it is
# `<shared>/.git/worktrees/<name>`.
if ! git_dir="$(git -C "${toplevel}" rev-parse --git-dir 2>/dev/null)"; then
  printf 'agent-launch-lock: not a git worktree: %s\n' "${toplevel}" >&2
  exit 2
fi

# Absolute path.
git_dir_abs="$(cd "${toplevel}" && cd "${git_dir}" && pwd)"

# Normalise the toplevel for comparison (resolve symlinks).
toplevel_abs="$(cd "${toplevel}" && pwd)"

lock_file="${git_dir_abs}/provii-agent.lock"

# Read the four fields of an existing lock file. Sets globals:
# LOCK_PID, LOCK_CWD, LOCK_TOPLEVEL, LOCK_TIMESTAMP
# Returns 0 on success, 1 if the file is absent or malformed.
read_lock() {
  if [[ ! -e "${lock_file}" ]]; then
    return 1
  fi
  LOCK_PID=""
  LOCK_CWD=""
  LOCK_TOPLEVEL=""
  LOCK_TIMESTAMP=""
  while IFS='=' read -r key value; do
    case "${key}" in
      pid)       LOCK_PID="${value}" ;;
      cwd)       LOCK_CWD="${value}" ;;
      toplevel)  LOCK_TOPLEVEL="${value}" ;;
      timestamp) LOCK_TIMESTAMP="${value}" ;;
    esac
  done < "${lock_file}"
  if [[ -z "${LOCK_PID}" || -z "${LOCK_TOPLEVEL}" ]]; then
    return 1
  fi
  return 0
}

# Check whether a pid is still alive. `kill -0` is the POSIX way.
pid_alive() {
  local p="$1"
  if [[ -z "${p}" ]]; then
    return 1
  fi
  kill -0 "${p}" 2>/dev/null
}

# Write a fresh lock file with the current session's identity.
write_lock() {
  local ts
  ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
 # noclobber so we fail rather than stomp a concurrent acquirer that
 # won the race in between our read and write.
  set -o noclobber
  {
    printf 'pid=%s\n'       "$$"
    printf 'cwd=%s\n'       "$(pwd)"
    printf 'toplevel=%s\n'  "${toplevel_abs}"
    printf 'timestamp=%s\n' "${ts}"
  } > "${lock_file}"
  set +o noclobber
}

case "${mode}" in
  acquire)
    if read_lock; then
      if pid_alive "${LOCK_PID}"; then
        printf 'agent-launch-lock: REFUSED.\n' >&2
        printf '  lock held by pid=%s cwd=%s toplevel=%s since=%s\n' \
          "${LOCK_PID}" "${LOCK_CWD}" "${LOCK_TOPLEVEL}" "${LOCK_TIMESTAMP}" >&2
        printf '  our pid=%s cwd=%s\n' "$$" "$(pwd)" >&2
        printf '\nAnother session is already editing this worktree. Either wait for\n' >&2
        printf 'the holder to release or launch in a dedicated worktree via\n' >&2
        printf '`git worktree add` (see CONTRIBUTING.md).\n' >&2
        exit 1
      fi
 # Stale (process gone). Remove and fall through to acquire.
      rm -f "${lock_file}"
    fi

 # The noclobber write can still fail if a peer acquirer beat us
 # between our read and write. Handle that path explicitly.
    if ! write_lock 2>/dev/null; then
 # Re-inspect; a live peer is the only reason we should refuse.
      if read_lock && pid_alive "${LOCK_PID}"; then
        printf 'agent-launch-lock: REFUSED (race).\n' >&2
        printf '  lock held by pid=%s cwd=%s toplevel=%s since=%s\n' \
          "${LOCK_PID}" "${LOCK_CWD}" "${LOCK_TOPLEVEL}" "${LOCK_TIMESTAMP}" >&2
        exit 1
      fi
 # Raced against a now-dead acquirer. Clear and retry exactly once.
      rm -f "${lock_file}"
      write_lock
    fi

    printf 'agent-launch-lock: acquired %s (pid %s, cwd %s)\n' \
      "${lock_file}" "$$" "$(pwd)"
    exit 0
    ;;

  release)
    if ! read_lock; then
      printf 'agent-launch-lock: no lock to release at %s\n' "${lock_file}" >&2
      exit 0
    fi
    if [[ "${LOCK_TOPLEVEL}" != "${toplevel_abs}" ]]; then
      printf 'agent-launch-lock: refuse to release; toplevel mismatch.\n' >&2
      printf '  lock toplevel = %s\n' "${LOCK_TOPLEVEL}" >&2
      printf '  release arg   = %s\n' "${toplevel_abs}" >&2
      exit 2
    fi
    if [[ "${LOCK_PID}" != "$$" ]]; then
 # Not ours. Only remove if the holder is demonstrably gone.
      if pid_alive "${LOCK_PID}"; then
        printf 'agent-launch-lock: refuse to release; lock owned by live pid %s\n' \
          "${LOCK_PID}" >&2
        exit 1
      fi
      printf 'agent-launch-lock: clearing stale lock (holder pid %s gone)\n' \
        "${LOCK_PID}" >&2
    fi
    rm -f "${lock_file}"
    printf 'agent-launch-lock: released %s\n' "${lock_file}"
    exit 0
    ;;

  status)
    if ! read_lock; then
      printf 'agent-launch-lock: no lock at %s\n' "${lock_file}"
      exit 0
    fi
    local_state="live"
    if ! pid_alive "${LOCK_PID}"; then
      local_state="stale (holder pid gone)"
    fi
    printf 'agent-launch-lock: %s\n' "${lock_file}"
    printf '  pid       = %s (%s)\n' "${LOCK_PID}" "${local_state}"
    printf '  cwd       = %s\n' "${LOCK_CWD}"
    printf '  toplevel  = %s\n' "${LOCK_TOPLEVEL}"
    printf '  timestamp = %s\n' "${LOCK_TIMESTAMP}"
    exit 0
    ;;

  *)
    usage
    ;;
esac
