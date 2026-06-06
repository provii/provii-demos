#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Provii
#
# Unit test for `agent-launch-lock.sh`.
#
# Exercises:
# 1. first acquirer wins
# 2. second acquirer against a live lock is refused (exit 1)
# 3. second acquirer against a stale lock (dead pid) succeeds
# 4. release clears the lock
# 5. status on an empty directory is a clean exit
#
# Runs in a throwaway git repo under $TMPDIR. No network, no side effects
# outside the temp directory.

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
LOCK_SCRIPT="${HERE}/agent-launch-lock.sh"

if [[ ! -x "${LOCK_SCRIPT}" ]]; then
  printf 'FAIL: %s is not executable\n' "${LOCK_SCRIPT}" >&2
  exit 2
fi

tmp_root="$(mktemp -d -t agent-launch-lock-test.XXXXXX)"
trap 'rm -rf "${tmp_root}"' EXIT

repo="${tmp_root}/repo"
git init -q -- "${repo}"
cd "${repo}"
git -c user.email=t@t.t -c user.name=t commit --allow-empty -q -m init

# Mimic a "real" agent acquiring the lock, then write the lock file
# ourselves with a chosen pid so we can script the scenarios without
# actually forking long-lived helper processes.

git_dir_abs="$(cd "${repo}" && git rev-parse --git-dir)"
git_dir_abs="$(cd "${repo}" && cd "${git_dir_abs}" && pwd)"
lock_file="${git_dir_abs}/provii-agent.lock"

pass=0
fail=0

check() {
  local label="$1" expected="$2" actual="$3"
  if [[ "${expected}" == "${actual}" ]]; then
    printf 'PASS: %s\n' "${label}"
    pass=$((pass + 1))
  else
    printf 'FAIL: %s (expected=%s actual=%s)\n' "${label}" "${expected}" "${actual}" >&2
    fail=$((fail + 1))
  fi
}

# Scenario A: first acquirer wins.
set +e
"${LOCK_SCRIPT}" acquire "${repo}" >/dev/null 2>&1
rc=$?
set -e
check "first acquire returns 0" "0" "${rc}"
check "lock file exists after acquire" "yes" "$([[ -f "${lock_file}" ]] && echo yes || echo no)"

# Inspect recorded pid. The first acquirer was a subshell of THIS test,
# and the script exited, so the recorded pid is dead by now. That is
# actually scenario C (stale lock). We want scenario B (live holder)
# first, so overwrite the lock with OUR shell's pid before scenario B.
# $$ is the running test's pid; guaranteed alive.
cat > "${lock_file}" <<EOF
pid=$$
cwd=${repo}
toplevel=${repo}
timestamp=2026-04-14T00:00:00Z
EOF

# Scenario B: second acquirer against a LIVE lock is refused.
set +e
out="$("${LOCK_SCRIPT}" acquire "${repo}" 2>&1)"
rc=$?
set -e
check "live-lock acquire returns 1" "1" "${rc}"
# The refusal message must name the holder's pid.
if printf '%s' "${out}" | grep -q "pid=$$"; then
  check "refusal message names holder pid" "yes" "yes"
else
  check "refusal message names holder pid" "yes" "no"
fi
# And the holder's cwd.
if printf '%s' "${out}" | grep -q "cwd=${repo}"; then
  check "refusal message names holder cwd" "yes" "yes"
else
  check "refusal message names holder cwd" "yes" "no"
fi

# Scenario C: second acquirer against a STALE lock (dead pid) succeeds.
# Pick a pid that is almost certainly not alive. 99999 is a safe bet on
# macOS; if it happens to be live we fall back to spawning and killing a
# throwaway process to guarantee a dead pid.
dead_pid=99999
if kill -0 "${dead_pid}" 2>/dev/null; then
 # Spawn `true` in the background; its pid dies immediately after exit.
  (true) &
  dead_pid=$!
  wait "${dead_pid}" 2>/dev/null || true
fi
cat > "${lock_file}" <<EOF
pid=${dead_pid}
cwd=${repo}
toplevel=${repo}
timestamp=2026-04-14T00:00:00Z
EOF
set +e
"${LOCK_SCRIPT}" acquire "${repo}" >/dev/null 2>&1
rc=$?
set -e
check "stale-lock acquire returns 0" "0" "${rc}"
# Verify the lock file now records a pid OTHER than the dead one. The
# script runs as a child process so its pid will not equal $$ (the
# test's pid); we assert non-equality with the stale dead_pid instead.
new_pid=""
if [[ -f "${lock_file}" ]]; then
  new_pid="$(awk -F= '/^pid=/{print $2}' "${lock_file}")"
fi
if [[ -n "${new_pid}" && "${new_pid}" != "${dead_pid}" ]]; then
  check "stale lock was replaced with a different pid" "ok" "ok"
else
  check "stale lock was replaced with a different pid" "ok" \
    "not-ok (new_pid=${new_pid} dead_pid=${dead_pid})"
fi

# Scenario D: release clears the lock.
set +e
"${LOCK_SCRIPT}" release "${repo}" >/dev/null 2>&1
rc=$?
set -e
check "release returns 0" "0" "${rc}"
check "lock file removed after release" "no" "$([[ -f "${lock_file}" ]] && echo yes || echo no)"

# Scenario E: status on empty lock state is a clean exit.
set +e
"${LOCK_SCRIPT}" status "${repo}" >/dev/null 2>&1
rc=$?
set -e
check "status on empty returns 0" "0" "${rc}"

printf '\n--- summary ---\n'
printf 'passed: %d\n' "${pass}"
printf 'failed: %d\n' "${fail}"
if [[ "${fail}" -gt 0 ]]; then
  exit 1
fi
exit 0
