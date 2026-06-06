#!/usr/bin/env bash
#
# Smoke tests for provii-provenance.
#
# Starts wrangler dev in local mode, runs a few curl assertions, then
# tears down the dev server. Local R2 is empty so file-serving tests
# expect 404; that is fine. Real testing requires --remote which needs
# R2 bucket access on the Cloudflare account.
#
# Usage:
# cd provii-provenance && bash scripts/smoke.sh

set -euo pipefail

PORT="${PORT:-8787}"
WORKER_URL="http://localhost:${PORT}"
WRANGLER_PID=""

cleanup() {
  if [[ -n "${WRANGLER_PID}" ]]; then
    kill "${WRANGLER_PID}" 2>/dev/null || true
    wait "${WRANGLER_PID}" 2>/dev/null || true
  fi
}
trap cleanup EXIT

echo "==> Starting wrangler dev --local on port ${PORT}..."
npx wrangler dev --local --port "${PORT}" &>/dev/null &
WRANGLER_PID=$!

# Wait for the server to come up
for i in $(seq 1 30); do
  if curl -sf "${WORKER_URL}/" >/dev/null 2>&1; then
    break
  fi
  if [[ "${i}" -eq 30 ]]; then
    echo "FAIL: wrangler dev did not start within 30 seconds"
    exit 1
  fi
  sleep 1
done

PASS=0
FAIL=0

assert_status() {
  local description="$1"
  local url="$2"
  local expected_status="$3"

  local actual_status
  actual_status=$(curl -o /dev/null -s -w '%{http_code}' "${url}" 2>/dev/null)

  if [[ "${actual_status}" == "${expected_status}" ]]; then
    echo "  PASS: ${description} (HTTP ${actual_status})"
    PASS=$((PASS + 1))
  else
    echo "  FAIL: ${description} (expected ${expected_status}, got ${actual_status})"
    FAIL=$((FAIL + 1))
  fi
}

assert_body_contains() {
  local description="$1"
  local url="$2"
  local needle="$3"

  local body
  body=$(curl -sf "${url}" 2>/dev/null || echo "")

  if echo "${body}" | grep -q "${needle}"; then
    echo "  PASS: ${description}"
    PASS=$((PASS + 1))
  else
    echo "  FAIL: ${description} (body does not contain '${needle}')"
    FAIL=$((FAIL + 1))
  fi
}

assert_header() {
  local description="$1"
  local url="$2"
  local header_name="$3"
  local expected_value="$4"

  local headers
  headers=$(curl -sf -I "${url}" 2>/dev/null || echo "")

  if echo "${headers}" | grep -qi "${header_name}: ${expected_value}"; then
    echo "  PASS: ${description}"
    PASS=$((PASS + 1))
  else
    echo "  FAIL: ${description} (header '${header_name}' not '${expected_value}')"
    FAIL=$((FAIL + 1))
  fi
}

echo ""
echo "==> Running smoke tests..."

# Root page returns 200 with expected title
assert_status "GET / returns 200" "${WORKER_URL}/" "200"
assert_body_contains "GET / contains title" "${WORKER_URL}/" "Provii Provenance Archive"
assert_body_contains "GET / contains artefact table" "${WORKER_URL}/" "What is stored here"
assert_body_contains "GET / contains verification section" "${WORKER_URL}/" "cosign verify-blob"

# Security headers present
assert_header "X-Content-Type-Options header" "${WORKER_URL}/" "x-content-type-options" "nosniff"
assert_header "X-Frame-Options header" "${WORKER_URL}/" "x-frame-options" "DENY"

# File request for nonexistent object returns 404
assert_status "GET /nonexistent.json returns 404" "${WORKER_URL}/nonexistent.json" "404"

# Method not allowed
actual_status=$(curl -o /dev/null -w '%{http_code}' -X POST "${WORKER_URL}/" 2>/dev/null)
if [[ "${actual_status}" == "405" ]]; then
  echo "  PASS: POST / returns 405"
  PASS=$((PASS + 1))
else
  echo "  FAIL: POST / returns 405 (got ${actual_status})"
  FAIL=$((FAIL + 1))
fi

echo ""
echo "==> Results: ${PASS} passed, ${FAIL} failed"

if [[ "${FAIL}" -gt 0 ]]; then
  exit 1
fi
