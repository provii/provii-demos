#!/usr/bin/env bash
# UAT rollback drill for the docs gateway.
#
# from the tracker. Two independent drills
# live behind this script so operators can exercise either path without
# copy-pasting the entire brief.
#
# kv-flip Flip docs-features:gateway:disabled in DOCS_SESSIONS KV,
# verify the gateway returns 503 with code docs_gateway_disabled,
# confirm playground traffic is unaffected, restore.
#
# deploy-rollback
# Find the deployment currently running one step behind the live
# one on provii-docs --env=uat, roll back to it, verify, then
# redeploy the current tag to restore. Targets the static docs
# Worker in the provii-docs repo (NOT the gateway Worker in
# provii-demos/demo-web-provii-agegate).
#
# Usage:
# uat-rollback-drill.sh <kv-flip|deploy-rollback|plan> [--apply]
#
# Without --apply the script prints the exact commands it would run and
# exits 0. --apply executes them. The --apply mode prompts once before the
# destructive step unless PROVII_UAT_DRILL_NONINTERACTIVE=1 is set.
#
# Requirements: wrangler >= 4, jq, curl, python3.
#
# Notes for readers: the current wrangler.toml for demo-web-provii-agegate has no
# [env.uat] block. The KV namespace DOCS_SESSIONS is shared byte-for-byte
# between top-level (production) and env.sandbox (id 5d3dc223363a44bab3db796b7f72f1c0).
# A flag flip therefore affects BOTH prod and sandbox docs gateway traffic.
# The script fail-closes with a big warning before touching KV unless the
# caller sets PROVII_UAT_DRILL_ACK_SHARED_KV=1.

set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
REPO_ROOT=$(cd -- "${SCRIPT_DIR}/.." &>/dev/null && pwd)
GATEWAY_DIR="${REPO_ROOT}/demo-web-provii-agegate"
DOCS_REPO="${PROVII_DOCS_REPO:-${REPO_ROOT}/../provii-docs}"

KILL_KEY="docs-features:gateway:disabled"
KV_BINDING="DOCS_SESSIONS"

GATEWAY_URL_PROD="https://docs.provii.app"
GATEWAY_URL_UAT="https://uat-docs.provii.app"
PLAYGROUND_URL="https://playground.provii.app"

MODE="${1:-plan}"
APPLY="no"
for arg in "${@:2}"; do
  if [[ "$arg" == "--apply" ]]; then APPLY="yes"; fi
done

log() { printf '[drill] %s\n' "$*" >&2; }
run() {
  log "\$ $*"
  if [[ "$APPLY" == "yes" ]]; then
    "$@"
  fi
}

confirm_once() {
  if [[ "$APPLY" != "yes" ]]; then return 0; fi
  if [[ "${PROVII_UAT_DRILL_NONINTERACTIVE:-0}" == "1" ]]; then return 0; fi
  printf '[drill] About to run a destructive step. Continue? (yes/no) ' >&2
  read -r answer
  if [[ "$answer" != "yes" ]]; then
    log "aborted by operator"
    exit 2
  fi
}

require_shared_kv_ack() {
  if [[ "${PROVII_UAT_DRILL_ACK_SHARED_KV:-0}" != "1" ]]; then
    cat >&2 <<'WARN'
[drill] REFUSING TO PROCEED.
        The DOCS_SESSIONS KV namespace (id 5d3dc223363a44bab3db796b7f72f1c0)
        is bound identically at top-level and env.sandbox in
        demo-web-provii-agegate/wrangler.toml. Flipping docs-features:gateway:disabled
        affects the production docs gateway at docs.provii.app as well
        as any UAT path that reuses the same binding.
        Set PROVII_UAT_DRILL_ACK_SHARED_KV=1 to acknowledge and continue.
WARN
    exit 3
  fi
}

pick_previous_deployment() {
 # Picks the second-most-recent deployment by created_on, reverse-sorted.
 # The tracker brief assumes a metadata.deployment_status field; wrangler 4
 # does not emit one, so this version sorts on created_on only.
  cd "$DOCS_REPO"
  wrangler deployments list --env=uat --json \
    | jq -r 'sort_by(.created_on) | reverse | .[1].id'
}

current_deployment() {
  cd "$DOCS_REPO"
  wrangler deployments list --env=uat --json \
    | jq -r 'sort_by(.created_on) | reverse | .[0].id'
}

plan() {
  cat <<PLAN
UAT rollback drill plan
=======================

Mode kv-flip (gateway kill switch):
  cd ${GATEWAY_DIR}
  wrangler kv key get --remote --binding=${KV_BINDING} ${KILL_KEY}
  wrangler kv key put --remote --binding=${KV_BINDING} ${KILL_KEY} true
  curl -sS -o /dev/null -w '%{http_code}\\n' ${GATEWAY_URL_PROD}/api/session/init -X POST
  curl -sS -o /dev/null -w '%{http_code}\\n' ${GATEWAY_URL_UAT}/api/session/init -X POST
  curl -sS -o /dev/null -w '%{http_code}\\n' ${PLAYGROUND_URL}/v1/config/demo-token
  wrangler kv key delete --remote --binding=${KV_BINDING} ${KILL_KEY}

Mode deploy-rollback (provii-docs UAT):
  cd ${DOCS_REPO}
  CURR=\$(wrangler deployments list --env=uat --json | jq -r 'sort_by(.created_on) | reverse | .[0].id')
  PREV=\$(wrangler deployments list --env=uat --json | jq -r 'sort_by(.created_on) | reverse | .[1].id')
  wrangler rollback "\$PREV" --env=uat --message="drill"
  curl -sS -o /dev/null -w '%{http_code}\\n' ${GATEWAY_URL_UAT}/
  wrangler deploy --env=uat

Acknowledgements required for --apply:
  PROVII_UAT_DRILL_ACK_SHARED_KV=1  (only for kv-flip)
  PROVII_UAT_DRILL_NONINTERACTIVE=1 (optional; skips the prompt)

Notes:
  - demo-web-provii-agegate has no [env.uat]. The brief's '--env=uat' on the gateway
    cannot target a UAT-only deployment; it would error out. Deploy rollback
    of the gateway must be done via 'wrangler rollback' on production or
    env.sandbox, which are not 'UAT' in any meaningful sense.
  - PLAYGROUND_SESSIONS KV is disjoint from DOCS_SESSIONS. Playground traffic
    is unaffected by the docs-features kill switch by construction.
PLAN
}

kv_flip() {
  require_shared_kv_ack
  cd "$GATEWAY_DIR"

  log "Step 1. Snapshot current KV state."
  if [[ "$APPLY" == "yes" ]]; then
    set +e
    current=$(wrangler kv key get --remote --binding="$KV_BINDING" "$KILL_KEY" 2>&1)
    rc=$?
    set -e
    log "current kill-switch value rc=${rc}:"
    printf '%s\n' "$current" >&2
  else
    log "(plan) would read current kill-switch value"
  fi

  log "Step 2. Flip kill switch to true."
  confirm_once
  run wrangler kv key put --remote --binding="$KV_BINDING" "$KILL_KEY" true

  log "Step 3. Verify gateway returns docs_gateway_disabled."
  run curl -sS -D - -o /tmp/uat-drill-gateway.json \
    -X POST "${GATEWAY_URL_UAT}/api/session/init" \
    -H 'content-type: application/json' --data '{}'
  if [[ "$APPLY" == "yes" ]]; then
    log "response body:"
    cat /tmp/uat-drill-gateway.json >&2 || true
    echo >&2
  fi

  log "Step 4. Verify playground unaffected."
  run curl -sS -o /tmp/uat-drill-playground.json -w '%{http_code}\n' \
    "${PLAYGROUND_URL}/v1/config/demo-token"
  if [[ "$APPLY" == "yes" ]]; then
    log "playground body snippet:"
    head -c 200 /tmp/uat-drill-playground.json >&2 || true
    echo >&2
  fi

  log "Step 5. Restore kill switch."
  run wrangler kv key delete --remote --binding="$KV_BINDING" "$KILL_KEY"

  log "Step 6. Post-drill verify gateway recovers."
  run curl -sS -o /dev/null -w '%{http_code}\n' \
    -X POST "${GATEWAY_URL_UAT}/api/session/init" \
    -H 'content-type: application/json' --data '{}'

  log "kv-flip drill complete."
}

deploy_rollback() {
  if [[ ! -d "$DOCS_REPO" ]]; then
    log "provii-docs repo not found at $DOCS_REPO; set PROVII_DOCS_REPO to override."
    exit 4
  fi
  cd "$DOCS_REPO"

  log "Step 1. Identify current and previous deployments."
  if [[ "$APPLY" == "yes" ]]; then
    CURR=$(current_deployment)
    PREV=$(pick_previous_deployment)
    log "current=${CURR}"
    log "previous=${PREV}"
    if [[ -z "$PREV" || "$PREV" == "null" ]]; then
      log "no previous deployment found; aborting"
      exit 5
    fi
  else
    log "(plan) would query wrangler deployments list --env=uat --json"
  fi

  log "Step 2. Roll back."
  confirm_once
  if [[ "$APPLY" == "yes" ]]; then
    run wrangler rollback "$PREV" --env=uat --message="drill"
  else
    run wrangler rollback '<PREV>' --env=uat --message="drill"
  fi

  log "Step 3. Verify the UAT page responds with rolled-back content."
  run curl -sS -o /dev/null -w '%{http_code}\n' "${GATEWAY_URL_UAT}/"

  log "Step 4. Redeploy current tag to restore."
  confirm_once
  run wrangler deploy --env=uat

  log "Step 5. Verify restore."
  run curl -sS -o /dev/null -w '%{http_code}\n' "${GATEWAY_URL_UAT}/"

  log "deploy-rollback drill complete."
}

case "$MODE" in
  plan) plan ;;
  kv-flip) kv_flip ;;
  deploy-rollback) deploy_rollback ;;
  *)
    log "unknown mode: $MODE"
    log "usage: $0 <kv-flip|deploy-rollback|plan> [--apply]"
    exit 64
    ;;
esac
