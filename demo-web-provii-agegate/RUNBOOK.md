# Docs Gateway Runbook

Operational procedures for the docs gateway (`docs.provii.app`,
sandbox environment only). Audience is on-call: someone with `wrangler`
access and the Cloudflare dashboard but not necessarily authoring
context on the gateway code.

Keep this file current. Every procedure here is exercised at least
quarterly so commands do not rot.

## Contents

- Rollback procedures
- KV sweep procedures
- Bearer kid rotation
- Feature flag controls

## Rollback Procedures

Use these when a deploy of the docs gateway introduces a regression
that affects the docs widget surface. The rollback is per-environment;
production routes for the docs domain are not yet live so all rollbacks
target the sandbox Worker.

### Symptom Triage

Before rolling back, classify the failure:

| Symptom | First action |
|------------------------------------------|-----------------------------------|
| All endpoints 5xx | Global feature flag kill |
| Single endpoint 5xx | Per-endpoint feature flag |
| KV reads return wrong shape | Rollback Worker, then KV sweep |
| Cookie validation rejects all sessions | Rollback Worker, do NOT sweep KV |
| Bot protection rejects everything | Check CF dashboard challenge rules|

If unsure: enable the global kill first, investigate next.

### 1. Enable Global Kill

The fastest way to take the gateway offline without redeploying. Every
flag-mapped endpoint short-circuits to `503 docs_gateway_disabled`
within one minute of the flip (per-isolate cache TTL).

```bash
wrangler kv key put --remote \
 --binding DOCS_SESSIONS \
 --env sandbox \
 "docs-features:gateway:disabled" "true"
```

To re-enable:

```bash
wrangler kv key put --remote \
 --binding DOCS_SESSIONS \
 --env sandbox \
 "docs-features:gateway:disabled" "false"
```

Or delete the key (default is "not killed"):

```bash
wrangler kv key delete --remote \
 --binding DOCS_SESSIONS \
 --env sandbox \
 "docs-features:gateway:disabled"
```

### 2. Worker Rollback

If the regression is in code rather than data, roll back the Worker
script to the previous deployment.

1. List recent deployments:

 ```bash
 wrangler deployments list --env sandbox
 ```

2. Identify the last known good deployment id (top of the list is the
 active one).

3. Roll back:

 ```bash
 wrangler rollback --env sandbox <deployment_id>
 ```

4. Verify by hitting `/api/fixtures` (read-only, session-required) and
 confirming the response shape matches the previous version.

5. Open a follow-up issue with the failing change so the rollback is
 not re-applied on the next deploy.

## KV Sweep Procedures

Do **not** sweep KV unless rollback alone does not resolve the issue.
KV stores session cookies, credentials, challenges, and rate-limit
state; a wholesale sweep invalidates every active session and forces
every docs widget to reauthenticate.

### Sweep a Single Key Prefix

Use this when a known-bad code path wrote schema-incompatible records
under one prefix.

```bash
# Example: sweep the credential records.
wrangler kv key list --remote \
 --binding DOCS_SESSIONS \
 --env sandbox \
 --prefix "docs-cred-v:" \
 | jq -r '.[].name' \
 | while read key; do
 wrangler kv key delete --remote \
 --binding DOCS_SESSIONS \
 --env sandbox \
 "$key"
 done
```

Replace the prefix with the affected one:

| Prefix | What it stores | Sweep impact |
|-------------------------|---------------------------------|-----------------------------------|
| `docs-session:` | Session record | Invalidates every live session |
| `docs-session-idx:` | bearer_hash to session_id index | Same; sweep both together |
| `docs-cred-v:` | Verifier credentials | Sessions stay; widgets re-mint |
| `docs-cred-i:` | Issuer credentials | Sessions stay; widgets re-mint |
| `docs-chal:` | In-flight challenges | Active polls return 410 |
| `docs-challenge-seen:` | Challenge dedupe | Brief replay window opens |
| `ratelimit:docs:` | Rate-limit counters | Caller can burst once |
| `docs-features:` | Feature flags | Falls back to defaults |

### Sweep All Sessions and Indexes Together

If a session schema change is the trigger:

```bash
for prefix in "docs-session:" "docs-session-idx:"; do
 wrangler kv key list --remote \
 --binding DOCS_SESSIONS \
 --env sandbox \
 --prefix "$prefix" \
 | jq -r '.[].name' \
 | while read key; do
 wrangler kv key delete --remote \
 --binding DOCS_SESSIONS \
 --env sandbox \
 "$key"
 done
done
```

### Verify After Sweep

```bash
wrangler kv key list --remote \
 --binding DOCS_SESSIONS \
 --env sandbox \
 --prefix "docs-session:" | jq 'length'
```

Should return 0 immediately after a session sweep.

## Bearer Kid Rotation

The docs session cookie is signed with `DOCS_SESSION_HMAC_KEY` under
key id `ACTIVE_SESSION_KID` (currently `v1`). Rotation is required at
least every 90 days, and immediately after any incident that may have
exposed the key.

### Why the Kid Lookup is Single-Shot

`verifySessionCookie` parses the cookie's `<kid>.<bearer_hex>.<tag_hex>`
prefix and resolves the key for that specific kid. Old cookies signed
under the previous kid keep verifying as long as the previous kid's
key is still bound; new cookies are minted under the active kid. This
gives us zero-downtime rotation: the moment we flip `ACTIVE_SESSION_KID`,
new sessions go to the new key, old sessions drain naturally as their
4-hour hard expiry hits.

### Rotation Cadence

| Trigger | Action |
|------------------------------------------|--------------------------------------|
| 90-day calendar tick | Standard rotation |
| Suspected key leak | Emergency rotation |
| Operator turnover with key access | Emergency rotation within 24h |

### Standard Rotation Procedure

1. Generate the next key. 32 bytes hex is the minimum accepted shape.

 ```bash
 openssl rand -hex 32
 ```

2. Pick the next kid name. Increment the suffix on the current
 `ACTIVE_SESSION_KID` (`v1` becomes `v2`, etc.).

3. Bind the new key under the new kid in Secrets Store. The Worker's
 secret name must match what `resolveSessionHmacKey` looks up; in the
 foundation phase that is `DOCS_SESSION_HMAC_KEY`. Add a second
 binding for the previous kid so old cookies still verify during the
 drain window:

 ```bash
 # Bind the new active key.
 wrangler secret put DOCS_SESSION_HMAC_KEY --env sandbox

 # Bind the previous-kid key under a kid-suffixed name so
 # resolveSessionHmacKey can pick it up after the next code change.
 wrangler secret put DOCS_SESSION_HMAC_KEY_V1 --env sandbox
 ```

4. Update `ACTIVE_SESSION_KID` in `src/docs/session.ts` to the new kid
 and extend `resolveSessionHmacKey` to look up the previous kid's
 binding by name. Open a PR for the change and get codeowner review
 (the platform owner + the integration owner per CODEOWNERS).

5. Deploy:

 ```bash
 cd demo-web-provii-agegate
 npm run build
 wrangler deploy --env sandbox
 ```

6. Verify:
 - Mint a fresh session via the docs widget. Inspect the cookie:
 the kid prefix should be the new value.
 - Reuse a cookie from before the rotation. It should keep verifying
 until its 4-hour expiry.

7. Drain window: wait `SESSION_HARD_TTL_MS` (4 hours) past the deploy
 timestamp. After the drain, no live cookie carries the old kid.

8. Remove the old-kid binding and delete the previous secret. Open a
 second PR removing the old-kid lookup branch in
 `resolveSessionHmacKey`. Deploy.

### Emergency Rotation Procedure

Skip the drain window. Existing sessions will be forcibly invalidated.

1. Steps 1-3 from standard rotation.
2. Update `ACTIVE_SESSION_KID` AND remove the old-kid lookup branch in
 the same PR. No fallback.
3. Deploy.
4. Sweep `docs-session:` and `docs-session-idx:` prefixes per the KV
 sweep procedure above so revoked cookies do not waste KV roundtrips
 only to fail HMAC.

### Audit Trail

Every rotation logs:

- Date and operator initials.
- Trigger (calendar / leak / turnover).
- Old kid, new kid.
- Deploy id from `wrangler deployments list`.
- Verification result.

Append to `docs/runbook-rotation-log.md` (create if missing) and
commit on the rotation branch.

## Feature Flag Controls

See "Enable Global Kill" above for the gateway-wide kill switch.
Per-endpoint flags follow the same pattern with a different key:

```bash
# Disable just the credentials/issuer widget.
wrangler kv key put --remote \
 --binding DOCS_SESSIONS \
 --env sandbox \
 "docs-features:credentials_issuer:enabled" "false"

# Re-enable.
wrangler kv key put --remote \
 --binding DOCS_SESSIONS \
 --env sandbox \
 "docs-features:credentials_issuer:enabled" "true"

# Or delete the key (default is enabled).
wrangler kv key delete --remote \
 --binding DOCS_SESSIONS \
 --env sandbox \
 "docs-features:credentials_issuer:enabled"
```

Valid endpoint keys (matches `DocsFeatureEndpoint` in
`src/docs/feature-flags.ts`):

- `session_init`
- `credentials_verifier`
- `credentials_issuer`
- `challenge`
- `status`
- `attestation`
- `simulate_proof`
- `fixtures`

The flag cache is per-isolate with a 60-second TTL. A flag flip
propagates to a given isolate within roughly one minute. Workers does
not expose a forced-purge primitive, so the operator must wait out the
TTL or trigger a redeploy to invalidate every isolate at once.
