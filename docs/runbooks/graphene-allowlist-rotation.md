# GrapheneOS verified-boot key allowlist rotation

Owner: the code change in `demo-web-provii-agegate/src/docs/attestation/key-attestation.ts`. the DevOps owner maintains the CI and runbook infrastructure.

Scope: this runbook covers rotations of `ALLOWED_SELF_SIGNED_OS_KEYS`. That constant holds the SHA-256 digests of GrapheneOS operating-system signing public keys we accept when an Android Hardware Key Attestation chain reports `verifiedBootState = SELF_SIGNED (1)`. Adding a new Pixel model to the allowlist, removing a deprecated device, or reacting to an upstream key rotation all follow the same flow below.

## Trigger

You will end up here for one of the following reasons.

1. The scheduled drift monitor at `.github/workflows/graphene-allowlist-drift.yml` opened a GitHub Issue labelled `security`, `attestation`, `drift`. The issue body carries a symmetric diff between the upstream JSON and the committed allowlist, plus the TLS fingerprint captured at fetch time. Start from the diff.
2. A user or tester on a real Pixel running GrapheneOS reports registration failing with `KeyAttestation: verifiedBootState is SELF_SIGNED and verifiedBootKey <hex> is not in ALLOWED_SELF_SIGNED_OS_KEYS`. Take the `<hex>` and cross-reference it against the steps below before adding. Never add a key you cannot independently attribute to GrapheneOS.
3. A GrapheneOS release announcement (mastodon, release notes) mentions a key rotation or a newly-supported Pixel SKU.
4. A security advisory calls a specific GrapheneOS key into question.

## Upstream sources

Two upstream sources, both authoritative. They must agree before you commit a change.

| Source | URL | Format |
| --- | --- | --- |
| Signed JSON | <https://grapheneos.org/attestation.json> | `{"verifiedBootKeys": [...], "timestamp": <unix>}` |
| HTML compatibility guide | <https://grapheneos.org/articles/attestation-compatibility-guide> | Human-readable, device-annotated |

If the JSON and the HTML disagree, stop. Do not pick a side silently. Open an issue referencing both URLs with the specific divergence and wait for GrapheneOS to reconcile or for a Tim decision. Record the finding in the issue body and link to it from the PR.

## Procedure

### Step 1. Capture the TLS leaf fingerprint

Do this first, before fetching anything else. The value goes into the PR description as evidence that the fetch was not intercepted. If the value differs across runs within a short window, note both and continue; rotation of GrapheneOS's short-lived TLS cert is routine, but abrupt changes in issuer should be flagged.

```sh
echo | openssl s_client -connect grapheneos.org:443 -servername grapheneos.org 2>/dev/null \
 | openssl x509 -noout -fingerprint -sha256
```

Expected output (example shape, value will differ per cert rotation):

```
sha256 Fingerprint=89:25:AB:24:2A:6C:B8:D0:51:49:1D:72:32:52:F0:87:FA:68:2F:86:27:47:B6:FF:05:F6:BE:35:38:DA:EF:38
```

Paste the full line into the PR description under a heading called `TLS fingerprint (fetch-time)`.

### Step 2. Pull the signed JSON and the HTML guide

```sh
curl -fsSL -o /tmp/attestation.json https://grapheneos.org/attestation.json
curl -fsSL -o /tmp/compat.html https://grapheneos.org/articles/attestation-compatibility-guide

jq -r '.verifiedBootKeys[]' /tmp/attestation.json | sort -u > /tmp/upstream-keys.txt
jq -r '.timestamp' /tmp/attestation.json
```

Record the `timestamp` field in the PR description. It is the Unix epoch when GrapheneOS last updated the JSON.

### Step 3. Cross-check JSON against HTML

Pull every 64-hex token out of the HTML and diff against the JSON set:

```sh
grep -oE '[0-9a-f]{64}' /tmp/compat.html | sort -u > /tmp/html-keys.txt
diff /tmp/upstream-keys.txt /tmp/html-keys.txt
```

Two outcomes.

Identical: proceed to step 4.

Divergent: stop. Document the disagreement in the PR description under a heading `Source disagreement` with both lists and the raw URLs. Do not choose a side. Ping Tim (code ownership) and (security review) on the PR and wait for direction. The drift monitor does not cross-check HTML, only JSON, so a JSON/HTML split will slip past CI. Your runbook pass is the only backstop.

### Step 4. Amend the allowlist

Edit `demo-web-provii-agegate/src/docs/attestation/key-attestation.ts`:

- Add new entries in the `ALLOWED_SELF_SIGNED_OS_KEYS` array with a trailing comment naming the device (match the existing style: `// GrapheneOS: Pixel <n>`).
- Keep ordering newest-device-first to match what already exists. Reviewers scan for order breaks when eyeballing the array.
- Remove deprecated entries only when the upstream JSON has also removed them and the HTML guide confirms (you already verified in step 3).
- The file has a module-load sanity check that rejects anything not 64 lowercase-hex chars and rejects duplicates. Run the TypeScript build locally to catch a typo before the PR opens:

```sh
cd demo-web-provii-agegate && npm run build
```

The check lives inside an IIFE at lines 188-208 of `key-attestation.ts` (as of commit 3d54d4a); errors there surface at module load time, which in a Cloudflare Worker means request zero fails loudly.

### Step 5. Update the on-disk cross-check timestamp

The header comment for `ALLOWED_SELF_SIGNED_OS_KEYS` carries a "cross-checked YYYY-MM-DD" line. Update it to today's date when you commit a change that verifies either source. That line is the sole provenance marker in the source tree, so keep it honest.

### Step 6. Open the PR

PR description template:

```
## Summary
Rotation of ALLOWED_SELF_SIGNED_OS_KEYS.

## Upstream evidence
- JSON URL: https://grapheneos.org/attestation.json
- JSON timestamp field: <unix epoch from step 2>
- HTML URL: https://grapheneos.org/articles/attestation-compatibility-guide
- HTML/JSON agreement: yes | see Source disagreement section

## TLS fingerprint (fetch-time)
sha256 Fingerprint=<paste output from step 1>

## Diff
- Added: <device names and digest prefixes>
- Removed: <device names and digest prefixes>
- Unchanged: <count>
- Ordering: newest-first preserved

## Drift-monitor issue
Closes #<issue-number> (if rotation is in response to a drift alert)
```

### Step 7. Merge and re-run the drift monitor

Once merged to `main`, trigger `.github/workflows/graphene-allowlist-drift.yml` manually via `workflow_dispatch` to confirm the diff is empty. A clean run exits 0 and posts no issue; a drift-persist run will update the existing issue with a comment.

## Drift-monitor workflow reference

| Attribute | Value |
| --- | --- |
| Path | `.github/workflows/graphene-allowlist-drift.yml` |
| Schedule | Weekly, Mondays 03:00 UTC |
| Manual trigger | `workflow_dispatch` (Actions tab, Run workflow) |
| Issue title format | `GrapheneOS allowlist drift detected (YYYY-Www)` |
| Labels | `security`, `attestation`, `drift` |
| Assignee (best effort) | `sarah-chen` |
| Artefacts retained 90d | `upstream.json`, `upstream-keys.txt`, `local-keys.txt`, `only-upstream.txt`, `only-local.txt`, `issue-body.md` |

Log shape on a clean run:

```
TLS leaf fingerprint: <sha256 hex pairs>
upstream timestamp: <unix> (<iso>)
upstream count: 21
local count: 21
keys only in upstream: 0
keys only in local: 0
No drift. Upstream and local allowlist agree on 21 keys.
```

Log shape on a drifted run:

```
TLS leaf fingerprint: <sha256 hex pairs>
upstream timestamp: <unix> (<iso>)
upstream count: 22
local count: 21
keys only in upstream: 1
keys only in local: 0
<rendered markdown issue body>
::notice::opened issue #<n>
::error::drift detected (opened issue #<n>)
```

## What this runbook deliberately does not cover

- Rotation of the pinned Google Hardware Attestation root. That lives in `GOOGLE_HARDWARE_ATTESTATION_ROOT_DER_BASE64` in the same file and follows a separate playbook owned by Tim (see the rotation note at the bottom of `key-attestation.ts`).
- Addition of CalyxOS or any other non-GrapheneOS derivative. The source file explicitly does not include those. Adding support requires a verifiable public source for that vendor's keys and a Tim decision, not a runbook pass.
- Rotation inside the Cloudflare Worker env vars. `ALLOWED_SELF_SIGNED_OS_KEYS` is source-controlled policy, not runtime config. There is no env override.
