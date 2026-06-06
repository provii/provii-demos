# Mobile Sandbox Contract 

For the provii-mobile integration. All endpoints live under
`docs.provii.app/api/mobile/sandbox/`.

## Authentication model

`/challenge` and `/register` are unauthenticated (rate-limited by IP).
`/revoke` and `/refresh` require HMAC-SHA-256 authentication with the
secret minted by `/register`.

HMAC-signed requests carry two headers:

 X-Mwallet-Auth: Mwallet-Sandbox client_id=<cid>,ts=<unix_seconds>,nonce=<hex>
 X-Mwallet-Sig: <hex lowercase HMAC-SHA-256 tag>

The canonical message signed is:

 mwallet-sbx/v1\n
 <HTTP method>\n
 <path>\n
 <timestamp_unix_seconds>\n
 <nonce_hex>\n
 <JCS-canonicalised body bytes>

JCS follows RFC 8785. The gateway re-canonicalises the received body
before verifying, so whitespace or key order differences are tolerated.
Timestamp must be within 60 seconds of the gateway's wall clock.

## Error envelope

Every 4xx/5xx response body is:

```json
{
 "error": {
 "code": "<machine_readable>",
 "message": "<human_readable>"
 }
}
```

The `code` field is stable. Do not switch on `message`.


## `GET /api/mobile/sandbox/challenge`

Mint a fresh 32-byte random nonce.

**Query parameters**

| Name | Required | Values | Notes |
|------|----------|--------|-------|
| `platform` | no | `ios`, `android` | Echoed into the stored nonce record. Informational only; the gateway does not enforce platform consistency between challenge and register. |

**Response 200**

```json
{
 "nonce": "<64 hex chars>",
 "expires_at": 1713113100000,
 "ttl_seconds": 300
}
```

Nonces expire after 300 seconds (5 min). Using an expired or
already-consumed nonce on `/register` returns 409.


## `POST /api/mobile/sandbox/register`

Consume the nonce, verify device attestation, mint a sandbox issuer
identity with a 7-day TTL.

**Headers**: `Content-Type: application/json`

**Body (iOS)**

```json
{
 "install_uuid": "550e8400-e29b-41d4-a716-446655440000",
 "platform": "ios",
 "app_version": "1.2.3",
 "attestation_nonce": "<64 hex chars from /challenge>",
 "app_attest_token": "<base64-encoded CBOR App Attest receipt>"
}
```

**Body (Android)**

```json
{
 "install_uuid": "550e8400-e29b-41d4-a716-446655440000",
 "platform": "android",
 "app_version": "1.2.3",
 "attestation_nonce": "<64 hex chars from /challenge>",
 "key_attestation_chain": [
 "<base64 DER leaf>",
 "<base64 DER intermediate>",
 "<base64 DER root>"
 ]
}
```

**Cross-field rules**

- iOS: `app_attest_token` required, `key_attestation_chain` forbidden.
- Android: `key_attestation_chain` required (min 2 certs), `app_attest_token` forbidden.
- `install_uuid` must be a canonical lowercase UUIDv4.
- `attestation_nonce` must be exactly 64 lowercase hex characters.
- `app_version` must be 1-32 characters.

**Response 200**

```json
{
 "client_id": "mwallet-sbx-a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
 "hmac_secret": "<64 hex chars>",
 "expires_at": 1713717600000,
 "refresh_ttl_remaining": 604800,
 "envelope_version": "mwallet-sbx/v1"
}
```

Persist `client_id` and `hmac_secret` in the device keychain. The
`hmac_secret` is the raw signing key for all subsequent HMAC-signed
requests.

`envelope_version` names the canonical envelope shape. If we ever
change the signing format the version string will change; the client
should store this and submit it in a future re-registration header so
the gateway can handle version skew without breaking existing installs.

**Error codes**

| Status | Code | Trigger |
|--------|------|---------|
| 400 | `mobile_malformed_body` | Body is not JSON or is unreadable |
| 400 | `mobile_schema_mismatch` | Body fails schema or cross-field check |
| 400 | `mobile_attestation_rejected` | Attestation verification failed |
| 409 | `mobile_nonce_unknown_or_consumed` | Nonce is expired, unknown, or already used |
| 413 | `mobile_payload_too_large` | Body exceeds 32 KiB |
| 429 | `mobile_rate_limited` | IP ceiling (5 per hour) reached |
| 503 | `mobile_state_unavailable` | Counter store temporarily unreachable |
| 503 | `mobile_sandbox_capacity_reached` | 100k global active-issuer ceiling hit |

**Rate limits**

5 register attempts per hour per `CF-Connecting-IP`. The `Retry-After`
header in the 429 response carries the number of seconds until the
next hourly bucket opens.


## `POST /api/mobile/sandbox/revoke`

Tombstone a sandbox issuer identity.

**Headers**: `Content-Type: application/json`, `X-Mwallet-Auth`, `X-Mwallet-Sig`

**Body**

```json
{
 "client_id": "mwallet-sbx-a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
}
```

**Response 200**

```json
{
 "revoked": true,
 "client_id": "mwallet-sbx-a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
}
```

After revocation the `client_id` is irrecoverable. A fresh
`/challenge` then `/register` cycle must start from scratch.

**Error codes**

| Status | Code | Trigger |
|--------|------|---------|
| 400 | `mobile_malformed_body` | Body is not valid JSON |
| 400 | `mobile_schema_mismatch` | Body fails lifecycle schema |
| 400 | `mobile_client_id_mismatch` | Auth header cid differs from body cid |
| 401 | `mobile_invalid_auth_header` | Missing or malformed `X-Mwallet-Auth` |
| 401 | `mobile_invalid_signature_header` | Missing or malformed `X-Mwallet-Sig` |
| 401 | `mobile_timestamp_skew` | Timestamp outside 60s window |
| 401 | `mobile_signature_mismatch` | HMAC tag does not match |
| 404 | `mobile_client_id_unknown` | client_id not registered or expired |


## `POST /api/mobile/sandbox/refresh`

Extend the sandbox issuer TTL to 7 days from now.

**Headers**: `Content-Type: application/json`, `X-Mwallet-Auth`, `X-Mwallet-Sig`

**Body**

```json
{
 "client_id": "mwallet-sbx-a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
}
```

**Response 200**

```json
{
 "client_id": "mwallet-sbx-a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
 "expires_at": 1713717600000,
 "refresh_ttl_remaining": 604800
}
```

Refreshes do not stack. Each call resets the TTL to a full 7 days
from now.

**Error codes**: same as `/revoke`.


## iOS token format

The `app_attest_token` field is a base64 encoding of the CBOR
attestation object returned by `DCAppAttestService.attestKey`. The
CBOR outer shape is:

```
{
 "fmt": "apple-appattest",
 "attStmt": { "x5c": [<leaf DER>, <intermediate DER>], "receipt": <bytes> },
 "authData": <bytes>
}
```

The gateway verifies the x5c chain against the pinned Apple App
Attest Root CA, then extracts the nonce from the leaf extension at
OID `1.2.840.113635.100.8.2` and compares it to
`SHA-256(authData || SHA-256(challenge))`.

The AAGUID in authData must match:

- Production: `appattest` + 7 NUL bytes
- Development: `appattestdevelop` (16 ASCII bytes)

The rpIdHash in authData must equal `SHA-256(appId)` where appId is
the configured bundle identifier (currently `com.provii.wallet`).


## Android token format

`key_attestation_chain` is a leaf-first array of base64-encoded DER
X.509 certificates from `KeyStore.getCertificateChain(alias)`. The
leaf's extension at OID `1.3.6.1.4.1.11129.2.1.17` carries the
KeyDescription ASN.1 structure.

The gateway verifies:

- Chain terminates at the pinned Google Hardware Attestation root.
- `attestationChallenge` in the KeyDescription matches the issued nonce.
- `attestationSecurityLevel` and `keymasterSecurityLevel` are both TRUSTED_ENVIRONMENT (1) or STRONG_BOX (2). SOFTWARE (0) is rejected.
- `rootOfTrust.verifiedBootState` is VERIFIED (0).
- `rootOfTrust.deviceLocked` is true.
- Optional: `attestationApplicationId` contains the expected package name.

Key generation on the device must include
`setAttestationChallenge(nonceBytes)` where `nonceBytes` is the raw
32-byte decode of the hex nonce from `/challenge`.


## curl examples

**Challenge**

```bash
curl -s https://docs.provii.app/api/mobile/sandbox/challenge
```

**Revoke**

```bash
TS=$(date +%s)
NONCE=$(openssl rand -hex 16)
BODY='{"client_id":"mwallet-sbx-a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"}'
CANONICAL="mwallet-sbx/v1\nPOST\n/api/mobile/sandbox/revoke\n${TS}\n${NONCE}\n${BODY}"
SIG=$(printf '%b' "$CANONICAL" | openssl dgst -sha256 -hmac "$HMAC_SECRET_HEX" -binary | xxd -p -c 64)

curl -X POST https://docs.provii.app/api/mobile/sandbox/revoke \
 -H "Content-Type: application/json" \
 -H "X-Mwallet-Auth: Mwallet-Sandbox client_id=mwallet-sbx-a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6,ts=${TS},nonce=${NONCE}" \
 -H "X-Mwallet-Sig: ${SIG}" \
 -d "$BODY"
```


## Wrangler bindings (not yet provisioned)

These env vars are needed in `wrangler.toml` before the endpoints
produce real attestation verifications:

| Binding | Example value | Purpose |
|---------|--------------|---------|
| `MOBILE_APP_BUNDLE_ID` | `com.provii.wallet` | rpIdHash + package cross-check |
| `MOBILE_APPLE_AAGUID_ENV` | `dev` or `prod` | Selects Apple AAGUID |
| `MOBILE_ANDROID_PINNED_ROOT_DER_B64` | (large base64) | Google root CA |
| `MOBILE_ANDROID_PACKAGE_NAME` | `com.provii.wallet` | Optional attestationApplicationId |

Until `MOBILE_ANDROID_PINNED_ROOT_DER_B64` is populated, the verifier
falls back to the module-level constant
`GOOGLE_HARDWARE_ATTESTATION_ROOT_DER_BASE64`, which is intentionally
empty until Tim pastes the DER.
