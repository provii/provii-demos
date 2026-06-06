# React Native Integration Guide

This guide shows exactly what code to copy into your existing React Native app to add Provii credential issuance.

## Quick Start (2 minutes)

### Option 1: Use the Hook (Recommended)

Copy `src/provii/useProviiIssuer.ts` into your app and use it:

```typescript
import { useProviiIssuer } from './provii/useProviiIssuer';

function IssueCredentialButton({ customerDob }: { customerDob: string }) {
 const { issueCredential, isLoading, error } = useProviiIssuer;

 const handlePress = async => {
 const success = await issueCredential(customerDob);
 if (success) {
 // Provii Wallet opened - credential issuance in progress
 }
 };

 return (
 <TouchableOpacity onPress={handlePress} disabled={isLoading}>
 <Text>{isLoading ? 'Issuing...' : 'Issue Credential'}</Text>
 </TouchableOpacity>
 );
}
```

### Option 2: Direct API Call

If you prefer not to use the hook, here's the minimal code:

```typescript
import { Linking } from 'react-native';

async function issueProviiCredential(dob: string): Promise<void> {
 // 1. Call your issuer backend
 const response = await fetch('https://your-backend.com/api/create-attestation-from-dob', {
 method: 'POST',
 headers: { 'Content-Type': 'application/json' },
 body: JSON.stringify({ dob }), // Format: YYYY-MM-DD
 });

 const { deep_link } = await response.json;

 // 2. Open Provii Wallet
 await Linking.openURL(deep_link);
}
```

## Files to Copy

| File | Purpose | Required? |
|------|---------|-----------|
| `src/provii/useProviiIssuer.ts` | Complete hook with loading/error states | Recommended |
| `src/api/issuerApi.ts` | Simpler API function | Alternative |
| `src/types.ts` | TypeScript interfaces | If using TypeScript |

## What You Need to Change

1. **Backend URL**: Update `ISSUER_BACKEND_URL` in the hook or config
2. **Error handling**: Customize the Alert messages for your app's UX
3. **Loading states**: Integrate with your app's loading indicators
4. **Platform config**: On iOS, add `provii` to `LSApplicationQueriesSchemes` in `Info.plist`

## Flow Diagram

```
Your App Your Backend Provii
 │ │ │
 │ POST /create-attestation │ │
 │ { dob: "1990-05-15" } │ │
 │ ─────────────────────────► │ │
 │ │ HMAC auth → provii-issuer │
 │ ◄───────────────────────── │ │
 │ { deep_link: "https://provii.app/attest?d=..." } │
 │ │ │
 │ Linking.openURL(deep_link) │ │
 │ ──────────────────────────────────────────────────────►
 │ │ │
 │ │ Wallet verifies & │
 │ │ stores credential │
```

## Backend Setup

You need an issuer backend that:
1. Has your HMAC-SHA256 credentials (client_id and hmac_secret)
2. Is registered with Provii
3. Exposes the `/api/create-attestation-from-dob` endpoint
4. Uses HTTPS for all API communication

See `backends/issuer/nodejs/` for a reference implementation.

## Testing

1. Install Provii Wallet from App Store / Play Store
2. Enable Sandbox Mode: Settings → tap 5 times → toggle Sandbox Mode
3. Run your app and issue a test credential
4. Confirm the credential appears in the wallet's credential list

## Common Issues

### "Provii Wallet Not Found"
The deep link couldn't open. Ensure Provii Wallet is installed.

### "Failed to create attestation"
Backend error. Check:
- Backend is running and reachable
- Backend URL is correct (use `10.0.2.2` for Android emulator)
- Your HMAC credentials are configured
- Sandbox credentials have not expired (72-hour TTL)

### Credential not appearing in wallet
- Ensure Sandbox Mode is enabled for testing
- Check wallet logs for verification errors
