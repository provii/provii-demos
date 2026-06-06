# Provii Verifier Integration Guide - React Native

This guide explains how to integrate Provii age verification into your React Native app.

## Quick Start (5 minutes)

### 1. Copy the integration files

Copy these files to your project:
- `src/provii/useProviiVerifier.ts`
- `src/api/verifierApi.ts`
- `src/types.ts`
- `src/config.ts`

### 2. Configure your backend URL

```typescript
// src/config.ts
export const Config = {
 VERIFIER_BACKEND_URL: 'https://your-backend.com',
 POLLING_INTERVAL_MS: 1500,
 POLLING_TIMEOUT_MS: 600000,
};
```

### 3. Use the hook

```tsx
import { useProviiVerifier } from './provii/useProviiVerifier';

function AgeGatedContent {
 const {
 state,
 startVerification,
 reset,
 error,
 } = useProviiVerifier;

 if (state === 'redeemed') {
 return <YourProtectedContent />;
 }

 return (
 <View>
 {error && <Text style={{color: 'red'}}>{error.message}</Text>}

 <Button
 title="Verify I'm 21+"
 onPress={ => startVerification(21)}
 disabled={state !== 'initial'}
 />

 {state === 'polling' && <ActivityIndicator />}
 </View>
 );
}
```

## Hook API Reference

### `useProviiVerifier`

Returns an object with:

| Property | Type | Description |
|----------|------|-------------|
| `state` | `VerificationState` | Current state of verification flow |
| `session` | `VerificationSession \| null` | Active session data (if any) |
| `isLoading` | `boolean` | Whether an async operation is in progress |
| `error` | `Error \| null` | Last error (if any) |
| `startVerification` | `(age: number) => Promise<boolean>` | Start verification for given age |
| `redeem` | ` => Promise<boolean>` | Manually redeem (usually automatic) |
| `reset` | ` => void` | Reset to initial state |
| `clearError` | ` => void` | Clear current error |

### Verification States

```typescript
type VerificationState =
 | 'initial' // Ready to start
 | 'creating' // Creating challenge
 | 'challenge_created' // Challenge created, opening wallet
 | 'polling' // Waiting for user to verify in wallet
 | 'verified' // User verified, redeeming
 | 'redeeming' // Calling redeem endpoint
 | 'redeemed' // Success! Access can be granted
 | 'expired' // Challenge expired
 | 'failed'; // Verification failed
```

## Backend Requirements

Your backend must implement these endpoints:

### POST /api/create-challenge

Creates a new verification challenge.

**Request:**
```json
{
 "minimum_age": 21,
 "expires_in": 300
}
```

**Response:**
```json
{
 "session_id": "abc123",
 "deep_link": "https://provii.app/verify?d=...",
 "expires_at": 1735600000,
 "status_url": "/api/status/abc123"
}
```

### GET /api/status/:sessionId

Checks verification status.

**Response:**
```json
{
 "state": "pending",
 "verified": false,
 "proof_verified": false
}
```

### POST /api/redeem/:sessionId

Redeems a verified challenge.

**Response:**
```json
{
 "result": "verified",
 "verified": true
}
```

See `backends/verifier/nodejs` for a complete backend implementation.

## iOS Setup

Add to your `Info.plist` to query if Provii Wallet is installed:

```xml
<key>LSApplicationQueriesSchemes</key>
<array>
 <string>provii</string>
</array>
```

## Android Setup

No additional configuration needed. The `Linking` API handles `https://provii.app/` URLs automatically.

## Error Handling

```tsx
function VerifyScreen {
 const { error, clearError, startVerification } = useProviiVerifier;

 const handleVerify = async => {
 const success = await startVerification(21);
 if (!success) {
 // Error is already set in hook state
 Alert.alert('Verification Failed', error?.message);
 }
 };

 return (
 <View>
 {error && (
 <TouchableOpacity onPress={clearError}>
 <Text style={{color: 'red'}}>{error.message}</Text>
 </TouchableOpacity>
 )}
 <Button title="Verify" onPress={handleVerify} />
 </View>
 );
}
```

## Full Example

```tsx
import React from 'react';
import {
 View,
 Text,
 TouchableOpacity,
 ActivityIndicator,
 StyleSheet,
} from 'react-native';
import { useProviiVerifier } from './provii/useProviiVerifier';

export default function AgeVerificationScreen({ onVerified }) {
 const {
 state,
 error,
 startVerification,
 reset,
 } = useProviiVerifier;

 // Handle successful verification
 React.useEffect( => {
 if (state === 'redeemed') {
 onVerified;
 }
 }, [state, onVerified]);

 const isPolling = state === 'polling' || state === 'creating';
 const isFailed = state === 'failed' || state === 'expired';

 return (
 <View style={styles.container}>
 <Text style={styles.title}>Age Verification Required</Text>
 <Text style={styles.subtitle}>
 You must be 21 or older to access this content.
 </Text>

 {error && (
 <View style={styles.errorBox}>
 <Text style={styles.errorText}>{error.message}</Text>
 </View>
 )}

 {isPolling ? (
 <View style={styles.pollingContainer}>
 <ActivityIndicator size="large" />
 <Text style={styles.pollingText}>
 Complete verification in Provii Wallet...
 </Text>
 </View>
 ) : (
 <TouchableOpacity
 style={styles.button}
 onPress={ => isFailed ? reset : startVerification(21)}>
 <Text style={styles.buttonText}>
 {isFailed ? 'Try Again' : 'Verify My Age'}
 </Text>
 </TouchableOpacity>
 )}
 </View>
 );
}

const styles = StyleSheet.create({
 container: { flex: 1, padding: 20, justifyContent: 'center' },
 title: { fontSize: 24, fontWeight: 'bold', marginBottom: 12 },
 subtitle: { fontSize: 16, color: '#666', marginBottom: 24 },
 errorBox: { backgroundColor: '#ffebee', padding: 12, borderRadius: 8, marginBottom: 16 },
 errorText: { color: '#c62828' },
 pollingContainer: { alignItems: 'center' },
 pollingText: { marginTop: 16, color: '#666' },
 button: { backgroundColor: '#1a73e8', padding: 16, borderRadius: 8, alignItems: 'center' },
 buttonText: { color: '#fff', fontSize: 16, fontWeight: '600' },
});
```

## Security Considerations

1. **Never store verification results in AsyncStorage** - they can be modified
2. **Always verify on your backend** - the mobile app is untrusted
3. **Use HTTPS** for all backend communication
4. **The deep link only opens Provii Wallet** - no sensitive data is exposed
5. **Sessions expire** - don't cache verification results indefinitely
