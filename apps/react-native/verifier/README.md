# Provii Verifier Demo - React Native

A demo React Native app showing how third-party verifiers integrate with Provii Wallet for privacy-preserving age verification.

## Overview

This app demonstrates the complete verifier flow:
1. User selects an age threshold (18+, 21+, etc.)
2. App creates a verification challenge via the backend
3. Provii Wallet opens for the user to prove their age
4. App polls for verification status
5. Once verified, the user is granted access

**Key feature**: The user's actual date of birth is never revealed. The app only learns whether the user meets the age requirement via a zero knowledge proof.

## Prerequisites

- Node.js 20+
- React Native development environment ([setup guide](https://reactnative.dev/docs/environment-setup))
- Provii Wallet installed on test device (with Sandbox Mode enabled)
- A running verifier backend (see `backends/verifier/nodejs` or similar)

## Quick Start

```bash
# Install dependencies
npm install

# Start Metro bundler
npm start

# Run on iOS
npm run ios

# Run on Android
npm run android
```

## Configuration

Edit `src/config.ts` to point to your verifier backend:

```typescript
export const Config = {
 VERIFIER_BACKEND_URL: 'https://your-verifier-backend.com',
 // For local development:
 // iOS Simulator: 'http://localhost:3001'
 // Android Emulator: 'http://10.0.2.2:3001'
};
```

## Project Structure

```
├── App.tsx # Navigation setup
├── src/
│ ├── types.ts # TypeScript type definitions
│ ├── config.ts # Configuration
│ ├── api/
│ │ └── verifierApi.ts # Backend API client
│ ├── provii/
│ │ └── useProviiVerifier.ts # Main integration hook
│ └── screens/
│ ├── SandboxInstructionsScreen.tsx
│ ├── AgeThresholdScreen.tsx
│ ├── VerificationScreen.tsx
│ └── ResultScreen.tsx
```

## Integration

To add Provii age verification to your own React Native app:

1. Copy `src/provii/useProviiVerifier.ts` and its dependencies
2. Configure your backend URL
3. On iOS, add `provii` to `LSApplicationQueriesSchemes` in Info.plist
4. Use the hook in your verification flow:

```tsx
import { useProviiVerifier } from './provii/useProviiVerifier';

function MyVerificationScreen {
 const { state, startVerification, reset } = useProviiVerifier;

 const handleVerify = async => {
 const success = await startVerification(21); // Verify 21+
 if (success) {
 // Hook will poll automatically
 }
 };

 // State: 'initial' | 'creating' | 'polling' | 'verified' | 'redeemed' | 'failed'
 if (state === 'redeemed') {
 return <Text>Access granted!</Text>;
 }

 return <Button onPress={handleVerify} title="Verify Age" />;
}
```

## Verifier Flow

```
Your App Your Backend Provii
 | | |
 |-- POST /create-challenge ->| |
 | |-- HMAC auth -------->|
 |<-- session_id, deep_link --|<-- challenge --------|
 | | |
 |-- Open deep link --------->| |
 | | [User proves age in wallet]
 | | |
 |-- Poll /status ----------->|-- Check status ----->|
 |<-- state: verified --------|<-- verified ---------|
 | | |
 |-- POST /redeem ----------->|-- Redeem ----------->|
 |<-- success ----------------|<-- success ----------|
 | | |
 [Grant access]
```

## Security Notes

- The `code_verifier` (PKCE) stays on your backend - never exposed to the client
- Your backend authenticates to Provii with HMAC-SHA256
- Deep links are validated before opening
- Sessions expire after the configured timeout

## Testing

1. Enable Sandbox Mode in Provii Wallet (Settings, tap 5 times, enable)
2. Issue a test credential using the Issuer Demo app
3. Run this Verifier Demo and complete verification
4. Confirm the result screen shows the age threshold was satisfied

## License

MIT
