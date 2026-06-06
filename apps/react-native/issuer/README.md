# Provii Issuer Demo (React Native)

A demo bank application that issues age verification credentials to the Provii Wallet.

## What This App Does

This demo app simulates a bank's mobile app that:

1. Presents age buttons for quick demo credential issuance
2. Calls the issuer backend to create a signed attestation
3. Opens the Provii Wallet via deep link to store the credential
4. Shows the result status after the wallet completes issuance

The credential allows the user to prove their age (e.g., 18+ or 21+) without revealing their exact date of birth.

## Prerequisites

- Node.js 20+ and npm
- React Native CLI (`npm install -g @react-native-community/cli`)
- For iOS: Xcode 15+, CocoaPods
- For Android: Android Studio, JDK 17+
- Provii Wallet app installed on the device or simulator (with sandbox mode enabled)

## Configuration

### Backend URL

Edit `src/config.ts` to configure the issuer backend URL:

```typescript
export const Config = {
 ISSUER_BACKEND_URL: 'https://issuer-demo.provii.app',
};
```

The default points to the Provii sandbox issuer. No local backend is needed for sandbox testing.

For local development:

| Environment | URL |
|-------------|-----|
| iOS Simulator | `http://localhost:3000` |
| Android Emulator | `http://10.0.2.2:3000` |
| Physical Device | Use your machine's local IP (e.g., `http://192.168.1.100:3000`) |

## Installation

```bash
# Install dependencies
npm install

# For iOS, install CocoaPods dependencies
cd ios && pod install && cd ..
```

## Running the App

### iOS

```bash
npm run ios
```

Or open `ios/ProviiIssuerDemo.xcworkspace` in Xcode and run from there.

### Android

```bash
npm run android
```

Or open the `android` folder in Android Studio and run from there.

## Using the App

1. **Enable Sandbox Mode**: Open the Provii Wallet, go to Settings, tap the Settings header 5 times to reveal the toggle, then enable Sandbox Mode.

2. **Select an Age**: The app shows 7 age buttons (13, 16, 18, 21, 40, 60, 80). Tap one to issue a credential for that age.

3. **Accept in Wallet**: Provii Wallet opens with the credential for the user to accept.

## Project Structure

```
apps/react-native/issuer/
├── App.tsx # Main app with navigation
├── index.js # Entry point
├── package.json # Dependencies
├── tsconfig.json # TypeScript config
└── src/
 ├── config.ts # Backend URL configuration
 ├── types.ts # TypeScript interfaces
 ├── api/
 │ ├── issuerApi.ts # API client for backend
 │ └── demoToken.ts # Demo authentication token
 ├── provii/
 │ └── useProviiIssuer.ts # Reusable integration hook
 └── screens/
 ├── SandboxInstructionsScreen.tsx # Sandbox setup guide
 └── AgeSelectionScreen.tsx # Age button grid
```

## Troubleshooting

### "Wallet Not Found" Error

Make sure the Provii Wallet app is installed on the device or simulator.

### "Failed to create attestation" Error

1. Check that the issuer backend is running on the configured URL
2. For Android emulator, make sure you are using `10.0.2.2` instead of `localhost`
3. Confirm the backend's `.env` has valid sandbox credentials
4. Check the backend logs for any errors

### Credential Not Appearing in Wallet

1. Make sure sandbox mode is enabled in the Provii Wallet
2. Check that the deep link opened the wallet correctly

## Development

### Type Checking

```bash
npx tsc --noEmit
```

### Starting Metro

```bash
npm start
```

## Licence

See the LICENCE file in the repository root.
