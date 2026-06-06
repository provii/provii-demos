# Provii Issuer Demo (Flutter)

A demo bank application that demonstrates issuing Provii age credentials via the Provii Wallet.

## Overview

This app simulates a bank's mobile application that can issue age verification credentials. The credentials are issued through the Provii Wallet app via deep links.

## Features

- Sandbox mode setup instructions
- Age button grid for quick demo credential issuance (13, 16, 18, 21, 40, 60, 80)
- Deep link integration with Provii Wallet
- Material 3 design

## Prerequisites

1. **Flutter SDK** (version 3.2.0 or higher)
 - Install from: https://flutter.dev/docs/get-started/install

2. **Provii Wallet** installed on your device
 - Must be in sandbox mode to accept demo credentials

## Configuration

### Backend URL

Edit `lib/config.dart` to configure the issuer backend URL. The default points to the Provii sandbox issuer at `https://issuer-demo.provii.app`. No local backend is needed for sandbox testing.

For local development:
- iOS Simulator: `http://localhost:3000`
- Android Emulator: `http://10.0.2.2:3000`
- Physical device: Use your machine's local network IP
- Remote sandbox (default): `https://issuer-demo.provii.app`

## Running the App

1. Install dependencies:
 ```bash
 flutter pub get
 ```

2. Run the Flutter app:
 ```bash
 flutter run
 ```

## Flow

1. App displays sandbox mode instructions on first launch
2. User confirms sandbox mode is enabled in Provii Wallet
3. User taps one of 7 age buttons (13, 16, 18, 21, 40, 60, 80)
4. App calculates a date of birth and calls the issuer backend
5. App opens Provii Wallet via deep link with the credential
6. User accepts the credential in Provii Wallet

## Project Structure

```
lib/
 main.dart # App entry point and routing
 config.dart # Backend URL configuration
 api/
 issuer_api.dart # Issuer backend API client
 demo_token.dart # Demo authentication token
 models/
 customer.dart # Age and DOB helpers
 provii/
 provii_issuer.dart # Reusable integration helper
 screens/
 sandbox_instructions_screen.dart # Sandbox setup instructions
 age_selection_screen.dart # Age button grid
```

## Troubleshooting

### Cannot launch Provii Wallet
- Ensure Provii Wallet is installed on your device
- Verify the app is registered for the `https://provii.app/` URL scheme

### Connection refused
- Verify the issuer backend is running (if using a local backend)
- Check the backend URL in `lib/config.dart`
- For Android emulator, use `10.0.2.2` instead of `localhost`
- Confirm the backend's `.env` has valid sandbox credentials

### Credential not accepted
- Ensure Provii Wallet is in sandbox mode
