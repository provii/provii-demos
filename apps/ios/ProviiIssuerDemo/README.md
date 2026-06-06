# Provii Issuer Demo (iOS)

A demo iOS app that simulates a bank issuing age credentials to customers via the Provii Wallet.

## What This App Does

This demo app simulates a financial institution that:

1. Has pre-verified customer information (KYC)
2. Can issue age attestation credentials to customers
3. Authenticates to the issuer backend with HMAC-SHA256
4. Integrates with Provii Wallet via deep links

The app demonstrates the issuer flow where:
- The user taps an age button (13, 16, 18, 21, 40, 60, or 80)
- The app calculates a date of birth for that age and calls the issuer backend
- The backend returns a deep link containing a signed attestation
- Provii Wallet opens to store the credential

## Prerequisites

- **Xcode 15.0+**
- **iOS 16.0+** minimum deployment target
- **Provii Wallet** installed on the test device or simulator
- **Provii Wallet in Sandbox Mode** (see below)

## Setting Up Provii Wallet for Sandbox Mode

1. Open Provii Wallet
2. Go to Settings
3. Tap the Settings header 5 times to reveal the Sandbox Mode toggle
4. Enable Sandbox Mode
5. Return to this app

## Building and Running

### Using Xcode

1. Open the project:
 ```bash
 open apps/ios/ProviiIssuerDemo/ProviiIssuerDemo.xcodeproj
 ```

2. Select your target device or simulator

3. Build and run (Cmd+R)

## Configuring the Backend URL

By default, the app connects to the Provii sandbox issuer at `https://issuer-demo.provii.app`. No local backend is needed for sandbox testing.

To use a local backend instead, add this to `Info.plist`:

```xml
<key>BACKEND_URL</key>
<string>http://localhost:3000</string>
```

For device testing with a local backend, use your machine's IP address (e.g., `http://192.168.1.100:3000`) and ensure both device and machine are on the same network.

## Project Structure

| File | Purpose |
|------|---------|
| `AgeSelectionView.swift` | Main screen with age buttons |
| `SandboxInstructionsView.swift` | First-run sandbox setup instructions |
| `ContentView.swift` | Navigation root |
| `APIClient.swift` | HTTP client for the issuer backend |
| `Models.swift` | Request and response types |
| `Config.swift` | Backend URL configuration |
| `DemoTokenManager.swift` | Demo authentication token handling |
| `Provii/ProviiIssuer.swift` | Reusable integration helper |

## App Flow

1. **Sandbox Instructions** - First-time users see instructions for enabling sandbox mode in Provii Wallet
2. **Age Selection** - Tap one of 7 age buttons (13, 16, 18, 21, 40, 60, 80)
3. **Backend Call** - The app sends the calculated date of birth to the issuer backend
4. **Deep Link to Wallet** - The credential is sent to Provii Wallet for storage

## API Integration

The app calls the issuer backend's `/api/create-attestation-from-dob` endpoint:

**Request:**
```json
POST /api/create-attestation-from-dob
{
 "dob": "1990-05-15"
}
```

**Response:**
```json
{
 "deep_link": "https://provii.app/attest?d=...",
 "dob_days": 12919,
 "expires_at": 1740000000
}
```

## Troubleshooting

### "Failed to open Provii Wallet"
- Ensure Provii Wallet is installed on the device
- Check that the wallet is in sandbox mode

### Network errors
- Verify the backend is running (if using a local backend)
- Check the `BACKEND_URL` configuration
- For device testing, ensure the device can reach the backend server
- Confirm the backend's `.env` has valid sandbox credentials

### Build errors
- Clean the build folder (Cmd+Shift+K) and rebuild
- Ensure you're using Xcode 15.0 or later

## Licence

See the LICENCE file in the repository root.
