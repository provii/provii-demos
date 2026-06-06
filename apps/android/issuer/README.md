# Provii Issuer Demo - Android

A demo Android application that simulates a bank or service provider issuing age credentials to customers using Provii's zero knowledge proof infrastructure.

## What This App Does

This app demonstrates the **issuer flow** for Provii credentials:

1. A bank/service provider has verified customer information (name, date of birth, KYC status)
2. The customer requests an age credential from the bank
3. The bank's app calls the issuer backend with the customer's DOB
4. The backend generates a signed attestation deep link
5. The app opens Provii Wallet via the deep link
6. Provii Wallet receives and stores the credential

The credential can then be used to prove age (e.g., "over 18", "over 21") at various relying parties without revealing the actual date of birth.

## Prerequisites

- **Android Studio** Arctic Fox (2020.3.1) or later
- **Android SDK** 26+ (Android 8.0 Oreo)
- **Provii Wallet** app installed on the device/emulator
- **Provii Wallet in Sandbox Mode** (required for demo)
- **Issuer Backend** running locally or accessible

### Enabling Sandbox Mode in Provii Wallet

This demo uses Provii's sandbox environment. You must enable sandbox mode in Provii Wallet:

1. Open Provii Wallet
2. Go to Settings
3. Tap the screen 5 times
4. Enable Sandbox Mode
5. The app will restart

## Configuration

### Backend URL

By default, the app connects to `http://10.0.2.2:3000`, which maps to `localhost:3000` from the Android emulator.

#### For Emulator Testing (Default)

No configuration needed. Just run the issuer backend on `localhost:3000`:

```bash
cd demo-issuer-backend
npm install
npm run dev
```

#### For Physical Device Testing

You need to change the backend URL to your computer's IP address. Edit `app/build.gradle.kts`:

```kotlin
buildConfigField("String", "ISSUER_BACKEND_URL", "\"http://YOUR_COMPUTER_IP:3000\"")
```

Make sure your phone and computer are on the same network.

#### For Production

Update the URL to point to your production issuer backend:

```kotlin
buildConfigField("String", "ISSUER_BACKEND_URL", "\"https://your-issuer-backend.example.com\"")
```

## Build and Run

### Using Android Studio

1. Open Android Studio
2. Select "Open an Existing Project"
3. Navigate to `apps/android/issuer/` and open it
4. Wait for Gradle sync to complete
5. Connect a device or start an emulator
6. Click "Run" (green play button) or press Shift+F10

### Using Command Line

```bash
# Navigate to the project
cd apps/android/issuer

# Build debug APK
./gradlew assembleDebug

# Install on connected device
./gradlew installDebug

# Or build and install in one step
./gradlew installDebug
```

The debug APK will be at: `app/build/outputs/apk/debug/app-debug.apk`

## Demo Customers

The app includes three demo customers for testing:

| Name | DOB | KYC Status | Notes |
|------|-----|------------|-------|
| Alice Johnson | 1990-05-15 | Verified | Age 34+ |
| Bob Smith | 2005-08-22 | Verified | Age 19+ (may be under 21) |
| Charlie Brown | 1985-12-01 | Not Verified | Cannot issue credentials |

## API Endpoint

The app uses the `/api/create-attestation-from-dob` endpoint:

**Request:**
```json
POST /api/create-attestation-from-dob
Content-Type: application/json

{
 "dob": "1990-05-15"
}
```

**Response:**
```json
{
 "deep_link": "https://provii.app/attest?d=...",
 "expires_at": 1704067200
}
```

## Project Structure

```
apps/android/issuer/
├── app/
│ ├── build.gradle.kts # App build configuration
│ ├── proguard-rules.pro # ProGuard rules
│ └── src/main/
│ ├── AndroidManifest.xml
│ ├── kotlin/app/provii/demo/issuer/
│ │ ├── MainActivity.kt # Main activity with navigation
│ │ ├── ProviiIssuerDemoApp.kt # Application class
│ │ ├── api/
│ │ │ └── IssuerApiClient.kt # Backend API client
│ │ └── ui/
│ │ ├── MainViewModel.kt # UI state management
│ │ ├── SandboxInstructionsScreen.kt # First-launch instructions
│ │ └── theme/
│ │ └── Theme.kt # Material 3 theme
│ └── res/
│ ├── drawable/ # Icons and graphics
│ ├── mipmap-*/ # App launcher icons
│ ├── values/ # Colors, strings, themes
│ └── xml/ # Backup rules
├── build.gradle.kts # Root build file
├── settings.gradle.kts # Project settings
├── gradle.properties # Gradle configuration
└── gradle/
 └── libs.versions.toml # Dependency versions catalog
```

## Troubleshooting

### "Provii Wallet not installed"

Make sure Provii Wallet is installed on the device/emulator. The demo requires the wallet to receive credentials.

### Backend connection errors

On the emulator, ensure the backend is running on `localhost:3000`. On a physical device, update `ISSUER_BACKEND_URL` in build.gradle.kts to your computer's IP address. In both cases, confirm that `android:usesCleartextTraffic="true"` is set in AndroidManifest.xml for HTTP connections.

### Credentials not recognized by wallet

Make sure Provii Wallet is in **Sandbox Mode**. Production wallets will not accept sandbox credentials.

## License

This demo is part of the Provii project and is provided for demonstration purposes.
