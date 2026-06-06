# Provii Verifier Demo - Android Kotlin

A demo Android app (Kotlin + Jetpack Compose) showing how third-party verifiers integrate with Provii Wallet for privacy-preserving age verification.

## Overview

This app demonstrates the complete verifier flow:
1. User selects an age threshold (18+, 21+, etc.)
2. App creates a verification challenge via the backend
3. Provii Wallet opens for the user to prove their age
4. App polls for verification status
5. Once verified, the user is granted access

**Key feature**: The user's actual date of birth is never revealed. The app only learns whether the user meets the age requirement via a zero knowledge proof.

## Requirements

- Android Studio Hedgehog (2023.1.1) or newer
- Android SDK 26+ (minimum), 34 (target)
- Kotlin 1.9+
- Provii Wallet installed on test device (with Sandbox Mode enabled)
- A running verifier backend (see `backends/verifier/nodejs` or similar)

## Quick Start

```bash
# Open in Android Studio
# Or build from command line:
./gradlew assembleDebug

# Install on connected device
./gradlew installDebug
```

## Configuration

The verifier backend URL is wired via `buildConfigField` in `app/build.gradle.kts`. Override the default by editing that file or by passing a `-P` property at build time:

```kotlin
// app/build.gradle.kts
defaultConfig {
 buildConfigField("String", "VERIFIER_BACKEND_URL", "\"https://verifier-demo.provii.app\"")
}
```

For local development, swap the URL to one of these:

- Android Emulator: `http://10.0.2.2:3001`
- Physical device on same Wi-Fi: `http://192.168.1.100:3001`
- Custom production deployment: `https://your-verifier-backend.com`
- Remote sandbox backend (default): `https://verifier-demo.provii.app`

Polling cadence and challenge expiry constants still live in `Config.kt`.

## Project Structure

```
app/src/main/kotlin/com/provii/verifierdemo/
├── MainActivity.kt # App entry & navigation
├── MainViewModel.kt # State management
├── Config.kt # Configuration
├── data/
│ └── Models.kt # Data models & enums
├── api/
│ └── VerifierApiClient.kt # Backend API client (Retrofit)
├── provii/
│ └── ProviiVerifier.kt # Main integration class
└── ui/
 ├── theme/
 │ └── Theme.kt # Material 3 theme
 └── screens/
 ├── SandboxInstructionsScreen.kt
 ├── AgeThresholdScreen.kt
 ├── VerificationScreen.kt
 └── ResultScreen.kt
```

## Architecture

| Layer | Technology |
|-------|------------|
| UI | Jetpack Compose with Material 3 |
| Navigation | Navigation Compose |
| State | StateFlow in ViewModel |
| Networking | Retrofit + OkHttp + Moshi |
| Concurrency | Kotlin Coroutines |

## Integration

To add Provii age verification to your own Android app:

1. Copy the `provii/` package and `api/` package
2. Add dependencies to your `build.gradle.kts`:

```kotlin
dependencies {
 // Networking
 implementation("com.squareup.retrofit2:retrofit:2.9.0")
 implementation("com.squareup.retrofit2:converter-moshi:2.9.0")
 implementation("com.squareup.okhttp3:okhttp:4.12.0")
 implementation("com.squareup.moshi:moshi-kotlin:1.15.0")

 // Coroutines
 implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.7.3")
}
```

3. Add to `AndroidManifest.xml`:

```xml
<uses-permission android:name="android.permission.INTERNET" />

<queries>
 <package android:name="com.provii.app" />
 <intent>
 <action android:name="android.intent.action.VIEW" />
 <data android:scheme="provii" />
 </intent>
</queries>
```

4. Use in your app:

```kotlin
class MyActivity : AppCompatActivity {
 private val verifier = ProviiVerifier(this)

 private fun verifyAge {
 lifecycleScope.launch {
 val result = verifier.startVerification(age = 21, mode = VerificationMode.OVER_AGE)

 result.onSuccess { session ->
 verifier.startPolling(
 sessionId = session.sessionId,
 onStatusChange = { status -> /* Update UI */ },
 onVerified = {
 lifecycleScope.launch {
 val redeemResult = verifier.redeem(session.sessionId)
 redeemResult.onSuccess { response ->
 if (response.verified) {
 // Grant access
 }
 }
 }
 },
 onError = { error -> /* Show error */ }
 )
 }
 }
 }

 override fun onDestroy {
 super.onDestroy
 verifier.dispose
 }
}
```

## Testing

1. Enable Sandbox Mode in Provii Wallet (Settings, tap version 5 times, enable)
2. Issue a test credential using the Issuer Demo app
3. Run this Verifier Demo and complete verification
4. Confirm the result screen shows the age threshold was satisfied

## License

MIT
