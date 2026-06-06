# Provii Verifier Integration Guide - Android Kotlin

This guide explains how to integrate Provii age verification into your Android app using Kotlin.

## Quick Start (10 minutes)

### 1. Add dependencies

```kotlin
// build.gradle.kts (app level)
dependencies {
 // Networking
 implementation("com.squareup.retrofit2:retrofit:2.9.0")
 implementation("com.squareup.retrofit2:converter-moshi:2.9.0")
 implementation("com.squareup.okhttp3:okhttp:4.12.0")
 implementation("com.squareup.okhttp3:logging-interceptor:4.12.0")
 implementation("com.squareup.moshi:moshi:1.15.0")
 implementation("com.squareup.moshi:moshi-kotlin:1.15.0")

 // Coroutines
 implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.7.3")

 // Lifecycle (for ViewModel)
 implementation("androidx.lifecycle:lifecycle-viewmodel-ktx:2.7.0")
 implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.7.0")
}
```

### 2. Update AndroidManifest.xml

```xml
<!-- Internet permission -->
<uses-permission android:name="android.permission.INTERNET" />

<!-- Query for Provii Wallet -->
<queries>
 <package android:name="com.provii.app" />
 <intent>
 <action android:name="android.intent.action.VIEW" />
 <data android:scheme="provii" />
 </intent>
</queries>
```

### 3. Copy integration files

Copy these files to your project:
- `provii/ProviiVerifier.kt`
- `api/VerifierApiClient.kt`
- `data/Models.kt`
- `Config.kt`

### 4. Use ProviiVerifier

```kotlin
import com.provii.verifierdemo.provii.ProviiVerifier

class AgeGatedActivity : AppCompatActivity {
 private lateinit var verifier: ProviiVerifier
 private var isVerified = false

 override fun onCreate(savedInstanceState: Bundle?) {
 super.onCreate(savedInstanceState)
 verifier = ProviiVerifier(this)
 }

 private fun verifyAge {
 lifecycleScope.launch {
 try {
 val result = verifier.startVerification(age = 21, mode = VerificationMode.OVER_AGE)

 result.onSuccess { session ->
 verifier.startPolling(
 sessionId = session.sessionId,
 onStatusChange = { status ->
 // Update UI with status if needed
 },
 onVerified = {
 handleVerified(session.sessionId)
 },
 onError = { error ->
 showError(error)
 }
 )
 }.onFailure { error ->
 showError(error.message ?: "Failed to start verification")
 }
 } catch (e: Exception) {
 showError(e.message ?: "An error occurred")
 }
 }
 }

 private fun handleVerified(sessionId: String) {
 lifecycleScope.launch {
 val result = verifier.redeem(sessionId)
 result.onSuccess { response ->
 isVerified = response.verified
 if (isVerified) {
 showProtectedContent
 } else {
 showError("Verification incomplete")
 }
 }.onFailure { error ->
 showError(error.message ?: "Failed to redeem")
 }
 }
 }

 override fun onDestroy {
 super.onDestroy
 verifier.dispose
 }
}
```

## API Reference

### ProviiVerifier

```kotlin
class ProviiVerifier(
 context: Context,
 backendUrl: String = BuildConfig.VERIFIER_BACKEND_URL
) {
 /**
 * Start verification and open Provii Wallet.
 * @param age The age threshold to verify
 * @param mode Whether to verify over-age or under-age
 * @param expiresIn Challenge expiration time in seconds (default: 300)
 * @return Result containing VerificationSession on success
 */
 suspend fun startVerification(
 age: Int = 18,
 mode: VerificationMode = VerificationMode.OVER_AGE,
 expiresIn: Int = 300
 ): Result<VerificationSession>

 /**
 * Start polling for verification status.
 * @param sessionId The session ID to poll
 * @param onStatusChange Called when status changes
 * @param onVerified Called when verification is complete
 * @param onError Called on error or timeout
 */
 fun startPolling(
 sessionId: String,
 onStatusChange: (StatusResponse) -> Unit,
 onVerified: -> Unit,
 onError: (String) -> Unit
 )

 /**
 * Stop polling.
 */
 fun stopPolling

 /**
 * Redeem a verified challenge.
 * @param sessionId The session ID to redeem
 * @return Result containing RedeemResponse
 */
 suspend fun redeem(sessionId: String): Result<RedeemResponse>

 /**
 * Reset state.
 */
 fun reset

 /**
 * Clean up resources.
 */
 fun dispose

 companion object {
 /**
 * Check if Provii Wallet is installed.
 */
 fun isProviiInstalled(context: Context): Boolean
 }
}
```

### Data Models

```kotlin
data class VerificationSession(
 val sessionId: String,
 val deepLink: String,
 val expiresAt: Long, // Unix timestamp
 val ageThreshold: Int,
 val mode: VerificationMode,
 val createdAt: Long
) {
 fun timeRemainingSeconds: Int
 fun isExpired: Boolean
}

data class StatusResponse(
 val state: String, // "pending", "verified", "expired", "failed"
 val verified: Boolean,
 val proofVerified: Boolean?
)

data class RedeemResponse(
 val result: String,
 val verified: Boolean
)

enum class VerificationState {
 INITIAL,
 CREATING,
 CHALLENGE_CREATED,
 POLLING,
 VERIFIED,
 REDEEMING,
 REDEEMED,
 EXPIRED,
 FAILED
}
```

## Backend Requirements

Your backend must implement these endpoints:

### POST /api/create-challenge
```json
// Request
{ "minimum_age": 21, "expires_in": 300 }

// Response
{
 "session_id": "abc123",
 "deep_link": "https://provii.app/verify?d=...",
 "expires_at": 1735600000,
 "status_url": "/api/status/abc123"
}
```

### GET /api/status/:sessionId
```json
{ "state": "pending", "verified": false }
```

### POST /api/redeem/:sessionId
```json
{ "result": "verified", "verified": true }
```

## Network Security

For development, add a network security config:

`res/xml/network_security_config.xml`:
```xml
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
 <domain-config cleartextTrafficPermitted="true">
 <domain includeSubdomains="true">10.0.2.2</domain>
 <domain includeSubdomains="true">localhost</domain>
 </domain-config>
</network-security-config>
```

Reference in `AndroidManifest.xml`:
```xml
<application
 android:networkSecurityConfig="@xml/network_security_config"
 ...>
```

## Jetpack Compose Example

```kotlin
@Composable
fun AgeVerificationFlow(
 onVerified: -> Unit
) {
 val context = LocalContext.current
 val verifier = remember { ProviiVerifier(context) }
 var state by remember { mutableStateOf<VerificationState>(VerificationState.INITIAL) }
 var error by remember { mutableStateOf<String?>(null) }
 val scope = rememberCoroutineScope

 DisposableEffect(Unit) {
 onDispose { verifier.dispose }
 }

 Column(
 modifier = Modifier.fillMaxSize,
 horizontalAlignment = Alignment.CenterHorizontally,
 verticalArrangement = Arrangement.Center
 ) {
 when (state) {
 VerificationState.INITIAL,
 VerificationState.FAILED -> {
 if (error != null) {
 Text(error!!, color = MaterialTheme.colorScheme.error)
 Spacer(modifier = Modifier.height(16.dp))
 }

 Button(onClick = {
 scope.launch {
 state = VerificationState.CREATING
 error = null

 val result = verifier.startVerification(age = 21, mode = VerificationMode.OVER_AGE)
 result.onSuccess { session ->
 state = VerificationState.POLLING
 verifier.startPolling(
 sessionId = session.sessionId,
 onStatusChange = { },
 onVerified = {
 scope.launch {
 state = VerificationState.REDEEMING
 val redeemResult = verifier.redeem(session.sessionId)
 redeemResult.onSuccess { response ->
 if (response.verified) {
 onVerified
 } else {
 state = VerificationState.FAILED
 error = "Verification incomplete"
 }
 }.onFailure { e ->
 state = VerificationState.FAILED
 error = e.message
 }
 }
 },
 onError = { e ->
 state = VerificationState.FAILED
 error = e
 }
 )
 }.onFailure { e ->
 state = VerificationState.FAILED
 error = e.message
 }
 }
 }) {
 Text("Verify I'm 21+")
 }
 }

 VerificationState.CREATING,
 VerificationState.POLLING,
 VerificationState.REDEEMING -> {
 CircularProgressIndicator
 Spacer(modifier = Modifier.height(16.dp))
 Text("Verifying...")
 }

 else -> { /* Handle other states */ }
 }
 }
}
```

## ViewModel Example

```kotlin
class AgeVerificationViewModel(application: Application) : AndroidViewModel(application) {
 private val verifier = ProviiVerifier(application)

 private val _uiState = MutableStateFlow(AgeVerificationUiState)
 val uiState: StateFlow<AgeVerificationUiState> = _uiState.asStateFlow

 fun startVerification(age: Int, mode: VerificationMode = VerificationMode.OVER_AGE) {
 viewModelScope.launch {
 _uiState.update { it.copy(isLoading = true, error = null) }

 val result = verifier.startVerification(age, mode)
 result.onSuccess { session ->
 verifier.startPolling(
 sessionId = session.sessionId,
 onStatusChange = { },
 onVerified = { handleVerified(session.sessionId) },
 onError = { error ->
 _uiState.update { it.copy(isLoading = false, error = error) }
 }
 )
 }.onFailure { e ->
 _uiState.update { it.copy(isLoading = false, error = e.message) }
 }
 }
 }

 private fun handleVerified(sessionId: String) {
 viewModelScope.launch {
 val result = verifier.redeem(sessionId)
 result.onSuccess { response ->
 _uiState.update { it.copy(isLoading = false, isVerified = response.verified) }
 }.onFailure { e ->
 _uiState.update { it.copy(isLoading = false, error = e.message) }
 }
 }
 }

 override fun onCleared {
 super.onCleared
 verifier.dispose
 }
}

data class AgeVerificationUiState(
 val isLoading: Boolean = false,
 val isVerified: Boolean = false,
 val error: String? = null
)
```

## Security Considerations

1. **Use HTTPS** for all backend communication in production
2. **Don't persist verification results** in SharedPreferences
3. **Always verify on your backend** - the mobile app is untrusted
4. **Dispose the verifier** when done to stop polling
5. **Handle timeouts gracefully** - challenges expire
6. **Validate session expiry** before attempting operations

## ProGuard Rules

Add to `proguard-rules.pro`:

```proguard
# Keep data classes for Moshi
-keep class com.yourpackage.data.** { *; }

# Moshi
-keepclassmembers class * {
 @com.squareup.moshi.FromJson <methods>;
 @com.squareup.moshi.ToJson <methods>;
}

# Retrofit
-keepattributes Signature
-keepattributes Exceptions
-keepattributes *Annotation*

# OkHttp
-dontwarn okhttp3.**
-dontwarn okio.**
```
