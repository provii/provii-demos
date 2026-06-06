# Android (Kotlin) Integration Guide

This guide shows exactly what code to copy into your existing Android app to add Provii credential issuance.

## Quick Start (2 minutes)

### Option 1: Copy the API Client (Recommended)

Copy `app/src/main/kotlin/app/provii/demo/issuer/api/IssuerApiClient.kt`:

```kotlin
class YourActivity : AppCompatActivity {
 private val issuerClient = IssuerApiClient(
 baseUrl = "https://your-backend.com"
 )

 private fun issueCredential(customerDob: String) {
 lifecycleScope.launch {
 issuerClient.createAttestationFromDob(customerDob)
 .onSuccess { response ->
 // Open Provii Wallet
 val intent = Intent(Intent.ACTION_VIEW, Uri.parse(response.deep_link))
 startActivity(intent)
 }
 .onFailure { error ->
 showError(error.message)
 }
 }
 }
}
```

### Option 2: Minimal Integration

If you don't want the full client:

```kotlin
suspend fun issueProviiCredential(dob: String) {
 // 1. Call your issuer backend
 val client = HttpClient(Android) {
 install(ContentNegotiation) { json }
 }

 val response = client.post("https://your-backend.com/api/create-attestation-from-dob") {
 contentType(ContentType.Application.Json)
 setBody(mapOf("dob" to dob))
 }

 val data = response.body<Map<String, String>>
 val deepLink = data["deep_link"]!!

 // 2. Open Provii Wallet
 val intent = Intent(Intent.ACTION_VIEW, Uri.parse(deepLink))
 startActivity(intent)
}
```

## Files to Copy

| File | Purpose | Required? |
|------|---------|-----------|
| `api/IssuerApiClient.kt` | Complete API client with error handling | Recommended |

## Dependencies

Add to your `build.gradle.kts`:

```kotlin
dependencies {
 // Ktor for HTTP (or use your preferred HTTP client)
 implementation("io.ktor:ktor-client-android:3.4.0")
 implementation("io.ktor:ktor-client-content-negotiation:3.4.0")
 implementation("io.ktor:ktor-serialization-kotlinx-json:3.4.0")
}
```

## What You Need to Change

1. **Backend URL**: Update `BuildConfig.ISSUER_BACKEND_URL` or pass URL to constructor
2. **Error handling**: Customize error messages for your app's UX
3. **Build config**: Add to `build.gradle.kts`:
4. **Network security**: Allow cleartext traffic for local development only, enforce HTTPS in production

```kotlin
android {
 buildFeatures {
 buildConfig = true
 }
 defaultConfig {
 buildConfigField("String", "ISSUER_BACKEND_URL", "\"https://your-backend.com\"")
 }
}
```

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
 │ startActivity(Intent) │ │
 │ ──────────────────────────────────────────────────────►
 │ │ │
 │ │ Wallet verifies & │
 │ │ stores credential │
```

## Jetpack Compose Example

```kotlin
@Composable
fun IssueCredentialScreen(customer: Customer) {
 val context = LocalContext.current
 val scope = rememberCoroutineScope
 var isLoading by remember { mutableStateOf(false) }

 val issuerClient = remember {
 IssuerApiClient(baseUrl = "https://your-backend.com")
 }

 Button(
 onClick = {
 isLoading = true
 scope.launch {
 issuerClient.createAttestationFromDob(customer.dob)
 .onSuccess { response ->
 val intent = Intent(Intent.ACTION_VIEW, Uri.parse(response.deep_link))
 context.startActivity(intent)
 }
 .onFailure { error ->
 Toast.makeText(context, error.message, Toast.LENGTH_SHORT).show
 }
 isLoading = false
 }
 },
 enabled = !isLoading
 ) {
 if (isLoading) {
 CircularProgressIndicator(modifier = Modifier.size(16.dp))
 } else {
 Text("Issue Credential")
 }
 }
}
```

## Backend Setup

You need an issuer backend that:
1. Has your HMAC-SHA256 credentials (client_id and hmac_secret)
2. Is registered with Provii
3. Exposes the `/api/create-attestation-from-dob` endpoint
4. Uses HTTPS for all API communication

See `backends/issuer/nodejs/` for a reference implementation.

## Testing

1. Install Provii Wallet from the Play Store
2. Enable Sandbox Mode: Settings → tap 5 times → toggle Sandbox Mode
3. Run your app and issue a test credential
4. Confirm the credential appears in the wallet's credential list

**Emulator Note**: Use `http://10.0.2.2:3000` to reach localhost from Android Emulator.

## Common Issues

### Deep link not opening wallet
Ensure Provii Wallet is installed. The app shows a Toast error if no app can handle the URL.

### Network error on emulator
Use `10.0.2.2` instead of `localhost` to reach your development machine.

### "Failed to create attestation"
Check:
- Backend is running and reachable
- Backend URL is correct
- Cleartext traffic is allowed (for HTTP during development)
- Your HMAC credentials are configured in the backend's `.env`

### Credential not appearing in wallet
- Ensure Sandbox Mode is enabled for testing
- Check wallet logs for verification errors
