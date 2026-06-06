# iOS (Swift) Integration Guide

This guide shows exactly what code to copy into your existing iOS app to add Provii credential issuance.

## Quick Start (2 minutes)

### Option 1: Use ProviiIssuer Class (Recommended)

Copy `ProviiIssuerDemo/Provii/ProviiIssuer.swift` into your app:

```swift
import UIKit

class YourViewController: UIViewController {
 private let proviiIssuer = ProviiIssuer(backendURL: "https://your-backend.com")

 func issueCredentialTapped {
 Task {
 do {
 try await proviiIssuer.issueCredential(dob: customer.dateOfBirth)
 // Success - Provii Wallet opened
 } catch {
 showError(error.localizedDescription)
 }
 }
 }
}
```

### Option 2: Direct API Call

Minimal code without the helper class:

```swift
func issueProviiCredential(dob: String) async throws {
 // 1. Call your issuer backend
 let url = URL(string: "https://your-backend.com/api/create-attestation-from-dob")!
 var request = URLRequest(url: url)
 request.httpMethod = "POST"
 request.setValue("application/json", forHTTPHeaderField: "Content-Type")
 request.httpBody = try JSONEncoder.encode(["dob": dob])

 let (data, _) = try await URLSession.shared.data(for: request)
 let response = try JSONDecoder.decode([String: String].self, from: data)

 // 2. Open Provii Wallet
 if let deepLink = response["deep_link"],
 let url = URL(string: deepLink) {
 await UIApplication.shared.open(url)
 }
}
```

## Files to Copy

| File | Purpose | Required? |
|------|---------|-----------|
| `ProviiIssuerDemo/Provii/ProviiIssuer.swift` | Complete integration class | Recommended |
| `ProviiIssuerDemo/APIClient.swift` | Alternative with more error handling | Alternative |
| `ProviiIssuerDemo/Models.swift` | Response types (if needed) | Optional |

## What You Need to Change

1. **Backend URL**: Update the `backendURL` parameter when initialising `ProviiIssuer`
2. **Error handling**: Customise error alerts for your app's UX
3. **Info.plist**: Add `provii` to `LSApplicationQueriesSchemes`
4. **App Transport Security**: Ensure your backend URL uses HTTPS in production

```xml
<key>LSApplicationQueriesSchemes</key>
<array>
 <string>provii</string>
</array>
```

4. **App Transport Security**: Ensure your backend URL uses HTTPS in production

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
 │ UIApplication.open(url) │ │
 │ ──────────────────────────────────────────────────────►
 │ │ │
 │ │ Wallet verifies & │
 │ │ stores credential │
```

## SwiftUI Example

```swift
import SwiftUI

struct IssueCredentialView: View {
 let customer: Customer
 @State private var isLoading = false
 @State private var error: Error?

 private let issuer = ProviiIssuer(backendURL: "https://your-backend.com")

 var body: some View {
 Button(action: issueCredential) {
 if isLoading {
 ProgressView
 } else {
 Text("Issue Credential")
 }
 }
 .disabled(isLoading)
 .alert("Error", isPresented: .constant(error != nil)) {
 Button("OK") { error = nil }
 } message: {
 Text(error?.localizedDescription ?? "")
 }
 }

 private func issueCredential {
 isLoading = true
 Task {
 do {
 try await issuer.issueCredential(dob: customer.dob)
 } catch {
 self.error = error
 }
 isLoading = false
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

1. Install Provii Wallet from the App Store
2. Enable Sandbox Mode: Settings → tap 5 times → toggle Sandbox Mode
3. Run your app and issue a test credential
4. Confirm the credential appears in the wallet's credential list

## Common Issues

### "Provii Wallet is not installed"
Add `provii` to `LSApplicationQueriesSchemes` in Info.plist.

### "Network error"
Check:
- Backend is running and reachable
- Backend URL is correct
- App Transport Security allows your backend URL
- The backend's `.env` has valid sandbox credentials

### Credential not appearing in wallet
- Ensure Sandbox Mode is enabled for testing
- Check wallet logs for verification errors
