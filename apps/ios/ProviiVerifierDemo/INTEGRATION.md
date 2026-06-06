# Provii Verifier Integration Guide - iOS Swift

This guide explains how to integrate Provii age verification into your iOS app.

## Quick Start (5 minutes)

### 1. Copy the integration files

Copy these files to your project:
- `Provii/ProviiVerifier.swift`
- `Models.swift` (or just the types you need)
- `APIClient.swift`
- `Config.swift`

### 2. Configure Info.plist

Add URL scheme query:

```xml
<key>LSApplicationQueriesSchemes</key>
<array>
 <string>provii</string>
</array>
```

### 3. Use ProviiVerifier

```swift
import SwiftUI

struct AgeGatedView: View {
 private let verifier = ProviiVerifier(backendURL: "https://your-backend.com")
 @State private var isVerified = false
 @State private var isLoading = false
 @State private var errorMessage: String?

 var body: some View {
 VStack {
 if isVerified {
 Text("Access granted!")
 } else {
 Button(action: verify) {
 if isLoading {
 ProgressView
 } else {
 Text("Verify I'm 21+")
 }
 }
 .disabled(isLoading)

 if let error = errorMessage {
 Text(error)
 .foregroundColor(.red)
 }
 }
 }
 }

 private func verify {
 isLoading = true
 errorMessage = nil

 Task {
 do {
 let session = try await verifier.startVerification(age: 21, mode: .overAge)

 verifier.startPolling(
 sessionId: session.sessionId,
 onStatusChange: { _ in },
 onVerified: { await handleVerified(session.sessionId) },
 onError: { await handleError($0) }
 )
 } catch {
 await handleError(error)
 }
 }
 }

 @MainActor
 private func handleVerified(_ sessionId: String) async {
 do {
 let result = try await verifier.redeem(sessionId: sessionId)
 isVerified = result.verified
 } catch {
 errorMessage = error.localizedDescription
 }
 isLoading = false
 }

 @MainActor
 private func handleError(_ error: Error) {
 errorMessage = error.localizedDescription
 isLoading = false
 }
}
```

## API Reference

### ProviiVerifier

```swift
public class ProviiVerifier {
 public init(backendURL: String)

 @MainActor
 public func startVerification(age: Int, mode: VerificationMode, expiresIn: Int = 300) async throws -> VerificationSession

 public func startPolling(
 sessionId: String,
 onStatusChange: @escaping (StatusResponse) -> Void,
 onVerified: @escaping -> Void,
 onError: @escaping (Error) -> Void
 )

 public func stopPolling

 @MainActor
 public func redeem(sessionId: String) async throws -> RedeemResponse

 public func reset
}
```

### Error Types

```swift
public enum ProviiVerifierError: Error {
 case invalidURL
 case networkError(Error)
 case serverError(Int)
 case invalidResponse
 case invalidDeepLink
 case walletNotInstalled
 case cannotOpenURL
 case verificationFailed(String)
 case verificationExpired
 case pollingTimeout
 case noActiveSession
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
// Response
{ "state": "pending", "verified": false }
```

### POST /api/redeem/:sessionId

```json
// Response
{ "result": "verified", "verified": true }
```

## Complete Example

```swift
import SwiftUI

@main
struct MyApp: App {
 var body: some Scene {
 WindowGroup {
 ContentView
 }
 }
}

struct ContentView: View {
 @State private var isVerified = false

 var body: some View {
 NavigationStack {
 if isVerified {
 ProtectedContentView
 } else {
 AgeVerificationView(onVerified: { isVerified = true })
 }
 }
 }
}

struct AgeVerificationView: View {
 let onVerified: -> Void
 private let verifier = ProviiVerifier

 @State private var state: VerificationState = .initial
 @State private var sessionId: String?

 var body: some View {
 VStack(spacing: 20) {
 Image(systemName: "person.badge.shield.checkmark")
 .font(.system(size: 60))
 .foregroundColor(.blue)

 Text("Age Verification Required")
 .font(.title2)
 .fontWeight(.bold)

 Text("You must be 21 or older to access this content.")
 .foregroundColor(.secondary)
 .multilineTextAlignment(.center)

 switch state {
 case .initial:
 Button("Verify My Age") {
 startVerification
 }
 .buttonStyle(.borderedProminent)

 case .polling:
 ProgressView("Waiting for verification...")

 case .failed(let message):
 Text(message)
 .foregroundColor(.red)

 Button("Try Again") {
 startVerification
 }
 default:
 ProgressView
 }
 }
 .padding
 .navigationTitle("Verify Age")
 }

 private func startVerification {
 state = .creating

 Task {
 do {
 let session = try await verifier.startVerification(age: 21, mode: .overAge)
 sessionId = session.sessionId
 state = .polling

 verifier.startPolling(
 sessionId: session.sessionId,
 onStatusChange: { _ in },
 onVerified: {
 Task { await handleVerified }
 },
 onError: { error in
 Task { await MainActor.run { state = .failed(error.localizedDescription) } }
 }
 )
 } catch {
 state = .failed(error.localizedDescription)
 }
 }
 }

 @MainActor
 private func handleVerified async {
 guard let sessionId = sessionId else { return }

 do {
 let result = try await verifier.redeem(sessionId: sessionId)
 if result.verified {
 onVerified
 } else {
 state = .failed("Verification incomplete")
 }
 } catch {
 state = .failed(error.localizedDescription)
 }
 }
}
```

## Security Considerations

1. **Use HTTPS** for all backend communication
2. **Don't cache verification results** indefinitely
3. **The deep link only opens Provii Wallet** - no sensitive data exposed
4. **Always verify on your backend** - the mobile app is untrusted
5. **Sessions expire** - handle expiration gracefully
