# Provii Verifier Demo - iOS Swift

A demo iOS app showing how third-party verifiers integrate with Provii Wallet for privacy-preserving age verification.

## Overview

This app demonstrates the complete verifier flow:
1. User selects an age threshold (18+, 21+, etc.)
2. App creates a verification challenge via the backend
3. Provii Wallet opens for the user to prove their age
4. App polls for verification status
5. Once verified, the user is granted access

**Key feature**: The user's actual date of birth is never revealed. The app only learns whether the user meets the age requirement via a zero knowledge proof.

## Requirements

- iOS 16.0+
- Xcode 15.0+
- Provii Wallet installed on test device (with Sandbox Mode enabled)
- A running verifier backend (see `backends/verifier/nodejs` or similar)

## Quick Start

1. Open `ProviiVerifierDemo.xcodeproj` in Xcode
2. Update `Config.swift` with your backend URL
3. Select your target device or simulator
4. Build and run (Cmd+R)

## Configuration

Edit `Config.swift` or set `VERIFIER_BACKEND_URL` in Info.plist:

```swift
enum Config {
 static var verifierBackendURL: String {
 return "https://your-verifier-backend.com"
 }
}
```

## Project Structure

```
ProviiVerifierDemo/
├── ProviiVerifierDemoApp.swift # App entry point
├── ContentView.swift # Root navigation
├── Config.swift # Configuration
├── Models.swift # Data models
├── APIClient.swift # Backend API client
├── Provii/
│ └── ProviiVerifier.swift # Main integration class
├── SandboxInstructionsView.swift
├── AgeThresholdView.swift
├── VerificationView.swift
└── ResultView.swift
```

## Integration

To add Provii age verification to your own iOS app:

1. Copy `Provii/ProviiVerifier.swift` and supporting files
2. Add `provii` to `LSApplicationQueriesSchemes` in Info.plist
3. Configure your backend URL
4. Use the verifier in your flow:

```swift
import SwiftUI

struct MyView: View {
 let verifier = ProviiVerifier(backendURL: "https://your-backend.com")
 @State private var isVerified = false

 var body: some View {
 Button("Verify Age") {
 Task {
 do {
 let session = try await verifier.startVerification(age: 21, mode: .overAge)

 verifier.startPolling(
 sessionId: session.sessionId,
 onStatusChange: { _ in },
 onVerified: {
 Task {
 let result = try await verifier.redeem(sessionId: session.sessionId)
 isVerified = result.verified
 }
 },
 onError: { error in
 print("Error: \(error)")
 }
 )
 } catch {
 print("Failed to start: \(error)")
 }
 }
 }
 }
}
```

## Info.plist Configuration

Add to your Info.plist to query if Provii Wallet is installed:

```xml
<key>LSApplicationQueriesSchemes</key>
<array>
 <string>provii</string>
</array>
```

## Testing

1. Enable Sandbox Mode in Provii Wallet (Settings, tap 5 times, enable)
2. Issue a test credential using the Issuer Demo app
3. Run this Verifier Demo and complete verification
4. Confirm the result screen shows the age threshold was satisfied

## License

MIT
