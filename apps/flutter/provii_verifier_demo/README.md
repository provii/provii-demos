# Provii Verifier Demo - Flutter

A demo Flutter app showing how third-party verifiers integrate with Provii Wallet for privacy-preserving age verification.

## Overview

This app demonstrates the complete verifier flow:
1. User selects an age threshold (18+, 21+, etc.)
2. App creates a verification challenge via the backend
3. Provii Wallet opens for the user to prove their age
4. App polls for verification status
5. Once verified, the user is granted access

**Key feature**: The user's actual date of birth is never revealed. The app only learns whether the user meets the age requirement via a zero knowledge proof.

## Requirements

- Flutter 3.16+
- Dart 3.2+
- Provii Wallet installed on test device (with Sandbox Mode enabled)
- A running verifier backend (see `backends/verifier/nodejs` or similar)

## Quick Start

```bash
# Install dependencies
flutter pub get

# Run on connected device
flutter run
```

## Configuration

Edit `lib/config.dart`:

```dart
class Config {
 static const String verifierBackendUrl = 'https://your-backend.com';
 // For local development:
 // Android Emulator: 'http://10.0.2.2:3001'
 // iOS Simulator: 'http://localhost:3001'
}
```

## Project Structure

```
lib/
├── main.dart # App entry & routing
├── config.dart # Configuration
├── models/
│ └── verification_session.dart # Data models
├── api/
│ └── verifier_api.dart # Backend API client
├── provii/
│ └── provii_verifier.dart # Main integration class
└── screens/
 ├── sandbox_instructions_screen.dart
 ├── age_threshold_screen.dart
 ├── verification_screen.dart
 └── result_screen.dart
```

## Integration

To add Provii age verification to your own Flutter app:

1. Copy `lib/provii/provii_verifier.dart` and dependencies
2. Add dependencies to `pubspec.yaml`:
 ```yaml
 dependencies:
 http: ^1.2.0
 url_launcher: ^6.2.3
 ```
3. Use in your app:

```dart
import 'provii/provii_verifier.dart';

class MyWidget extends StatefulWidget {
 @override
 State<MyWidget> createState => _MyWidgetState;
}

class _MyWidgetState extends State<MyWidget> {
 final _verifier = ProviiVerifier(backendUrl: 'https://your-backend.com');
 bool _isVerified = false;

 Future<void> _verify async {
 try {
 final session = await _verifier.startVerification(age: 21);

 _verifier.startPolling(
 sessionId: session.sessionId,
 onStatusChange: (_) {},
 onVerified: async {
 final result = await _verifier.redeem(session.sessionId);
 setState( => _isVerified = result.verified);
 },
 onError: (error) => print('Error: $error'),
 );
 } catch (e) {
 print('Failed: $e');
 }
 }

 @override
 void dispose {
 _verifier.dispose;
 super.dispose;
 }

 @override
 Widget build(BuildContext context) {
 if (_isVerified) {
 return Text('Access granted!');
 }
 return ElevatedButton(
 onPressed: _verify,
 child: Text('Verify Age'),
 );
 }
}
```

## Testing

1. Enable Sandbox Mode in Provii Wallet (Settings, tap 5 times, enable)
2. Issue a test credential using the Issuer Demo app
3. Run this Verifier Demo and complete verification
4. Confirm the result screen shows the age threshold was satisfied

## License

MIT
