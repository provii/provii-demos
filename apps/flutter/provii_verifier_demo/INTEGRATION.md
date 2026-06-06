# Provii Verifier Integration Guide - Flutter

This guide explains how to integrate Provii age verification into your Flutter app.

## Quick Start (5 minutes)

### 1. Add dependencies

```yaml
# pubspec.yaml
dependencies:
 http: ^1.2.0
 url_launcher: ^6.2.3
```

### 2. Copy integration files

Copy these files to your project:
- `lib/provii/provii_verifier.dart`
- `lib/api/verifier_api.dart`
- `lib/models/verification_session.dart`
- `lib/config.dart`

### 3. Use ProviiVerifier

```dart
import 'provii/provii_verifier.dart';

class AgeGatedScreen extends StatefulWidget {
 @override
 State<AgeGatedScreen> createState => _AgeGatedScreenState;
}

class _AgeGatedScreenState extends State<AgeGatedScreen> {
 final _verifier = ProviiVerifier(backendUrl: 'https://your-backend.com');
 bool _isLoading = false;
 bool _isVerified = false;
 String? _error;

 Future<void> _verify async {
 setState( {
 _isLoading = true;
 _error = null;
 });

 try {
 final session = await _verifier.startVerification(age: 21);

 _verifier.startPolling(
 sessionId: session.sessionId,
 onStatusChange: (_) {},
 onVerified: async {
 final result = await _verifier.redeem(session.sessionId);
 setState( {
 _isVerified = result.verified;
 _isLoading = false;
 });
 },
 onError: (error) {
 setState( {
 _error = error;
 _isLoading = false;
 });
 },
 );
 } catch (e) {
 setState( {
 _error = e.toString;
 _isLoading = false;
 });
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
 return YourProtectedContent;
 }

 return Column(
 children: [
 if (_error != null)
 Text(_error!, style: TextStyle(color: Colors.red)),

 ElevatedButton(
 onPressed: _isLoading ? null : _verify,
 child: _isLoading
 ? CircularProgressIndicator
 : Text('Verify I\'m 21+'),
 ),
 ],
 );
 }
}
```

## API Reference

### ProviiVerifier

```dart
class ProviiVerifier {
 ProviiVerifier({String? backendUrl});

 /// Start verification and open Provii Wallet
 Future<VerificationSession> startVerification({
 required int age,
 VerificationMode mode = VerificationMode.overAge,
 int expiresIn = 300,
 });

 /// Start polling for verification status
 void startPolling({
 required String sessionId,
 required void Function(StatusResponse) onStatusChange,
 required void Function onVerified,
 required void Function(String error) onError,
 });

 /// Stop polling
 void stopPolling;

 /// Redeem a verified challenge
 Future<RedeemResponse> redeem(String sessionId);

 /// Reset state
 void reset;

 /// Clean up resources
 void dispose;
}
```

### Data Models

```dart
class VerificationSession {
 final String sessionId;
 final String deepLink;
 final DateTime expiresAt;
 final int ageThreshold;
 final VerificationMode mode;
 final DateTime createdAt;
}

class StatusResponse {
 final String state; // 'pending', 'verified', 'expired', 'failed'
 final bool verified;
 final bool? proofVerified;
}

class RedeemResponse {
 final String result;
 final bool verified;
}
```

## Backend Requirements

Your backend must implement:

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

## iOS Setup

Add to `ios/Runner/Info.plist`:

```xml
<key>LSApplicationQueriesSchemes</key>
<array>
 <string>provii</string>
</array>
```

## Android Setup

No additional configuration needed.

## Complete Example

```dart
import 'package:flutter/material.dart';
import 'provii/provii_verifier.dart';
import 'models/verification_session.dart';

class AgeVerificationFlow extends StatefulWidget {
 final VoidCallback onVerified;

 const AgeVerificationFlow({required this.onVerified});

 @override
 State<AgeVerificationFlow> createState => _AgeVerificationFlowState;
}

class _AgeVerificationFlowState extends State<AgeVerificationFlow> {
 final _verifier = ProviiVerifier;
 VerificationState _state = VerificationState.initial;
 String? _error;
 int _timeRemaining = 0;

 Future<void> _startVerification async {
 setState( {
 _state = VerificationState.creating;
 _error = null;
 });

 try {
 final session = await _verifier.startVerification(age: 21);

 setState( => _state = VerificationState.polling);

 // Start countdown
 _startCountdown(session.expiresAt);

 _verifier.startPolling(
 sessionId: session.sessionId,
 onStatusChange: (_) {},
 onVerified: => _handleVerified(session.sessionId),
 onError: (error) => setState( {
 _state = VerificationState.failed;
 _error = error;
 }),
 );
 } catch (e) {
 setState( {
 _state = VerificationState.failed;
 _error = e.toString;
 });
 }
 }

 Future<void> _handleVerified(String sessionId) async {
 setState( => _state = VerificationState.redeeming);

 try {
 final result = await _verifier.redeem(sessionId);
 if (result.verified) {
 widget.onVerified;
 } else {
 setState( {
 _state = VerificationState.failed;
 _error = 'Verification incomplete';
 });
 }
 } catch (e) {
 setState( {
 _state = VerificationState.failed;
 _error = e.toString;
 });
 }
 }

 void _startCountdown(DateTime expiresAt) {
 // Timer implementation...
 }

 @override
 void dispose {
 _verifier.dispose;
 super.dispose;
 }

 @override
 Widget build(BuildContext context) {
 return Scaffold(
 appBar: AppBar(title: Text('Age Verification')),
 body: Center(
 child: Column(
 mainAxisAlignment: MainAxisAlignment.center,
 children: [
 if (_state == VerificationState.initial ||
 _state == VerificationState.failed)
 ElevatedButton(
 onPressed: _startVerification,
 child: Text('Verify I\'m 21+'),
 ),

 if (_state == VerificationState.polling)
 Column(
 children: [
 CircularProgressIndicator,
 SizedBox(height: 16),
 Text('Complete verification in Provii Wallet...'),
 ],
 ),

 if (_error != null)
 Padding(
 padding: EdgeInsets.all(16),
 child: Text(_error!, style: TextStyle(color: Colors.red)),
 ),
 ],
 ),
 ),
 );
 }
}
```

## Security Considerations

1. **Use HTTPS** for all backend communication
2. **Don't persist verification results** in SharedPreferences
3. **Always verify on your backend** - the mobile app is untrusted
4. **Dispose the verifier** when done to stop polling
5. **Handle timeouts gracefully** - challenges expire
