# Flutter Integration Guide

This guide shows exactly what code to copy into your existing Flutter app to add Provii credential issuance.

## Quick Start (2 minutes)

### Option 1: Use ProviiIssuer Class (Recommended)

Copy `lib/provii/provii_issuer.dart` into your app:

```dart
import 'package:your_app/provii/provii_issuer.dart';

class IssueCredentialPage extends StatefulWidget {
 final String customerDob;

 const IssueCredentialPage({required this.customerDob});

 @override
 State<IssueCredentialPage> createState => _IssueCredentialPageState;
}

class _IssueCredentialPageState extends State<IssueCredentialPage> {
 final _issuer = ProviiIssuer(backendUrl: 'https://your-backend.com');
 bool _isLoading = false;

 Future<void> _issueCredential async {
 setState( => _isLoading = true);

 try {
 await _issuer.issueCredential(dob: widget.customerDob);
 // Success - Provii Wallet opened
 } on ProviiException catch (e) {
 ScaffoldMessenger.of(context).showSnackBar(
 SnackBar(content: Text(e.message)),
 );
 } finally {
 setState( => _isLoading = false);
 }
 }

 @override
 Widget build(BuildContext context) {
 return ElevatedButton(
 onPressed: _isLoading ? null : _issueCredential,
 child: _isLoading
 ? const CircularProgressIndicator
 : const Text('Issue Credential'),
 );
 }
}
```

### Option 2: Direct API Call

Minimal code without the helper class:

```dart
import 'dart:convert';
import 'package:http/http.dart' as http;
import 'package:url_launcher/url_launcher.dart';

Future<void> issueProviiCredential(String dob) async {
 // 1. Call your issuer backend
 final response = await http.post(
 Uri.parse('https://your-backend.com/api/create-attestation-from-dob'),
 headers: {'Content-Type': 'application/json'},
 body: jsonEncode({'dob': dob}), // Format: YYYY-MM-DD
 );

 final data = jsonDecode(response.body);
 final deepLink = data['deep_link'] as String;

 // 2. Open Provii Wallet
 await launchUrl(Uri.parse(deepLink), mode: LaunchMode.externalApplication);
}
```

## Files to Copy

| File | Purpose | Required? |
|------|---------|-----------|
| `lib/provii/provii_issuer.dart` | Complete integration with error handling | Recommended |
| `lib/api/issuer_api.dart` | Simpler API-only approach | Alternative |

## Dependencies

Add to your `pubspec.yaml`:

```yaml
dependencies:
 http: ^1.2.0
 url_launcher: ^6.2.3
```

## What You Need to Change

Update the `backendUrl` parameter when creating `ProviiIssuer` to point at your own backend. Customise the `ProviiException` handling to fit your app's UX.

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
 │ launchUrl(deepLink) │ │
 │ ──────────────────────────────────────────────────────►
 │ │ │
 │ │ Wallet verifies & │
 │ │ stores credential │
```

## Riverpod Example

```dart
import 'package:flutter_riverpod/flutter_riverpod.dart';

final proviiIssuerProvider = Provider((ref) {
 return ProviiIssuer(backendUrl: 'https://your-backend.com');
});

final issueCredentialProvider = FutureProvider.family<void, String>((ref, dob) {
 return ref.read(proviiIssuerProvider).issueCredential(dob: dob);
});

class IssueCredentialButton extends ConsumerWidget {
 final String customerDob;

 const IssueCredentialButton({required this.customerDob});

 @override
 Widget build(BuildContext context, WidgetRef ref) {
 return ElevatedButton(
 onPressed: {
 ref.read(issueCredentialProvider(customerDob));
 },
 child: const Text('Issue Credential'),
 );
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

1. Install Provii Wallet from the App Store / Play Store
2. Enable Sandbox Mode: Settings → tap 5 times → toggle Sandbox Mode
3. Run your app and issue a test credential
4. Confirm the credential appears in the wallet's credential list

**Android Emulator Note**: Use `http://10.0.2.2:3000` to reach localhost.

## Common Issues

### "Provii Wallet is not installed"
The `canLaunchUrl` check failed. Ensure:
- Provii Wallet is installed on the device
- iOS: Add `provii` to `LSApplicationQueriesSchemes` in `Info.plist`

### "Failed to create attestation"
Backend error. Check:
- Backend is running and reachable
- Backend URL is correct
- For Android emulator, use `10.0.2.2` instead of `localhost`
- The backend's `.env` has valid sandbox credentials

### Credential not appearing in wallet
- Ensure Sandbox Mode is enabled for testing
- Check wallet logs for verification errors

## iOS Configuration

Add to `ios/Runner/Info.plist`:

```xml
<key>LSApplicationQueriesSchemes</key>
<array>
 <string>provii</string>
</array>
```
