// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Provii

// Provii Issuer Integration
//
// This file encapsulates the complete flow for issuing age credentials
// to the Provii Wallet. Copy this file into your Flutter app.
//
// USAGE:
//   final issuer = ProviiIssuer(backendUrl: 'https://your-backend.com');
//   await issuer.issueCredential(dob: '1990-05-15');
//
// REQUIREMENTS:
//   - Your issuer backend running (see backends/issuer/)
//   - Provii Wallet installed on the device
//   - For testing: Sandbox mode enabled in Provii Wallet

import 'dart:convert';
import 'package:http/http.dart' as http;
import 'package:url_launcher/url_launcher.dart';

// ============================================================================
// COPY FROM HERE
// ============================================================================

/// Error thrown when Provii credential issuance fails.
class ProviiException implements Exception {
  /// Human-readable description of the failure.
  final String message;

  /// Creates a [ProviiException] with the given [message].
  ProviiException(this.message);

  @override
  String toString() => message;
}

/// A simple client for issuing Provii age credentials.
///
/// Copy this class into your Flutter app to add credential issuance.
class ProviiIssuer {
  /// The URL of your issuer backend.
  final String backendUrl;

  /// Initialize the Provii Issuer client.
  ///
  /// [backendUrl] - Your issuer backend URL (e.g., 'https://issuer.yourcompany.com')
  ProviiIssuer({required this.backendUrl});

  /// Issues a credential for the given date of birth.
  ///
  /// This method calls your backend to create a signed attestation, then
  /// opens Provii Wallet via a deep link. The wallet handles cryptographic
  /// verification and stores the credential locally on the device.
  ///
  /// [dob] - Date of birth in YYYY-MM-DD format (e.g., '1990-05-15')
  ///
  /// Throws [ProviiException] if the request fails or wallet cannot be opened.
  ///
  /// Example:
  /// ```dart
  /// final issuer = ProviiIssuer(backendUrl: 'https://your-backend.com');
  /// await issuer.issueCredential(dob: '1990-05-15');
  /// ```
  Future<void> issueCredential({required String dob}) async {
    // Step 1: Call backend to create signed attestation
    final response = await http.post(
      Uri.parse('$backendUrl/api/create-attestation-from-dob'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({'dob': dob}),
    );

    if (response.statusCode != 200) {
      throw ProviiException(
          'Failed to create attestation: ${response.statusCode}');
    }

    final Map<String, dynamic> data;
    try {
      data = jsonDecode(response.body) as Map<String, dynamic>;
    } on FormatException {
      throw ProviiException('Invalid JSON in attestation response');
    } on TypeError {
      throw ProviiException(
          'Unexpected response format from attestation endpoint');
    }
    final deepLink = data['deep_link'] as String?;

    // SECURITY: Validate deep link points to the expected Provii domain.
    if (deepLink == null ||
        !deepLink.startsWith('https://provii.app/attest?')) {
      throw ProviiException('Invalid deep link from backend');
    }

    // Step 2: Open Provii Wallet (HTTPS universal link)
    // If the wallet is installed, the OS opens it directly.
    // If not, the user lands on the fallback page at provii.app.
    final uri = Uri.parse(deepLink);

    final launched = await launchUrl(
      uri,
      mode: LaunchMode.externalApplication,
    );

    if (!launched) {
      throw ProviiException('Failed to open Provii Wallet');
    }
  }
}

// ============================================================================
// END OF INTEGRATION CODE
// ============================================================================
