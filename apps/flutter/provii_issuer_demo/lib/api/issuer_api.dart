// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Provii

// Provii Issuer API Client
//
// ============================================================================
// INTEGRATION GUIDE
// ============================================================================
//
// To add Provii credential issuance to your Flutter app:
//
// 1. Copy this file (or use provii/provii_issuer.dart for a complete solution)
// 2. Update Config.issuerBackendUrl to point to your backend
// 3. Call createAttestation(dob) with the user's date of birth
// 4. Open the returned deep_link with url_launcher
// 5. The Provii Wallet handles all cryptography and credential storage
//
// ============================================================================

import 'dart:convert';
import 'package:http/http.dart' as http;
import '../config.dart';
import 'demo_token.dart';

// ============================================================================
// COPY THIS CLASS INTO YOUR APP
// ============================================================================

/// API client for creating Provii attestations.
///
/// For a complete integration solution with error handling and URL launching,
/// see provii/provii_issuer.dart instead.
class IssuerApi {
  /// Creates an attestation from date of birth.
  ///
  /// Your backend authenticates with HMAC-SHA256. Provii signs the attestation internally.
  /// The returned deep link opens Provii Wallet to complete credential issuance.
  ///
  /// [dob] - Date of birth in YYYY-MM-DD format (e.g., '1990-05-15')
  ///
  /// Returns a Map containing:
  /// - 'deep_link': The URL to open Provii Wallet (https://provii.app/attest?d=...)
  /// - 'dob_days': Days since Unix epoch used for the attestation
  /// - 'expires_at': Expiration timestamp
  ///
  /// Example:
  /// ```dart
  /// final response = await IssuerApi.createAttestation('1990-05-15');
  /// final deepLink = response['deep_link'] as String;
  /// await launchUrl(Uri.parse(deepLink));
  /// ```
  static Future<Map<String, dynamic>> createAttestation(String dob) async {
    // SECURITY: Demo token authenticates this request to the demo backend.
    final headers = await DemoTokenManager.instance.getHeadersWithToken(
      {'Content-Type': 'application/json'},
    );

    final response = await http.post(
      Uri.parse('${Config.issuerBackendUrl}/api/create-attestation-from-dob'),
      headers: headers,
      body: jsonEncode({'dob': dob}),
    );

    if (response.statusCode != 200) {
      throw Exception('Failed to create attestation: ${response.statusCode}');
    }

    try {
      return jsonDecode(response.body) as Map<String, dynamic>;
    } on FormatException {
      throw Exception('Invalid JSON in attestation response');
    } on TypeError {
      throw Exception('Unexpected response format from attestation endpoint');
    }
  }
}

// ============================================================================
// END OF INTEGRATION CODE
// ============================================================================
