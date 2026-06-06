// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Provii

// Demo Token Manager for Provii Demo Apps
//
// Fetches and caches the rotating demo token from playground.provii.app.
// This token is used to authenticate requests to the demo backends
// and prevent unauthorised bot/spam access.
//
// Token format: demo_token_v1_YYYYMMDD_16-char-hmac
// Tokens are valid for 48 hours (today + yesterday) for timezone handling.

import 'dart:convert';
import 'package:http/http.dart' as http;

// SECURITY: Token endpoint for demo authentication.
const _tokenEndpoint = 'https://playground.provii.app/v1/config/demo-token';

class _DemoTokenResponse {
  final String token;
  final int expiresAt;
  final int cacheSeconds;

  _DemoTokenResponse({
    required this.token,
    required this.expiresAt,
    required this.cacheSeconds,
  });

  factory _DemoTokenResponse.fromJson(Map<String, dynamic> json) {
    return _DemoTokenResponse(
      token: json['token'] as String,
      expiresAt: json['expires_at'] as int,
      cacheSeconds: json['cache_seconds'] as int,
    );
  }
}

/// Singleton manager for demo authentication tokens.
///
/// Usage:
/// ```dart
/// final token = await DemoTokenManager.instance.getToken();
/// // Add to your request headers: {'X-Demo-Token': token}
/// ```
class DemoTokenManager {
  static final DemoTokenManager instance = DemoTokenManager._();

  DemoTokenManager._();

  String? _cachedToken;
  int _tokenExpiresAt = 0;

  /// Get the current demo token, fetching a new one if needed.
  ///
  /// Returns the demo token string.
  /// Throws an exception if token fetch fails.
  Future<String> getToken() async {
    final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;

    // Return cached token if still valid (with 1 hour buffer)
    final cached = _cachedToken;
    if (cached != null && _tokenExpiresAt > now + 3600) {
      return cached;
    }

    // Fetch new token
    final response = await http.get(
      Uri.parse(_tokenEndpoint),
      headers: {'Accept': 'application/json'},
    );

    if (response.statusCode != 200) {
      throw Exception('Failed to fetch demo token: ${response.statusCode}');
    }

    final _DemoTokenResponse tokenResponse;
    try {
      tokenResponse = _DemoTokenResponse.fromJson(
        jsonDecode(response.body) as Map<String, dynamic>,
      );
    } on FormatException {
      throw Exception('Invalid JSON in demo token response');
    } on TypeError {
      throw Exception('Unexpected field type in demo token response');
    }

    _cachedToken = tokenResponse.token;
    _tokenExpiresAt = tokenResponse.expiresAt;

    return tokenResponse.token;
  }

  /// Get headers with the demo token included.
  ///
  /// [additionalHeaders] - Additional headers to merge with the token header.
  /// Returns a Map containing all headers including X-Demo-Token.
  Future<Map<String, String>> getHeadersWithToken([
    Map<String, String>? additionalHeaders,
  ]) async {
    final token = await getToken();
    return {
      if (additionalHeaders != null) ...additionalHeaders,
      'X-Demo-Token': token,
    };
  }
}
