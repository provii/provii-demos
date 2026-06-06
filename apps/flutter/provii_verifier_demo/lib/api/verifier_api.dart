// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Provii

// Verifier Backend API Client
//
// This client communicates with YOUR verifier backend, not directly with
// Provii's provii-verifier.

import 'dart:convert';
import 'package:flutter/foundation.dart';
import 'package:http/http.dart' as http;
import '../config.dart';
import '../models/verification_session.dart';
import 'demo_token.dart';

/// Exception thrown when a verifier API call fails.
class VerifierApiException implements Exception {
  /// Human-readable description of the failure.
  final String message;

  /// HTTP status code, if available.
  final int? statusCode;

  /// Creates a [VerifierApiException] with the given [message] and optional [statusCode].
  VerifierApiException(this.message, [this.statusCode]);

  @override
  String toString() => message;
}

/// API client for communicating with the verifier backend.
///
/// Wraps challenge creation, status polling, and redemption. All requests
/// include a demo token via [DemoTokenManager].
class VerifierApi {
  /// Base URL of the verifier backend.
  final String baseUrl;

  final http.Client _client;

  /// Creates a [VerifierApi] targeting [baseUrl], or the default from [Config].
  VerifierApi({String? baseUrl})
      : baseUrl = baseUrl ?? Config.verifierBackendUrl,
        _client = http.Client();

  /// Creates a new age verification challenge.
  Future<CreateChallengeResponse> createChallenge({
    required int age,
    VerificationMode mode = VerificationMode.overAge,
    int expiresIn = 300,
  }) async {
    final uri = Uri.parse('$baseUrl/api/create-challenge');

    // SECURITY: Demo token authenticates this request to the demo backend.
    final headers = await DemoTokenManager.instance.getHeadersWithToken(
      {'Content-Type': 'application/json'},
    );

    final body = mode == VerificationMode.underAge
        ? {'maximum_age': age, 'expires_in': expiresIn}
        : {'minimum_age': age, 'expires_in': expiresIn};

    try {
      final response = await _client.post(
        uri,
        headers: headers,
        body: jsonEncode(body),
      );

      if (response.statusCode != 200) {
        String errorMessage = 'Failed to create challenge';
        try {
          final errorBody = jsonDecode(response.body);
          if (errorBody is Map && errorBody['error'] is String) {
            errorMessage = errorBody['error'] as String;
          }
        } catch (_) {
          // Response body is not valid JSON; use default message
        }
        throw VerifierApiException(errorMessage, response.statusCode);
      }

      try {
        return CreateChallengeResponse.fromJson(jsonDecode(response.body));
      } on FormatException {
        throw VerifierApiException('Invalid JSON in challenge response');
      } on TypeError {
        throw VerifierApiException(
            'Unexpected field type in challenge response');
      }
    } catch (e) {
      if (e is VerifierApiException) rethrow;
      debugPrint('Network error during createChallenge: $e');
      throw VerifierApiException('Network error. Check your connection.');
    }
  }

  /// Checks the status of a verification challenge identified by [sessionId].
  Future<StatusResponse> checkStatus(String sessionId) async {
    final uri = Uri.parse('$baseUrl/api/status/$sessionId');

    // SECURITY: Demo token authenticates this request to the demo backend.
    final headers = await DemoTokenManager.instance.getHeadersWithToken(
      {'Content-Type': 'application/json'},
    );

    try {
      final response = await _client.get(
        uri,
        headers: headers,
      );

      if (response.statusCode == 404) {
        throw VerifierApiException('Session not found', 404);
      }

      if (response.statusCode != 200) {
        String errorMessage = 'Failed to check status';
        try {
          final errorBody = jsonDecode(response.body);
          if (errorBody is Map && errorBody['error'] is String) {
            errorMessage = errorBody['error'] as String;
          }
        } catch (_) {
          // Response body is not valid JSON; use default message
        }
        throw VerifierApiException(errorMessage, response.statusCode);
      }

      try {
        return StatusResponse.fromJson(jsonDecode(response.body));
      } on FormatException {
        throw VerifierApiException('Invalid JSON in status response');
      } on TypeError {
        throw VerifierApiException('Unexpected field type in status response');
      }
    } catch (e) {
      if (e is VerifierApiException) rethrow;
      debugPrint('Network error during checkStatus: $e');
      throw VerifierApiException('Network error. Check your connection.');
    }
  }

  /// Redeems a verified challenge identified by [sessionId].
  ///
  /// Should only be called after [checkStatus] returns a verified state.
  Future<RedeemResponse> redeemChallenge(String sessionId) async {
    final uri = Uri.parse('$baseUrl/api/redeem/$sessionId');

    // SECURITY: Demo token authenticates this request to the demo backend.
    final headers = await DemoTokenManager.instance.getHeadersWithToken(
      {'Content-Type': 'application/json'},
    );

    try {
      final response = await _client.post(
        uri,
        headers: headers,
      );

      if (response.statusCode == 404) {
        throw VerifierApiException('Session not found', 404);
      }

      if (response.statusCode != 200) {
        String errorMessage = 'Failed to redeem challenge';
        try {
          final errorBody = jsonDecode(response.body);
          if (errorBody is Map && errorBody['error'] is String) {
            errorMessage = errorBody['error'] as String;
          }
        } catch (_) {
          // Response body is not valid JSON; use default message
        }
        throw VerifierApiException(errorMessage, response.statusCode);
      }

      try {
        return RedeemResponse.fromJson(jsonDecode(response.body));
      } on FormatException {
        throw VerifierApiException('Invalid JSON in redeem response');
      } on TypeError {
        throw VerifierApiException('Unexpected field type in redeem response');
      }
    } catch (e) {
      if (e is VerifierApiException) rethrow;
      debugPrint('Network error during redeemChallenge: $e');
      throw VerifierApiException('Network error. Check your connection.');
    }
  }

  /// Closes the underlying HTTP client, releasing resources.
  void dispose() {
    _client.close();
  }
}
