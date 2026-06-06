// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Provii

// ProviiVerifier - Integration class for Provii age verification
//
// This class encapsulates the complete verifier flow:
// 1. Create challenge (generates deep link)
// 2. Open Provii Wallet
// 3. Poll for verification status
// 4. Redeem when verified
// 5. Navigate to result screen
//
// === COPY THIS FILE INTO YOUR PROJECT ===
// This is a self-contained class that can be copied into any Flutter app.
// You'll also need: verifier_api.dart, verification_session.dart, config.dart

import 'dart:async';
import 'package:flutter/foundation.dart';
import 'package:url_launcher/url_launcher.dart';
import '../config.dart';
import '../api/verifier_api.dart';
import '../models/verification_session.dart';

/// Exception thrown when the Provii verification flow encounters an error.
class ProviiVerifierException implements Exception {
  /// Human-readable description of the failure.
  final String message;

  /// Creates a [ProviiVerifierException] with the given [message].
  ProviiVerifierException(this.message);

  @override
  String toString() => message;
}

/// High-level client that orchestrates the full Provii verification flow.
///
/// Creates a challenge, opens Provii Wallet via deep link, polls for the
/// proof result, and redeems the session once verified.
class ProviiVerifier {
  final VerifierApi _api;
  Timer? _pollingTimer;
  DateTime? _pollingStartTime;
  VerificationSession? _currentSession;

  /// Creates a [ProviiVerifier] targeting [backendUrl], or the default from [Config].
  ProviiVerifier({String? backendUrl})
      : _api = VerifierApi(baseUrl: backendUrl);

  /// Create a verification challenge and open Provii Wallet
  Future<VerificationSession> startVerification({
    required int age,
    VerificationMode mode = VerificationMode.overAge,
    int expiresIn = 300,
  }) async {
    // 1. Create challenge
    final response = await _api.createChallenge(
      age: age,
      mode: mode,
      expiresIn: expiresIn,
    );

    // SECURITY: Validate deep link points to the expected Provii domain.
    if (!response.deepLink.startsWith('https://provii.app/verify?')) {
      throw ProviiVerifierException('Invalid deep link format from backend');
    }

    final uri = Uri.parse(response.deepLink);

    // 3. Store session
    final session = VerificationSession(
      sessionId: response.sessionId,
      deepLink: response.deepLink,
      expiresAt: DateTime.fromMillisecondsSinceEpoch(response.expiresAt * 1000),
      ageThreshold: age,
      mode: mode,
      createdAt: DateTime.now(),
    );
    _currentSession = session;

    // 4. Open wallet (HTTPS universal link; fallback page handles "not installed")
    final launched = await launchUrl(
      uri,
      mode: LaunchMode.externalApplication,
    );

    if (!launched) {
      throw ProviiVerifierException('Could not open Provii Wallet');
    }

    return session;
  }

  /// Starts polling the backend for verification status.
  ///
  /// Calls [onStatusChange] on every poll response, [onVerified] when the
  /// proof is accepted, and [onError] on timeout or failure.
  void startPolling({
    required String sessionId,
    required void Function(StatusResponse) onStatusChange,
    required void Function() onVerified,
    required void Function(String error) onError,
  }) {
    stopPolling();
    _pollingStartTime = DateTime.now();

    _pollingTimer = Timer.periodic(
      const Duration(milliseconds: Config.pollingIntervalMs),
      (_) async {
        // Check timeout
        final startTime = _pollingStartTime;
        if (startTime == null) return;
        final elapsed = DateTime.now().difference(startTime);
        if (elapsed.inMilliseconds > Config.pollingTimeoutMs) {
          stopPolling();
          onError('Verification timed out');
          return;
        }

        try {
          final status = await _api.checkStatus(sessionId);
          onStatusChange(status);

          if (status.verified || status.proofVerified == true) {
            stopPolling();
            onVerified();
          } else if (status.state == 'expired') {
            stopPolling();
            onError('Challenge expired');
          } else if (status.state == 'failed') {
            stopPolling();
            onError('Verification failed');
          }
        } catch (e) {
          // Log but continue polling on transient errors
          if (kDebugMode) {
            debugPrint('Polling error (will retry): $e');
          }
        }
      },
    );
  }

  /// Stops the active polling timer, if any.
  void stopPolling() {
    _pollingTimer?.cancel();
    _pollingTimer = null;
    _pollingStartTime = null;
  }

  /// Redeems a verified challenge identified by [sessionId].
  Future<RedeemResponse> redeem(String sessionId) async {
    return await _api.redeemChallenge(sessionId);
  }

  /// Resets the verifier to its initial state.
  void reset() {
    stopPolling();
    _currentSession = null;
  }

  /// Get the current session
  VerificationSession? get currentSession => _currentSession;

  /// Releases all resources held by this verifier.
  void dispose() {
    stopPolling();
    _api.dispose();
  }
}
