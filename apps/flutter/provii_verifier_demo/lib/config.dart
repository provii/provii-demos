// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Provii

/// Configuration for the Provii Verifier Demo app.
///
/// For local development, override [verifierBackendUrl]:
/// - Android Emulator: http://10.0.2.2:3001
/// - iOS Simulator: http://localhost:3001
///
/// For production, replace with your actual verifier backend URL.
class Config {
  /// The URL of your verifier backend (NOT provii-verifier directly).
  static const String verifierBackendUrl = 'https://verifier-demo.provii.app';

  /// Polling interval in milliseconds when checking verification status.
  static const int pollingIntervalMs = 1500;

  /// Maximum polling duration in milliseconds before timing out.
  static const int pollingTimeoutMs = 600000; // 10 minutes
}
