// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Provii

// Provii Verifier Demo App
//
// Demonstrates how third-party apps integrate with Provii for age verification.

import 'package:flutter/material.dart';
import 'screens/sandbox_instructions_screen.dart';
import 'screens/age_threshold_screen.dart';
import 'screens/verification_screen.dart';
import 'screens/result_screen.dart';
import 'models/verification_session.dart';

/// Entry point for the Provii Verifier Demo app.
void main() {
  runApp(const ProviiVerifierDemoApp());
}

/// Root widget for the Provii Verifier Demo.
///
/// Demonstrates Mobile App Verification (integration scenario 3): a custom
/// backend calls provii-verifier with HMAC-SHA256 + nonce + PKCE, and the
/// wallet responds with a zero knowledge proof via deep link.
class ProviiVerifierDemoApp extends StatelessWidget {
  /// Creates a [ProviiVerifierDemoApp].
  const ProviiVerifierDemoApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Provii Verifier Demo',
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(seedColor: Colors.blue),
        useMaterial3: true,
      ),
      initialRoute: '/',
      onGenerateRoute: (settings) {
        switch (settings.name) {
          case '/':
            return MaterialPageRoute(
              builder: (_) => const SandboxInstructionsScreen(),
            );
          case '/threshold':
            return MaterialPageRoute(
              builder: (_) => const AgeThresholdScreen(),
            );
          case '/verification':
            final threshold = settings.arguments;
            if (threshold is! AgeThreshold) {
              return MaterialPageRoute(
                builder: (_) => const SandboxInstructionsScreen(),
              );
            }
            return MaterialPageRoute(
              builder: (_) => VerificationScreen(threshold: threshold),
            );
          case '/result':
            final args = settings.arguments;
            if (args is! Map<String, dynamic>) {
              return MaterialPageRoute(
                builder: (_) => const SandboxInstructionsScreen(),
              );
            }
            return MaterialPageRoute(
              builder: (_) => ResultScreen(
                verified: args['verified'] as bool? ?? false,
                minimumAge: args['minimumAge'] as int? ?? 0,
                errorMessage: args['error'] as String?,
              ),
            );
          default:
            return MaterialPageRoute(
              builder: (_) => const SandboxInstructionsScreen(),
            );
        }
      },
    );
  }
}
