// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Provii

import 'package:flutter/material.dart';
import 'screens/sandbox_instructions_screen.dart';
import 'screens/age_selection_screen.dart';

/// Entry point for the Provii Issuer Demo app.
void main() {
  runApp(const ProviiIssuerDemoApp());
}

/// Root widget for the Provii Issuer Demo.
///
/// Demonstrates Mobile App Issuance (integration scenario 4): an issuer
/// backend signs an Ed25519 attestation, then the wallet receives it via
/// deep link.
class ProviiIssuerDemoApp extends StatelessWidget {
  /// Creates a [ProviiIssuerDemoApp].
  const ProviiIssuerDemoApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Provii Issuer Demo',
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(seedColor: Colors.green),
        useMaterial3: true,
      ),
      initialRoute: '/',
      onGenerateRoute: (settings) {
        switch (settings.name) {
          case '/':
            return MaterialPageRoute(
              builder: (context) => const SandboxInstructionsScreen(),
            );
          case '/customers':
            return MaterialPageRoute(
              builder: (context) => const AgeSelectionScreen(),
            );
          default:
            return MaterialPageRoute(
              builder: (context) => const SandboxInstructionsScreen(),
            );
        }
      },
    );
  }
}
