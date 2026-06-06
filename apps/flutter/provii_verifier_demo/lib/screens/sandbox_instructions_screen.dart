// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Provii

// Sandbox Instructions Screen
//
// Guides the user to enable sandbox mode in Provii Wallet before testing.

import 'package:flutter/material.dart';
import 'package:shared_preferences/shared_preferences.dart';

/// Screen shown on first launch, guiding the user to enable sandbox mode in
/// Provii Wallet before testing age verification.
class SandboxInstructionsScreen extends StatefulWidget {
  /// Creates a [SandboxInstructionsScreen].
  const SandboxInstructionsScreen({super.key});

  @override
  State<SandboxInstructionsScreen> createState() =>
      _SandboxInstructionsScreenState();
}

class _SandboxInstructionsScreenState extends State<SandboxInstructionsScreen> {
  bool _isLoading = true;

  @override
  void initState() {
    super.initState();
    _checkSandboxAcknowledged();
  }

  Future<void> _checkSandboxAcknowledged() async {
    final prefs = await SharedPreferences.getInstance();
    final acknowledged =
        prefs.getBool('verifier_sandbox_acknowledged') ?? false;

    if (acknowledged && mounted) {
      Navigator.pushReplacementNamed(context, '/threshold');
    } else {
      setState(() => _isLoading = false);
    }
  }

  Future<void> _acknowledgeAndProceed() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setBool('verifier_sandbox_acknowledged', true);

    if (mounted) {
      Navigator.pushReplacementNamed(context, '/threshold');
    }
  }

  @override
  Widget build(BuildContext context) {
    if (_isLoading) {
      return const Scaffold(
        body: Center(child: CircularProgressIndicator()),
      );
    }

    return Scaffold(
      appBar: AppBar(
        title: const Text('Getting Started'),
        backgroundColor: Theme.of(context).colorScheme.primaryContainer,
      ),
      body: SafeArea(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(20),
          child: Column(
            children: [
              const Icon(
                Icons.warning_amber_rounded,
                size: 64,
                color: Colors.orange,
              ),
              const SizedBox(height: 16),
              Text(
                'Enable Sandbox Mode',
                style: Theme.of(context).textTheme.headlineSmall?.copyWith(
                      fontWeight: FontWeight.bold,
                    ),
              ),
              const SizedBox(height: 12),
              Text(
                'Before testing age verification, you need to enable Sandbox Mode in Provii Wallet. This allows testing without real credentials.',
                textAlign: TextAlign.center,
                style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                      color: Colors.grey[600],
                    ),
              ),
              const SizedBox(height: 24),

              // Instructions card
              Card(
                child: Padding(
                  padding: const EdgeInsets.all(16),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        'Instructions:',
                        style:
                            Theme.of(context).textTheme.titleMedium?.copyWith(
                                  fontWeight: FontWeight.bold,
                                ),
                      ),
                      const SizedBox(height: 16),
                      _buildInstructionRow(
                          1, 'Open Provii Wallet on your device'),
                      _buildInstructionRow(2, 'Go to Settings (gear icon)'),
                      _buildInstructionRow(3,
                          'Tap the screen 5 times to reveal developer options'),
                      _buildInstructionRow(4, 'Enable "Sandbox Mode"'),
                      _buildInstructionRow(
                          5, 'The app will restart in sandbox mode'),
                    ],
                  ),
                ),
              ),
              const SizedBox(height: 16),

              // Info box
              Container(
                padding: const EdgeInsets.all(16),
                decoration: BoxDecoration(
                  color: Colors.blue.withOpacity(0.1),
                  borderRadius: BorderRadius.circular(12),
                ),
                child: Row(
                  children: [
                    const Icon(Icons.info_outline, color: Colors.blue),
                    const SizedBox(width: 12),
                    Expanded(
                      child: Text(
                        'In sandbox mode, you can use demo credentials that were issued from the Provii Issuer Demo app for testing age verification.',
                        style: Theme.of(context).textTheme.bodySmall?.copyWith(
                              color: Colors.blue[700],
                            ),
                      ),
                    ),
                  ],
                ),
              ),
              const SizedBox(height: 24),

              FilledButton(
                onPressed: _acknowledgeAndProceed,
                style: FilledButton.styleFrom(
                  minimumSize: const Size(double.infinity, 50),
                ),
                child: const Text("I've Enabled Sandbox Mode"),
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildInstructionRow(int number, String text) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 12),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          CircleAvatar(
            radius: 12,
            backgroundColor: Colors.blue,
            child: Text(
              '$number',
              style: const TextStyle(
                color: Colors.white,
                fontSize: 12,
                fontWeight: FontWeight.bold,
              ),
            ),
          ),
          const SizedBox(width: 12),
          Expanded(child: Text(text)),
        ],
      ),
    );
  }
}
