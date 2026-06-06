// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Provii

import 'package:flutter/material.dart';
import 'package:shared_preferences/shared_preferences.dart';

/// Instructions screen shown on first launch, guiding the user to enable
/// sandbox mode in Provii Wallet before issuing demo credentials.
class SandboxInstructionsScreen extends StatelessWidget {
  /// Creates a [SandboxInstructionsScreen].
  const SandboxInstructionsScreen({super.key});

  Future<void> _onSandboxEnabled(BuildContext context) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setBool('sandbox_mode_enabled', true);
    if (context.mounted) {
      Navigator.pushReplacementNamed(context, '/customers');
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Demo Bank'),
        centerTitle: true,
      ),
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.all(24.0),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              const SizedBox(height: 24),
              Icon(
                Icons.warning_amber_rounded,
                size: 64,
                color: Theme.of(context).colorScheme.primary,
              ),
              const SizedBox(height: 24),
              Text(
                'Sandbox Mode Required',
                style: Theme.of(context).textTheme.headlineMedium?.copyWith(
                      fontWeight: FontWeight.bold,
                    ),
                textAlign: TextAlign.center,
              ),
              const SizedBox(height: 24),
              Card(
                child: Padding(
                  padding: const EdgeInsets.all(16.0),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        'Before continuing, please enable sandbox mode in the Provii Wallet app:',
                        style: Theme.of(context).textTheme.bodyLarge,
                      ),
                      const SizedBox(height: 16),
                      _buildStep(context, '1', 'Open the Provii Wallet app'),
                      _buildStep(context, '2', 'Go to Settings'),
                      _buildStep(context, '3',
                          'Tap the Settings header 5 times to reveal the Sandbox Mode toggle, then enable it'),
                      _buildStep(context, '4', 'Return to this app'),
                    ],
                  ),
                ),
              ),
              const SizedBox(height: 16),
              Card(
                color: Theme.of(context).colorScheme.secondaryContainer,
                child: Padding(
                  padding: const EdgeInsets.all(16.0),
                  child: Row(
                    children: [
                      Icon(
                        Icons.info_outline,
                        color:
                            Theme.of(context).colorScheme.onSecondaryContainer,
                      ),
                      const SizedBox(width: 12),
                      Expanded(
                        child: Text(
                          'Sandbox mode allows the wallet to accept credentials from demo issuers.',
                          style: TextStyle(
                            color: Theme.of(context)
                                .colorScheme
                                .onSecondaryContainer,
                          ),
                        ),
                      ),
                    ],
                  ),
                ),
              ),
              const Spacer(),
              FilledButton.icon(
                onPressed: () => _onSandboxEnabled(context),
                icon: const Icon(Icons.check_circle),
                label: const Text("I've enabled sandbox mode"),
                style: FilledButton.styleFrom(
                  padding: const EdgeInsets.symmetric(vertical: 16),
                ),
              ),
              const SizedBox(height: 24),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildStep(BuildContext context, String number, String text) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 8.0),
      child: Row(
        children: [
          CircleAvatar(
            radius: 14,
            backgroundColor: Theme.of(context).colorScheme.primary,
            child: Text(
              number,
              style: TextStyle(
                color: Theme.of(context).colorScheme.onPrimary,
                fontWeight: FontWeight.bold,
                fontSize: 14,
              ),
            ),
          ),
          const SizedBox(width: 12),
          Expanded(
            child: Text(
              text,
              style: Theme.of(context).textTheme.bodyLarge,
            ),
          ),
        ],
      ),
    );
  }
}
