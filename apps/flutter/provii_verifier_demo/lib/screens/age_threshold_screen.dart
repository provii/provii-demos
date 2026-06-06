// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Provii

// Age Threshold Selection Screen
//
// Allows the user to select which age threshold to verify.
// Supports both over-age and under-age verification modes.

import 'package:flutter/material.dart';
import '../models/verification_session.dart';

/// Screen where the user selects which age threshold to verify against.
///
/// Offers both over-age and under-age modes via a segmented button toggle.
class AgeThresholdScreen extends StatefulWidget {
  /// Creates an [AgeThresholdScreen].
  const AgeThresholdScreen({super.key});

  @override
  State<AgeThresholdScreen> createState() => _AgeThresholdScreenState();
}

class _AgeThresholdScreenState extends State<AgeThresholdScreen> {
  VerificationMode _selectedMode = VerificationMode.overAge;

  @override
  Widget build(BuildContext context) {
    final thresholds = ageThresholdsForMode(_selectedMode);

    return Scaffold(
      appBar: AppBar(
        title: const Text('Verify Age'),
        backgroundColor: Theme.of(context).colorScheme.primaryContainer,
      ),
      body: SafeArea(
        child: Column(
          children: [
            // Mode toggle
            Padding(
              padding: const EdgeInsets.fromLTRB(16, 16, 16, 0),
              child: SegmentedButton<VerificationMode>(
                segments: const [
                  ButtonSegment(
                    value: VerificationMode.overAge,
                    label: Text('Over Age'),
                  ),
                  ButtonSegment(
                    value: VerificationMode.underAge,
                    label: Text('Under Age'),
                  ),
                ],
                selected: {_selectedMode},
                onSelectionChanged: (newSelection) {
                  setState(() {
                    _selectedMode = newSelection.first;
                  });
                },
              ),
            ),
            Padding(
              padding: const EdgeInsets.all(16),
              child: Text(
                _selectedMode == VerificationMode.overAge
                    ? 'Select the minimum age you want to verify. The user will prove they meet this requirement without revealing their actual date of birth.'
                    : 'Select the maximum age you want to verify. The user will prove they are under this age without revealing their actual date of birth.',
                style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                      color: Colors.grey[600],
                    ),
              ),
            ),
            Expanded(
              child: ListView.builder(
                padding: const EdgeInsets.symmetric(horizontal: 16),
                itemCount: thresholds.length,
                itemBuilder: (context, index) {
                  final threshold = thresholds[index];
                  final isUnder = threshold.mode == VerificationMode.underAge;
                  return Card(
                    margin: const EdgeInsets.only(bottom: 12),
                    child: ListTile(
                      contentPadding: const EdgeInsets.all(16),
                      leading: CircleAvatar(
                        radius: 28,
                        backgroundColor: isUnder
                            ? Colors.orange.withOpacity(0.1)
                            : Colors.blue.withOpacity(0.1),
                        child: Text(
                          isUnder ? '<${threshold.age}' : '${threshold.age}+',
                          style: TextStyle(
                            color: isUnder ? Colors.orange : Colors.blue,
                            fontWeight: FontWeight.bold,
                          ),
                        ),
                      ),
                      title: Text(
                        threshold.title,
                        style: const TextStyle(fontWeight: FontWeight.w600),
                      ),
                      subtitle: Padding(
                        padding: const EdgeInsets.only(top: 4),
                        child: Text(
                          threshold.description,
                          style: TextStyle(
                            color: Colors.grey[600],
                            fontSize: 13,
                          ),
                        ),
                      ),
                      trailing: const Icon(Icons.chevron_right),
                      onTap: () {
                        Navigator.pushNamed(
                          context,
                          '/verification',
                          arguments: threshold,
                        );
                      },
                    ),
                  );
                },
              ),
            ),
            Padding(
              padding: const EdgeInsets.all(16),
              child: Text(
                'Powered by zero knowledge proofs. The user\'s actual age is never revealed to your application.',
                textAlign: TextAlign.center,
                style: Theme.of(context).textTheme.bodySmall?.copyWith(
                      color: Colors.grey[500],
                    ),
              ),
            ),
          ],
        ),
      ),
    );
  }
}
