// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Provii

import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:url_launcher/url_launcher.dart';
import '../models/customer.dart';
import '../api/issuer_api.dart';

/// Validates that a deep link has the expected Provii wallet format.
///
/// Accepts both HTTPS universal links and the custom scheme fallback.
/// Returns true if valid, false otherwise.
bool _isValidProviiDeepLink(String deepLink) {
  try {
    final uri = Uri.parse(deepLink);
    // HTTPS universal link: https://provii.app/attest?d=...
    if (uri.scheme == 'https' &&
        uri.host == 'provii.app' &&
        uri.path.contains('attest')) {
      final data = uri.queryParameters['d'];
      return data != null && data.isNotEmpty;
    }
    // Custom scheme fallback: provii://attest?d=...
    if (uri.scheme == 'provii' &&
        (uri.host == 'attest' || uri.path.contains('attest'))) {
      final data = uri.queryParameters['d'];
      return data != null && data.isNotEmpty;
    }
    return false;
  } catch (_) {
    return false;
  }
}

/// Screen that lets the user pick a demo age and issue a credential.
///
/// Calls the issuer backend, validates the returned deep link, and opens
/// Provii Wallet to complete credential issuance.
class AgeSelectionScreen extends StatefulWidget {
  /// Creates an [AgeSelectionScreen].
  const AgeSelectionScreen({super.key});

  @override
  State<AgeSelectionScreen> createState() => _AgeSelectionScreenState();
}

class _AgeSelectionScreenState extends State<AgeSelectionScreen> {
  bool _isLoading = false;
  int? _selectedAge;
  String? _errorMessage;
  bool _credentialIssued = false;

  Future<void> _issueCredential(int age) async {
    setState(() {
      _isLoading = true;
      _selectedAge = age;
      _errorMessage = null;
      _credentialIssued = false;
    });

    try {
      final dob = calculateDobForAge(age);
      final response = await IssuerApi.createAttestation(dob);
      final deepLink = response['deep_link'] as String?;

      if (deepLink == null) {
        throw Exception('No deep link received from server');
      }

      // SECURITY: Validate deep link format before launching.
      if (!_isValidProviiDeepLink(deepLink)) {
        if (kDebugMode) {
          debugPrint('Invalid deep link format received: $deepLink');
        }
        throw Exception('Invalid credential link format');
      }

      final uri = Uri.parse(deepLink);
      final launched = await launchUrl(
        uri,
        mode: LaunchMode.externalApplication,
      );

      if (!launched) {
        throw Exception('Could not launch Provii Wallet. Is it installed?');
      }

      setState(() {
        _credentialIssued = true;
      });
    } catch (e) {
      if (kDebugMode) {
        debugPrint('Error issuing credential: $e');
      }
      // Show user-friendly error messages, not raw exception details
      String userMessage;
      final errorString = e.toString();
      if (errorString.contains('SocketException') ||
          errorString.contains('Connection refused')) {
        userMessage =
            'Unable to connect to the server. Please check your network connection.';
      } else if (errorString.contains('No deep link')) {
        userMessage = 'Server did not return a valid credential link.';
      } else if (errorString.contains('Invalid credential link')) {
        userMessage = 'Received an invalid credential link from the server.';
      } else if (errorString.contains('Could not launch Provii Wallet')) {
        userMessage =
            'Could not open Provii Wallet. Please ensure it is installed.';
      } else {
        userMessage = 'Failed to issue credential. Please try again.';
      }
      setState(() {
        _errorMessage = userMessage;
      });
    } finally {
      setState(() {
        _isLoading = false;
      });
    }
  }

  void _reset() {
    setState(() {
      _isLoading = false;
      _selectedAge = null;
      _errorMessage = null;
      _credentialIssued = false;
    });
  }

  @override
  Widget build(BuildContext context) {
    final greenTheme = Theme.of(context).copyWith(
      colorScheme: ColorScheme.fromSeed(
        seedColor: Colors.green,
        brightness: Theme.of(context).brightness,
      ),
    );

    return Theme(
      data: greenTheme,
      child: Scaffold(
        appBar: AppBar(
          title: const Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              Text('Demo Bank '),
              Text(
                '\u{1F3E6}', // bank emoji
                style: TextStyle(fontSize: 20),
              ),
            ],
          ),
          centerTitle: true,
          backgroundColor: greenTheme.colorScheme.primaryContainer,
          foregroundColor: greenTheme.colorScheme.onPrimaryContainer,
        ),
        body: SafeArea(
          child: Padding(
            padding: const EdgeInsets.all(24.0),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                const SizedBox(height: 16),
                Text(
                  'Issue Age Credential',
                  style: Theme.of(context).textTheme.headlineMedium?.copyWith(
                        fontWeight: FontWeight.bold,
                      ),
                  textAlign: TextAlign.center,
                ),
                const SizedBox(height: 12),
                Text(
                  'Tap an age to issue a demo credential to Provii Wallet',
                  style: Theme.of(context).textTheme.bodyLarge?.copyWith(
                        color: Theme.of(context).colorScheme.onSurfaceVariant,
                      ),
                  textAlign: TextAlign.center,
                ),
                const SizedBox(height: 32),
                if (_isLoading)
                  Column(
                    children: [
                      const CircularProgressIndicator(),
                      const SizedBox(height: 16),
                      Text(
                        'Creating credential for age $_selectedAge...',
                        style: Theme.of(context).textTheme.bodyMedium,
                      ),
                    ],
                  )
                else if (_credentialIssued)
                  Card(
                    color: greenTheme.colorScheme.primaryContainer,
                    child: Padding(
                      padding: const EdgeInsets.all(20.0),
                      child: Column(
                        children: [
                          Icon(
                            Icons.check_circle,
                            size: 48,
                            color: greenTheme.colorScheme.onPrimaryContainer,
                          ),
                          const SizedBox(height: 12),
                          Text(
                            'Credential Sent!',
                            style: Theme.of(context)
                                .textTheme
                                .titleLarge
                                ?.copyWith(
                                  fontWeight: FontWeight.bold,
                                  color:
                                      greenTheme.colorScheme.onPrimaryContainer,
                                ),
                          ),
                          const SizedBox(height: 8),
                          Text(
                            'Age $_selectedAge credential sent to Provii Wallet. Check your wallet to accept it.',
                            style: TextStyle(
                              color: greenTheme.colorScheme.onPrimaryContainer,
                            ),
                            textAlign: TextAlign.center,
                          ),
                          const SizedBox(height: 16),
                          FilledButton.tonal(
                            onPressed: _reset,
                            child: const Text('Issue Another'),
                          ),
                        ],
                      ),
                    ),
                  )
                else if (_errorMessage != null)
                  Card(
                    color: Theme.of(context).colorScheme.errorContainer,
                    child: Padding(
                      padding: const EdgeInsets.all(20.0),
                      child: Column(
                        children: [
                          Icon(
                            Icons.error_outline,
                            size: 48,
                            color:
                                Theme.of(context).colorScheme.onErrorContainer,
                          ),
                          const SizedBox(height: 12),
                          Text(
                            _errorMessage ?? '',
                            style: TextStyle(
                              color: Theme.of(context)
                                  .colorScheme
                                  .onErrorContainer,
                            ),
                            textAlign: TextAlign.center,
                          ),
                          const SizedBox(height: 16),
                          FilledButton.tonal(
                            onPressed: _reset,
                            child: const Text('Try Again'),
                          ),
                        ],
                      ),
                    ),
                  )
                else
                  Wrap(
                    spacing: 12,
                    runSpacing: 12,
                    alignment: WrapAlignment.center,
                    children: demoAges.map((age) {
                      return FilledButton.tonal(
                        onPressed: () => _issueCredential(age),
                        style: FilledButton.styleFrom(
                          padding: const EdgeInsets.symmetric(
                            horizontal: 24,
                            vertical: 16,
                          ),
                        ),
                        child: Text(
                          '$age',
                          style: const TextStyle(
                            fontSize: 18,
                            fontWeight: FontWeight.bold,
                          ),
                        ),
                      );
                    }).toList(),
                  ),
                const Spacer(),
                Text(
                  'Demo App - Not for production use',
                  style: Theme.of(context).textTheme.bodySmall?.copyWith(
                        color: Theme.of(context).colorScheme.onSurfaceVariant,
                      ),
                  textAlign: TextAlign.center,
                ),
                const SizedBox(height: 16),
              ],
            ),
          ),
        ),
      ),
    );
  }
}
