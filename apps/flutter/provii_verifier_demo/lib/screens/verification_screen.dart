// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Provii

// Verification Screen
//
// Handles the verification flow:
// 1. Creates challenge and opens Provii Wallet
// 2. Displays a QR code for cross-device scanning
// 3. Polls for verification status
// 4. Redeems the challenge when verified
// 5. Navigates to the result screen

import 'dart:async';
import 'package:flutter/material.dart';
import 'package:qr_flutter/qr_flutter.dart';
import 'package:url_launcher/url_launcher.dart';
import '../models/verification_session.dart';
import '../provii/provii_verifier.dart';

/// Active verification screen that creates a challenge, shows a QR code,
/// polls for the proof, and navigates to the result.
class VerificationScreen extends StatefulWidget {
  /// The age threshold being verified.
  final AgeThreshold threshold;

  /// Creates a [VerificationScreen] for the given [threshold].
  const VerificationScreen({super.key, required this.threshold});

  @override
  State<VerificationScreen> createState() => _VerificationScreenState();
}

class _VerificationScreenState extends State<VerificationScreen> {
  final ProviiVerifier _verifier = ProviiVerifier();

  VerificationState _state = VerificationState.initial;
  VerificationSession? _session;
  int _timeRemaining = 0;
  Timer? _countdownTimer;

  @override
  void initState() {
    super.initState();
    _startVerification();
  }

  @override
  void dispose() {
    _verifier.dispose();
    _countdownTimer?.cancel();
    super.dispose();
  }

  Future<void> _startVerification() async {
    setState(() {
      _state = VerificationState.creating;
    });

    try {
      final session = await _verifier.startVerification(
        age: widget.threshold.age,
        mode: widget.threshold.mode,
      );

      setState(() {
        _session = session;
        _state = VerificationState.polling;
      });

      _startCountdown();

      _verifier.startPolling(
        sessionId: session.sessionId,
        onStatusChange: (_) {},
        onVerified: _handleVerified,
        onError: _handleError,
      );
    } catch (e) {
      debugPrint('Verification error: $e');
      setState(() {
        _state = VerificationState.failed;
      });
      _handleError('Verification failed. Check your connection and try again.');
    }
  }

  void _startCountdown() {
    final session = _session;
    if (session == null) return;

    _countdownTimer?.cancel();
    _countdownTimer = Timer.periodic(const Duration(seconds: 1), (_) {
      final now = DateTime.now();
      final remaining = session.expiresAt.difference(now).inSeconds;

      if (remaining <= 0) {
        _countdownTimer?.cancel();
        setState(() => _timeRemaining = 0);
      } else {
        setState(() => _timeRemaining = remaining);
      }
    });
  }

  Future<void> _handleVerified() async {
    setState(() => _state = VerificationState.verified);
    _countdownTimer?.cancel();

    final sessionToRedeem = _session;
    if (sessionToRedeem == null) {
      _handleError('No active session');
      return;
    }

    setState(() => _state = VerificationState.redeeming);

    try {
      final result = await _verifier.redeem(sessionToRedeem.sessionId);

      if (mounted) {
        Navigator.pushReplacementNamed(
          context,
          '/result',
          arguments: {
            'verified': result.verified,
            'minimumAge': widget.threshold.age,
            'error': result.verified ? null : 'Verification incomplete',
          },
        );
      }
    } catch (e) {
      if (mounted) {
        Navigator.pushReplacementNamed(
          context,
          '/result',
          arguments: {
            'verified': false,
            'minimumAge': widget.threshold.age,
            'error': e.toString(),
          },
        );
      }
    }
  }

  void _handleError(String error) {
    _countdownTimer?.cancel();

    if (mounted) {
      Navigator.pushReplacementNamed(
        context,
        '/result',
        arguments: {
          'verified': false,
          'minimumAge': widget.threshold.age,
          'error': error,
        },
      );
    }
  }

  void _cancel() {
    _verifier.stopPolling();
    _countdownTimer?.cancel();
    Navigator.pop(context);
  }

  String _formatTime(int seconds) {
    final mins = seconds ~/ 60;
    final secs = seconds % 60;
    return '$mins:${secs.toString().padLeft(2, '0')}';
  }

  String get _statusMessage {
    switch (_state) {
      case VerificationState.initial:
      case VerificationState.creating:
        return 'Creating verification challenge...';
      case VerificationState.challengeCreated:
        return 'Opening Provii Wallet...';
      case VerificationState.polling:
        return 'Waiting for verification...';
      case VerificationState.verified:
        return 'Age verified! Completing...';
      case VerificationState.redeeming:
        return 'Finalizing verification...';
      case VerificationState.redeemed:
        return 'Verification complete!';
      case VerificationState.expired:
        return 'Challenge expired';
      case VerificationState.failed:
        return 'Verification failed';
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Verifying...'),
        automaticallyImplyLeading: false,
        backgroundColor: Theme.of(context).colorScheme.primaryContainer,
      ),
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.all(20),
          child: Column(
            children: [
              const Spacer(),

              // Status icon
              if (_state == VerificationState.failed)
                const Icon(Icons.cancel, size: 60, color: Colors.red)
              else
                const SizedBox(
                  width: 60,
                  height: 60,
                  child: CircularProgressIndicator(),
                ),

              const SizedBox(height: 24),

              Text(
                _statusMessage,
                style: Theme.of(context).textTheme.titleLarge,
                textAlign: TextAlign.center,
              ),

              const SizedBox(height: 12),

              Text(
                'Please complete the age verification in Provii Wallet and return to this app.',
                style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                      color: Colors.grey[600],
                    ),
                textAlign: TextAlign.center,
              ),

              // QR code for cross-device scanning
              if (_session != null && _state != VerificationState.failed) ...[
                const SizedBox(height: 24),
                QrImageView(
                  data: _session?.deepLink ?? '',
                  version: QrVersions.auto,
                  size: 220,
                  errorCorrectionLevel: QrErrorCorrectLevel.M,
                  backgroundColor: Colors.white,
                  semanticsLabel: 'QR code for cross-device verification',
                ),
                const SizedBox(height: 8),
                Text(
                  'Scan with Provii Wallet on another device',
                  style: TextStyle(
                    fontSize: 13,
                    color: Colors.grey[600],
                  ),
                ),
                const SizedBox(height: 16),
                FilledButton(
                  onPressed: () {
                    final link = _session?.deepLink;
                    if (link == null) return;
                    final uri = Uri.parse(link);
                    launchUrl(uri, mode: LaunchMode.externalApplication);
                  },
                  style: FilledButton.styleFrom(
                    minimumSize: const Size(double.infinity, 50),
                  ),
                  child: const Text('Open Provii Wallet'),
                ),
              ],

              const SizedBox(height: 24),

              if (_timeRemaining > 0)
                Container(
                  padding: const EdgeInsets.symmetric(
                    horizontal: 20,
                    vertical: 12,
                  ),
                  decoration: BoxDecoration(
                    color: Colors.grey[100],
                    borderRadius: BorderRadius.circular(8),
                  ),
                  child: Row(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      Text(
                        'Time remaining: ',
                        style: TextStyle(color: Colors.grey[600]),
                      ),
                      Text(
                        _formatTime(_timeRemaining),
                        style: const TextStyle(
                          fontWeight: FontWeight.bold,
                          color: Colors.blue,
                        ),
                      ),
                    ],
                  ),
                ),

              const SizedBox(height: 24),

              // Info card
              Card(
                child: Padding(
                  padding: const EdgeInsets.all(16),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        widget.threshold.mode == VerificationMode.underAge
                            ? 'Verifying: Under ${widget.threshold.age}'
                            : 'Verifying: Age ${widget.threshold.age}+',
                        style: const TextStyle(fontWeight: FontWeight.bold),
                      ),
                      const SizedBox(height: 8),
                      Text(
                        widget.threshold.mode == VerificationMode.underAge
                            ? 'The user will prove they are under ${widget.threshold.age} years old using a zero knowledge proof. Their actual date of birth will not be revealed.'
                            : 'The user will prove they are ${widget.threshold.age} years or older using a zero knowledge proof. Their actual date of birth will not be revealed.',
                        style: TextStyle(
                          color: Colors.grey[600],
                          fontSize: 13,
                        ),
                      ),
                    ],
                  ),
                ),
              ),

              const Spacer(),

              if (_state == VerificationState.failed)
                Padding(
                  padding: const EdgeInsets.only(bottom: 12),
                  child: FilledButton(
                    onPressed: _startVerification,
                    style: FilledButton.styleFrom(
                      minimumSize: const Size(double.infinity, 50),
                    ),
                    child: const Text('Try Again'),
                  ),
                ),

              OutlinedButton(
                onPressed: _cancel,
                style: OutlinedButton.styleFrom(
                  minimumSize: const Size(double.infinity, 50),
                  foregroundColor: Colors.red,
                  side: const BorderSide(color: Colors.red),
                ),
                child: const Text('Cancel Verification'),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
