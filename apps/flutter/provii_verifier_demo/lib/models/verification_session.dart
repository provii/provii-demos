// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Provii

// Data models for the Provii Verifier Demo app.

/// Whether the proof demonstrates the user is over or under a given age.
enum VerificationMode {
  /// Prove the user is at or above the threshold age.
  overAge('over_age'),

  /// Prove the user is below the threshold age.
  underAge('under_age');

  /// Wire value sent to the verifier backend.
  final String value;

  const VerificationMode(this.value);
}

/// Represents one selectable age threshold option for verification.
class AgeThreshold {
  /// Unique identifier for this threshold (e.g. 'over-18').
  final String id;

  /// The numeric age boundary.
  final int age;

  /// Display title shown to the user.
  final String title;

  /// Short description of the use case.
  final String description;

  /// Whether this is an over-age or under-age check.
  final VerificationMode mode;

  /// Creates an [AgeThreshold].
  const AgeThreshold({
    required this.id,
    required this.age,
    required this.title,
    required this.description,
    required this.mode,
  });
}

/// Predefined over-age verification thresholds for the demo.
const List<AgeThreshold> overAgeThresholds = [
  AgeThreshold(
    id: 'over-13',
    age: 13,
    title: 'Age 13+ Verification',
    description: 'Verify the user is 13 years or older (COPPA compliance)',
    mode: VerificationMode.overAge,
  ),
  AgeThreshold(
    id: 'over-18',
    age: 18,
    title: 'Age 18+ Verification',
    description: 'Verify the user is 18 years or older (general adult content)',
    mode: VerificationMode.overAge,
  ),
  AgeThreshold(
    id: 'over-21',
    age: 21,
    title: 'Age 21+ Verification',
    description: 'Verify the user is 21 years or older (alcohol, cannabis)',
    mode: VerificationMode.overAge,
  ),
  AgeThreshold(
    id: 'over-25',
    age: 25,
    title: 'Age 25+ Verification',
    description: 'Verify the user is 25 years or older (car rental, etc.)',
    mode: VerificationMode.overAge,
  ),
];

/// Predefined under-age verification thresholds for the demo.
const List<AgeThreshold> underAgeThresholds = [
  AgeThreshold(
    id: 'under-13',
    age: 13,
    title: 'Under 13 Verification',
    description: "Verify the user is under 13 years old (children's content)",
    mode: VerificationMode.underAge,
  ),
  AgeThreshold(
    id: 'under-16',
    age: 16,
    title: 'Under 16 Verification',
    description:
        'Verify the user is under 16 years old (GDPR parental consent)',
    mode: VerificationMode.underAge,
  ),
  AgeThreshold(
    id: 'under-18',
    age: 18,
    title: 'Under 18 Verification',
    description: 'Verify the user is under 18 years old (minor status)',
    mode: VerificationMode.underAge,
  ),
  AgeThreshold(
    id: 'under-21',
    age: 21,
    title: 'Under 21 Verification',
    description: 'Verify the user is under 21 years old (youth programs)',
    mode: VerificationMode.underAge,
  ),
];

/// Returns the list of [AgeThreshold] options appropriate for [mode].
List<AgeThreshold> ageThresholdsForMode(VerificationMode mode) {
  switch (mode) {
    case VerificationMode.overAge:
      return overAgeThresholds;
    case VerificationMode.underAge:
      return underAgeThresholds;
  }
}

/// Response from POST /api/create-challenge.
class CreateChallengeResponse {
  /// Server-assigned session identifier.
  final String sessionId;

  /// HTTPS deep link to open in Provii Wallet.
  final String deepLink;

  /// Unix timestamp (seconds) when the challenge expires.
  final int expiresAt;

  /// Creates a [CreateChallengeResponse].
  CreateChallengeResponse({
    required this.sessionId,
    required this.deepLink,
    required this.expiresAt,
  });

  factory CreateChallengeResponse.fromJson(Map<String, dynamic> json) {
    return CreateChallengeResponse(
      sessionId: json['session_id'] as String,
      deepLink: json['deep_link'] as String,
      expiresAt: json['expires_at'] as int,
    );
  }
}

/// Response from GET /api/status/:sessionId.
class StatusResponse {
  /// Current state of the verification flow (e.g. 'pending', 'verified', 'expired').
  final String state;

  /// Whether the verification has been confirmed.
  final bool verified;

  /// Whether the zero knowledge proof itself was valid, if available.
  final bool? proofVerified;

  /// Creates a [StatusResponse].
  StatusResponse({
    required this.state,
    required this.verified,
    this.proofVerified,
  });

  factory StatusResponse.fromJson(Map<String, dynamic> json) {
    return StatusResponse(
      state: json['state'] as String,
      verified: json['verified'] as bool,
      proofVerified: json['proof_verified'] as bool?,
    );
  }
}

/// Response from POST /api/redeem/:sessionId.
class RedeemResponse {
  /// Outcome label from the backend (e.g. 'redeemed').
  final String result;

  /// Whether the challenge was successfully verified and redeemed.
  final bool verified;

  /// Creates a [RedeemResponse].
  RedeemResponse({
    required this.result,
    required this.verified,
  });

  factory RedeemResponse.fromJson(Map<String, dynamic> json) {
    return RedeemResponse(
      result: json['result'] as String,
      verified: json['verified'] as bool,
    );
  }
}

/// States in the verification flow state machine.
enum VerificationState {
  /// No action taken yet.
  initial,

  /// Challenge creation request in flight.
  creating,

  /// Challenge created, waiting to open wallet.
  challengeCreated,

  /// Polling the backend for proof submission.
  polling,

  /// Proof received and valid.
  verified,

  /// Redeem request in flight.
  redeeming,

  /// Challenge fully redeemed.
  redeemed,

  /// Challenge expired before completion.
  expired,

  /// An error occurred during the flow.
  failed,
}

/// Session data stored during an active verification flow.
class VerificationSession {
  /// Server-assigned session identifier.
  final String sessionId;

  /// Deep link URL for Provii Wallet.
  final String deepLink;

  /// When this challenge expires.
  final DateTime expiresAt;

  /// The numeric age boundary being verified.
  final int ageThreshold;

  /// Whether this is an over-age or under-age check.
  final VerificationMode mode;

  /// When this session was created locally.
  final DateTime createdAt;

  /// Creates a [VerificationSession].
  VerificationSession({
    required this.sessionId,
    required this.deepLink,
    required this.expiresAt,
    required this.ageThreshold,
    required this.mode,
    required this.createdAt,
  });
}
