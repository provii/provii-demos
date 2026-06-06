// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Provii

import Foundation

// MARK: - Verification Mode

/// The direction of age verification.
enum VerificationMode: String, Codable, Hashable {
    /// Verify the user is at or above the threshold age.
    case overAge
    /// Verify the user is below the threshold age.
    case underAge
}

// MARK: - Age Thresholds

/// An age threshold that can be selected for verification.
struct AgeThreshold: Identifiable {
    /// Unique identifier for this threshold.
    let id: String

    /// The age value to verify against.
    let age: Int

    /// Display title for this threshold.
    let title: String

    /// Description text explaining the use case.
    let description: String

    /// Whether this is an over-age or under-age threshold.
    let mode: VerificationMode
}

/// Over-age thresholds available in the demo.
let overAgeThresholds: [AgeThreshold] = [
    AgeThreshold(
        id: "over-13",
        age: 13,
        title: String(localized: "Age 13+ Verification"),
        description: String(localized: "Verify the user is 13 years or older (COPPA compliance)"),
        mode: .overAge
    ),
    AgeThreshold(
        id: "over-18",
        age: 18,
        title: String(localized: "Age 18+ Verification"),
        description: String(localized: "Verify the user is 18 years or older (general adult content)"),
        mode: .overAge
    ),
    AgeThreshold(
        id: "over-21",
        age: 21,
        title: String(localized: "Age 21+ Verification"),
        description: String(localized: "Verify the user is 21 years or older (alcohol, cannabis)"),
        mode: .overAge
    ),
    AgeThreshold(
        id: "over-25",
        age: 25,
        title: String(localized: "Age 25+ Verification"),
        description: String(localized: "Verify the user is 25 years or older (car rental, etc.)"),
        mode: .overAge
    )
]

/// Under-age thresholds available in the demo.
let underAgeThresholds: [AgeThreshold] = [
    AgeThreshold(
        id: "under-13",
        age: 13,
        title: String(localized: "Under 13 Verification"),
        description: String(localized: "Verify the user is under 13 years old (children's content)"),
        mode: .underAge
    ),
    AgeThreshold(
        id: "under-16",
        age: 16,
        title: String(localized: "Under 16 Verification"),
        description: String(localized: "Verify the user is under 16 years old (GDPR parental consent)"),
        mode: .underAge
    ),
    AgeThreshold(
        id: "under-18",
        age: 18,
        title: String(localized: "Under 18 Verification"),
        description: String(localized: "Verify the user is under 18 years old (minor status)"),
        mode: .underAge
    ),
    AgeThreshold(
        id: "under-21",
        age: 21,
        title: String(localized: "Under 21 Verification"),
        description: String(localized: "Verify the user is under 21 years old (youth programs)"),
        mode: .underAge
    )
]

/// Returns the age thresholds for the given verification mode.
///
/// - Parameter mode: The verification mode to filter by
/// - Returns: Array of age thresholds matching the mode
func ageThresholds(for mode: VerificationMode) -> [AgeThreshold] {
    switch mode {
    case .overAge:
        return overAgeThresholds
    case .underAge:
        return underAgeThresholds
    }
}

// MARK: - API Request Types

/// Request body for creating a verification challenge.
struct CreateChallengeRequest: Encodable {
    /// Minimum age requirement (for over-age verification).
    let minimumAge: Int?

    /// Maximum age requirement (for under-age verification).
    let maximumAge: Int?

    /// Challenge expiry in seconds.
    let expiresIn: Int

    enum CodingKeys: String, CodingKey {
        case minimumAge = "minimum_age"
        case maximumAge = "maximum_age"
        case expiresIn = "expires_in"
    }
}

// MARK: - API Response Types

/// Response from the create-challenge endpoint.
struct CreateChallengeResponse: Decodable {
    /// Unique session identifier for polling and redemption.
    let sessionId: String

    /// Deep link URL to open Provii Wallet for verification.
    let deepLink: String

    /// Unix timestamp when the challenge expires.
    let expiresAt: Int64

    /// Optional URL for checking verification status.
    let statusUrl: String?

    /// Direction of the proof (over or under).
    let proofDirection: String?

    enum CodingKeys: String, CodingKey {
        case sessionId = "session_id"
        case deepLink = "deep_link"
        case expiresAt = "expires_at"
        case statusUrl = "status_url"
        case proofDirection = "proof_direction"
    }
}

/// Response from the status polling endpoint.
struct StatusResponse: Decodable {
    /// Current state of the verification (e.g., "pending", "verified", "expired", "failed").
    let state: String

    /// Whether the verification was successful.
    let verified: Bool

    /// Whether the cryptographic proof was verified (optional).
    let proofVerified: Bool?

    enum CodingKeys: String, CodingKey {
        case state
        case verified
        case proofVerified = "proof_verified"
    }
}

/// Response from the redeem endpoint.
struct RedeemResponse: Decodable {
    /// Result string from the redemption.
    let result: String

    /// Whether the verification was confirmed.
    let verified: Bool
}

/// Error response structure from the backend.
struct ErrorResponse: Decodable {
    /// Human-readable error message.
    let error: String

    /// Machine-readable error code (optional).
    let code: String?

    /// Reference ID for support (optional).
    let reference: String?
}

// MARK: - Verification State

/// The current state of the verification flow.
enum VerificationState: Equatable {
    /// No verification has been started.
    case initial
    /// The challenge is being created on the backend.
    case creating
    /// The challenge has been created and the wallet is being opened.
    case challengeCreated
    /// Polling the backend for verification status.
    case polling
    /// The proof has been verified successfully.
    case verified
    /// The verified challenge is being redeemed.
    case redeeming
    /// The challenge has been redeemed successfully.
    case redeemed
    /// The challenge has expired.
    case expired
    /// The verification failed with a reason.
    case failed(String)

    /// Whether this state represents a failure.
    var isFailed: Bool {
        if case .failed = self { return true }
        return false
    }
}

// MARK: - Verification Session

/// Holds the state of an active verification session.
struct VerificationSession {
    /// The backend session identifier.
    let sessionId: String

    /// The deep link URL for opening Provii Wallet.
    let deepLink: String

    /// When the challenge expires.
    let expiresAt: Date

    /// The age being verified.
    let ageThreshold: Int

    /// The verification mode (over-age or under-age).
    let mode: VerificationMode

    /// When this session was created.
    let createdAt: Date
}
