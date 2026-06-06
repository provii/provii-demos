// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Provii

import Foundation

// MARK: - Demo Ages

/// Available demo ages for credential issuance.
let demoAges: [Int] = [13, 16, 18, 21, 40, 60, 80]

// MARK: - Date Calculation

/// Calculates a date of birth string for a given age.
///
/// - Parameter age: The desired age in years
/// - Returns: Date of birth in YYYY-MM-DD format
func calculateDobForAge(_ age: Int) -> String {
    let calendar = Calendar.current
    let today = Date()
    guard let birthDate = calendar.date(byAdding: .year, value: -age, to: today) else {
        // Fallback to a reasonable default
        return "2000-01-01"
    }

    let formatter = DateFormatter()
    formatter.dateFormat = "yyyy-MM-dd"
    return formatter.string(from: birthDate)
}

// MARK: - API Request Models

/// Request body for the create-attestation-from-dob endpoint.
struct CreateAttestationRequest: Encodable {
    /// Date of birth in YYYY-MM-DD format.
    let dob: String
}

// MARK: - API Response Models

/// Response from the create-attestation-from-dob endpoint.
struct CreateAttestationResponse: Decodable {
    /// Deep link URL to open Provii Wallet with the attestation.
    let deepLink: String

    /// The date of birth expressed as days since the Unix epoch (optional).
    let dobDays: Int?

    /// Unix timestamp when the attestation expires.
    let expiresAt: Int

    enum CodingKeys: String, CodingKey {
        case deepLink = "deep_link"
        case dobDays = "dob_days"
        case expiresAt = "expires_at"
    }
}
