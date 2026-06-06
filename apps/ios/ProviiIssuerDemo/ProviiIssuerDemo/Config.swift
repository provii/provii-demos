// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Provii

import Foundation

// MARK: - App Configuration

/// Configuration constants for the Provii Issuer Demo app.
///
/// The backend URL can be overridden via the Info.plist key ``BACKEND_URL``.
/// When no override is set, the sandbox demo backend is used by default.
enum Config {
    /// Backend URL for the issuer API.
    ///
    /// Reads from Info.plist key "BACKEND_URL" if present, otherwise defaults to
    /// the Provii sandbox issuer demo backend.
    static var backendURL: String {
        if let plistURL = Bundle.main.object(forInfoDictionaryKey: "BACKEND_URL") as? String,
           !plistURL.isEmpty {
            return plistURL
        }
        return "https://issuer-demo.provii.app"
    }

    /// Full URL for the create-attestation-from-dob endpoint.
    static var createAttestationEndpoint: String {
        return "\(backendURL)/api/create-attestation-from-dob"
    }
}
