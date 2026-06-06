// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Provii

import Foundation

/// Configuration constants for the Provii Verifier Demo app.
///
/// The backend URL can be overridden via the Info.plist key ``VERIFIER_BACKEND_URL``.
/// When no override is set, the sandbox demo backend is used by default.
enum Config {
    /// The URL of your verifier backend (not provii-verifier directly).
    ///
    /// Reads from Info.plist key "VERIFIER_BACKEND_URL" if present, otherwise defaults
    /// to the Provii sandbox verifier demo backend.
    static var verifierBackendURL: String {
        if let plistURL = Bundle.main.object(forInfoDictionaryKey: "VERIFIER_BACKEND_URL") as? String,
           !plistURL.isEmpty {
            return plistURL
        }
        return "https://verifier-demo.provii.app"
    }

    /// Polling interval in seconds between status checks.
    static let pollingInterval: TimeInterval = 1.5

    /// Maximum polling duration in seconds before timing out.
    static let pollingTimeout: TimeInterval = 600
}
