// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Provii

// Provii Issuer Integration
//
// This file encapsulates the complete flow for issuing age credentials
// to the Provii Wallet. Copy this file into your iOS app.
//
// USAGE:
//   let issuer = ProviiIssuer(backendURL: "https://your-backend.com")
//   try await issuer.issueCredential(dob: "1990-05-15")
//
// REQUIREMENTS:
//   - Your issuer backend running (see backends/issuer/)
//   - Provii Wallet installed on the device
//   - For testing: Sandbox mode enabled in Provii Wallet

import Foundation
import UIKit

// MARK: - Provii Issuer

/// A self-contained client for issuing Provii age credentials.
///
/// Copy this class into your iOS app to add credential issuance. Your backend
/// handles HMAC-SHA256 authentication with the Provii issuer API, and this
/// client opens the wallet via a universal link deep link.
private struct AttestationRequest: Encodable {
    let dob: String
}

private struct AttestationResponse: Decodable {
    let deepLink: String

    enum CodingKeys: String, CodingKey {
        case deepLink = "deep_link"
    }
}

public class ProviiIssuer {

    // =========================================================================
    // CONFIGURATION
    // =========================================================================

    /// The base URL of your issuer backend.
    private let backendURL: String
    private let session: URLSession

    /// Optional demo token for authenticating with the demo backend.
    ///
    /// When set, this token is sent as the `X-Demo-Token` header on all API requests.
    /// The demo app sets this via ``DemoTokenManager``; production integrations do not
    /// need it and can leave this `nil`.
    public var demoToken: String?

    // =========================================================================
    // TYPES
    // =========================================================================

    /// Errors that can occur during credential issuance.
    public enum ProviiError: Error, LocalizedError {
        /// The backend URL is malformed.
        case invalidURL
        /// A network-level error prevented the request from completing.
        case networkError(Error)
        /// The server returned a non-2xx HTTP status code.
        case serverError(Int)
        /// The server response could not be parsed.
        case invalidResponse
        /// Provii Wallet is not installed on the device.
        case walletNotInstalled
        /// The deep link URL could not be opened.
        case cannotOpenURL

        public var errorDescription: String? {
            switch self {
            case .invalidURL:
                return String(localized: "Invalid backend URL configuration.")
            case .networkError(let error):
                return String(localized: "Network error: \(error.localizedDescription)")
            case .serverError(let code):
                return String(localized: "Server error (HTTP \(code))")
            case .invalidResponse:
                return String(localized: "Invalid response from server.")
            case .walletNotInstalled:
                return String(localized: "Provii Wallet is not installed.")
            case .cannotOpenURL:
                return String(localized: "Unable to open Provii Wallet.")
            }
        }
    }

    // =========================================================================
    // INITIALISATION
    // =========================================================================

    /// Initialise the Provii Issuer client.
    ///
    /// - Parameter backendURL: Your issuer backend URL (e.g., "https://issuer.yourcompany.com")
    public init(backendURL: String) {
        self.backendURL = backendURL

        let config = URLSessionConfiguration.default
        config.timeoutIntervalForRequest = 30
        self.session = URLSession(configuration: config)
    }

    // =========================================================================
    // PUBLIC API
    // =========================================================================

    /// Issues a credential for the given date of birth.
    ///
    /// This method calls your backend to create a signed attestation, then opens
    /// Provii Wallet with the deep link. The wallet handles cryptographic verification
    /// and credential storage.
    ///
    /// - Parameter dob: Date of birth in YYYY-MM-DD format (e.g., "1990-05-15")
    /// - Throws: ``ProviiError`` if the request fails or wallet cannot be opened
    @MainActor
    public func issueCredential(dob: String) async throws {
        // SECURITY: Backend creates a signed attestation; this client only forwards the deep link
        let deepLink = try await createAttestation(dob: dob)

        // Validate deep link format before opening
        guard deepLink.hasPrefix("https://provii.app/attest?") else {
            throw ProviiError.invalidResponse
        }

        guard let url = URL(string: deepLink) else {
            throw ProviiError.invalidURL
        }

        // Open Provii Wallet (HTTPS universal link).
        // If the wallet is installed, iOS opens it directly.
        // If not, the user lands on the fallback page at provii.app.
        await UIApplication.shared.open(url)
    }

    // =========================================================================
    // PRIVATE HELPERS
    // =========================================================================

    /// Applies the demo token header to a request when a token is configured.
    private func applyDemoToken(to request: inout URLRequest) {
        if let token = demoToken {
            request.setValue(token, forHTTPHeaderField: "X-Demo-Token")
        }
    }

    private func createAttestation(dob: String) async throws -> String {
        guard let url = URL(string: "\(backendURL)/api/create-attestation-from-dob") else {
            throw ProviiError.invalidURL
        }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        applyDemoToken(to: &request)
        request.httpBody = try JSONEncoder().encode(AttestationRequest(dob: dob))

        let data: Data
        let response: URLResponse

        do {
            (data, response) = try await session.data(for: request)
        } catch {
            throw ProviiError.networkError(error)
        }

        guard let httpResponse = response as? HTTPURLResponse else {
            throw ProviiError.invalidResponse
        }

        guard (200...299).contains(httpResponse.statusCode) else {
            throw ProviiError.serverError(httpResponse.statusCode)
        }

        let attestation = try JSONDecoder().decode(AttestationResponse.self, from: data)
        return attestation.deepLink
    }
}
