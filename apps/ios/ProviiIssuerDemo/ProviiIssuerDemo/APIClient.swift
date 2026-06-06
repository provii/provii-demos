// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Provii

// Provii Issuer API Client
//
// INTEGRATION GUIDE
//
// To add Provii credential issuance to your iOS app:
//
// 1. Copy Provii/ProviiIssuer.swift (recommended) or this file
// 2. Update the backend URL to point to your issuer backend
// 3. Call issueCredential(dob:) or createAttestation(dob:)
// 4. Open the returned deep_link with UIApplication.shared.open()
//
// The Provii Wallet handles all cryptography and credential storage.

import Foundation

// MARK: - API Error Types

/// Errors that can occur when communicating with the issuer backend.
enum APIError: Error, LocalizedError {
    /// The configured backend URL is malformed.
    case invalidURL
    /// A network-level error occurred (connectivity, timeout, DNS).
    case networkError(Error)
    /// The server returned a non-JSON or unexpected response.
    case invalidResponse
    /// The server returned a non-2xx HTTP status code.
    case serverError(Int)
    /// The response body could not be decoded from JSON.
    case decodingError

    var errorDescription: String? {
        switch self {
        case .invalidURL:
            return String(localized: "Invalid URL configuration. Please check the backend URL setting.")
        case .networkError:
            return String(localized:
                "Unable to connect to the server. Please check your internet connection and try again.")
        case .invalidResponse:
            return String(localized: "Received an unexpected response from the server.")
        case .serverError(let code):
            if (500...599).contains(code) {
                return String(localized: "The server encountered an error. Please try again later.")
            } else if code == 401 || code == 403 {
                return String(localized: "Authentication failed. Please contact support.")
            } else if code == 404 {
                return String(localized: "The requested resource was not found.")
            } else {
                return String(localized: "The request could not be completed. Please try again.")
            }
        case .decodingError:
            return String(localized: "Unable to process the server response. Please try again.")
        }
    }
}

// MARK: - API Client

/// Demo API client for the issuer backend. For production use, see ``ProviiIssuer``.
class APIClient {
    /// Shared singleton instance.
    static let shared = APIClient()

    private let session: URLSession

    private init() {
        let config = URLSessionConfiguration.default
        config.timeoutIntervalForRequest = 30
        config.timeoutIntervalForResource = 60
        self.session = URLSession(configuration: config)
    }

    // =========================================================================
    // COPY THIS METHOD INTO YOUR APP
    // =========================================================================

    /// Creates an attestation from date of birth.
    ///
    /// Your backend authenticates with HMAC-SHA256. Provii signs the attestation internally.
    /// The returned deep link opens Provii Wallet to complete credential issuance.
    ///
    /// - Parameter dob: Date of birth in YYYY-MM-DD format (e.g., "1990-05-15")
    /// - Returns: ``CreateAttestationResponse`` containing the deep_link
    /// - Throws: ``APIError`` if the request fails
    ///
    /// Example:
    /// ```swift
    /// let response = try await APIClient.shared.createAttestation(dob: "1990-05-15")
    /// if let url = URL(string: response.deepLink) {
    ///     await UIApplication.shared.open(url)
    /// }
    /// ```
    func createAttestation(dob: String) async throws -> CreateAttestationResponse {
        guard let url = URL(string: Config.createAttestationEndpoint) else {
            throw APIError.invalidURL
        }

        // SECURITY: Demo token is fetched for request authentication against the demo backend
        let demoToken = try await DemoTokenManager.shared.getToken()

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue(demoToken, forHTTPHeaderField: "X-Demo-Token")

        let body = CreateAttestationRequest(dob: dob)
        request.httpBody = try JSONEncoder().encode(body)

        let data: Data
        let response: URLResponse

        do {
            (data, response) = try await session.data(for: request)
        } catch {
            throw APIError.networkError(error)
        }

        guard let httpResponse = response as? HTTPURLResponse else {
            throw APIError.invalidResponse
        }

        guard (200...299).contains(httpResponse.statusCode) else {
            throw APIError.serverError(httpResponse.statusCode)
        }

        do {
            let decoder = JSONDecoder()
            return try decoder.decode(CreateAttestationResponse.self, from: data)
        } catch {
            throw APIError.decodingError
        }
    }

    // =========================================================================
    // END OF INTEGRATION CODE
    // =========================================================================
}
