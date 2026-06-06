// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Provii

// API Client for the Provii Verifier Demo app.
//
// Communicates with YOUR verifier backend, not directly with Provii's provii-verifier.

import Foundation

/// Errors that can occur when communicating with the verifier backend.
enum APIError: Error, LocalizedError {
    /// The configured backend URL is malformed.
    case invalidURL
    /// A network-level error occurred (connectivity, timeout, DNS).
    case networkError(Error)
    /// The server returned a non-2xx HTTP status code.
    case serverError(Int)
    /// The server returned a non-JSON or unexpected response.
    case invalidResponse
    /// The requested session was not found (HTTP 404).
    case notFound
    /// The response body could not be decoded from JSON.
    case decodingError(Error)

    var errorDescription: String? {
        switch self {
        case .invalidURL:
            return String(localized: "Invalid server URL")
        case .networkError(let error):
            return String(localized: "Network error: \(error.localizedDescription)")
        case .serverError(let code):
            return String(localized: "Server error (code: \(code))")
        case .invalidResponse:
            return String(localized: "Invalid response from server")
        case .notFound:
            return String(localized: "Session not found")
        case .decodingError(let error):
            return String(localized: "Failed to parse response: \(error.localizedDescription)")
        }
    }
}

/// Demo API client for the verifier backend. For production use, see ``ProviiVerifier``.
class APIClient {
    /// Shared singleton instance.
    static let shared = APIClient()

    private let baseURL: String
    private let session: URLSession

    private init() {
        self.baseURL = Config.verifierBackendURL
        let config = URLSessionConfiguration.default
        config.timeoutIntervalForRequest = 30
        self.session = URLSession(configuration: config)
    }

    /// Creates a new age verification challenge.
    ///
    /// - Parameters:
    ///   - age: The age threshold to verify against
    ///   - mode: Whether to verify over-age or under-age
    ///   - expiresIn: Challenge expiry in seconds (defaults to 300)
    /// - Returns: ``CreateChallengeResponse`` containing the session ID and deep link
    /// - Throws: ``APIError`` if the request fails
     func createChallenge(
        age: Int, mode: VerificationMode, expiresIn: Int = 300
     ) async throws -> CreateChallengeResponse {
        guard let url = URL(string: "\(baseURL)/api/create-challenge") else {
            throw APIError.invalidURL
        }

        // SECURITY: Demo token is fetched for request authentication against the demo backend
        let demoToken = try await DemoTokenManager.shared.getToken()

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue(demoToken, forHTTPHeaderField: "X-Demo-Token")

        let body: CreateChallengeRequest
        switch mode {
        case .overAge:
            body = CreateChallengeRequest(minimumAge: age, maximumAge: nil, expiresIn: expiresIn)
        case .underAge:
            body = CreateChallengeRequest(minimumAge: nil, maximumAge: age, expiresIn: expiresIn)
        }
        request.httpBody = try JSONEncoder().encode(body)

        do {
            let (data, response) = try await session.data(for: request)

            guard let httpResponse = response as? HTTPURLResponse else {
                throw APIError.invalidResponse
            }

            if httpResponse.statusCode != 200 {
                throw APIError.serverError(httpResponse.statusCode)
            }

            return try JSONDecoder().decode(CreateChallengeResponse.self, from: data)
        } catch let error as APIError {
            throw error
        } catch let error as DecodingError {
            throw APIError.decodingError(error)
        } catch {
            throw APIError.networkError(error)
        }
    }

    // UUID v4 format pattern for session ID validation.
    // Pattern is a compile-time constant; NSRegularExpression init only
    // throws for malformed patterns, so this is safe.
    // swiftlint:disable:next force_try
    private static let uuidPattern = try! NSRegularExpression(
        pattern: "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
        options: .caseInsensitive
    )

    /// Validates that a session ID matches UUID format to prevent path traversal.
    private func isValidSessionId(_ sessionId: String) -> Bool {
        let range = NSRange(sessionId.startIndex..<sessionId.endIndex, in: sessionId)
        return Self.uuidPattern.firstMatch(in: sessionId, range: range) != nil
    }

    /// Checks the status of a verification challenge.
    ///
    /// - Parameter sessionId: The session ID returned from ``createChallenge``
    /// - Returns: ``StatusResponse`` with the current verification state
    /// - Throws: ``APIError`` if the request fails or session is not found
    func checkStatus(sessionId: String) async throws -> StatusResponse {
        guard isValidSessionId(sessionId) else {
            throw APIError.invalidURL
        }
        guard let url = URL(string: "\(baseURL)/api/status/\(sessionId)") else {
            throw APIError.invalidURL
        }

        // SECURITY: Demo token is fetched for request authentication against the demo backend
        let demoToken = try await DemoTokenManager.shared.getToken()

        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue(demoToken, forHTTPHeaderField: "X-Demo-Token")

        do {
            let (data, response) = try await session.data(for: request)

            guard let httpResponse = response as? HTTPURLResponse else {
                throw APIError.invalidResponse
            }

            if httpResponse.statusCode == 404 {
                throw APIError.notFound
            }

            if httpResponse.statusCode != 200 {
                throw APIError.serverError(httpResponse.statusCode)
            }

            return try JSONDecoder().decode(StatusResponse.self, from: data)
        } catch let error as APIError {
            throw error
        } catch let error as DecodingError {
            throw APIError.decodingError(error)
        } catch {
            throw APIError.networkError(error)
        }
    }

    /// Redeems a verified challenge to confirm the result.
    ///
    /// - Parameter sessionId: The session ID of a verified challenge
    /// - Returns: ``RedeemResponse`` confirming the verification outcome
    /// - Throws: ``APIError`` if the request fails or session is not found
    func redeemChallenge(sessionId: String) async throws -> RedeemResponse {
        guard isValidSessionId(sessionId) else {
            throw APIError.invalidURL
        }
        guard let url = URL(string: "\(baseURL)/api/redeem/\(sessionId)") else {
            throw APIError.invalidURL
        }

        // SECURITY: Demo token is fetched for request authentication against the demo backend
        let demoToken = try await DemoTokenManager.shared.getToken()

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue(demoToken, forHTTPHeaderField: "X-Demo-Token")

        do {
            let (data, response) = try await session.data(for: request)

            guard let httpResponse = response as? HTTPURLResponse else {
                throw APIError.invalidResponse
            }

            if httpResponse.statusCode == 404 {
                throw APIError.notFound
            }

            if httpResponse.statusCode != 200 {
                throw APIError.serverError(httpResponse.statusCode)
            }

            return try JSONDecoder().decode(RedeemResponse.self, from: data)
        } catch let error as APIError {
            throw error
        } catch let error as DecodingError {
            throw APIError.decodingError(error)
        } catch {
            throw APIError.networkError(error)
        }
    }
}
