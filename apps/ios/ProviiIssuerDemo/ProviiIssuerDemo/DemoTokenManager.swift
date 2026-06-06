// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Provii

// Demo Token Manager for Provii Demo Apps
//
// Fetches and caches the rotating demo token from playground.provii.app.
// This token authenticates requests to the demo backends and prevents
// unauthorised bot/spam access.
//
// Token format: demo_token_v1_<YYYYMMDD>_<16-char-hmac>
// Tokens are valid for 48 hours (today + yesterday) for timezone handling.

import Foundation

/// Manages fetching and caching of the rotating demo authentication token.
///
/// The token is refreshed automatically when it approaches expiry. Cached tokens
/// are reused until they fall within one hour of expiration.
class DemoTokenManager {
    /// Shared singleton instance.
    static let shared = DemoTokenManager()

    private let tokenEndpoint = "https://playground.provii.app/v1/config/demo-token"
    private var cachedToken: String?
    private var tokenExpiresAt: TimeInterval = 0

    private init() {}

    /// Fetches the current demo token, returning a cached value if still valid.
    ///
    /// - Returns: The demo token string for use in X-Demo-Token headers
    /// - Throws: ``DemoTokenError`` if the token endpoint is unreachable or returns an error
    func getToken() async throws -> String {
        let now = Date().timeIntervalSince1970

        // Return cached token if still valid (with 1 hour buffer)
        if let token = cachedToken, tokenExpiresAt > now + 3600 {
            return token
        }

        // SECURITY: Token fetched over HTTPS from the demo configuration endpoint
        guard let url = URL(string: tokenEndpoint) else {
            throw DemoTokenError.invalidURL
        }

        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.setValue("application/json", forHTTPHeaderField: "Accept")

        let (data, response) = try await URLSession.shared.data(for: request)

        guard let httpResponse = response as? HTTPURLResponse,
              (200...299).contains(httpResponse.statusCode) else {
            throw DemoTokenError.fetchFailed
        }

        let tokenResponse = try JSONDecoder().decode(DemoTokenResponse.self, from: data)

        cachedToken = tokenResponse.token
        tokenExpiresAt = Double(tokenResponse.expiresAt)

        return tokenResponse.token
    }
}

// MARK: - Supporting Types

/// Errors that can occur when fetching the demo token.
enum DemoTokenError: Error, LocalizedError {
    /// The token endpoint URL is malformed.
    case invalidURL
    /// The token fetch request failed or returned a non-2xx status.
    case fetchFailed

    var errorDescription: String? {
        switch self {
        case .invalidURL:
            return "Invalid demo token endpoint URL"
        case .fetchFailed:
            return "Failed to fetch demo token"
        }
    }
}

/// Response structure from the demo token endpoint.
private struct DemoTokenResponse: Codable {
    let token: String
    let expiresAt: Int
    let cacheSeconds: Int

    enum CodingKeys: String, CodingKey {
        case token
        case expiresAt = "expires_at"
        case cacheSeconds = "cache_seconds"
    }
}
