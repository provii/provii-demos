// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Provii

// ProviiVerifier - Integration class for Provii age verification
//
// This class encapsulates the complete verifier flow:
// 1. Create challenge (generates deep link)
// 2. Open Provii Wallet
// 3. Poll for verification status
// 4. Redeem when verified
//
// === COPY THIS FILE INTO YOUR PROJECT ===
// This is a self-contained class that can be copied into any iOS app.
// You will also need the API models from Models.swift.

import Foundation
import UIKit

/// Errors that can occur during the verification flow.
enum ProviiVerifierError: Error, LocalizedError {
    /// The configured backend URL is malformed.
    case invalidURL
    /// A network-level error occurred.
    case networkError(Error)
    /// The server returned a non-2xx HTTP status code.
    case serverError(Int)
    /// The server response could not be parsed.
    case invalidResponse
    /// The deep link returned by the backend is malformed.
    case invalidDeepLink
    /// Provii Wallet is not installed on the device.
    case walletNotInstalled
    /// The deep link URL could not be opened.
    case cannotOpenURL
    /// The verification failed with a given reason.
    case verificationFailed(String)
    /// The verification challenge expired before completion.
    case verificationExpired
    /// Polling exceeded the configured timeout.
    case pollingTimeout
    /// No active verification session exists.
    case noActiveSession

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
        case .invalidDeepLink:
            return String(localized: "Invalid deep link format from backend")
        case .walletNotInstalled:
            return String(localized: "Provii Wallet is not installed")
        case .cannotOpenURL:
            return String(localized: "Could not open Provii Wallet")
        case .verificationFailed(let reason):
            return String(localized: "Verification failed: \(reason)")
        case .verificationExpired:
            return String(localized: "Verification challenge expired")
        case .pollingTimeout:
            return String(localized: "Verification timed out")
        case .noActiveSession:
            return String(localized: "No active verification session")
        }
    }
}

/// Self-contained verifier client for Provii age verification.
///
/// Manages the full lifecycle: challenge creation, wallet handoff, status polling,
/// and challenge redemption. Copy this file and ``Models.swift`` into your project.
class ProviiVerifier {
    private let backendURL: String
    private let session: URLSession
    private var pollingTask: Task<Void, Never>?
    private var currentSession: VerificationSession?

    /// Optional demo token for authenticating with the demo backend.
    ///
    /// When set, this token is sent as the `X-Demo-Token` header on all API requests.
    /// The demo app sets this via ``DemoTokenManager``; production integrations do not
    /// need it and can leave this `nil`.
    var demoToken: String?

    /// Creates a new verifier client.
    ///
    /// - Parameter backendURL: Your verifier backend URL (defaults to the demo backend)
    init(backendURL: String = Config.verifierBackendURL) {
        self.backendURL = backendURL
        let config = URLSessionConfiguration.default
        config.timeoutIntervalForRequest = 30
        self.session = URLSession(configuration: config)
    }

    deinit {
        stopPolling()
    }

    // MARK: - Public API

    /// Creates a verification challenge and opens Provii Wallet.
    ///
    /// - Parameters:
    ///   - age: The age threshold to verify
    ///   - mode: Whether to verify over-age or under-age
    ///   - expiresIn: Challenge expiry in seconds (defaults to 300)
    /// - Returns: The created ``VerificationSession``
    /// - Throws: ``ProviiVerifierError`` if challenge creation or wallet opening fails
    @MainActor
    func startVerification(age: Int, mode: VerificationMode, expiresIn: Int = 300) async throws -> VerificationSession {
        // SECURITY: Challenge created via backend which handles HMAC authentication with provii-verifier
        let response = try await createChallenge(age: age, mode: mode, expiresIn: expiresIn)

        // Validate deep link format before opening
        guard response.deepLink.hasPrefix("https://provii.app/verify?") else {
            throw ProviiVerifierError.invalidDeepLink
        }

        guard let url = URL(string: response.deepLink) else {
            throw ProviiVerifierError.invalidDeepLink
        }

        let verificationSession = VerificationSession(
            sessionId: response.sessionId,
            deepLink: response.deepLink,
            expiresAt: Date(timeIntervalSince1970: TimeInterval(response.expiresAt)),
            ageThreshold: age,
            mode: mode,
            createdAt: Date()
        )
        currentSession = verificationSession

        // Open wallet (HTTPS universal link; fallback page handles "not installed")
        let opened = await UIApplication.shared.open(url)
        guard opened else {
            throw ProviiVerifierError.cannotOpenURL
        }

        return verificationSession
    }

    /// Starts polling for verification status.
    ///
    /// Calls the status endpoint at the configured polling interval until the verification
    /// completes, expires, fails, or the polling timeout is reached.
    ///
    /// - Parameters:
    ///   - sessionId: The session ID to poll
    ///   - onStatusChange: Called each time a status response is received
    ///   - onVerified: Called when the verification succeeds
    ///   - onError: Called when the verification fails, expires, or times out
    func startPolling(
        sessionId: String,
        onStatusChange: @escaping (StatusResponse) -> Void,
        onVerified: @escaping () -> Void,
        onError: @escaping (Error) -> Void
    ) {
        stopPolling()

        let startTime = Date()

        pollingTask = Task {
            while !Task.isCancelled {
                // Check timeout
                let elapsed = Date().timeIntervalSince(startTime)
                if elapsed > Config.pollingTimeout {
                    onError(ProviiVerifierError.pollingTimeout)
                    break
                }

                do {
                    let status = try await checkStatus(sessionId: sessionId)
                    onStatusChange(status)

                    if status.verified || status.proofVerified == true {
                        onVerified()
                        break
                    } else if status.state == "expired" {
                        onError(ProviiVerifierError.verificationExpired)
                        break
                    } else if status.state == "failed" {
                        onError(ProviiVerifierError.verificationFailed("User did not meet age requirement"))
                        break
                    }
                } catch {
                    // Continue polling on transient errors
                    #if DEBUG
                    print("Polling error (will retry): \(error)")
                    #endif
                }

                // Wait before next poll
                try? await Task.sleep(nanoseconds: UInt64(Config.pollingInterval * 1_000_000_000))
            }
        }
    }

    /// Stops any active polling task.
    func stopPolling() {
        pollingTask?.cancel()
        pollingTask = nil
    }

    /// Redeems a verified challenge to confirm the result.
    ///
    /// - Parameter sessionId: The session ID of a verified challenge
    /// - Returns: ``RedeemResponse`` confirming the verification outcome
    /// - Throws: ``ProviiVerifierError`` if the redemption request fails
    @MainActor
    func redeem(sessionId: String) async throws -> RedeemResponse {
        return try await redeemChallenge(sessionId: sessionId)
    }

    /// Resets the verifier state, stopping polling and clearing the session.
    func reset() {
        stopPolling()
        currentSession = nil
    }

    // MARK: - Private Helpers

    /// Applies the demo token header to a request when a token is configured.
    private func applyDemoToken(to request: inout URLRequest) {
        if let token = demoToken {
            request.setValue(token, forHTTPHeaderField: "X-Demo-Token")
        }
    }

    // MARK: - Private API Methods

     private func createChallenge(
        age: Int, mode: VerificationMode, expiresIn: Int
     ) async throws -> CreateChallengeResponse {
        guard let url = URL(string: "\(backendURL)/api/create-challenge") else {
            throw ProviiVerifierError.invalidURL
        }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        applyDemoToken(to: &request)

        let body: CreateChallengeRequest
        switch mode {
        case .overAge:
            body = CreateChallengeRequest(minimumAge: age, maximumAge: nil, expiresIn: expiresIn)
        case .underAge:
            body = CreateChallengeRequest(minimumAge: nil, maximumAge: age, expiresIn: expiresIn)
        }
        request.httpBody = try JSONEncoder().encode(body)

        let (data, response) = try await session.data(for: request)

        guard let httpResponse = response as? HTTPURLResponse else {
            throw ProviiVerifierError.invalidResponse
        }

        if httpResponse.statusCode != 200 {
            throw ProviiVerifierError.serverError(httpResponse.statusCode)
        }

        return try JSONDecoder().decode(CreateChallengeResponse.self, from: data)
    }

    // UUID v4 format pattern for session ID validation.
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

    private func checkStatus(sessionId: String) async throws -> StatusResponse {
        guard isValidSessionId(sessionId) else {
            throw ProviiVerifierError.invalidResponse
        }
        guard let url = URL(string: "\(backendURL)/api/status/\(sessionId)") else {
            throw ProviiVerifierError.invalidURL
        }

        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        applyDemoToken(to: &request)

        let (data, response) = try await session.data(for: request)

        guard let httpResponse = response as? HTTPURLResponse else {
            throw ProviiVerifierError.invalidResponse
        }

        if httpResponse.statusCode != 200 {
            throw ProviiVerifierError.serverError(httpResponse.statusCode)
        }

        return try JSONDecoder().decode(StatusResponse.self, from: data)
    }

    private func redeemChallenge(sessionId: String) async throws -> RedeemResponse {
        guard isValidSessionId(sessionId) else {
            throw ProviiVerifierError.invalidResponse
        }
        guard let url = URL(string: "\(backendURL)/api/redeem/\(sessionId)") else {
            throw ProviiVerifierError.invalidURL
        }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        applyDemoToken(to: &request)

        let (data, response) = try await session.data(for: request)

        guard let httpResponse = response as? HTTPURLResponse else {
            throw ProviiVerifierError.invalidResponse
        }

        if httpResponse.statusCode != 200 {
            throw ProviiVerifierError.serverError(httpResponse.statusCode)
        }

        return try JSONDecoder().decode(RedeemResponse.self, from: data)
    }
}
