// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Provii

import SwiftUI

// Manages the active verification flow: challenge creation, wallet handoff, and status polling.
//
// Creates the challenge on appear, opens Provii Wallet, polls for status, then navigates
// to ResultView when the verification completes or fails.
// swiftlint:disable:next type_body_length
struct VerificationView: View {
    /// The age threshold being verified.
    let threshold: AgeThreshold

    @State private var state: VerificationState = .initial
    @State private var session: VerificationSession?
    @State private var timeRemaining: Int = 0
    @State private var showingResult = false
    @State private var verificationResult: Bool = false
    @State private var errorMessage: String?
    @State private var countdownTimer: Timer?

    private let verifier = ProviiVerifier()

    var body: some View {
        VStack(spacing: 24) {
            Spacer()

            // Status icon
            if case .failed = state {
                Image(systemName: "xmark.circle.fill")
                    .font(.system(size: 60))
                    .foregroundColor(.red)
                    .accessibilityLabel(String(localized: "Verification failed"))
            } else {
                ProgressView()
                    .scaleEffect(1.5)
                    .frame(width: 60, height: 60)
                    .accessibilityLabel(String(localized: "Verification in progress"))
            }

            Text(statusMessage)
                .font(.title3)
                .fontWeight(.semibold)
                .multilineTextAlignment(.center)

            Text(String(localized: "Please complete the age verification in Provii Wallet and return to this app."))
                .font(.body)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal)

            // QR code for cross-device scanning
            if let session = session, !state.isFailed {
                QRCodeView(session.deepLink)

                Text(String(localized: "Scan with Provii Wallet on another device"))
                    .font(.caption)
                    .foregroundColor(.secondary)

                Button(action: {
                    if let url = URL(string: session.deepLink) {
                        UIApplication.shared.open(url)
                    }
                }, label: {
                    Text(String(localized: "Open Provii Wallet"))
                        .fontWeight(.semibold)
                        .frame(maxWidth: .infinity)
                        .padding()
                        .background(Color.blue)
                        .foregroundColor(.white)
                        .cornerRadius(12)
                })
            }

            if timeRemaining > 0 {
                HStack {
                    Text(String(localized: "Time remaining:"))
                        .foregroundColor(.secondary)
                    Text(formatTime(timeRemaining))
                        .fontWeight(.bold)
                        .foregroundColor(.blue)
                }
                .padding()
                .background(Color(.systemGray6))
                .cornerRadius(8)
            }

            // Info card
            VStack(alignment: .leading, spacing: 8) {
                Text(infoCardTitle)
                    .font(.headline)

                Text(infoCardDescription)
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
            .padding()
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Color(.systemGray6))
            .cornerRadius(12)

            Spacer()

            if case .failed = state {
                Button(action: startVerification) {
                    Text(String(localized: "Try Again"))
                        .fontWeight(.semibold)
                        .frame(maxWidth: .infinity)
                        .padding()
                        .background(Color.blue)
                        .foregroundColor(.white)
                        .cornerRadius(12)
                }
            }

            Button(action: cancel) {
                HStack {
                    Image(systemName: "xmark")
                    Text(String(localized: "Cancel Verification"))
                }
                .fontWeight(.medium)
                .frame(maxWidth: .infinity)
                .padding()
                .background(Color.clear)
                .foregroundColor(.red)
                .overlay(
                    RoundedRectangle(cornerRadius: 12)
                        .stroke(Color.red, lineWidth: 1)
                )
            }
        }
        .padding()
        .navigationTitle(String(localized: "Verifying..."))
        .navigationBarBackButtonHidden(true)
        .navigationDestination(isPresented: $showingResult) {
            ResultView(
                verified: verificationResult,
                ageThreshold: threshold.age,
                mode: threshold.mode,
                errorMessage: errorMessage
            )
        }
        .onAppear {
            startVerification()
        }
        .onDisappear {
            countdownTimer?.invalidate()
            countdownTimer = nil
            verifier.stopPolling()
        }
    }

    private var infoCardTitle: String {
        switch threshold.mode {
        case .overAge:
            return String(localized: "Verifying: Age \(threshold.age)+")
        case .underAge:
            return String(localized: "Verifying: Under \(threshold.age)")
        }
    }

    private var infoCardDescription: String {
        let age = threshold.age
        let privacy = String(
            localized: "Their actual date of birth will not be revealed."
        )
        switch threshold.mode {
        case .overAge:
            let zkp = String(
                localized: "The user will prove they are \(age) or older using a zero knowledge proof."
            )
            return "\(zkp) \(privacy)"
        case .underAge:
            let zkp = String(
                localized: "The user will prove they are under \(age) using a zero knowledge proof."
            )
            return "\(zkp) \(privacy)"
        }
    }

    private var statusMessage: String {
        switch state {
        case .initial, .creating:
            return String(localized: "Creating verification challenge...")
        case .challengeCreated:
            return String(localized: "Opening Provii Wallet...")
        case .polling:
            return String(localized: "Waiting for verification...")
        case .verified:
            return String(localized: "Age verified! Completing...")
        case .redeeming:
            return String(localized: "Finalising verification...")
        case .redeemed:
            return String(localized: "Verification complete!")
        case .expired:
            return String(localized: "Challenge expired")
        case .failed(let reason):
            return String(localized: "Verification failed: \(reason)")
        }
    }

    private func startVerification() {
        state = .creating
        errorMessage = nil

        Task {
            do {
                // Fetch the demo token for backend authentication
                verifier.demoToken = try await DemoTokenManager.shared.getToken()

                let newSession = try await verifier.startVerification(age: threshold.age, mode: threshold.mode)
                await MainActor.run {
                    session = newSession
                    state = .polling
                    startTimer()
                    if #available(iOS 17.0, *) {
                        AccessibilityNotification.Announcement(
                            String(localized: "Waiting for verification in Provii Wallet")
                        ).post()
                    } else {
                        UIAccessibility.post(
                            notification: .announcement,
                            argument: String(localized: "Waiting for verification in Provii Wallet"))
                    }
                }

                verifier.startPolling(
                    sessionId: newSession.sessionId,
                    onStatusChange: { _ in
                        // Status updates handled via state transitions
                    },
                    onVerified: {
                        Task {
                            await handleVerified()
                        }
                    },
                    onError: { error in
                        Task {
                            await handleError(error)
                        }
                    }
                )
            } catch {
                await MainActor.run {
                    state = .failed(error.localizedDescription)
                    errorMessage = error.localizedDescription
                    if #available(iOS 17.0, *) {
                        AccessibilityNotification.Announcement(String(localized: "Verification failed")).post()
                    } else {
                        UIAccessibility.post(
                            notification: .announcement,
                            argument: String(localized: "Verification failed"))
                    }
                }
            }
        }
    }

    @MainActor
    private func handleVerified() async {
        state = .verified
        verifier.stopPolling()
        if #available(iOS 17.0, *) {
            AccessibilityNotification.Announcement(String(localized: "Age verified, completing")).post()
        } else {
            UIAccessibility.post(notification: .announcement, argument: String(localized: "Age verified, completing"))
        }

        guard let session = session else {
            state = .failed(String(localized: "No active session"))
            return
        }

        state = .redeeming
        do {
            let result = try await verifier.redeem(sessionId: session.sessionId)
            if result.verified {
                state = .redeemed
                verificationResult = true
                showingResult = true
            } else {
                state = .failed(String(localized: "Redemption returned unverified"))
                errorMessage = String(localized: "Verification could not be completed")
                verificationResult = false
                showingResult = true
            }
        } catch {
            state = .failed(error.localizedDescription)
            errorMessage = error.localizedDescription
            verificationResult = false
            showingResult = true
        }
    }

    @MainActor
    private func handleError(_ error: Error) {
        verifier.stopPolling()
        state = .failed(error.localizedDescription)
        errorMessage = error.localizedDescription
        verificationResult = false
        showingResult = true
        if #available(iOS 17.0, *) {
            AccessibilityNotification.Announcement(String(localized: "Verification failed")).post()
        } else {
            UIAccessibility.post(notification: .announcement, argument: String(localized: "Verification failed"))
        }
    }

    private func startTimer() {
        guard let session = session else { return }
        let expiresAt = Int(session.expiresAt.timeIntervalSince1970)

        // Invalidate any existing timer before creating a new one
        countdownTimer?.invalidate()
        countdownTimer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { timer in
            let now = Int(Date().timeIntervalSince1970)
            let remaining = expiresAt - now
            if remaining <= 0 {
                timer.invalidate()
                countdownTimer = nil
                timeRemaining = 0
            } else {
                timeRemaining = remaining
            }
        }
    }

    /// Formats seconds into a "M:SS" display string.
    private func formatTime(_ seconds: Int) -> String {
        let mins = seconds / 60
        let secs = seconds % 60
        return String(format: "%d:%02d", mins, secs)
    }

    private func cancel() {
        verifier.stopPolling()
        verifier.reset()
    }
}

#Preview {
    NavigationStack {
        VerificationView(threshold: overAgeThresholds[1])
    }
}
