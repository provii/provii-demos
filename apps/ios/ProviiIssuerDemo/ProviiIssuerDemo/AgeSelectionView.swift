// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Provii

import SwiftUI

/// Grid view for selecting a demo age and issuing a credential to Provii Wallet.
///
/// The user taps an age button, which calls the issuer backend to create an attestation,
/// then opens Provii Wallet via a deep link to complete credential storage.
struct AgeSelectionView: View {
    @State private var selectedAge: Int?
    @State private var isLoading = false
    @State private var showSuccess = false
    @State private var errorMessage: String?
    @State private var showingError = false

    private let columns = [
        GridItem(.flexible()),
        GridItem(.flexible()),
        GridItem(.flexible())
    ]

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                // Green header with bank icon
                VStack(spacing: 8) {
                    HStack(spacing: 8) {
                        Image(systemName: "building.columns.fill")
                            .font(.title2)
                            .accessibilityLabel(String(localized: "Demo Bank"))
                        Text(String(localized: "Demo Bank"))
                            .font(.title2)
                            .fontWeight(.bold)
                    }
                    .foregroundColor(.white)
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 20)
                .background(Color.green)

                ScrollView {
                    VStack(spacing: 24) {
                        // Title section
                        VStack(spacing: 8) {
                            Text(String(localized: "Issue Age Credential"))
                                .font(.title)
                                .fontWeight(.bold)
                                .accessibilityAddTraits(.isHeader)

                            Text(String(localized: "Tap an age to issue a demo credential to Provii Wallet"))
                                .font(.subheadline)
                                .foregroundColor(.secondary)
                                .multilineTextAlignment(.center)
                        }
                        .padding(.top, 24)

                        if let selected = selectedAge, selected < 18, !showSuccess {
                            HStack(spacing: 8) {
                                Image(systemName: "info.circle.fill")
                                    .foregroundColor(.blue)
                                    .accessibilityHidden(true)
                                // swiftlint:disable:next line_length
                                Text(String(localized: "This credential can be used for under-age verification (e.g., COPPA compliance, child safety features)."))
                                    .font(.caption)
                                    .foregroundColor(.blue)
                            }
                            .padding()
                            .background(Color.blue.opacity(0.1))
                            .cornerRadius(12)
                        }

                        if showSuccess {
                            successCard
                        } else {
                            ageButtonsGrid
                        }

                        Spacer(minLength: 40)
                    }
                    .padding(.horizontal)
                }

                // Footer
                Text(String(localized: "Demo App - Not for production use"))
                    .font(.caption)
                    .foregroundColor(.secondary)
                    .padding(.bottom, 16)
            }
            .navigationBarHidden(true)
            .alert(String(localized: "Error"), isPresented: $showingError) {
                Button(String(localized: "OK"), role: .cancel) {}
            } message: {
                Text(errorMessage ?? String(localized: "An unknown error occurred"))
            }
        }
    }

    private var ageButtonsGrid: some View {
        LazyVGrid(columns: columns, spacing: 16) {
            ForEach(demoAges, id: \.self) { age in
                AgeButton(
                    age: age,
                    isLoading: isLoading && selectedAge == age,
                    isDisabled: isLoading
                ) {
                    Task {
                        await issueCredential(forAge: age)
                    }
                }
                .accessibilityLabel(String(localized: "Issue credential for age \(age)"))
                .accessibilityHint(String(localized: "Double tap to issue a test credential"))
            }
        }
        .padding(.top, 16)
    }

    private var successCard: some View {
        VStack(spacing: 20) {
            Image(systemName: "checkmark.circle.fill")
                .font(.system(size: 60))
                .foregroundColor(.green)
                .accessibilityLabel(String(localized: "Success"))

            Text(String(localized: "Opening Provii Wallet"))
                .font(.headline)

            if let age = selectedAge {
                Text(String(localized: "Age \(age) credential issued"))
                    .font(.subheadline)
                    .foregroundColor(.secondary)
            }

            Button {
                resetState()
            } label: {
                Text(String(localized: "Issue Another"))
                    .font(.headline)
                    .foregroundColor(.white)
                    .frame(maxWidth: .infinity)
                    .padding()
                    .background(Color.blue)
                    .cornerRadius(12)
            }
            .padding(.top, 8)
        }
        .padding(24)
        .background(Color(.systemGray6))
        .cornerRadius(16)
        .padding(.top, 16)
    }

    /// Issues a credential for the given age by calling the issuer backend and opening the wallet.
    ///
    /// - Parameter age: The demo age to issue a credential for
    private func issueCredential(forAge age: Int) async {
        selectedAge = age
        isLoading = true
        errorMessage = nil

        let dob = calculateDobForAge(age)

        do {
            // SECURITY: Demo token is fetched and attached by APIClient for request authentication
            let response = try await APIClient.shared.createAttestation(dob: dob)

            guard let url = URL(string: response.deepLink) else {
                throw APIError.invalidURL
            }

            await MainActor.run {
                showSuccess = true
                isLoading = false
                if #available(iOS 17.0, *) {
                    let msg = String(localized: "Credential issued. Opening Provii Wallet.")
                    AccessibilityNotification.Announcement(msg).post()
                } else {
                    UIAccessibility.post(
                        notification: .announcement,
                        argument: String(localized: "Credential issued. Opening Provii Wallet."))
                }

                UIApplication.shared.open(url) { success in
                    if !success {
                        showSuccess = false
                        errorMessage = String(localized:
                            "Failed to open Provii Wallet. Make sure the app is installed.")
                        showingError = true
                    }
                }
            }
        } catch {
            await MainActor.run {
                isLoading = false
                errorMessage = error.localizedDescription
                showingError = true
            }
        }
    }

    /// Resets all view state to allow issuing another credential.
    private func resetState() {
        selectedAge = nil
        isLoading = false
        showSuccess = false
        errorMessage = nil
    }
}

/// A tappable age button displayed in the grid.
struct AgeButton: View {
    let age: Int
    let isLoading: Bool
    let isDisabled: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            ZStack {
                RoundedRectangle(cornerRadius: 12)
                    .fill(isDisabled && !isLoading ? Color.gray.opacity(0.3) : Color.blue)
                    .frame(height: 80)

                if isLoading {
                    ProgressView()
                        .progressViewStyle(CircularProgressViewStyle(tint: .white))
                        .scaleEffect(1.2)
                } else {
                    Text("\(age)")
                        .font(.system(size: 32, weight: .bold))
                        .foregroundColor(.white)
                }
            }
        }
        .disabled(isDisabled)
    }
}

#Preview {
    AgeSelectionView()
}
