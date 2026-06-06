// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Provii

import SwiftUI

/// Age threshold selection view for choosing which age requirement to verify.
///
/// Supports both over-age and under-age verification modes via a segmented picker.
/// Each threshold navigates to the verification flow when tapped.
struct AgeThresholdView: View {
    @State private var selectedMode: VerificationMode = .overAge

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Picker(String(localized: "Verification Mode"), selection: $selectedMode) {
                Text(String(localized: "Over Age"))
                    .tag(VerificationMode.overAge)
                Text(String(localized: "Under Age"))
                    .tag(VerificationMode.underAge)
            }
            .pickerStyle(.segmented)
            .padding(.horizontal)
            .accessibilityHint(String(localized: "Switch between over-age and under-age verification modes"))

            Text(descriptionText)
                .font(.subheadline)
                .foregroundColor(.secondary)
                .padding(.horizontal)

            List(ageThresholds(for: selectedMode)) { threshold in
                NavigationLink(destination: VerificationView(threshold: threshold)) {
                    AgeThresholdRow(threshold: threshold)
                }
            }
            .listStyle(.plain)

            Text(String(localized:
                "Powered by zero knowledge proofs. The user's actual age is never revealed to your application."))
                .font(.caption)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)
                .padding()
        }
        .navigationTitle(String(localized: "Verify Age"))
    }

    private var descriptionText: String {
        switch selectedMode {
        case .overAge:
            // swiftlint:disable:next line_length
            return String(localized: "Select the minimum age you want to verify. The user will prove they meet this requirement without revealing their actual date of birth.")
        case .underAge:
            // swiftlint:disable:next line_length
            return String(localized: "Select the maximum age you want to verify. The user will prove they are under this age without revealing their actual date of birth.")
        }
    }
}

/// A row displaying an age threshold with a circle indicator and description text.
struct AgeThresholdRow: View {
    /// The age threshold to display.
    let threshold: AgeThreshold

    var body: some View {
        HStack(spacing: 16) {
            ageCircle
                .accessibilityLabel(ageCircleAccessibilityLabel)

            VStack(alignment: .leading, spacing: 4) {
                Text(threshold.title)
                    .font(.body)
                    .fontWeight(.medium)
                    .accessibilityAddTraits(.isHeader)

                Text(threshold.description)
                    .font(.caption)
                    .foregroundColor(.secondary)
            }

            Spacer()
        }
        .padding(.vertical, 8)
    }

    @ViewBuilder
    private var ageCircle: some View {
        switch threshold.mode {
        case .overAge:
            Text("\(threshold.age)+")
                .font(.headline)
                .fontWeight(.bold)
                .foregroundColor(.blue)
                .frame(width: 56, height: 56)
                .background(Color.blue.opacity(0.1))
                .clipShape(Circle())
        case .underAge:
            Text("<\(threshold.age)")
                .font(.headline)
                .fontWeight(.bold)
                .foregroundColor(.orange)
                .frame(width: 56, height: 56)
                .background(Color.orange.opacity(0.1))
                .clipShape(Circle())
        }
    }

    private var ageCircleAccessibilityLabel: String {
        switch threshold.mode {
        case .overAge:
            return String(localized: "Age \(threshold.age) and older")
        case .underAge:
            return String(localized: "Under age \(threshold.age)")
        }
    }
}

#Preview {
    NavigationStack {
        AgeThresholdView()
    }
}
