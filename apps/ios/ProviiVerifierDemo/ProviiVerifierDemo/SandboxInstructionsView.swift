// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Provii

import SwiftUI

/// Guides the user to enable sandbox mode in Provii Wallet before testing verification.
///
/// Displayed on first launch. Once acknowledged, the user proceeds to the age threshold view.
struct SandboxInstructionsView: View {
    @AppStorage("hasAcknowledgedSandbox") private var hasAcknowledgedSandbox = false

    var body: some View {
        ScrollView {
            VStack(spacing: 24) {
                // Warning icon
                Image(systemName: "exclamationmark.triangle.fill")
                    .font(.system(size: 48))
                    .foregroundColor(.orange)
                    .accessibilityLabel(String(localized: "Warning"))

                Text(String(localized: "Enable Sandbox Mode"))
                    .font(.title)
                    .fontWeight(.bold)
                    .accessibilityAddTraits(.isHeader)

                // swiftlint:disable:next line_length
                Text(String(localized: "Before testing age verification, you need to enable Sandbox Mode in Provii Wallet. This allows testing without real credentials."))
                    .font(.body)
                    .foregroundColor(.secondary)
                    .multilineTextAlignment(.center)

                // Instructions card
                VStack(alignment: .leading, spacing: 16) {
                    Text(String(localized: "Instructions:"))
                        .font(.headline)

                    InstructionRow(number: 1, text: String(localized: "Open Provii Wallet on your device"))
                    InstructionRow(number: 2, text: String(localized: "Go to Settings (gear icon)"))
                    InstructionRow(
                        number: 3,
                        text: String(localized: "Tap the screen 5 times to reveal developer options"))
                    InstructionRow(number: 4, text: String(localized: "Enable \"Sandbox Mode\""))
                    InstructionRow(number: 5, text: String(localized: "The app will restart in sandbox mode"))
                }
                .padding()
                .background(Color(.systemGray6))
                .cornerRadius(12)

                // Info box
                HStack {
                    Image(systemName: "info.circle.fill")
                        .foregroundColor(.blue)
                        .accessibilityLabel(String(localized: "Information"))
                    // swiftlint:disable:next line_length
                    Text(String(localized: "In sandbox mode, you can use demo credentials that were issued from the Provii Issuer Demo app for testing age verification."))
                        .font(.footnote)
                        .foregroundColor(.blue)
                }
                .padding()
                .background(Color.blue.opacity(0.1))
                .cornerRadius(12)

                Button(action: {
                    hasAcknowledgedSandbox = true
                }, label: {
                    Text(String(localized: "I've Enabled Sandbox Mode"))
                        .fontWeight(.semibold)
                        .frame(maxWidth: .infinity)
                        .padding()
                        .background(Color.blue)
                        .foregroundColor(.white)
                        .cornerRadius(12)
                })
            }
            .padding()
        }
        .navigationTitle(String(localized: "Getting Started"))
    }
}

/// A numbered instruction row used in sandbox setup guides.
struct InstructionRow: View {
    /// The step number displayed in the circle.
    let number: Int

    /// The instruction text for this step.
    let text: String

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Text("\(number)")
                .font(.caption)
                .fontWeight(.bold)
                .foregroundColor(.white)
                .frame(width: 24, height: 24)
                .background(Color.blue)
                .clipShape(Circle())

            Text(text)
                .font(.body)
        }
    }
}

#Preview {
    NavigationStack {
        SandboxInstructionsView()
    }
}
