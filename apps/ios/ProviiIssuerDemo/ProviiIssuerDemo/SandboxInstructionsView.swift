// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Provii

import SwiftUI

/// Guides the user to enable sandbox mode in Provii Wallet before testing credential issuance.
///
/// Displayed on first launch. Once acknowledged, the user proceeds to the age selection view.
struct SandboxInstructionsView: View {
    // AppStorage is appropriate for non-sensitive UI state like acknowledgement flags
    @AppStorage("hasAcknowledgedSandbox") private var hasAcknowledgedSandbox = false

    var body: some View {
        VStack(spacing: 24) {
            Spacer()

            // Warning icon and title
            VStack(spacing: 12) {
                HStack(spacing: 4) {
                    Text("\u{26A0}\u{FE0F}")
                        .accessibilityHidden(true)
                    Text(String(localized: "Sandbox Mode Required"))
                        .accessibilityAddTraits(.isHeader)
                }
                .font(.title)
                .fontWeight(.bold)
                .multilineTextAlignment(.center)
            }

            // Instructions
            VStack(alignment: .leading, spacing: 16) {
                Text(String(localized:
                    "This demo uses Provii's sandbox environment. To enable sandbox mode in Provii Wallet:"))
                    .font(.body)
                    .foregroundColor(.secondary)

                VStack(alignment: .leading, spacing: 12) {
                    InstructionRow(number: 1, text: String(localized: "Open Provii Wallet"))
                    InstructionRow(number: 2, text: String(localized: "Go to Settings"))
                    InstructionRow(number: 3, text: String(localized: "Tap the screen 5 times"))
                    InstructionRow(number: 4, text: String(localized: "Enable Sandbox Mode"))
                    InstructionRow(number: 5, text: String(localized: "App will restart"))
                }
            }
            .padding()
            .background(Color(.systemGray6))
            .cornerRadius(12)

            Spacer()

            // Acknowledgement button
            Button {
                hasAcknowledgedSandbox = true
            } label: {
                Text(String(localized: "I've enabled sandbox mode"))
                    .font(.headline)
                    .foregroundColor(.white)
                    .frame(maxWidth: .infinity)
                    .padding()
                    .background(Color.blue)
                    .cornerRadius(12)
            }
        }
        .padding()
    }
}

/// A numbered instruction row used in sandbox setup guides.
struct InstructionRow: View {
    /// The step number displayed to the left.
    let number: Int

    /// The instruction text for this step.
    let text: String

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Text("\(number).")
                .font(.body)
                .fontWeight(.semibold)
                .foregroundColor(.blue)
                .frame(width: 24, alignment: .trailing)

            Text(text)
                .font(.body)
        }
    }
}

#Preview {
    SandboxInstructionsView()
}
