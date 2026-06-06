// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Provii

import SwiftUI

/// Root content view that gates the app behind sandbox mode acknowledgement.
///
/// Shows sandbox instructions on first launch. Once the user confirms they have
/// enabled sandbox mode in Provii Wallet, navigates to the age selection flow.
struct ContentView: View {
    // AppStorage is appropriate for non-sensitive UI state like acknowledgement flags
    @AppStorage("hasAcknowledgedSandbox") private var hasAcknowledgedSandbox = false

    var body: some View {
        if hasAcknowledgedSandbox {
            AgeSelectionView()
        } else {
            SandboxInstructionsView()
        }
    }
}

#Preview {
    ContentView()
}
