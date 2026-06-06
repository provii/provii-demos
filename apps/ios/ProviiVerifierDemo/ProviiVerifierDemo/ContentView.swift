// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Provii

import SwiftUI

/// Root content view that gates the app behind sandbox mode acknowledgement.
///
/// Shows sandbox instructions on first launch. Once the user confirms they have
/// enabled sandbox mode in Provii Wallet, navigates to the age threshold selection.
struct ContentView: View {
    @AppStorage("hasAcknowledgedSandbox") private var hasAcknowledgedSandbox = false

    var body: some View {
        if hasAcknowledgedSandbox {
            NavigationStack {
                AgeThresholdView()
            }
        } else {
            SandboxInstructionsView()
        }
    }
}

#Preview {
    ContentView()
}
