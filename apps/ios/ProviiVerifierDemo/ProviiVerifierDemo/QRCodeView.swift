// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Provii

import SwiftUI
import CoreImage.CIFilterBuiltins

/// Renders a QR code image from a string payload.
///
/// Used during the verification flow to allow cross-device scanning
/// when the wallet is on a different device from the verifier.
struct QRCodeView: View {
    /// The string content to encode into the QR code.
    let content: String

    /// The display size of the QR code in points.
    let size: CGFloat

    /// Creates a QR code view with the given content and optional size.
    ///
    /// - Parameters:
    ///   - content: The string to encode
    ///   - size: Display size in points (defaults to 220)
    init(_ content: String, size: CGFloat = 220) {
        self.content = content
        self.size = size
    }

    var body: some View {
        if let image = generateQRCode() {
            Image(uiImage: image)
                .interpolation(.none)
                .resizable()
                .scaledToFit()
                .frame(width: size, height: size)
                .accessibilityLabel(String(localized: "QR code for cross-device verification"))
        }
    }

    /// Generates a UIImage containing the QR code.
    ///
    /// - Returns: The rendered QR code image, or nil if generation fails
    private func generateQRCode() -> UIImage? {
        let filter = CIFilter.qrCodeGenerator()
        guard let data = content.data(using: .utf8) else { return nil }
        filter.setValue(data, forKey: "inputMessage")
        filter.setValue("M", forKey: "inputCorrectionLevel")

        guard let ciImage = filter.outputImage else { return nil }

        let scale = size / ciImage.extent.size.width
        let scaledImage = ciImage.transformed(by: CGAffineTransform(scaleX: scale, y: scale))

        let context = CIContext()
        guard let cgImage = context.createCGImage(scaledImage, from: scaledImage.extent) else {
            return nil
        }

        return UIImage(cgImage: cgImage)
    }
}
