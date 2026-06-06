// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Provii

import Flutter
import UIKit

/// iOS application delegate for the Provii Issuer Demo.
///
/// Registers Flutter plugins and delegates lifecycle events to the
/// Flutter engine.
@main
@objc class AppDelegate: FlutterAppDelegate {
  override func application(
    _ application: UIApplication,
    didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?
  ) -> Bool {
    GeneratedPluginRegistrant.register(with: self)
    return super.application(application, didFinishLaunchingWithOptions: launchOptions)
  }
}
