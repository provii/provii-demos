// Basic Flutter widget test for Provii Verifier Demo.

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'package:provii_verifier_demo/main.dart';

void main() {
  testWidgets('App builds successfully', (WidgetTester tester) async {
    // The initial SandboxInstructionsScreen reads from SharedPreferences
    // before deciding whether to auto-navigate; install an empty mock so
    // the future resolves synchronously inside the test.
    SharedPreferences.setMockInitialValues({});

    // Use a phone-sized surface so the SandboxInstructionsScreen Column
    // does not overflow the default Flutter test viewport.
    await tester.binding.setSurfaceSize(const Size(420, 1200));
    addTearDown(() => tester.binding.setSurfaceSize(null));

    await tester.pumpWidget(const ProviiVerifierDemoApp());
    // Drain the SharedPreferences future so the screen leaves the
    // loading-spinner branch.
    await tester.pumpAndSettle();

    expect(find.text('Getting Started'), findsOneWidget);
    expect(find.text('Enable Sandbox Mode'), findsOneWidget);
  });
}
