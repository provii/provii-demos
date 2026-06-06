// Basic Flutter widget test for Provii Issuer Demo.

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:provii_issuer_demo/main.dart';

void main() {
  testWidgets('App builds successfully', (WidgetTester tester) async {
    // Use a phone-sized surface so the SandboxInstructionsScreen Column
    // does not overflow the default 800×600 Flutter test viewport. The
    // RenderFlex overflow throws as a TestFailure even though it is a
    // layout fit issue and not a real assertion failure.
    await tester.binding.setSurfaceSize(const Size(420, 1200));
    addTearDown(() => tester.binding.setSurfaceSize(null));

    await tester.pumpWidget(const ProviiIssuerDemoApp());

    // Initial screen is SandboxInstructionsScreen with the bank-branded
    // app bar title; assert that landing page actually renders.
    expect(find.text('Demo Bank'), findsOneWidget);
    expect(find.text('Sandbox Mode Required'), findsOneWidget);
  });
}
