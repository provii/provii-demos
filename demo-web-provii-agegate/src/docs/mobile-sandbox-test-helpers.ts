// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Provii
//
// Test-only helpers extracted from mobile-sandbox.ts (LOW-8). Import paths
// stay stable for existing tests; production bundles tree-shake this file
// because it is never imported from handler.ts or any prod entry point.

export {
  __signMobileEnvelopeForTests,
  __mobileTestExports,
} from "./mobile-sandbox";
