// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Provii
//
// Test-only helpers extracted from feature-flags.ts (LOW-8). Import paths
// stay stable for existing tests; production bundles tree-shake this file.

export { __resetFeatureFlagCacheForTests } from "./feature-flags";
