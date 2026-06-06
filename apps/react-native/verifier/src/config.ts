// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Provii

/**
 * Configuration for the Provii Verifier Demo app.
 *
 * For local development with the demo backend:
 * - iOS Simulator: Use http://localhost:3001
 * - Android Emulator: Use http://10.0.2.2:3001 (special alias for host localhost)
 *
 * For production, replace with your actual verifier backend URL.
 */
export const Config = {
 // SECURITY: Points to YOUR verifier backend (NOT provii-verifier directly).
 // Your backend handles PKCE, HMAC auth, session management, and redemption.
  VERIFIER_BACKEND_URL: 'https://verifier-demo.provii.app',

 // Polling configuration
  POLLING_INTERVAL_MS: 1500, // 1.5 seconds between status checks
  POLLING_TIMEOUT_MS: 600000, // 10 minutes max polling time
};
