// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Provii

/**
 * Configuration for the Provii Issuer Demo app.
 *
 * For local development with the demo backend:
 * - iOS Simulator: Use http://localhost:3000
 * - Android Emulator: Use http://10.0.2.2:3000 (special alias for host localhost)
 *
 * For production, replace with your actual issuer backend URL.
 */
export const Config = {
  // SECURITY: Points to YOUR issuer backend (NOT provii-issuer directly).
  // Your backend handles HMAC auth and the attestation creation flow.
  ISSUER_BACKEND_URL: 'https://issuer-demo.provii.app',
};
