// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Provii

/**
 * Verifier Backend API Client
 *
 * SECURITY: This client communicates with YOUR verifier backend, not
 * directly with Provii's provii-verifier. Your backend handles PKCE
 * code_verifier generation, HMAC authentication, session management,
 * and redemption with code_verifier.
 */

import {Config} from '../config';
import type {
  CreateChallengeResponse,
  StatusResponse,
  RedeemResponse,
  VerificationMode,
} from '../types';
import {getHeadersWithDemoToken} from './demoToken';

const API_BASE = Config.VERIFIER_BACKEND_URL;

/** UUID v4 format pattern for session ID validation. */
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Validates that a session ID matches UUID format to prevent path traversal. */
function isValidSessionId(sessionId: string): boolean {
  return UUID_PATTERN.test(sessionId);
}

/**
 * Create a new age verification challenge.
 *
 * @param age - The age threshold to verify (e.g., 18, 21)
 * @param mode - Verification mode: 'over_age' or 'under_age'
 * @param expiresIn - Optional expiration time in seconds (default: 300, max: 300)
 * @returns Challenge response with session_id and deep_link
 */
export async function createChallenge(
  age: number,
  mode: VerificationMode = 'over_age',
  expiresIn: number = 300,
): Promise<CreateChallengeResponse> {
  const headers = await getHeadersWithDemoToken({'Content-Type': 'application/json'});

  const body =
    mode === 'under_age'
      ? {maximum_age: age, expires_in: expiresIn}
      : {minimum_age: age, expires_in: expiresIn};

  const response = await fetch(`${API_BASE}/api/create-challenge`, {
    method: 'POST',
    headers,
    body: JSON.stringify(body),
  });

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(
      errorData.error || `Failed to create challenge: ${response.status}`,
    );
  }

  try {
    return await response.json();
  } catch {
    throw new Error('Failed to parse challenge response');
  }
}

/**
 * Check the status of a verification challenge.
 *
 * @param sessionId - The session ID from challenge creation
 * @returns Current verification status
 */
export async function checkStatus(sessionId: string): Promise<StatusResponse> {
  if (!isValidSessionId(sessionId)) {
    throw new Error('Invalid session ID format');
  }

  const headers = await getHeadersWithDemoToken({'Content-Type': 'application/json'});

  const response = await fetch(`${API_BASE}/api/status/${sessionId}`, {
    method: 'GET',
    headers,
  });

  if (!response.ok) {
    if (response.status === 404) {
      throw new Error('Session not found or expired');
    }
    const errorData = await response.json().catch(() => ({}));
    throw new Error(
      errorData.error || `Failed to check status: ${response.status}`,
    );
  }

  try {
    return await response.json();
  } catch {
    throw new Error('Failed to parse status response');
  }
}

/**
 * Redeem a verified challenge.
 * Only call this after status shows verified: true.
 *
 * @param sessionId - The session ID from challenge creation
 * @returns Redemption result
 */
export async function redeemChallenge(
  sessionId: string,
): Promise<RedeemResponse> {
  if (!isValidSessionId(sessionId)) {
    throw new Error('Invalid session ID format');
  }

  const headers = await getHeadersWithDemoToken({'Content-Type': 'application/json'});

  const response = await fetch(`${API_BASE}/api/redeem/${sessionId}`, {
    method: 'POST',
    headers,
  });

  if (!response.ok) {
    if (response.status === 404) {
      throw new Error('Session not found');
    }
    const errorData = await response.json().catch(() => ({}));
    throw new Error(
      errorData.error || `Failed to redeem challenge: ${response.status}`,
    );
  }

  try {
    return await response.json();
  } catch {
    throw new Error('Failed to parse redeem response');
  }
}
