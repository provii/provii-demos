// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Provii

/**
 * Demo Token Manager for Provii Demo Apps
 *
 * Fetches and caches the rotating demo token from playground.provii.app.
 * This token is used to authenticate requests to the demo backends
 * and prevent unauthorised bot/spam access.
 *
 * SECURITY: Token is rotated daily; cached with a 1-hour buffer before expiry.
 * Token format: demo_token_v1_<YYYYMMDD>_<16-char-hmac>
 * Tokens are valid for 48 hours (today + yesterday) for timezone handling.
 */

const DEMO_TOKEN_ENDPOINT = 'https://playground.provii.app/v1/config/demo-token';

interface DemoTokenResponse {
  token: string;
  expires_at: number;
  cache_seconds: number;
}

// Cached token state
let cachedToken: string | null = null;
let tokenExpiresAt: number = 0;

/**
 * Get the current demo token, fetching a new one if needed.
 *
 * @returns Promise resolving to the demo token string
 * @throws Error if token fetch fails
 */
export async function getDemoToken(): Promise<string> {
  const now = Math.floor(Date.now() / 1000);

 // Return cached token if still valid (with 1 hour buffer)
  if (cachedToken && tokenExpiresAt > now + 3600) {
    return cachedToken;
  }

 // Fetch new token
  const response = await fetch(DEMO_TOKEN_ENDPOINT, {
    method: 'GET',
    headers: {
      Accept: 'application/json',
    },
  });

  if (!response.ok) {
    throw new Error(`Failed to fetch demo token: ${response.status}`);
  }

  let data: DemoTokenResponse;
  try {
    data = await response.json();
  } catch {
    throw new Error('Failed to parse demo token response');
  }

  cachedToken = data.token;
  tokenExpiresAt = data.expires_at;

  return cachedToken;
}

/**
 * Get headers with the demo token included.
 * Use this to add auth headers to API requests.
 *
 * @param additionalHeaders - Additional headers to include
 * @returns Promise resolving to headers object with X-Demo-Token
 */
export async function getHeadersWithDemoToken(
  additionalHeaders: Record<string, string> = {},
): Promise<Record<string, string>> {
  const token = await getDemoToken();

  return {
    ...additionalHeaders,
    'X-Demo-Token': token,
  };
}
