// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Provii

/**
 * Provii Issuer Integration Hook
 *
 * This hook encapsulates the complete flow for issuing age credentials
 * to the Provii Wallet. Copy this file into your React Native app.
 *
 * USAGE:
 * const { issueCredential, isLoading, error } = useProviiIssuer();
 * await issueCredential('1990-05-15'); // YYYY-MM-DD format
 *
 * REQUIREMENTS:
 * - Your issuer backend running (see backends/issuer/)
 * - Provii Wallet installed on the device
 * - For testing: Sandbox mode enabled in Provii Wallet
 * - Network connectivity to reach the issuer backend
 */

import {useState, useCallback} from 'react';
import {Linking} from 'react-native';
import {getHeadersWithDemoToken} from '../api/demoToken';
import {Config} from '../config';

// ============================================================================
// TYPES
// ============================================================================

interface AttestationResponse {
  deep_link: string;
  dob_days: number;
  expires_at: number;
}

interface UseProviiIssuerResult {
  /** Issue a credential for the given date of birth */
  issueCredential: (dob: string) => Promise<boolean>;
  /** Whether an issuance is currently in progress */
  isLoading: boolean;
  /** The last error that occurred, if any */
  error: Error | null;
  /** Clear the current error */
  clearError: () => void;
}

// ============================================================================
// HOOK IMPLEMENTATION
// ============================================================================

export function useProviiIssuer(): UseProviiIssuerResult {
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  const clearError = useCallback(() => {
    setError(null);
  }, []);

  const issueCredential = useCallback(async (dob: string): Promise<boolean> => {
    setIsLoading(true);
    setError(null);

    try {
 // SECURITY: Call issuer backend to create a signed attestation (demo token auth)
      const headers = await getHeadersWithDemoToken({'Content-Type': 'application/json'});
      const response = await fetch(
        `${Config.ISSUER_BACKEND_URL}/api/create-attestation-from-dob`,
        {
          method: 'POST',
          headers,
          body: JSON.stringify({dob}),
        },
      );

      if (!response.ok) {
        throw new Error('Failed to create attestation');
      }

      let data: AttestationResponse;
      try {
        data = await response.json();
      } catch {
        throw new Error('Failed to parse attestation response');
      }

 // SECURITY: Validate deep link uses the expected HTTPS origin before opening
      if (
        typeof data.deep_link !== 'string' ||
        !data.deep_link.startsWith('https://provii.app/attest?')
      ) {
        throw new Error('Invalid deep link format from backend');
      }

 // Step 3: Open Provii Wallet with the deep link (HTTPS universal link)
 // If the wallet is installed, the OS opens it directly.
 // If not, the user lands on the fallback page at provii.app.
      await Linking.openURL(data.deep_link);
      return true;
    } catch (err) {
      const error = err instanceof Error ? err : new Error('Unknown error');
      setError(error);
      return false;
    } finally {
      setIsLoading(false);
    }
  }, []);

  return {
    issueCredential,
    isLoading,
    error,
    clearError,
  };
}

export default useProviiIssuer;
