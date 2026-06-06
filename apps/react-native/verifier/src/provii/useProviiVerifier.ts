// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Provii

/**
 * useProviiVerifier - React Hook for Provii Age Verification
 *
 * This hook encapsulates the complete verifier flow:
 * 1. Create challenge (generates deep link)
 * 2. Open Provii Wallet
 * 3. Poll for verification status
 * 4. Redeem when verified
 *
 * === COPY THIS FILE INTO YOUR PROJECT ===
 * This is a self-contained hook that can be copied into any React Native app.
 * You'll also need: ../api/verifierApi.ts, ../api/demoToken.ts, ../types.ts, ../config.ts
 */

import {useState, useRef, useCallback, useEffect} from 'react';
import {Linking} from 'react-native';
import {Config} from '../config';
import {createChallenge, checkStatus, redeemChallenge} from '../api/verifierApi';
import type {
  VerificationMode,
  VerificationState,
  VerificationSession,
  StatusResponse,
} from '../types';

interface UseProviiVerifierReturn {
 // State
  state: VerificationState;
  session: VerificationSession | null;
  isLoading: boolean;
  error: Error | null;

 // Actions
  startVerification: (age: number, mode?: VerificationMode) => Promise<boolean>;
  redeem: () => Promise<boolean>;
  reset: () => void;
  clearError: () => void;
}

export function useProviiVerifier(): UseProviiVerifierReturn {
  const [state, setState] = useState<VerificationState>('initial');
  const [session, setSession] = useState<VerificationSession | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  const pollingTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const pollingStartTimeRef = useRef<number>(0);
 // Ref tracks session to avoid stale closures in polling/redeem callbacks.
  const sessionRef = useRef<VerificationSession | null>(null);
 // Tracks whether the component is still mounted to prevent setState after unmount.
  const mountedRef = useRef(true);

 // Cleanup polling on unmount and track mounted state
  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      if (pollingTimeoutRef.current) {
        clearTimeout(pollingTimeoutRef.current);
      }
    };
  }, []);

  const stopPolling = useCallback(() => {
    if (pollingTimeoutRef.current) {
      clearTimeout(pollingTimeoutRef.current);
      pollingTimeoutRef.current = null;
    }
  }, []);

  const handleVerified = useCallback(async () => {
    stopPolling();
    if (!mountedRef.current) { return; }
    setState('verified');

 // Auto-redeem when verified. Use ref to avoid stale closure over session state.
    const currentSession = sessionRef.current;
    if (currentSession) {
      if (!mountedRef.current) { return; }
      setState('redeeming');
      try {
        const result = await redeemChallenge(currentSession.sessionId);
        if (!mountedRef.current) { return; }
        if (result.verified) {
          setState('redeemed');
        } else {
          setState('failed');
          setError(new Error('Redemption returned unverified'));
        }
      } catch (err) {
        if (!mountedRef.current) { return; }
        const error = err instanceof Error ? err : new Error('Redemption failed');
        setError(error);
        setState('failed');
        if (__DEV__) {
          console.error('Redemption error:', error);
        }
      }
    }
  }, [stopPolling]);

  const startPolling = useCallback(
    (sessionId: string) => {
      pollingStartTimeRef.current = Date.now();
      setState('polling');

      const poll = async () => {
 // Check for timeout
        const elapsed = Date.now() - pollingStartTimeRef.current;
        if (elapsed > Config.POLLING_TIMEOUT_MS) {
          stopPolling();
          if (!mountedRef.current) { return; }
          setState('expired');
          setError(new Error('Verification timed out'));
          return;
        }

        try {
          const status: StatusResponse = await checkStatus(sessionId);

          if (status.verified || status.proof_verified === true) {
            handleVerified();
            return;
          } else if (status.state === 'expired') {
            stopPolling();
            if (!mountedRef.current) { return; }
            setState('expired');
            setError(new Error('Challenge expired'));
            return;
          } else if (status.state === 'failed') {
            stopPolling();
            if (!mountedRef.current) { return; }
            setState('failed');
            setError(new Error('Verification failed'));
            return;
          }
 // If still pending, schedule next poll after this one completes
        } catch (err) {
 // Don't stop polling on transient errors, just log
          if (__DEV__) {
            console.warn('Polling error (will retry):', err);
          }
        }

 // Schedule next poll only after the current one finishes
        if (mountedRef.current) {
          pollingTimeoutRef.current = setTimeout(poll, Config.POLLING_INTERVAL_MS);
        }
      };

 // Start the first poll after the initial delay
      pollingTimeoutRef.current = setTimeout(poll, Config.POLLING_INTERVAL_MS);
    },
    [stopPolling, handleVerified],
  );

  const startVerification = useCallback(
    async (age: number, mode: VerificationMode = 'over_age'): Promise<boolean> => {
      setIsLoading(true);
      setError(null);
      setState('creating');

      try {
 // 1. Create challenge
        const response = await createChallenge(age, mode);

 // SECURITY: Validate deep link uses the expected HTTPS origin before opening
        if (
          typeof response.deep_link !== 'string' ||
          !response.deep_link.startsWith('https://provii.app/verify?')
        ) {
          throw new Error('Invalid deep link format from backend');
        }

 // 3. Store session
        const newSession: VerificationSession = {
          sessionId: response.session_id,
          deepLink: response.deep_link,
          expiresAt: response.expires_at,
          minimumAge: age,
          createdAt: Date.now(),
        };
        sessionRef.current = newSession;
        setSession(newSession);
        setState('challenge_created');

 // 4. Open wallet (HTTPS universal link; fallback page handles "not installed")
        await Linking.openURL(response.deep_link);

 // 5. Start polling for status
        startPolling(response.session_id);

        setIsLoading(false);
        return true;
      } catch (err) {
        const error =
          err instanceof Error ? err : new Error('Failed to start verification');
        setError(error);
        setState('failed');
        setIsLoading(false);

        if (__DEV__) {
          console.error('Verification error:', error);
        }
        return false;
      }
    },
    [startPolling],
  );

  const redeem = useCallback(async (): Promise<boolean> => {
    if (!session) {
      setError(new Error('No active session'));
      return false;
    }

    setIsLoading(true);
    setState('redeeming');

    try {
      const result = await redeemChallenge(session.sessionId);
      if (result.verified) {
        setState('redeemed');
        setIsLoading(false);
        return true;
      } else {
        setState('failed');
        setError(new Error('Redemption returned unverified'));
        setIsLoading(false);
        return false;
      }
    } catch (err) {
      const error = err instanceof Error ? err : new Error('Redemption failed');
      setError(error);
      setState('failed');
      setIsLoading(false);

      if (__DEV__) {
        console.error('Redemption error:', error);
      }
      return false;
    }
  }, [session]);

  const reset = useCallback(() => {
    stopPolling();
    setState('initial');
    sessionRef.current = null;
    setSession(null);
    setError(null);
    setIsLoading(false);
  }, [stopPolling]);

  const clearError = useCallback(() => {
    setError(null);
  }, []);

  return {
    state,
    session,
    isLoading,
    error,
    startVerification,
    redeem,
    reset,
    clearError,
  };
}
