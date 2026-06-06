// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Provii

/**
 * Type definitions for Provii Verifier Demo
 */

// Verification direction mode
export type VerificationMode = 'over_age' | 'under_age';

// Age threshold options for verification
export interface AgeThreshold {
  id: string;
  age: number;
  title: string;
  description: string;
  mode: VerificationMode;
}

// Response from POST /api/create-challenge
export interface CreateChallengeResponse {
  session_id: string;
  deep_link: string;
  expires_at: number;
  status_url: string;
  proof_direction: string;
}

// Response from GET /api/status/:sessionId
export interface StatusResponse {
  state: 'pending' | 'verified' | 'expired' | 'failed';
  verified: boolean;
  proof_verified?: boolean;
}

// Response from POST /api/redeem/:sessionId
export interface RedeemResponse {
  result: string;
  verified: boolean;
}

// Verification state machine
export type VerificationState =
  | 'initial'
  | 'creating'
  | 'challenge_created'
  | 'polling'
  | 'verified'
  | 'redeeming'
  | 'redeemed'
  | 'expired'
  | 'failed';

// Session data stored during verification
export interface VerificationSession {
  sessionId: string;
  deepLink: string;
  expiresAt: number;
  minimumAge: number;
  createdAt: number;
}
