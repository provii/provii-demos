// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Provii

/**
 * Demo ages available for credential issuance.
 * These match the Android issuer demo implementation.
 */
export const demoAges = [13, 16, 18, 21, 40, 60, 80] as const;

export type DemoAge = (typeof demoAges)[number];

/**
 * Calculate a date of birth for a given age.
 * Returns today's date minus the specified number of years in YYYY-MM-DD format.
 *
 * @param age - The age in years
 * @returns Date string in YYYY-MM-DD format
 */
export function calculateDobForAge(age: number): string {
  const today = new Date();
  const birthYear = today.getFullYear() - age;
  const month = String(today.getMonth() + 1).padStart(2, '0');
  const day = String(today.getDate()).padStart(2, '0');
  return `${birthYear}-${month}-${day}`;
}
