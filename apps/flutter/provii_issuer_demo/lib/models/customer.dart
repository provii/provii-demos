// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Provii

/// Demo ages available for testing age credential issuance.
const List<int> demoAges = [13, 16, 18, 21, 40, 60, 80];

/// Calculates a DOB string in YYYY-MM-DD format for a given [age].
///
/// Uses today's date and subtracts [age] years to produce a date of birth
/// suitable for the attestation API.
String calculateDobForAge(int age) {
  final today = DateTime.now();
  final dob = DateTime(today.year - age, today.month, today.day);
  return '${dob.year}-${dob.month.toString().padLeft(2, '0')}-${dob.day.toString().padLeft(2, '0')}';
}
