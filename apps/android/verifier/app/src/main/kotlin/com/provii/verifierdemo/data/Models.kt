// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Provii

package com.provii.verifierdemo.data

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

/** State machine for the verification flow. */
enum class VerificationState {
    INITIAL,
    CREATING,
    CHALLENGE_CREATED,
    POLLING,
    VERIFIED,
    REDEEMING,
    REDEEMED,
    EXPIRED,
    FAILED
}

/** Verification direction mode: prove the user is over or under a given age. */
enum class VerificationMode(val value: String) {
    OVER_AGE("over_age"),
    UNDER_AGE("under_age")
}

/** Request body for creating a new verification challenge. */
@JsonClass(generateAdapter = true)
data class CreateChallengeRequest(
    @Json(name = "minimum_age") val minimumAge: Int? = null,
    @Json(name = "maximum_age") val maximumAge: Int? = null,
    @Json(name = "expires_in") val expiresIn: Int
)

/** Response from the create-challenge endpoint containing session details and deep link. */
@JsonClass(generateAdapter = true)
data class CreateChallengeResponse(
    @Json(name = "session_id") val sessionId: String,
    @Json(name = "deep_link") val deepLink: String,
    @Json(name = "expires_at") val expiresAt: Long,
    @Json(name = "status_url") val statusUrl: String? = null,
    @Json(name = "proof_direction") val proofDirection: String? = null
)

/** Polling response indicating current verification state. */
@JsonClass(generateAdapter = true)
data class StatusResponse(
    val state: String,
    val verified: Boolean,
    @Json(name = "proof_verified") val proofVerified: Boolean? = null
)

/** Response from the redeem endpoint confirming whether the proof was valid. */
@JsonClass(generateAdapter = true)
data class RedeemResponse(
    val result: String,
    val verified: Boolean
)

private const val MILLIS_PER_SECOND = 1000L

/** Local representation of an active verification session with expiry tracking. */
data class VerificationSession(
    val sessionId: String,
    val deepLink: String,
    val expiresAt: Long,
    val createdAt: Long = System.currentTimeMillis(),
    val ageThreshold: Int = 18,
    val mode: VerificationMode = VerificationMode.OVER_AGE
) {
    /** Time remaining in seconds until expiry. */
    fun timeRemainingSeconds(): Int {
        val remaining = (expiresAt * MILLIS_PER_SECOND - System.currentTimeMillis()) / MILLIS_PER_SECOND
        return remaining.coerceAtLeast(0).toInt()
    }

    /** Whether the session has expired. */
    fun isExpired(): Boolean = System.currentTimeMillis() > expiresAt * MILLIS_PER_SECOND
}
