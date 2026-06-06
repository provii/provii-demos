// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Provii

package com.provii.verifierdemo.provii

import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.net.Uri
import com.provii.verifierdemo.BuildConfig
import com.provii.verifierdemo.Config
import com.provii.verifierdemo.api.VerifierApiClient
import com.provii.verifierdemo.data.RedeemResponse
import com.provii.verifierdemo.data.StatusResponse
import com.provii.verifierdemo.data.VerificationMode
import com.provii.verifierdemo.data.VerificationSession
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import timber.log.Timber

/**
 * Main integration class for Provii age verification.
 *
 * This class handles the complete verification flow:
 * 1. Creating a verification challenge
 * 2. Opening Provii Wallet for user verification
 * 3. Polling for verification status
 * 4. Redeeming verified challenges
 *
 * Usage:
 * ```kotlin
 * val verifier = ProviiVerifier(context)
 *
 * // Start verification
 * val session = verifier.startVerification(age = 21, mode = VerificationMode.OVER_AGE)
 *
 * // Poll for status
 * verifier.startPolling(
 *     sessionId = session.sessionId,
 *     onStatusChange = { status -> ... },
 *     onVerified = { ... },
 *     onError = { error -> ... }
 * )
 *
 * // When done
 * verifier.dispose()
 * ```
 */
class ProviiVerifier(
    private val context: Context,
    backendUrl: String = BuildConfig.VERIFIER_BACKEND_URL
) {
    private val apiClient = VerifierApiClient(backendUrl)
    private val scope = CoroutineScope(Dispatchers.Main)
    private var pollingJob: Job? = null
    private var pollingStartTime: Long = 0

    /**
     * Starts the verification flow.
     *
     * Creates a challenge on the backend and opens Provii Wallet.
     *
     * // SECURITY: The challenge is created server-side. The deep link URL is
     * // opened via an Android Intent; no proof material passes through app memory.
     *
     * @param age The age threshold to verify
     * @param mode Whether to verify over-age or under-age
     * @param expiresIn Challenge expiry time in seconds (default: 300)
     * @return The verification session
     */
    suspend fun startVerification(
        age: Int = 18,
        mode: VerificationMode = VerificationMode.OVER_AGE,
        expiresIn: Int = Config.DEFAULT_EXPIRES_IN
    ): Result<VerificationSession> {
        Timber.d("Starting verification (age=$age, mode=${mode.value})")

        val challengeResult = apiClient.createChallenge(age, mode, expiresIn)

        return challengeResult.map { response ->
            val session = VerificationSession(
                sessionId = response.sessionId,
                deepLink = response.deepLink,
                expiresAt = response.expiresAt,
                ageThreshold = age,
                mode = mode
            )

            // Open Provii Wallet
            openProvii(response.deepLink)

            session
        }
    }

    /** Opens Provii Wallet with the verification deep link. */
    private fun openProvii(deepLink: String) {
        try {
            val intent = Intent(Intent.ACTION_VIEW, Uri.parse(deepLink)).apply {
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            context.startActivity(intent)
            Timber.d("Opened Provii Wallet")
        } catch (e: ActivityNotFoundException) {
            Timber.e(e, "Failed to open Provii Wallet")
            error("Provii Wallet is not installed")
        }
    }

    /**
     * Starts polling for verification status.
     *
     * @param sessionId The session ID to poll
     * @param onStatusChange Called when status changes
     * @param onVerified Called when verification is complete
     * @param onError Called on error or timeout
     */
    fun startPolling(
        sessionId: String,
        onStatusChange: (StatusResponse) -> Unit,
        onVerified: () -> Unit,
        onError: (String) -> Unit
    ) {
        stopPolling()
        pollingStartTime = System.currentTimeMillis()

        Timber.d("Starting polling for session $sessionId")

        pollingJob = scope.launch {
            pollUntilComplete(sessionId, onStatusChange, onVerified, onError)
        }
    }

    private suspend fun pollUntilComplete(
        sessionId: String,
        onStatusChange: (StatusResponse) -> Unit,
        onVerified: () -> Unit,
        onError: (String) -> Unit
    ) {
        while (scope.isActive) {
            if (System.currentTimeMillis() - pollingStartTime > Config.POLLING_TIMEOUT_MS) {
                Timber.w("Polling timeout reached")
                onError("Verification timed out")
                break
            }

            val result = apiClient.getStatus(sessionId)

            result.fold(
                onSuccess = { status ->
                    Timber.d(
                        "Status: %s, verified: %s, proof_verified: %s",
                        status.state, status.verified, status.proofVerified
                    )
                    onStatusChange(status)

                    if (handleStatusTransition(status, onVerified, onError)) return
                },
                onFailure = { statusError ->
                    Timber.e(statusError, "Polling error")
                    // Don't stop on transient errors, keep polling
                }
            )

            delay(Config.POLLING_INTERVAL_MS)
        }
    }

    /**
     * Handles a status transition, returning true if polling should stop.
     */
    private fun handleStatusTransition(
        status: StatusResponse,
        onVerified: () -> Unit,
        onError: (String) -> Unit
    ): Boolean {
        val shouldStop = when {
            status.verified || status.proofVerified == true -> {
                Timber.d(
                    "Verification complete (verified=%s, proof_verified=%s)",
                    status.verified, status.proofVerified
                )
                onVerified()
                true
            }
            status.state.equals("expired", ignoreCase = true) -> {
                Timber.w("Challenge expired")
                onError("Verification challenge expired")
                true
            }
            status.state.equals("failed", ignoreCase = true) -> {
                Timber.w("Verification failed")
                onError("Verification failed")
                true
            }
            else -> false
        }
        return shouldStop
    }

    /** Stops the polling loop and cancels the coroutine job. */
    fun stopPolling() {
        pollingJob?.cancel()
        pollingJob = null
        Timber.d("Stopped polling")
    }

    /**
     * Redeems a verified challenge.
     *
     * Call this after onVerified is triggered.
     *
     * @param sessionId The session ID to redeem
     * @return The redeem response
     */
    suspend fun redeem(sessionId: String): Result<RedeemResponse> {
        Timber.d("Redeeming session $sessionId")
        return apiClient.redeem(sessionId)
    }

    /** Resets the verifier state by stopping any active polling. */
    fun reset() {
        stopPolling()
        Timber.d("Verifier reset")
    }

    /** Disposes of resources by stopping polling. Call when the verifier is no longer needed. */
    fun dispose() {
        stopPolling()
        Timber.d("Verifier disposed")
    }

    companion object {
        /**
         * Checks if Provii Wallet is installed.
         * With HTTPS universal links, this check is informational only.
         * The fallback page at provii.app handles the "not installed" case.
         */
        fun isProviiInstalled(context: Context): Boolean {
            val intent = Intent(Intent.ACTION_VIEW, Uri.parse("provii://"))
            return intent.resolveActivity(context.packageManager) != null
        }
    }
}
