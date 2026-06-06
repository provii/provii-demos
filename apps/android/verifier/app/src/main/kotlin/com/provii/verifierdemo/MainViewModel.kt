// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Provii

package com.provii.verifierdemo

import android.content.Context
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.provii.verifierdemo.data.StatusResponse
import com.provii.verifierdemo.data.VerificationMode
import com.provii.verifierdemo.data.VerificationSession
import com.provii.verifierdemo.data.VerificationState
import com.provii.verifierdemo.provii.ProviiVerifier
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import timber.log.Timber

/** UI state for the verification flow. */
data class VerificationUiState(
    val verificationState: VerificationState = VerificationState.INITIAL,
    val session: VerificationSession? = null,
    val timeRemaining: Int = 0,
    val isVerified: Boolean = false,
    val errorMessage: String? = null,
    val lastStatus: StatusResponse? = null,
    val selectedMode: VerificationMode = VerificationMode.OVER_AGE,
    val selectedAge: Int = 18
)

private const val COUNTDOWN_INTERVAL_MS = 1000L

/** ViewModel for the verification flow, managing challenge creation, polling, and redemption. */
class MainViewModel : ViewModel() {
    private val _uiState = MutableStateFlow(VerificationUiState())
    val uiState: StateFlow<VerificationUiState> = _uiState.asStateFlow()

    private var verifier: ProviiVerifier? = null

    /** Initialises the verifier with the application context. */
    fun initialize(context: Context) {
        if (verifier == null) {
            verifier = ProviiVerifier(context.applicationContext)
        }
    }

    /** Sets the verification mode (over-age or under-age). */
    fun setMode(mode: VerificationMode) {
        _uiState.value = _uiState.value.copy(selectedMode = mode)
    }

    /** Sets the age threshold for verification. */
    fun setAge(age: Int) {
        _uiState.value = _uiState.value.copy(selectedAge = age)
    }

    /**
     * Starts the verification flow with the specified age and mode.
     *
     * // SECURITY: Challenge is created on the backend over HTTPS with a
     * // demo token. The app never handles raw proof material.
     *
     * @param context The Android context
     * @param age The age threshold to verify
     * @param mode Whether to verify over-age or under-age
     */
    fun startVerification(context: Context, age: Int, mode: VerificationMode) {
        initialize(context)

        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(
                verificationState = VerificationState.CREATING,
                errorMessage = null,
                isVerified = false,
                selectedAge = age,
                selectedMode = mode
            )

            val result = verifier?.startVerification(age = age, mode = mode)

            result?.fold(
                onSuccess = { session ->
                    _uiState.value = _uiState.value.copy(
                        verificationState = VerificationState.POLLING,
                        session = session,
                        timeRemaining = session.timeRemainingSeconds()
                    )

                    // Start countdown
                    startCountdown(session)

                    // Start polling
                    verifier?.startPolling(
                        sessionId = session.sessionId,
                        onStatusChange = { status ->
                            _uiState.value = _uiState.value.copy(lastStatus = status)
                        },
                        onVerified = { handleVerified() },
                        onError = { error -> handleError(error) }
                    )
                },
                onFailure = { error ->
                    Timber.e(error, "Failed to start verification")
                    _uiState.value = _uiState.value.copy(
                        verificationState = VerificationState.FAILED,
                        errorMessage = error.message ?: "Failed to start verification"
                    )
                }
            ) ?: run {
                _uiState.value = _uiState.value.copy(
                    verificationState = VerificationState.FAILED,
                    errorMessage = "Verifier not initialized"
                )
            }
        }
    }

    /** Starts the countdown timer, updating [VerificationUiState.timeRemaining] each second. */
    private fun startCountdown(session: VerificationSession) {
        viewModelScope.launch {
            while (_uiState.value.verificationState == VerificationState.POLLING) {
                val remaining = session.timeRemainingSeconds()
                _uiState.value = _uiState.value.copy(timeRemaining = remaining)

                if (remaining <= 0) {
                    handleError("Challenge expired")
                    break
                }

                delay(COUNTDOWN_INTERVAL_MS)
            }
        }
    }

    /**
     * Handles successful verification by redeeming the session.
     *
     * // SECURITY: Redemption is a one-time server-side operation that consumes
     * // the verified proof. The result boolean is authoritative.
     */
    private fun handleVerified() {
        val session = _uiState.value.session ?: return

        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(
                verificationState = VerificationState.REDEEMING
            )

            val result = verifier?.redeem(session.sessionId)

            result?.fold(
                onSuccess = { redeemResponse ->
                    _uiState.value = _uiState.value.copy(
                        verificationState = VerificationState.REDEEMED,
                        isVerified = redeemResponse.verified
                    )
                },
                onFailure = { error ->
                    Timber.e(error, "Failed to redeem")
                    _uiState.value = _uiState.value.copy(
                        verificationState = VerificationState.FAILED,
                        errorMessage = error.message ?: "Failed to redeem verification"
                    )
                }
            ) ?: run {
                _uiState.value = _uiState.value.copy(
                    verificationState = VerificationState.FAILED,
                    errorMessage = "Verifier not initialized"
                )
            }
        }
    }

    /** Handles verification errors by updating UI state and stopping the polling loop. */
    private fun handleError(error: String) {
        _uiState.value = _uiState.value.copy(
            verificationState = VerificationState.FAILED,
            errorMessage = error
        )
        verifier?.stopPolling()
    }

    /** Cancels the current verification and resets state to [VerificationState.INITIAL]. */
    fun cancelVerification() {
        verifier?.stopPolling()
        _uiState.value = _uiState.value.copy(
            verificationState = VerificationState.INITIAL,
            session = null,
            errorMessage = null
        )
    }

    /** Resets the entire verification flow to its initial state. */
    fun reset() {
        verifier?.reset()
        _uiState.value = VerificationUiState()
    }

    override fun onCleared() {
        super.onCleared()
        verifier?.dispose()
    }
}
