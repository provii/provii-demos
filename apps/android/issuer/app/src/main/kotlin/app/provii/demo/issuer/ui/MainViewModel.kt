// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Provii

package app.provii.demo.issuer.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import app.provii.demo.issuer.BuildConfig
import app.provii.demo.issuer.api.DemoCustomer
import app.provii.demo.issuer.api.IssuerApiClient
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import java.time.LocalDate
import java.time.format.DateTimeFormatter

/**
 * UI state for the main screen
 */
data class MainUiState(
    val isLoading: Boolean = false,
    val error: String? = null,
    val selectedCustomer: DemoCustomer? = null,
    val issueDeepLink: String? = null,
    val isCredentialIssued: Boolean = false
)

/**
 * ViewModel for the main screen.
 *
 * Manages the state of customer selection and credential issuance.
 *
 * SIMPLIFIED FLOW:
 * 1. User selects a demo customer
 * 2. App calls backend /api/create-attestation-from-dob with DOB
 * 3. Backend returns https://provii.app/attest?d=... URL
 * 4. User taps "Issue Credential"
 * 5. App opens the deep link
 * 6. Provii Wallet handles all crypto and issuance
 */
class MainViewModel(
    private val apiClient: IssuerApiClient = IssuerApiClient(BuildConfig.ISSUER_BACKEND_URL)
) : ViewModel() {

    private val _uiState = MutableStateFlow(MainUiState())
    val uiState: StateFlow<MainUiState> = _uiState.asStateFlow()

    /**
     * Demo ages available for testing.
     *
     * Ages are chosen to cover common age verification thresholds
     * from COPPA (13) through elderly demographics (80).
     */
    val demoAges: List<Int> = DEMO_AGE_THRESHOLDS

    companion object {
        /** COPPA compliance threshold. */
        private const val AGE_COPPA = 13
        /** UK/EU digital consent age. */
        private const val AGE_EU_CONSENT = 16
        /** Legal adult in most jurisdictions. */
        private const val AGE_ADULT = 18
        /** US alcohol/cannabis age. */
        private const val AGE_US_ALCOHOL = 21
        /** Middle age demographic. */
        private const val AGE_MIDDLE = 40
        /** Senior demographic. */
        private const val AGE_SENIOR = 60
        /** Elderly demographic. */
        private const val AGE_ELDERLY = 80

        private val DEMO_AGE_THRESHOLDS = listOf(
            AGE_COPPA, AGE_EU_CONSENT, AGE_ADULT, AGE_US_ALCOHOL,
            AGE_MIDDLE, AGE_SENIOR, AGE_ELDERLY
        )

        /**
         * Calculate DOB for a given age (today minus years)
         */
        fun calculateDobForAge(age: Int): String {
            val today = LocalDate.now()
            val dob = today.minusYears(age.toLong())
            return dob.format(DateTimeFormatter.ISO_LOCAL_DATE)
        }
    }

    /**
     * Issue credential for the given age.
     *
     * This is a one-tap flow: clicking an age immediately issues the credential.
     * The backend returns a signed deep link URL, and the app opens it
     * to trigger credential issuance in Provii Wallet.
     *
     * SECURITY: The deep link URL is HMAC-signed by the backend. The app
     * never handles raw credentials or signing keys.
     */
    fun issueForAge(age: Int) {
        val dob = calculateDobForAge(age)

        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(
                isLoading = true,
                error = null,
                issueDeepLink = null,
                selectedCustomer = DemoCustomer("age-$age", "Age $age", age, dob, true)
            )

            apiClient.createAttestationFromDob(dob)
                .onSuccess { response ->
                    _uiState.value = _uiState.value.copy(
                        isLoading = false,
                        issueDeepLink = response.deepLink,
                        isCredentialIssued = true
                    )
                }
                .onFailure { error ->
                    _uiState.value = _uiState.value.copy(
                        isLoading = false,
                        error = error.message ?: "Failed to create attestation"
                    )
                }
        }
    }

    /**
     * Clear any error messages
     */
    fun clearError() {
        _uiState.value = _uiState.value.copy(error = null)
    }

    /**
     * Reset to initial state
     */
    fun reset() {
        _uiState.value = MainUiState()
    }

    override fun onCleared() {
        super.onCleared()
        apiClient.close()
    }
}
