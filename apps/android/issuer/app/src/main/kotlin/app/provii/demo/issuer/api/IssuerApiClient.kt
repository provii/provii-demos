// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Provii

/**
 * Provii Issuer API Client.
 *
 * To add Provii credential issuance to your Android app:
 *
 * 1. Copy this file into your project
 * 2. Update the baseUrl to point to your issuer backend
 * 3. Call createAttestationFromDob(dob) with the user's date of birth
 * 4. Open the returned deep_link with Intent(ACTION_VIEW, Uri.parse(deep_link))
 *
 * The Provii Wallet handles all cryptography and credential storage.
 */

package app.provii.demo.issuer.api

import android.util.Log
import app.provii.demo.issuer.BuildConfig
import io.ktor.client.HttpClient
import io.ktor.client.call.body
import io.ktor.client.engine.android.Android
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.client.plugins.logging.LogLevel
import io.ktor.client.plugins.logging.Logger
import io.ktor.client.plugins.logging.Logging
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.serialization.kotlinx.json.json
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

private const val TAG = "IssuerApiClient"

/** Demo customer data class. */
data class DemoCustomer(
    val id: String,
    val name: String,
    val age: Int,
    val dob: String,  // Format: YYYY-MM-DD (dynamically calculated from age)
    val kycVerified: Boolean
)

/** Request to create an attestation from a date of birth. */
@Serializable
data class CreateAttestationRequest(
    val dob: String  // Format: YYYY-MM-DD
)

/** Response containing the deep link for credential issuance. */
@Serializable
data class AttestationResponse(
    @SerialName("deep_link") val deepLink: String,
    @SerialName("expires_at") val expiresAt: Long? = null
)

/** Error response from the API. */
@Serializable
data class ErrorResponse(
    val error: String,
    val details: String? = null
)

/**
 * API client for communicating with the demo issuer backend.
 *
 * This client handles all HTTP communication with the issuer backend.
 * The backend returns a signed deep link URL that opens Provii Wallet
 * to initiate credential issuance.
 *
 * SIMPLIFIED FLOW:
 * 1. App calls createAttestationFromDob(dob)
 * 2. Backend returns deep_link URL (https://provii.app/attest?d=...)
 * 3. App opens the deep link
 * 4. Wallet handles all cryptography and issuance
 */
class IssuerApiClient(
    private val baseUrl: String = BuildConfig.ISSUER_BACKEND_URL
) {
    private val client = HttpClient(Android) {
        install(ContentNegotiation) {
            json(Json {
                prettyPrint = true
                isLenient = true
                ignoreUnknownKeys = true
            })
        }

        install(Logging) {
            logger = object : Logger {
                override fun log(message: String) {
                    Log.d(TAG, message)
                }
            }
            // Only log in debug builds to prevent sensitive data exposure in production
            level = if (BuildConfig.DEBUG) LogLevel.ALL else LogLevel.NONE
        }

        expectSuccess = false
    }

    /**
     * Create attestation from date of birth.
     *
     * The backend generates an HMAC-signed deep link URL that the app
     * can open to trigger credential issuance in Provii Wallet.
     *
     * @param dob Date of birth in YYYY-MM-DD format
     * @return Result containing the attestation response or error
     */
    suspend fun createAttestationFromDob(dob: String): Result<AttestationResponse> {
        return try {
            // SECURITY: Demo token authenticates requests to the demo backend.
            // Token is fetched over HTTPS and rotated daily.
            val demoToken = DemoTokenManager.getToken()

            val response = client.post("$baseUrl/api/create-attestation-from-dob") {
                contentType(ContentType.Application.Json)
                header("X-Demo-Token", demoToken)
                setBody(CreateAttestationRequest(dob = dob))
            }

            when (response.status) {
                HttpStatusCode.OK -> {
                    val data = response.body<AttestationResponse>()
                    Result.success(data)
                }
                HttpStatusCode.BadRequest -> {
                    val error = response.body<ErrorResponse>()
                    Result.failure(Exception(error.error))
                }
                else -> {
                    val error = try {
                        response.body<ErrorResponse>()
                    } catch (e: kotlinx.serialization.SerializationException) {
                        Log.w(TAG, "Could not parse error response", e)
                        ErrorResponse(error = "Unknown error: ${response.status}")
                    }
                    Result.failure(Exception(error.error))
                }
            }
        } catch (e: java.io.IOException) {
            if (BuildConfig.DEBUG) {
                Log.e(TAG, "Network error creating attestation", e)
            }
            Result.failure(e)
        }
    }

    /**
     * Close the HTTP client.
     * Call this when the app is shutting down.
     */
    fun close() {
        client.close()
    }
}
