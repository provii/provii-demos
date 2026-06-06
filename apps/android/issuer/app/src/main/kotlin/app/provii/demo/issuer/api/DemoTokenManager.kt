// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Provii

/**
 * Demo Token Manager for Provii Demo Apps.
 *
 * Fetches and caches the rotating demo token from playground.provii.app.
 * This token is used to authenticate requests to the demo backends
 * and prevent unauthorised bot/spam access.
 *
 * Token format: demo_token_v1_<YYYYMMDD>_<16-char-hmac>
 * Tokens are valid for 48 hours (today + yesterday) for timezone handling.
 */

package app.provii.demo.issuer.api

import android.util.Log
import app.provii.demo.issuer.BuildConfig
import io.ktor.client.HttpClient
import io.ktor.client.call.body
import io.ktor.client.engine.android.Android
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.client.request.accept
import io.ktor.client.request.get
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.serialization.kotlinx.json.json
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

private const val TAG = "DemoTokenManager"
private const val TOKEN_ENDPOINT = "https://playground.provii.app/v1/config/demo-token"
private const val MILLIS_PER_SECOND = 1000
private const val TOKEN_REFRESH_BUFFER_SECONDS = 3600

@Serializable
private data class DemoTokenResponse(
    val token: String,
    @SerialName("expires_at") val expiresAt: Long,
    @SerialName("cache_seconds") val cacheSeconds: Int
)

/**
 * Singleton manager for demo authentication tokens.
 *
 * Usage:
 * ```kotlin
 * val token = DemoTokenManager.getToken()
 * // Add to your request headers: "X-Demo-Token" to token
 * ```
 */
object DemoTokenManager {
    private var cachedToken: String? = null
    private var tokenExpiresAt: Long = 0

    private val client = HttpClient(Android) {
        install(ContentNegotiation) {
            json(Json {
                ignoreUnknownKeys = true
            })
        }
    }

    /**
     * Get the current demo token, fetching a new one if needed.
     *
     * // SECURITY: Token is fetched over HTTPS and cached with a 1-hour buffer
     * // before expiry to avoid using stale credentials.
     *
     * @return The demo token string
     * @throws java.io.IOException if network request fails
     * @throws IllegalStateException if the server returns a non-200 response
     */
    suspend fun getToken(): String {
        val now = System.currentTimeMillis() / MILLIS_PER_SECOND

        // Return cached token if still valid (with 1 hour buffer)
        cachedToken?.let { token ->
            if (tokenExpiresAt > now + TOKEN_REFRESH_BUFFER_SECONDS) {
                return token
            }
        }

        // Fetch new token
        return try {
            val response = client.get(TOKEN_ENDPOINT) {
                accept(ContentType.Application.Json)
            }

            check(response.status == HttpStatusCode.OK) {
                "Failed to fetch demo token: ${response.status}"
            }

            val tokenResponse = response.body<DemoTokenResponse>()
            cachedToken = tokenResponse.token
            tokenExpiresAt = tokenResponse.expiresAt

            tokenResponse.token
        } catch (e: java.io.IOException) {
            if (BuildConfig.DEBUG) {
                Log.e(TAG, "Network error fetching demo token", e)
            }
            throw e
        }
    }
}
