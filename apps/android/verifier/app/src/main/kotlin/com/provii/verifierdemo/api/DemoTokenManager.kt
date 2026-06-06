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

package com.provii.verifierdemo.api

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import com.squareup.moshi.Moshi
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import okhttp3.Interceptor
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import timber.log.Timber
import java.util.concurrent.TimeUnit

private const val TOKEN_ENDPOINT = "https://playground.provii.app/v1/config/demo-token"
private const val MILLIS_PER_SECOND = 1000
private const val TOKEN_REFRESH_BUFFER_SECONDS = 3600

@JsonClass(generateAdapter = true)
private data class DemoTokenResponse(
    @Json(name = "token") val token: String,
    @Json(name = "expires_at") val expiresAt: Long,
    @Json(name = "cache_seconds") val cacheSeconds: Int
)

/**
 * Singleton manager for demo authentication tokens.
 *
 * Usage with Retrofit:
 * ```kotlin
 * val okHttpClient = OkHttpClient.Builder()
 *     .addInterceptor(DemoTokenManager.interceptor)
 *     .build()
 * ```
 */
object DemoTokenManager {
    private var cachedToken: String? = null
    private var tokenExpiresAt: Long = 0

    private val moshi = Moshi.Builder()
        .addLast(KotlinJsonAdapterFactory())
        .build()

    private val tokenClient = OkHttpClient.Builder()
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(10, TimeUnit.SECONDS)
        .build()

    /**
     * OkHttp Interceptor that automatically adds the X-Demo-Token header to all requests.
     *
     * // SECURITY: Token is injected into every outbound request. The interceptor
     * // fetches a fresh token when the cached one is near expiry.
     */
    val interceptor: Interceptor = Interceptor { chain ->
        val token = runBlocking { getToken() }
        val newRequest = chain.request().newBuilder()
            .header("X-Demo-Token", token)
            .build()
        chain.proceed(newRequest)
    }

    /**
     * Get the current demo token, fetching a new one if needed.
     *
     * @return The demo token string
     * @throws Exception if token fetch fails
     */
    suspend fun getToken(): String = withContext(Dispatchers.IO) {
        val now = System.currentTimeMillis() / MILLIS_PER_SECOND

        // Return cached token if still valid (with 1 hour buffer)
        cachedToken?.let { token ->
            if (tokenExpiresAt > now + TOKEN_REFRESH_BUFFER_SECONDS) {
                return@withContext token
            }
        }

        // Fetch new token
        try {
            val request = Request.Builder()
                .url(TOKEN_ENDPOINT)
                .get()
                .build()

            val response = tokenClient.newCall(request).execute()

            check(response.isSuccessful) {
                "Failed to fetch demo token: ${response.code}"
            }

            val body = response.body?.string()
            check(!body.isNullOrEmpty()) { "Empty response body" }

            val adapter = moshi.adapter(DemoTokenResponse::class.java)
            val tokenResponse = checkNotNull(adapter.fromJson(body)) {
                "Failed to parse token response"
            }

            cachedToken = tokenResponse.token
            tokenExpiresAt = tokenResponse.expiresAt

            tokenResponse.token
        } catch (e: java.io.IOException) {
            Timber.e(e, "Network error fetching demo token")
            throw e
        } catch (e: IllegalStateException) {
            Timber.e(e, "Invalid demo token response")
            throw e
        }
    }
}
