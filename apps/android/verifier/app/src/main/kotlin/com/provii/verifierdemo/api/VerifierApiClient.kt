// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Provii

package com.provii.verifierdemo.api

import com.provii.verifierdemo.BuildConfig
import com.provii.verifierdemo.Config
import com.provii.verifierdemo.data.CreateChallengeRequest
import com.provii.verifierdemo.data.CreateChallengeResponse
import com.provii.verifierdemo.data.RedeemResponse
import com.provii.verifierdemo.data.StatusResponse
import com.provii.verifierdemo.data.VerificationMode
import com.squareup.moshi.Moshi
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory
import okhttp3.OkHttpClient
import okhttp3.logging.HttpLoggingInterceptor
import retrofit2.Response
import retrofit2.Retrofit
import retrofit2.converter.moshi.MoshiConverterFactory
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.Path
import timber.log.Timber
import java.io.IOException
import java.util.concurrent.TimeUnit

/** Retrofit service interface for the verifier backend API. */
interface VerifierApiService {
    /** Creates a new verification challenge with the given age constraints. */
    @POST("api/create-challenge")
    suspend fun createChallenge(@Body request: CreateChallengeRequest): Response<CreateChallengeResponse>

    /** Polls the current status of a verification session. */
    @GET("api/status/{sessionId}")
    suspend fun getStatus(@Path("sessionId") sessionId: String): Response<StatusResponse>

    /** Redeems a verified session, consuming the one-time proof. */
    @POST("api/redeem/{sessionId}")
    suspend fun redeem(@Path("sessionId") sessionId: String): Response<RedeemResponse>
}

/**
 * API client for communicating with the verifier backend.
 *
 * // SECURITY: All requests are authenticated via [DemoTokenManager.interceptor]
 * // which injects the X-Demo-Token header. Logging is restricted to debug builds.
 */
class VerifierApiClient(
    baseUrl: String = BuildConfig.VERIFIER_BACKEND_URL
) {
    private val moshi = Moshi.Builder()
        .addLast(KotlinJsonAdapterFactory())
        .build()

    private val okHttpClient = OkHttpClient.Builder()
        .connectTimeout(30, TimeUnit.SECONDS)
        .readTimeout(30, TimeUnit.SECONDS)
        .writeTimeout(30, TimeUnit.SECONDS)
        .addInterceptor(DemoTokenManager.interceptor)
        .addInterceptor(HttpLoggingInterceptor { message ->
            Timber.tag("VerifierAPI").d(message)
        }.apply {
            // SECURITY: Only log headers in release builds; BODY logging leaks
            // request/response content (including tokens) to logcat.
            level = if (BuildConfig.DEBUG) {
                HttpLoggingInterceptor.Level.BODY
            } else {
                HttpLoggingInterceptor.Level.BASIC
            }
        })
        .build()

    private val retrofit = Retrofit.Builder()
        .baseUrl(baseUrl.trimEnd('/') + "/")
        .client(okHttpClient)
        .addConverterFactory(MoshiConverterFactory.create(moshi))
        .build()

    private val service = retrofit.create(VerifierApiService::class.java)

    /**
     * Creates a verification challenge.
     *
     * @param age The age threshold to verify
     * @param mode Whether to verify over-age or under-age
     * @param expiresIn Challenge expiry time in seconds
     * @return The challenge response containing session ID and deep link
     */
    suspend fun createChallenge(
        age: Int,
        mode: VerificationMode = VerificationMode.OVER_AGE,
        expiresIn: Int = Config.DEFAULT_EXPIRES_IN
    ): Result<CreateChallengeResponse> {
        return try {
            val request = when (mode) {
                VerificationMode.OVER_AGE -> CreateChallengeRequest(minimumAge = age, expiresIn = expiresIn)
                VerificationMode.UNDER_AGE -> CreateChallengeRequest(maximumAge = age, expiresIn = expiresIn)
            }
            val response = service.createChallenge(request)
            val body = response.body()
            if (response.isSuccessful && body != null) {
                Result.success(body)
            } else {
                Result.failure(
                    IOException("Failed to create challenge: ${response.code()} ${response.message()}")
                )
            }
        } catch (e: IOException) {
            Timber.e(e, "Network error creating challenge")
            Result.failure(e)
        }
    }

    /**
     * Gets the current verification status.
     *
     * @param sessionId The session ID to check
     * @return The current status
     */
    suspend fun getStatus(sessionId: String): Result<StatusResponse> {
        return try {
            val response = service.getStatus(sessionId)
            val body = response.body()
            if (response.isSuccessful && body != null) {
                Result.success(body)
            } else {
                Result.failure(
                    IOException("Failed to get status: ${response.code()} ${response.message()}")
                )
            }
        } catch (e: IOException) {
            Timber.e(e, "Network error getting status")
            Result.failure(e)
        }
    }

    /**
     * Redeems a verified challenge.
     *
     * @param sessionId The session ID to redeem
     * @return The redeem response
     */
    suspend fun redeem(sessionId: String): Result<RedeemResponse> {
        return try {
            val response = service.redeem(sessionId)
            val body = response.body()
            if (response.isSuccessful && body != null) {
                Result.success(body)
            } else {
                Result.failure(
                    IOException("Failed to redeem: ${response.code()} ${response.message()}")
                )
            }
        } catch (e: IOException) {
            Timber.e(e, "Network error redeeming challenge")
            Result.failure(e)
        }
    }
}
