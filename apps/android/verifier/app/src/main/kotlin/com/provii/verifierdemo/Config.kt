// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Provii

package com.provii.verifierdemo

/**
 * Configuration for the Provii Verifier Demo app.
 *
 * The verifier backend URL lives in `BuildConfig.VERIFIER_BACKEND_URL` so it can
 * be overridden per build variant. See `app/build.gradle.kts` for the default.
 */
object Config {
    /**
     * Polling interval in milliseconds when waiting for verification.
     */
    const val POLLING_INTERVAL_MS = 1500L

    /**
     * Maximum polling duration before timeout (10 minutes).
     */
    const val POLLING_TIMEOUT_MS = 600_000L

    /**
     * Default challenge expiry time in seconds.
     */
    const val DEFAULT_EXPIRES_IN = 300
}
