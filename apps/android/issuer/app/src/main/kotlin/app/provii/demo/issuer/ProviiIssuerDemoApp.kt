// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Provii

package app.provii.demo.issuer

import android.app.Application
import android.content.Context
import android.content.SharedPreferences

/**
 * Application class for the Provii Issuer Demo app.
 *
 * This demo simulates a bank or service provider that issues age credentials
 * to their customers using Provii's zero knowledge proof infrastructure.
 */
class ProviiIssuerDemoApp : Application() {

    /** Shared preferences for non-sensitive UI state such as sandbox acknowledgement. */
    val preferences: SharedPreferences by lazy {
        getSharedPreferences("provii_issuer_demo", Context.MODE_PRIVATE)
    }

    override fun onCreate() {
        super.onCreate()
        instance = this
    }

    companion object {
        /** Singleton application instance, set during [onCreate]. */
        lateinit var instance: ProviiIssuerDemoApp
            private set

        /** Preferences key tracking whether the user has acknowledged sandbox instructions. */
        const val PREF_SANDBOX_ACKNOWLEDGED = "sandbox_acknowledged"
    }
}
