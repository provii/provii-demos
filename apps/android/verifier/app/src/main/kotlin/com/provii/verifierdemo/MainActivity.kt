// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Provii

package com.provii.verifierdemo

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.viewModels
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.navigation.NavHostController
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import com.provii.verifierdemo.data.VerificationState
import com.provii.verifierdemo.ui.screens.AgeThresholdScreen
import com.provii.verifierdemo.ui.screens.ResultScreen
import com.provii.verifierdemo.ui.screens.SandboxInstructionsScreen
import com.provii.verifierdemo.ui.screens.VerificationScreen
import com.provii.verifierdemo.ui.theme.ProviiVerifierDemoTheme
import timber.log.Timber

/**
 * Navigation routes for the app.
 */
object Routes {
    /** Initial screen showing sandbox setup instructions. */
    const val SANDBOX = "sandbox"
    /** Age threshold selection screen. */
    const val THRESHOLD = "threshold"
    /** Active verification polling screen. */
    const val VERIFICATION = "verification"
    /** Final result screen showing verification outcome. */
    const val RESULT = "result"
}

/** Entry point activity for the Provii Verifier Demo app. */
class MainActivity : ComponentActivity() {
    private val viewModel: MainViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()

        // Initialize Timber for logging in debug builds
        if (BuildConfig.DEBUG) {
            Timber.plant(Timber.DebugTree())
        }

        setContent {
            ProviiVerifierDemoTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    ProviiVerifierApp(viewModel)
                }
            }
        }
    }
}

/** Root composable managing navigation between sandbox, threshold, verification, and result screens. */
@Composable
fun ProviiVerifierApp(viewModel: MainViewModel) {
    val navController = rememberNavController()
    val uiState by viewModel.uiState.collectAsState()
    val context = LocalContext.current

    NavHost(
        navController = navController,
        startDestination = Routes.SANDBOX
    ) {
        composable(Routes.SANDBOX) {
            SandboxInstructionsScreen(
                onContinue = { navController.navigate(Routes.THRESHOLD) }
            )
        }

        composable(Routes.THRESHOLD) {
            AgeThresholdScreen(
                selectedMode = uiState.selectedMode,
                onModeChanged = { viewModel.setMode(it) },
                onVerifyAge = { age, mode ->
                    viewModel.setAge(age)
                    viewModel.startVerification(context, age, mode)
                    navController.navigate(Routes.VERIFICATION)
                }
            )
        }

        composable(Routes.VERIFICATION) {
            VerificationDestination(uiState, navController, viewModel, context)
        }

        composable(Routes.RESULT) {
            ResultScreen(
                verified = uiState.isVerified,
                errorMessage = uiState.errorMessage,
                mode = uiState.selectedMode,
                ageThreshold = uiState.selectedAge,
                onStartOver = {
                    viewModel.reset()
                    navController.navigate(Routes.THRESHOLD) {
                        popUpTo(Routes.SANDBOX) { inclusive = false }
                    }
                }
            )
        }
    }
}

@Composable
private fun VerificationDestination(
    uiState: VerificationUiState,
    navController: NavHostController,
    viewModel: MainViewModel,
    context: android.content.Context
) {
    // Navigate to result when verification completes or fails
    val verificationState = uiState.verificationState
    if (verificationState == VerificationState.REDEEMED ||
        (verificationState == VerificationState.FAILED && uiState.errorMessage != null)
    ) {
        if (navController.currentDestination?.route == Routes.VERIFICATION) {
            navController.navigate(Routes.RESULT) {
                popUpTo(Routes.VERIFICATION) { inclusive = true }
            }
        }
    }

    VerificationScreen(
        uiState = uiState,
        onRetry = {
            viewModel.startVerification(context, uiState.selectedAge, uiState.selectedMode)
        },
        onCancel = {
            viewModel.cancelVerification()
            navController.popBackStack(Routes.THRESHOLD, false)
        },
        onOpenWallet = {
            uiState.session?.deepLink?.let { deepLink ->
                val intent = Intent(Intent.ACTION_VIEW, Uri.parse(deepLink)).apply {
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                }
                context.startActivity(intent)
            }
        }
    )
}
