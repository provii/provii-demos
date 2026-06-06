// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Provii

package com.provii.verifierdemo.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Cancel
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.provii.verifierdemo.R
import com.provii.verifierdemo.VerificationUiState
import com.provii.verifierdemo.data.VerificationMode
import com.provii.verifierdemo.data.VerificationState
import com.provii.verifierdemo.ui.components.QrCodeImage

private const val SECONDS_PER_MINUTE = 60
private const val TIME_PAD_LENGTH = 2

/** Active verification screen showing QR code, countdown timer, and polling status. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun VerificationScreen(
    uiState: VerificationUiState,
    onRetry: () -> Unit,
    onCancel: () -> Unit,
    onOpenWallet: () -> Unit = {}
) {
    val isFailed = uiState.verificationState == VerificationState.FAILED

    Scaffold(
        topBar = { VerificationTopBar() }
    ) { paddingValues ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues)
                .padding(20.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Spacer(modifier = Modifier.weight(1f))

            StatusSection(isFailed, uiState)

            QrCodeSection(uiState, isFailed, onOpenWallet)

            TimeRemainingBadge(uiState, isFailed)

            VerificationInfoCard(uiState)

            // Error message
            if (uiState.errorMessage != null) {
                Spacer(modifier = Modifier.height(16.dp))
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(
                        containerColor = MaterialTheme.colorScheme.errorContainer
                    )
                ) {
                    Text(
                        text = uiState.errorMessage,
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onErrorContainer,
                        modifier = Modifier.padding(16.dp)
                    )
                }
            }

            Spacer(modifier = Modifier.weight(1f))

            RetryButton(isFailed, onRetry)

            CancelButton(onCancel)
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun VerificationTopBar() {
    TopAppBar(
        title = { Text(stringResource(R.string.verification_title)) },
        colors = TopAppBarDefaults.topAppBarColors(
            containerColor = MaterialTheme.colorScheme.primaryContainer,
            titleContentColor = MaterialTheme.colorScheme.onPrimaryContainer
        )
    )
}

@Composable
private fun StatusSection(isFailed: Boolean, uiState: VerificationUiState) {
    val errorDescription = stringResource(R.string.verification_error_icon)
    val progressDescription = stringResource(R.string.verification_progress)

    if (isFailed) {
        Icon(
            imageVector = Icons.Default.Cancel,
            contentDescription = errorDescription,
            modifier = Modifier.size(60.dp),
            tint = MaterialTheme.colorScheme.error
        )
    } else {
        CircularProgressIndicator(
            modifier = Modifier
                .size(60.dp)
                .semantics { contentDescription = progressDescription },
            strokeWidth = 4.dp
        )
    }

    Spacer(modifier = Modifier.height(24.dp))

    Text(
        text = getStatusMessage(uiState.verificationState),
        style = MaterialTheme.typography.titleLarge,
        textAlign = TextAlign.Center,
        modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite }
    )

    Spacer(modifier = Modifier.height(12.dp))

    Text(
        text = stringResource(R.string.verification_instructions),
        style = MaterialTheme.typography.bodyMedium,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        textAlign = TextAlign.Center
    )
}

@Composable
private fun QrCodeSection(
    uiState: VerificationUiState,
    isFailed: Boolean,
    onOpenWallet: () -> Unit
) {
    if (uiState.session == null || isFailed) return

    Spacer(modifier = Modifier.height(24.dp))

    QrCodeImage(
        content = uiState.session.deepLink,
        modifier = Modifier.size(220.dp),
        contentDescription = stringResource(R.string.qr_code_description)
    )

    Spacer(modifier = Modifier.height(8.dp))

    Text(
        text = stringResource(R.string.qr_code_label),
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        textAlign = TextAlign.Center
    )

    Spacer(modifier = Modifier.height(16.dp))

    Button(
        onClick = onOpenWallet,
        modifier = Modifier
            .fillMaxWidth()
            .height(50.dp)
    ) {
        Text(stringResource(R.string.open_provii_wallet))
    }
}

@Composable
private fun TimeRemainingBadge(uiState: VerificationUiState, isFailed: Boolean) {
    if (uiState.timeRemaining <= 0 || isFailed) return

    Spacer(modifier = Modifier.height(24.dp))

    Box(
        modifier = Modifier
            .background(
                color = MaterialTheme.colorScheme.surfaceVariant,
                shape = RoundedCornerShape(8.dp)
            )
            .padding(horizontal = 20.dp, vertical = 12.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                text = stringResource(R.string.verification_time_remaining),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Text(
                text = formatTime(uiState.timeRemaining),
                style = MaterialTheme.typography.bodyMedium,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.primary
            )
        }
    }

    Spacer(modifier = Modifier.height(24.dp))
}

@Composable
private fun VerificationInfoCard(uiState: VerificationUiState) {
    val mode = uiState.session?.mode ?: uiState.selectedMode
    val ageThreshold = uiState.session?.ageThreshold ?: uiState.selectedAge

    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surface
        )
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(
                text = if (mode == VerificationMode.OVER_AGE) {
                    stringResource(R.string.verification_info_title_over, ageThreshold)
                } else {
                    stringResource(R.string.verification_info_title_under, ageThreshold)
                },
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.Bold
            )
            Spacer(modifier = Modifier.height(8.dp))
            Text(
                text = if (mode == VerificationMode.OVER_AGE) {
                    stringResource(R.string.verification_info_body_over, ageThreshold)
                } else {
                    stringResource(R.string.verification_info_body_under, ageThreshold)
                },
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

@Composable
private fun RetryButton(isFailed: Boolean, onRetry: () -> Unit) {
    if (!isFailed) return

    Button(
        onClick = onRetry,
        modifier = Modifier
            .fillMaxWidth()
            .height(50.dp)
    ) {
        Text(stringResource(R.string.common_try_again))
    }
    Spacer(modifier = Modifier.height(12.dp))
}

@Composable
private fun CancelButton(onCancel: () -> Unit) {
    OutlinedButton(
        onClick = onCancel,
        modifier = Modifier
            .fillMaxWidth()
            .height(50.dp),
        colors = ButtonDefaults.outlinedButtonColors(
            contentColor = MaterialTheme.colorScheme.error
        )
    ) {
        Icon(
            imageVector = Icons.Default.Close,
            contentDescription = stringResource(R.string.verification_cancel_icon),
            modifier = Modifier.size(18.dp)
        )
        Spacer(modifier = Modifier.width(8.dp))
        Text(stringResource(R.string.verification_cancel))
    }
}

@Composable
private fun getStatusMessage(state: VerificationState): String {
    return when (state) {
        VerificationState.INITIAL,
        VerificationState.CREATING -> stringResource(R.string.verification_status_creating)
        VerificationState.CHALLENGE_CREATED -> stringResource(R.string.verification_status_opening)
        VerificationState.POLLING -> stringResource(R.string.verification_status_waiting)
        VerificationState.VERIFIED -> stringResource(R.string.verification_status_verified)
        VerificationState.REDEEMING -> stringResource(R.string.verification_status_redeeming)
        VerificationState.REDEEMED -> stringResource(R.string.verification_status_redeemed)
        VerificationState.EXPIRED -> stringResource(R.string.verification_status_expired)
        VerificationState.FAILED -> stringResource(R.string.verification_status_failed)
    }
}

private fun formatTime(seconds: Int): String {
    val mins = seconds / SECONDS_PER_MINUTE
    val secs = seconds % SECONDS_PER_MINUTE
    return "$mins:${secs.toString().padStart(TIME_PAD_LENGTH, '0')}"
}
