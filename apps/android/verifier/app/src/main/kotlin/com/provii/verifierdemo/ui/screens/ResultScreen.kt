// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Provii

package com.provii.verifierdemo.ui.screens

import androidx.compose.foundation.background
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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Cancel
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.LockOpen
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.provii.verifierdemo.R
import com.provii.verifierdemo.data.VerificationMode

private val SuccessGreen = Color(0xFF4CAF50)
private const val STATUS_BACKGROUND_ALPHA = 0.1f

/** Screen displaying the outcome of a verification attempt with contextual information. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ResultScreen(
    verified: Boolean,
    errorMessage: String?,
    mode: VerificationMode,
    ageThreshold: Int,
    onStartOver: () -> Unit
) {
    val statusColor = if (verified) SuccessGreen else MaterialTheme.colorScheme.error

    Scaffold(
        topBar = { ResultTopBar() }
    ) { paddingValues ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues)
                .padding(20.dp)
                .verticalScroll(rememberScrollState()),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Spacer(modifier = Modifier.weight(1f))

            ResultIconAndTitle(verified, statusColor)

            ResultDescription(verified, errorMessage, mode, ageThreshold)

            ResultDetailsCard(verified, mode, ageThreshold)

            AccessStatusCard(verified, statusColor, mode)

            Spacer(modifier = Modifier.weight(1f))

            Button(
                onClick = onStartOver,
                modifier = Modifier
                    .fillMaxWidth()
                    .height(50.dp)
            ) {
                Text(
                    if (verified) {
                        stringResource(R.string.common_start_over)
                    } else {
                        stringResource(R.string.common_try_again)
                    }
                )
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ResultTopBar() {
    TopAppBar(
        title = { Text(stringResource(R.string.result_title)) },
        colors = TopAppBarDefaults.topAppBarColors(
            containerColor = MaterialTheme.colorScheme.primaryContainer,
            titleContentColor = MaterialTheme.colorScheme.onPrimaryContainer
        )
    )
}

@Composable
private fun ResultIconAndTitle(verified: Boolean, statusColor: Color) {
    Icon(
        imageVector = if (verified) Icons.Default.CheckCircle else Icons.Default.Cancel,
        contentDescription = if (verified) {
            stringResource(R.string.result_success_icon)
        } else {
            stringResource(R.string.result_failure_icon)
        },
        modifier = Modifier.size(80.dp),
        tint = statusColor
    )

    Spacer(modifier = Modifier.height(24.dp))

    Text(
        text = if (verified) {
            stringResource(R.string.result_success_title)
        } else {
            stringResource(R.string.result_failure_title)
        },
        style = MaterialTheme.typography.headlineSmall,
        fontWeight = FontWeight.Bold,
        color = statusColor,
        modifier = Modifier.semantics { heading() }
    )

    Spacer(modifier = Modifier.height(12.dp))
}

@Composable
private fun ResultDescription(
    verified: Boolean,
    errorMessage: String?,
    mode: VerificationMode,
    ageThreshold: Int
) {
    val text = if (verified) {
        if (mode == VerificationMode.OVER_AGE) {
            stringResource(R.string.result_success_description_over, ageThreshold)
        } else {
            stringResource(R.string.result_success_description_under, ageThreshold)
        }
    } else {
        errorMessage ?: if (mode == VerificationMode.OVER_AGE) {
            stringResource(R.string.result_failure_description_over, ageThreshold)
        } else {
            stringResource(R.string.result_failure_description_under, ageThreshold)
        }
    }

    Text(
        text = text,
        style = MaterialTheme.typography.bodyMedium,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        textAlign = TextAlign.Center
    )

    Spacer(modifier = Modifier.height(24.dp))
}

@Composable
private fun ResultDetailsCard(
    verified: Boolean,
    mode: VerificationMode,
    ageThreshold: Int
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surface
        )
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(
                text = if (verified) {
                    stringResource(R.string.result_what_happened)
                } else {
                    stringResource(R.string.result_possible_reasons)
                },
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.Bold
            )
            Spacer(modifier = Modifier.height(12.dp))

            if (verified) {
                SuccessBulletPoints(mode, ageThreshold)
            } else {
                FailureBulletPoints(mode)
            }
        }
    }

    Spacer(modifier = Modifier.height(16.dp))
}

@Composable
private fun SuccessBulletPoints(mode: VerificationMode, ageThreshold: Int) {
    BulletPoint(stringResource(R.string.result_bullet_zkp))
    BulletPoint(stringResource(R.string.result_bullet_crypto))
    BulletPoint(stringResource(R.string.result_bullet_private))
    if (mode == VerificationMode.OVER_AGE) {
        BulletPoint(stringResource(R.string.result_bullet_over_proven, ageThreshold))
    } else {
        BulletPoint(stringResource(R.string.result_bullet_under_proven, ageThreshold))
    }
}

@Composable
private fun FailureBulletPoints(mode: VerificationMode) {
    BulletPoint(stringResource(R.string.result_bullet_cancelled))
    BulletPoint(stringResource(R.string.result_bullet_expired))
    if (mode == VerificationMode.OVER_AGE) {
        BulletPoint(stringResource(R.string.result_bullet_not_meet_over))
    } else {
        BulletPoint(stringResource(R.string.result_bullet_not_meet_under))
    }
    BulletPoint(stringResource(R.string.result_bullet_network_error))
}

@Composable
private fun AccessStatusCard(
    verified: Boolean,
    statusColor: Color,
    mode: VerificationMode
) {
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .background(
                color = statusColor.copy(alpha = STATUS_BACKGROUND_ALPHA),
                shape = RoundedCornerShape(12.dp)
            )
            .padding(16.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(
                imageVector = if (verified) Icons.Default.LockOpen else Icons.Default.Lock,
                contentDescription = if (verified) {
                    stringResource(R.string.result_lock_open_icon)
                } else {
                    stringResource(R.string.result_lock_icon)
                },
                tint = statusColor
            )
            Spacer(modifier = Modifier.width(12.dp))
            Text(
                text = if (verified) {
                    if (mode == VerificationMode.OVER_AGE) {
                        stringResource(R.string.result_success_access_over)
                    } else {
                        stringResource(R.string.result_success_access_under)
                    }
                } else {
                    stringResource(R.string.result_failure_access)
                },
                style = MaterialTheme.typography.bodyMedium,
                color = statusColor
            )
        }
    }
}

@Composable
private fun BulletPoint(text: String) {
    Row(
        modifier = Modifier.padding(vertical = 4.dp)
    ) {
        Text(
            text = "• ",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Text(
            text = text,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}
