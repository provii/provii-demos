// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Provii

package com.provii.verifierdemo.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Share
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.provii.verifierdemo.R
import com.provii.verifierdemo.data.VerificationMode

/** Age thresholds for "prove I am at least this old" checks. */
private val OVER_AGE_OPTIONS = listOf(13, 18, 21, 25)

/** Age thresholds for "prove I am younger than this" checks. */
private val UNDER_AGE_OPTIONS = listOf(13, 16, 18, 21)

/** Screen where the user selects the verification mode and age threshold before starting a check. */
@OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)
@Composable
fun AgeThresholdScreen(
    selectedMode: VerificationMode,
    onModeChanged: (VerificationMode) -> Unit,
    onVerifyAge: (Int, VerificationMode) -> Unit
) {
    Scaffold(
        topBar = { ThresholdTopBar() }
    ) { paddingValues ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues)
                .padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Spacer(modifier = Modifier.weight(1f))

            ThresholdHeaderSection()

            ModeSelector(selectedMode, onModeChanged)

            ModeDescription(selectedMode)

            AgeSelectionGrid(selectedMode, onVerifyAge)

            Spacer(modifier = Modifier.weight(1f))

            Text(
                text = stringResource(R.string.common_demo_footer),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ThresholdTopBar() {
    TopAppBar(
        title = {
            Row(
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(stringResource(R.string.threshold_app_title))
            }
        },
        colors = TopAppBarDefaults.topAppBarColors(
            containerColor = MaterialTheme.colorScheme.primaryContainer,
            titleContentColor = MaterialTheme.colorScheme.onPrimaryContainer
        )
    )
}

@Composable
private fun ThresholdHeaderSection() {
    Icon(
        imageVector = Icons.Default.Share,
        contentDescription = stringResource(R.string.threshold_share_icon),
        modifier = Modifier.size(80.dp),
        tint = MaterialTheme.colorScheme.primary
    )

    Spacer(modifier = Modifier.height(24.dp))

    Text(
        text = stringResource(R.string.threshold_heading),
        style = MaterialTheme.typography.headlineMedium,
        fontWeight = FontWeight.Bold,
        textAlign = TextAlign.Center,
        modifier = Modifier.semantics { heading() }
    )

    Spacer(modifier = Modifier.height(16.dp))
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ModeSelector(
    selectedMode: VerificationMode,
    onModeChanged: (VerificationMode) -> Unit
) {
    SingleChoiceSegmentedButtonRow(
        modifier = Modifier.fillMaxWidth()
    ) {
        SegmentedButton(
            selected = selectedMode == VerificationMode.OVER_AGE,
            onClick = { onModeChanged(VerificationMode.OVER_AGE) },
            shape = SegmentedButtonDefaults.itemShape(index = 0, count = 2)
        ) {
            Text(stringResource(R.string.threshold_mode_over_age))
        }
        SegmentedButton(
            selected = selectedMode == VerificationMode.UNDER_AGE,
            onClick = { onModeChanged(VerificationMode.UNDER_AGE) },
            shape = SegmentedButtonDefaults.itemShape(index = 1, count = 2)
        ) {
            Text(stringResource(R.string.threshold_mode_under_age))
        }
    }

    Spacer(modifier = Modifier.height(16.dp))
}

@Composable
private fun ModeDescription(selectedMode: VerificationMode) {
    Text(
        text = if (selectedMode == VerificationMode.OVER_AGE) {
            stringResource(R.string.threshold_description_over)
        } else {
            stringResource(R.string.threshold_description_under)
        },
        style = MaterialTheme.typography.bodyLarge,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        textAlign = TextAlign.Center
    )

    Spacer(modifier = Modifier.height(24.dp))

    Text(
        text = stringResource(R.string.threshold_select_age),
        style = MaterialTheme.typography.titleSmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant
    )

    Spacer(modifier = Modifier.height(12.dp))
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun AgeSelectionGrid(
    selectedMode: VerificationMode,
    onVerifyAge: (Int, VerificationMode) -> Unit
) {
    val ageOptions = if (selectedMode == VerificationMode.OVER_AGE) OVER_AGE_OPTIONS else UNDER_AGE_OPTIONS
    FlowRow(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(12.dp, Alignment.CenterHorizontally),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        ageOptions.forEach { age ->
            Button(
                onClick = { onVerifyAge(age, selectedMode) },
                modifier = Modifier
                    .widthIn(min = 96.dp)
                    .height(48.dp)
            ) {
                Text(
                    text = if (selectedMode == VerificationMode.OVER_AGE) {
                        stringResource(R.string.threshold_age_over, age)
                    } else {
                        stringResource(R.string.threshold_age_under, age)
                    },
                    style = MaterialTheme.typography.titleMedium
                )
            }
        }
    }
}
