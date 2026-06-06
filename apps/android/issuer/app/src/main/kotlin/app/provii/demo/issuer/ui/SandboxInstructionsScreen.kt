// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Provii

package app.provii.demo.issuer.ui

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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Info
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import app.provii.demo.issuer.R

/**
 * Screen that shows setup instructions on first app launch.
 *
 * This screen explains that users need to have Provii Wallet installed
 * and configured before testing the demo.
 */
@Composable
fun SandboxInstructionsScreen(
    onAcknowledge: () -> Unit
) {
    Surface(
        modifier = Modifier.fillMaxSize(),
        color = MaterialTheme.colorScheme.background
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(24.dp)
                .verticalScroll(rememberScrollState()),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            Spacer(modifier = Modifier.height(32.dp))

            SandboxHeader()

            Spacer(modifier = Modifier.height(8.dp))

            SandboxInstructionsCard()

            Spacer(modifier = Modifier.height(16.dp))

            // Note
            Text(
                text = stringResource(R.string.sandbox_note),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center
            )

            Spacer(modifier = Modifier.weight(1f))

            Button(
                onClick = onAcknowledge,
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(stringResource(R.string.sandbox_acknowledge))
            }

            Spacer(modifier = Modifier.height(16.dp))
        }
    }
}

@Composable
private fun SandboxHeader() {
    Icon(
        imageVector = Icons.Default.Info,
        contentDescription = stringResource(R.string.sandbox_info_icon_desc),
        modifier = Modifier.size(64.dp),
        tint = MaterialTheme.colorScheme.primary
    )

    Text(
        text = stringResource(R.string.sandbox_title),
        style = MaterialTheme.typography.headlineMedium,
        fontWeight = FontWeight.Bold,
        textAlign = TextAlign.Center,
        modifier = Modifier.semantics { heading() }
    )
}

@Composable
private fun SandboxInstructionsCard() {
    Card(
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.secondaryContainer
        )
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Text(
                text = stringResource(R.string.sandbox_setup_prompt),
                style = MaterialTheme.typography.bodyLarge,
                fontWeight = FontWeight.Medium
            )

            InstructionStep(number = 1, text = stringResource(R.string.sandbox_step_install))
            InstructionStep(number = 2, text = stringResource(R.string.sandbox_step_launch))
            InstructionStep(number = 3, text = stringResource(R.string.sandbox_step_language))
            InstructionStep(number = 4, text = stringResource(R.string.sandbox_step_accessibility))
        }
    }
}

@Composable
private fun InstructionStep(number: Int, text: String) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        Surface(
            shape = MaterialTheme.shapes.small,
            color = MaterialTheme.colorScheme.primary,
            modifier = Modifier.size(28.dp)
        ) {
            Box(contentAlignment = Alignment.Center) {
                Text(
                    text = number.toString(),
                    style = MaterialTheme.typography.labelLarge,
                    color = MaterialTheme.colorScheme.onPrimary
                )
            }
        }

        Text(
            text = text,
            style = MaterialTheme.typography.bodyMedium
        )
    }
}
