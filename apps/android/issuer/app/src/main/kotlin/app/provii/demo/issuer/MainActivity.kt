// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Provii

package app.provii.demo.issuer

import android.content.ActivityNotFoundException
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.viewModels
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
import androidx.compose.foundation.layout.width
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import app.provii.demo.issuer.ui.MainViewModel
import app.provii.demo.issuer.ui.SandboxInstructionsScreen
import app.provii.demo.issuer.ui.theme.ProviiIssuerDemoTheme

/**
 * Main activity for the Demo Bank issuer app.
 *
 * ONE-TAP FLOW:
 * 1. Show sandbox instructions on first launch
 * 2. Tap an age button to immediately issue credential
 * 3. Deep link opens Provii Wallet
 * 4. Wallet handles all cryptography and issuance
 */
class MainActivity : ComponentActivity() {

    private val viewModel: MainViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        setContent {
            ProviiIssuerDemoTheme {
                val preferences = ProviiIssuerDemoApp.instance.preferences
                var sandboxAcknowledged by remember {
                    mutableStateOf(
                        preferences.getBoolean(ProviiIssuerDemoApp.PREF_SANDBOX_ACKNOWLEDGED, false)
                    )
                }

                if (!sandboxAcknowledged) {
                    SandboxInstructionsScreen(
                        onAcknowledge = {
                            preferences.edit()
                                .putBoolean(ProviiIssuerDemoApp.PREF_SANDBOX_ACKNOWLEDGED, true)
                                .apply()
                            sandboxAcknowledged = true
                        }
                    )
                } else {
                    Surface(
                        modifier = Modifier.fillMaxSize(),
                        color = MaterialTheme.colorScheme.background
                    ) {
                        MainScreen(viewModel = viewModel)
                    }
                }
            }
        }
    }
}

private const val UNDER_18_THRESHOLD = 18
private const val ALPHA_HALF = 0.5f

/** Main screen composable displaying age selection buttons and credential issuance status. */
@OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)
@Composable
fun MainScreen(viewModel: MainViewModel) {
    val uiState by viewModel.uiState.collectAsStateWithLifecycle()
    val context = LocalContext.current
    val walletOpenFailedTemplate = stringResource(R.string.issuer_wallet_open_failed)

    MainScreenEffects(uiState, context, walletOpenFailedTemplate, viewModel)

    Scaffold(
        topBar = { IssuerTopBar() }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            IssuerHeader()

            AgeButtonGrid(viewModel, uiState)

            Spacer(modifier = Modifier.height(32.dp))

            UnderEighteenBanner(uiState)

            CredentialIssuedCard(uiState, viewModel)

            Spacer(modifier = Modifier.weight(1f))

            Text(
                text = stringResource(R.string.demo_footer),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

@Composable
private fun MainScreenEffects(
    uiState: app.provii.demo.issuer.ui.MainUiState,
    context: android.content.Context,
    walletOpenFailedTemplate: String,
    viewModel: MainViewModel
) {
    // Show error toast
    LaunchedEffect(uiState.error) {
        uiState.error?.let { error ->
            Toast.makeText(context, error, Toast.LENGTH_LONG).show()
            viewModel.clearError()
        }
    }

    // Open Provii Wallet when deep link is ready
    LaunchedEffect(uiState.issueDeepLink) {
        uiState.issueDeepLink?.let { deepLink ->
            try {
                val intent = Intent(Intent.ACTION_VIEW, Uri.parse(deepLink))
                context.startActivity(intent)
            } catch (e: ActivityNotFoundException) {
                Toast.makeText(
                    context,
                    String.format(walletOpenFailedTemplate, e.message ?: ""),
                    Toast.LENGTH_LONG
                ).show()
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun IssuerTopBar() {
    TopAppBar(
        title = {
            Row(
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text("💵")
                Text(stringResource(R.string.app_name))
            }
        },
        colors = TopAppBarDefaults.topAppBarColors(
            containerColor = MaterialTheme.colorScheme.primaryContainer,
            titleContentColor = MaterialTheme.colorScheme.onPrimaryContainer
        )
    )
}

@Composable
private fun IssuerHeader() {
    Spacer(modifier = Modifier.height(16.dp))

    Text(
        text = stringResource(R.string.issuer_title),
        style = MaterialTheme.typography.headlineSmall,
        fontWeight = FontWeight.Bold,
        modifier = Modifier.semantics { heading() }
    )

    Spacer(modifier = Modifier.height(8.dp))

    Text(
        text = stringResource(R.string.issuer_subtitle),
        style = MaterialTheme.typography.bodyMedium,
        color = MaterialTheme.colorScheme.onSurfaceVariant
    )

    Spacer(modifier = Modifier.height(24.dp))
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun AgeButtonGrid(
    viewModel: MainViewModel,
    uiState: app.provii.demo.issuer.ui.MainUiState
) {
    FlowRow(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.Center,
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        viewModel.demoAges.forEach { age ->
            AgeButton(age, uiState, viewModel)
        }
    }
}

@Composable
private fun AgeButton(
    age: Int,
    uiState: app.provii.demo.issuer.ui.MainUiState,
    viewModel: MainViewModel
) {
    val isSelected = uiState.selectedCustomer?.age == age
    val isLoading = uiState.isLoading && isSelected

    FilledTonalButton(
        onClick = { viewModel.issueForAge(age) },
        enabled = !uiState.isLoading,
        modifier = Modifier.padding(horizontal = 4.dp),
        colors = if (isSelected) {
            ButtonDefaults.filledTonalButtonColors(
                containerColor = MaterialTheme.colorScheme.primary,
                contentColor = MaterialTheme.colorScheme.onPrimary
            )
        } else {
            ButtonDefaults.filledTonalButtonColors()
        }
    ) {
        if (isLoading) {
            CircularProgressIndicator(
                modifier = Modifier.size(16.dp),
                strokeWidth = 2.dp,
                color = MaterialTheme.colorScheme.onPrimary
            )
        } else {
            Text(
                text = "$age",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold
            )
        }
    }
}

@Composable
private fun UnderEighteenBanner(uiState: app.provii.demo.issuer.ui.MainUiState) {
    val selectedAge = uiState.selectedCustomer?.age
    if (selectedAge != null && selectedAge < UNDER_18_THRESHOLD && !uiState.isCredentialIssued) {
        Card(
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.primaryContainer.copy(alpha = ALPHA_HALF)
            ),
            modifier = Modifier.fillMaxWidth()
        ) {
            Row(
                modifier = Modifier.padding(12.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Icon(
                    Icons.Default.Info,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(20.dp)
                )
                Text(
                    text = stringResource(R.string.issuer_under_18_info),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurface
                )
            }
        }
        Spacer(modifier = Modifier.height(16.dp))
    }
}

@Composable
private fun CredentialIssuedCard(
    uiState: app.provii.demo.issuer.ui.MainUiState,
    viewModel: MainViewModel
) {
    if (!uiState.isCredentialIssued) return

    Card(
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.tertiaryContainer
        ),
        modifier = Modifier.fillMaxWidth()
    ) {
        Row(
            modifier = Modifier.padding(16.dp),
            horizontalArrangement = Arrangement.spacedBy(12.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(
                Icons.Default.CheckCircle,
                contentDescription = stringResource(R.string.issuer_success_icon_desc),
                tint = MaterialTheme.colorScheme.tertiary
            )
            Column {
                Text(
                    text = stringResource(R.string.issuer_opening_wallet),
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.Bold
                )
                Text(
                    text = stringResource(R.string.issuer_complete_in_wallet),
                    style = MaterialTheme.typography.bodySmall
                )
            }
        }
    }

    Spacer(modifier = Modifier.height(16.dp))

    TextButton(onClick = { viewModel.reset() }) {
        Icon(
            Icons.Default.Refresh,
            contentDescription = stringResource(R.string.issuer_refresh_icon_desc)
        )
        Spacer(modifier = Modifier.width(4.dp))
        Text(stringResource(R.string.issuer_issue_another))
    }
}
