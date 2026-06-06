// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Provii

package app.provii.demo.issuer.ui.theme

import android.app.Activity
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.SideEffect
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.platform.LocalView
import androidx.core.view.WindowCompat

// Bank green color palette
private val BankGreen = Color(0xFF2E7D32)
private val BankGreenLight = Color(0xFF60AD5E)
private val BankGreenDark = Color(0xFF005005)
private val BankGreenContainer = Color(0xFFC8E6C9)
private val OnBankGreenContainer = Color(0xFF1B5E20)

private val DarkColorScheme = darkColorScheme(
    primary = BankGreenLight,
    primaryContainer = BankGreenDark,
    secondary = BankGreenLight
)

private val LightColorScheme = lightColorScheme(
    primary = BankGreen,
    primaryContainer = BankGreenContainer,
    onPrimaryContainer = OnBankGreenContainer,
    secondary = BankGreenLight
)

/** Material 3 theme for the Provii Issuer Demo app, using a bank-green colour palette. */
@Composable
fun ProviiIssuerDemoTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit
) {
    val colorScheme = if (darkTheme) DarkColorScheme else LightColorScheme
    val view = LocalView.current

    if (!view.isInEditMode) {
        SideEffect {
            val window = (view.context as Activity).window
            window.statusBarColor = colorScheme.primary.toArgb()
            WindowCompat.getInsetsController(window, view).isAppearanceLightStatusBars = !darkTheme
        }
    }

    MaterialTheme(
        colorScheme = colorScheme,
        content = content
    )
}
