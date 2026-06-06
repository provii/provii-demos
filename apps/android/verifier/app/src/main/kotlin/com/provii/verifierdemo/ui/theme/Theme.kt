// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Provii

package com.provii.verifierdemo.ui.theme

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

// Social media purple/violet color palette
private val SocialPurple = Color(0xFF7C3AED)
private val SocialPurpleLight = Color(0xFFA78BFA)
private val SocialPurpleDark = Color(0xFF5B21B6)
private val SocialPurpleContainer = Color(0xFFEDE9FE)
private val OnSocialPurpleContainer = Color(0xFF4C1D95)

private val LightColorScheme = lightColorScheme(
    primary = SocialPurple,
    onPrimary = Color.White,
    primaryContainer = SocialPurpleContainer,
    onPrimaryContainer = OnSocialPurpleContainer,
    secondary = SocialPurpleLight,
    onSecondary = Color.White,
    secondaryContainer = Color(0xFFF3E8FF),
    onSecondaryContainer = Color(0xFF6B21A8),
    tertiary = Color(0xFFEC4899),
    onTertiary = Color.White,
    tertiaryContainer = Color(0xFFFCE7F3),
    onTertiaryContainer = Color(0xFFBE185D),
    error = Color(0xFFD32F2F),
    onError = Color.White,
    errorContainer = Color(0xFFFFEBEE),
    onErrorContainer = Color(0xFFC62828),
    background = Color(0xFFFAFAFA),
    onBackground = Color(0xFF1C1B1F),
    surface = Color.White,
    onSurface = Color(0xFF1C1B1F),
    surfaceVariant = Color(0xFFF5F5F5),
    onSurfaceVariant = Color(0xFF49454F),
    outline = Color(0xFF79747E)
)

private val DarkColorScheme = darkColorScheme(
    primary = SocialPurpleLight,
    onPrimary = SocialPurpleDark,
    primaryContainer = SocialPurpleDark,
    onPrimaryContainer = SocialPurpleContainer,
    secondary = Color(0xFFC4B5FD),
    onSecondary = Color(0xFF4C1D95),
    secondaryContainer = Color(0xFF6B21A8),
    onSecondaryContainer = Color(0xFFE9D5FF),
    tertiary = Color(0xFFF9A8D4),
    onTertiary = Color(0xFF9D174D),
    tertiaryContainer = Color(0xFFBE185D),
    onTertiaryContainer = Color(0xFFFCE7F3),
    error = Color(0xFFEF9A9A),
    onError = Color(0xFFB71C1C),
    errorContainer = Color(0xFFC62828),
    onErrorContainer = Color(0xFFFFCDD2),
    background = Color(0xFF1C1B1F),
    onBackground = Color(0xFFE6E1E5),
    surface = Color(0xFF1C1B1F),
    onSurface = Color(0xFFE6E1E5),
    surfaceVariant = Color(0xFF49454F),
    onSurfaceVariant = Color(0xFFCAC4D0),
    outline = Color(0xFF938F99)
)

/** Material 3 theme for the Provii Verifier Demo app, using a purple/violet colour palette. */
@Composable
fun ProviiVerifierDemoTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit
) {
    val colorScheme = if (darkTheme) DarkColorScheme else LightColorScheme

    val view = LocalView.current
    if (!view.isInEditMode) {
        SideEffect {
            val window = (view.context as Activity).window
            window.statusBarColor = colorScheme.primaryContainer.toArgb()
            WindowCompat.getInsetsController(window, view).isAppearanceLightStatusBars = !darkTheme
        }
    }

    MaterialTheme(
        colorScheme = colorScheme,
        content = content
    )
}
