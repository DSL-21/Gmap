package com.dsl.gmap.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

private val GmapColorScheme = darkColorScheme(
    primary = Color(0xFF50E3C2),
    onPrimary = Color(0xFF06231E),
    secondary = Color(0xFF73BFFF),
    background = Color(0xFF0A1016),
    onBackground = Color(0xFFE8F0F5),
    surface = Color(0xFF111A23),
    onSurface = Color(0xFFE8F0F5),
    surfaceVariant = Color(0xFF1B2834),
    onSurfaceVariant = Color(0xFFB7C6D1),
    outline = Color(0xFF405160),
    error = Color(0xFFFF7777)
)

@Composable
fun GmapTheme(content: @Composable () -> Unit) {
    MaterialTheme(colorScheme = GmapColorScheme, content = content)
}
