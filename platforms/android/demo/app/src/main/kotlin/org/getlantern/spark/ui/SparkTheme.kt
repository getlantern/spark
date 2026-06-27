package org.getlantern.spark.ui

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Typography
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.Font
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import org.getlantern.spark.R

// Lantern palette (gui-tauri/src/routes/+layout.svelte). Names mirror the CSS vars.
object SparkColors {
    val bg = Color(0xFFF8FAFB)
    val surface = Color(0xFFFFFFFF)
    val brand = Color(0xFF00BDD6)
    val off = Color(0xFF616569)
    val knob = Color(0xFFFFFFFF)
    val textPrimary = Color(0xFF1B1C1D)
    val textSecondary = Color(0xFF3E464E)
    val textTertiary = Color(0xFF616569)
    val border = Color(0xFFEDEFEF)
    val success = Color(0xFF00531F)
    val indicatorOff = Color(0xFFDEDFDF)
    val bolt = Color(0xFFF5B800)
    // Latency ramp connotes speed, not danger: green (fast) -> yellow-green -> gold (slower).
    // No red — a slow server is "slower", not an error/stop.
    val latGood = Color(0xFF1F9D55)
    val latAmber = Color(0xFF7CA006)
    val latSlow = Color(0xFFC98A00)
    val shadow = Color(0x19006162)
}

val Urbanist = FontFamily(
    Font(R.font.urbanist_regular, FontWeight.Normal),
    Font(R.font.urbanist_medium, FontWeight.Medium),
    Font(R.font.urbanist_semibold, FontWeight.SemiBold),
    Font(R.font.urbanist_bold, FontWeight.Bold),
)

private val SparkTypography = Typography().let { base ->
    base.copy(
        bodyLarge = base.bodyLarge.copy(fontFamily = Urbanist),
        bodyMedium = base.bodyMedium.copy(fontFamily = Urbanist),
        titleLarge = base.titleLarge.copy(fontFamily = Urbanist, fontWeight = FontWeight.Bold),
        labelLarge = base.labelLarge.copy(fontFamily = Urbanist),
    )
}

@Composable
fun SparkTheme(content: @Composable () -> Unit) {
    val scheme = lightColorScheme(
        primary = SparkColors.brand,
        background = SparkColors.bg,
        surface = SparkColors.surface,
        onBackground = SparkColors.textPrimary,
        onSurface = SparkColors.textPrimary,
    )
    MaterialTheme(colorScheme = scheme, typography = SparkTypography, content = content)
}
