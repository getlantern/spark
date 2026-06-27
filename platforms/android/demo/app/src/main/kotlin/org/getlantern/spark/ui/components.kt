package org.getlantern.spark.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import org.getlantern.spark.R
import org.getlantern.spark.ServerInfo

/** ISO-3166 alpha-2 -> flag emoji; blank/odd -> white flag. Mirrors lib/format.ts flagEmoji. */
fun flagEmoji(code: String?): String {
    if (code == null || code.length != 2) return "🏳️"
    val base = 0x1F1E6
    val a = code[0].uppercaseChar() - 'A'
    val b = code[1].uppercaseChar() - 'A'
    if (a !in 0..25 || b !in 0..25) return "🏳️"
    return String(Character.toChars(base + a)) + String(Character.toChars(base + b))
}

/** "Country – City" (or whichever present), else name, else [fallback]. Mirrors serverLabel.
 *  [fallback] is passed in (a localized string) since this is a plain helper, not a composable. */
fun serverLabel(s: ServerInfo, fallback: String): String =
    listOfNotNull(s.country, s.city).filter { it.isNotBlank() }
        .joinToString(" – ").ifEmpty { s.name ?: fallback }

/** Canonical protocol name. Mirrors lib/format.ts protocolLabel (+ fronted-meek -> Meek). */
fun protocolLabel(p: String?): String = when (p?.lowercase()) {
    null, "" -> ""
    "anytls" -> "AnyTLS"
    "samizdat" -> "Samizdat"
    "shadowsocks" -> "Shadowsocks"
    "hysteria2" -> "Hysteria2"
    "wasm" -> "WASM"
    "fronted-meek" -> "Meek"
    "tunnel" -> "Tunnel"
    else -> p
}

/** good <80, amber <160, else slow; null -> slow. Mirrors latencyClass. Pill = colored text on a
 *  12%-alpha tint of the same hue (so the bg always tracks the fg — no stale duplicated hex). */
private fun latColors(ms: Long?): Pair<Color, Color> {
    val fg = when {
        ms == null -> SparkColors.latSlow
        ms < 80 -> SparkColors.latGood
        ms < 160 -> SparkColors.latAmber
        else -> SparkColors.latSlow
    }
    return fg to fg.copy(alpha = 0.12f)
}

@Composable
fun LatencyPill(ms: Long) {
    val (fg, bg) = latColors(ms)
    Box(Modifier.background(bg, RoundedCornerShape(999.dp)).padding(horizontal = 8.dp, vertical = 3.dp)) {
        Text(stringResource(R.string.ms_format, ms), fontFamily = Urbanist, color = fg, fontSize = 12.sp, fontWeight = FontWeight.Bold)
    }
}
