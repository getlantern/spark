package org.getlantern.spark.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
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

/** "Country – City" (or whichever present), else name, else "Server". Mirrors serverLabel. */
fun serverLabel(s: ServerInfo): String =
    listOfNotNull(s.country, s.city).filter { it.isNotBlank() }
        .joinToString(" – ").ifEmpty { s.name ?: "Server" }

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

/** good <80, amber <160, else slow; null -> slow. Mirrors latencyClass. (fg, bg) */
private fun latColors(ms: Long?): Pair<Color, Color> = when {
    ms == null -> SparkColors.latSlow to Color(0x1FC0341D)
    ms < 80 -> SparkColors.latGood to Color(0x1F1F9D55)
    ms < 160 -> SparkColors.latAmber to Color(0x1FC98A00)
    else -> SparkColors.latSlow to Color(0x1FC0341D)
}

@Composable
fun LatencyPill(ms: Long) {
    val (fg, bg) = latColors(ms)
    Box(Modifier.background(bg, RoundedCornerShape(999.dp)).padding(horizontal = 8.dp, vertical = 3.dp)) {
        Text("$ms ms", fontFamily = Urbanist, color = fg, fontSize = 12.sp, fontWeight = FontWeight.Bold)
    }
}
