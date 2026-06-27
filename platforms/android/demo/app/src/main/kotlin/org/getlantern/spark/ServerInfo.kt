package org.getlantern.spark

import org.json.JSONArray
import org.json.JSONObject

/** One pool member, mirroring the Rust snapshot JSON (fd_tunnel::snapshot_to_json). */
data class ServerInfo(
    val index: Int,
    val name: String? = null,
    val country: String? = null,
    val countryCode: String? = null,
    val city: String? = null,
    val protocol: String? = null,
    val latencyMs: Long? = null,
    val healthy: Boolean = false,
    val isCurrent: Boolean = false,
)

/**
 * Parse the nativeServers() JSON array. Null/empty/garbage -> empty list (never throws).
 * Parses per-element: a single malformed member (e.g. a missing/invalid index) is skipped,
 * not allowed to drop the whole list — this is polled repeatedly and drives the UI.
 */
fun parseServers(json: String?): List<ServerInfo> {
    if (json.isNullOrBlank()) return emptyList()
    val arr = try {
        JSONArray(json)
    } catch (_: Exception) {
        return emptyList()
    }
    val out = ArrayList<ServerInfo>(arr.length())
    for (i in 0 until arr.length()) {
        try {
            val o = arr.getJSONObject(i)
            out.add(
                ServerInfo(
                    index = o.getInt("index"),
                    name = o.optStringOrNull("name"),
                    country = o.optStringOrNull("country"),
                    countryCode = o.optStringOrNull("countryCode"),
                    city = o.optStringOrNull("city"),
                    protocol = o.optStringOrNull("protocol"),
                    latencyMs = if (o.isNull("latencyMs")) null else o.optLong("latencyMs"),
                    healthy = o.optBoolean("healthy", false),
                    isCurrent = o.optBoolean("isCurrent", false),
                ),
            )
        } catch (_: Exception) {
            // Skip this malformed element; keep the rest.
        }
    }
    return out
}

private fun JSONObject.optStringOrNull(key: String): String? =
    if (isNull(key) || !has(key)) null else optString(key)
