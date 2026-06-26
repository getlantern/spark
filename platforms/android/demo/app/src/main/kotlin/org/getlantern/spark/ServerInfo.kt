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

/** Parse the nativeServers() JSON array. Null/empty/garbage -> empty list (never throws). */
fun parseServers(json: String?): List<ServerInfo> {
    if (json.isNullOrBlank()) return emptyList()
    return try {
        val arr = JSONArray(json)
        (0 until arr.length()).map { i ->
            val o = arr.getJSONObject(i)
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
            )
        }
    } catch (_: Exception) {
        emptyList()
    }
}

private fun JSONObject.optStringOrNull(key: String): String? =
    if (isNull(key) || !has(key)) null else optString(key)
