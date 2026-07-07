package org.getlantern.spark.vpn

import android.Manifest
import android.app.Activity
import android.net.VpnService
import android.os.Build
import android.util.Log
import androidx.activity.result.ActivityResult
import app.tauri.annotation.ActivityCallback
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.Permission
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin
import java.io.File
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import org.getlantern.spark.SparkBridge
import org.getlantern.spark.SparkState
import org.getlantern.spark.VpnController
import org.getlantern.spark.VpnState

/**
 * Tauri plugin bridging the SvelteKit UI to the Android tunnel. Registered from Rust via
 * `api.register_android_plugin("org.getlantern.spark.vpn", "SparkVpnPlugin")`.
 *
 * The request path is `invoke("plugin:spark-vpn|connect")` → Rust `#[command] connect`
 * (commands.rs) → `AndroidControl::connect` (mobile.rs) → `run_mobile_plugin("connect")` → the
 * [connect] @Command below. Each @Command parses its args, drives the [SparkVpnService] /
 * [SparkBridge], and resolves/rejects the [Invoke].
 *
 * Durable settings (split-tunnel list + routing mode) live in filesDir on this side, mirroring the
 * desktop `persist.rs` schema so behaviour matches other platforms. The [SparkVpnService] owns the
 * actual `nativeRun`; the readiness gate is observed here through [SparkState].
 */
@TauriPlugin(
    permissions = [
        Permission(strings = [Manifest.permission.POST_NOTIFICATIONS], alias = "postNotification"),
    ],
)
class SparkVpnPlugin(private val activity: Activity) : Plugin(activity) {
    // Process-lived scope for the readiness wait; SupervisorJob so one failure can't cancel siblings.
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    // Re-entrancy guard for the whole connect flow (consent round-trip + readiness wait). A second
    // connect() while one is in flight is rejected, so an Invoke can never be dropped/overwritten.
    @Volatile private var connecting = false

    init {
        // Pre-warm the installed-apps catalog in the background at launch so the split-tunnel picker
        // opens instantly the FIRST time too (enumeration rasterizes an icon per app, ~1s). No-op if
        // the cache already exists; listInstalledApps' stale-while-revalidate keeps it fresh after.
        scope.launch {
            if (!installedAppsCacheFile().exists()) {
                runCatching { writeInstalledAppsCache(enumerateInstalledApps()) }
            }
        }
    }

    /** Terminal for a connect: clear the in-flight guard, then resolve (error == null) or reject. */
    private fun finishConnect(invoke: Invoke, error: String?) {
        connecting = false
        if (error == null) invoke.resolve() else invoke.reject(error)
    }

    // ── connect / disconnect ────────────────────────────────────────────────────

    /**
     * `VpnService.prepare(activity)` → if it returns an Intent, launch it for result and continue in
     * [onConsentResult]; if null (already granted) proceed directly. On consent granted, ensure the
     * POST_NOTIFICATIONS permission on API 33+, start the foreground service, and gate on readiness.
     */
    @Command
    fun connect(invoke: Invoke) {
        // Only one connect may be in flight (through consent + readiness). A second tap while the
        // consent dialog or readiness wait is pending would otherwise overwrite/drop the first Invoke.
        if (connecting) {
            invoke.reject("a connect is already in progress")
            return
        }
        connecting = true
        // prepare() returns null when consent is already granted, or an Intent to request it. A
        // *thrown* exception is a real failure — reject rather than mistaking it for "granted".
        val consent = try {
            VpnService.prepare(activity)
        } catch (e: Exception) {
            finishConnect(invoke, "VPN prepare failed: ${e.message}")
            return
        }
        if (consent != null) {
            // Async: resolve/reject in onConsentResult (Tauri passes the Invoke to the callback).
            startActivityForResult(invoke, consent, "onConsentResult")
            return
        }
        // Already granted → proceed.
        proceedConnect(invoke)
    }

    /** Activity-result callback for the VpnService consent dialog. */
    @ActivityCallback
    fun onConsentResult(invoke: Invoke, result: ActivityResult) {
        if (result.resultCode == Activity.RESULT_OK) {
            proceedConnect(invoke)
        } else {
            finishConnect(invoke, "VPN consent was not granted")
        }
    }

    /**
     * Consent is granted here. Request POST_NOTIFICATIONS (API 33+) so the foreground-service
     * notification shows, then start the service and wait (bounded) for the readiness gate.
     */
    private fun proceedConnect(invoke: Invoke) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            val granted = activity.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) ==
                android.content.pm.PackageManager.PERMISSION_GRANTED
            if (!granted) {
                // Fire-and-forget: a denied notification permission doesn't block the tunnel (the
                // service still runs; only the notification is suppressed on 33+). We don't gate the
                // connect on the permission result.
                runCatching {
                    activity.requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 0)
                }
            }
        }
        startAndAwaitReady(invoke)
    }

    /**
     * Start the foreground service (which runs `nativeRun` with `config=null` self-fetch, dataDir =
     * `<filesDir>/config`, and the persisted split-tunnel/routing-mode) and wait off the main thread
     * for [SparkState] to leave CONNECTING. Resolve on CONNECTED, reject on FAILED/timeout.
     */
    private fun startAndAwaitReady(invoke: Invoke) {
        // Prime state to CONNECTING before the service publishes it, so the wait below can't observe
        // a stale CONNECTED/DISCONNECTED from a prior attempt.
        SparkState.set(VpnState.CONNECTING)
        VpnController.start(activity)
        scope.launch {
            // The service's own readiness gate (nativeWaitReady) uses READY_TIMEOUT_MS = 30s; wait a
            // little longer here so the service is the one to decide FAILED, not us racing it.
            val terminal = withTimeoutOrNull(READY_WAIT_MS) {
                SparkState.state.first { it == VpnState.CONNECTED || it == VpnState.FAILED }
            }
            when (terminal) {
                VpnState.CONNECTED -> finishConnect(invoke, null)
                VpnState.FAILED -> finishConnect(invoke, "tunnel did not become ready")
                else -> finishConnect(invoke, "timed out waiting for tunnel to become ready")
            }
        }
    }

    /** Send ACTION_STOP so the service tears itself down (stopForeground + stopSelf). */
    @Command
    fun disconnect(invoke: Invoke) {
        runCatching { VpnController.stop(activity) }
            .onFailure { Log.e(TAG, "disconnect failed", it) }
        invoke.resolve()
    }

    // ── status ──────────────────────────────────────────────────────────────────

    /**
     * The in-process tunnel state, mapped to the frontend's `{state,protocol,failOpen}` shape. Does
     * NOT block on the network — reads the current [SparkState] value.
     */
    @Command
    fun status(invoke: Invoke) {
        val state = when (SparkState.state.value) {
            VpnState.CONNECTED -> "connected"
            VpnState.CONNECTING -> "connecting"
            VpnState.FAILED -> "failed"
            VpnState.DISCONNECTED -> "disconnected"
        }
        val ret = JSObject()
        ret.put("state", state)
        ret.put("protocol", "AnyTLS")
        ret.put("failOpen", false)
        invoke.resolve(ret)
    }

    // ── servers / selectServer ────────────────────────────────────────────────────

    /**
     * The live server pool as a JSON array string, wrapped in `{value: <jsonString>}` so Rust
     * deserializes a `{value: String}` and parses it into `Vec<ServerInfo>`. "[]" before any connect.
     * nativeServers() is nullable only on a catastrophic JNI string-allocation failure → treat as "[]".
     */
    @Command
    fun servers(invoke: Invoke) {
        val json = runCatching { SparkBridge.nativeServers() }.getOrNull() ?: "[]"
        val ret = JSObject()
        ret.put("value", json)
        invoke.resolve(ret)
    }

    /** Pin which pool member new flows dial. Resolves `{ok: Boolean}`. */
    @Command
    fun selectServer(invoke: Invoke) {
        val args = invoke.parseArgs(SelectServerArgs::class.java)
        val ok = runCatching { SparkBridge.nativeSelectServer(args.index) }.getOrDefault(false)
        val ret = JSObject()
        ret.put("ok", ok)
        invoke.resolve(ret)
    }

    // ── installed apps (split-tunnel picker) ───────────────────────────────────────

    /**
     * Enumerate launchable, non-system-critical apps for the exclude picker. Returns
     * `{value: "<jsonArray>"}` where each element is `{id, name, icon}` (id = package name,
     * icon = a `data:image/png;base64,…` URL). Excludes our own package (already tunnel-excluded).
     */
    @Command
    fun listInstalledApps(invoke: Invoke) {
        // Enumeration rasterizes a PNG icon per launchable app (~100 apps → ~1s), so cache the result
        // to disk. Stale-while-revalidate: serve the cache instantly if present, then refresh it in
        // the background so newly installed / removed apps appear on the next open. First run (no
        // cache) enumerates on a background coroutine (never blocking the caller), caches, then
        // resolves — the launch-time pre-warm usually fills the cache before the picker is opened.
        val cached = runCatching { installedAppsCacheFile().readText() }
            .getOrNull()?.takeIf { it.isNotBlank() }
        if (cached != null) {
            val ret = JSObject()
            ret.put("value", cached)
            invoke.resolve(ret)
            scope.launch { runCatching { writeInstalledAppsCache(enumerateInstalledApps()) } }
            return
        }
        scope.launch {
            val json = enumerateInstalledApps()
            runCatching { writeInstalledAppsCache(json) }
            val ret = JSObject()
            ret.put("value", json)
            invoke.resolve(ret)
        }
    }

    private fun installedAppsCacheFile(): File = File(activity.filesDir, "installed_apps_cache.json")

    /** Atomically replace the installed-apps cache (temp-file + rename) so a concurrent reader in the
     *  stale-while-revalidate path can't observe a half-written file. */
    private fun writeInstalledAppsCache(json: String) {
        val f = installedAppsCacheFile()
        val tmp = File(f.parentFile, "${f.name}.tmp")
        tmp.writeText(json)
        // Atomically replace so a concurrent stale-while-revalidate reader never sees a half-written
        // file. On API 26+ use Files.move(ATOMIC_MOVE, REPLACE_EXISTING). On 21–25 File.renameTo maps
        // to POSIX rename(2), which atomically replaces an existing destination on the same filesystem
        // (the general-JVM "renameTo fails if dest exists" caveat doesn't apply on Android/Linux).
        // Only if both fail do we fall back to a direct (non-atomic) write.
        val replaced = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            runCatching {
                java.nio.file.Files.move(
                    tmp.toPath(),
                    f.toPath(),
                    java.nio.file.StandardCopyOption.REPLACE_EXISTING,
                    java.nio.file.StandardCopyOption.ATOMIC_MOVE,
                )
            }.isSuccess
        } else {
            tmp.renameTo(f)
        }
        if (!replaced) {
            tmp.delete()
            f.writeText(json)
        }
    }

    /**
     * Enumerate launchable apps as a JSON array string of `{id,name,icon}` (id = package name, icon =
     * a `data:image/png;base64,…` URL or null). Excludes our own package. Slow (rasterizes each icon)
     * — callers cache the result via [writeInstalledAppsCache].
     */
    private fun enumerateInstalledApps(): String {
        val pm = activity.packageManager
        val out = org.json.JSONArray()
        // Launchable apps only (have a launcher entry) — the useful, user-recognizable set.
        val launch = android.content.Intent(android.content.Intent.ACTION_MAIN)
            .addCategory(android.content.Intent.CATEGORY_LAUNCHER)
        val resolved = pm.queryIntentActivities(launch, 0)
        val seen = HashSet<String>()
        for (ri in resolved) {
            val pkg = ri.activityInfo.packageName
            if (pkg == activity.packageName || !seen.add(pkg)) continue
            val label = ri.loadLabel(pm).toString()
            val icon = runCatching { drawableToPngDataUrl(ri.loadIcon(pm)) }.getOrNull()
            out.put(
                org.json.JSONObject()
                    .put("id", pkg)
                    .put("name", label)
                    .put("icon", icon ?: org.json.JSONObject.NULL),
            )
        }
        return out.toString()
    }

    /** Rasterize a (possibly adaptive) launcher drawable to a small PNG data-URL for the web UI. */
    private fun drawableToPngDataUrl(d: android.graphics.drawable.Drawable): String {
        val size = 96
        val bmp = android.graphics.Bitmap.createBitmap(size, size, android.graphics.Bitmap.Config.ARGB_8888)
        val canvas = android.graphics.Canvas(bmp)
        d.setBounds(0, 0, size, size)
        d.draw(canvas)
        val baos = java.io.ByteArrayOutputStream()
        bmp.compress(android.graphics.Bitmap.CompressFormat.PNG, 100, baos)
        bmp.recycle()
        val b64 = android.util.Base64.encodeToString(baos.toByteArray(), android.util.Base64.NO_WRAP)
        return "data:image/png;base64,$b64"
    }

    // ── split tunnel ──────────────────────────────────────────────────────────────

    /** Read `<filesDir>/split_tunnel.json`, resolving `{value: <jsonString>}` (default disabled). */
    @Command
    fun getSplitTunnel(invoke: Invoke) {
        val json = loadSplitTunnel()
        val ret = JSObject()
        ret.put("value", json)
        invoke.resolve(ret)
    }

    /**
     * Persist the split-tunnel list to `<filesDir>/split_tunnel.json` and, if the tunnel is up, push
     * it live via `nativeSetSplitTunnel`.
     */
    @Command
    fun setSplitTunnel(invoke: Invoke) {
        val args = invoke.parseArgs(JsonArgs::class.java)
        // Validate + canonicalize first (mirrors desktop save_split_tunnel): reject wrong-shape input
        // rather than writing garbage that a later load would silently discard (losing the user's list).
        val canonical = canonicalizeSplitTunnel(args.json)
        if (canonical == null) {
            invoke.reject("invalid split-tunnel JSON")
            return
        }
        try {
            splitTunnelFile().writeText(canonical)
        } catch (e: Exception) {
            invoke.reject("failed to persist split-tunnel: ${e.message}")
            return
        }
        if (SparkState.state.value == VpnState.CONNECTED) {
            runCatching { SparkBridge.nativeSetSplitTunnel(canonical) }
                .onFailure { Log.w(TAG, "nativeSetSplitTunnel failed", it) }
        }
        invoke.resolve()
    }

    // ── excluded apps (app split tunneling) ───────────────────────────────────────

    /** Read `<filesDir>/excluded_apps.json`, resolving `{value: "<jsonArray>"}` (default "[]"). */
    @Command
    fun getExcludedApps(invoke: Invoke) {
        val ret = JSObject()
        ret.put("value", loadExcludedApps())
        invoke.resolve(ret)
    }

    /**
     * Persist the excluded-app package list to `<filesDir>/excluded_apps.json` and, if the tunnel is
     * up, apply it live by rebuilding the VpnService (new `addDisallowedApplication` set) — no
     * reconnect / re-consent. See [SparkVpnService.ACTION_APPLY_APPS].
     */
    @Command
    fun setExcludedApps(invoke: Invoke) {
        val args = invoke.parseArgs(JsonArgs::class.java)
        val canonical = canonicalizeExcludedApps(args.json)
        if (canonical == null) {
            invoke.reject("invalid excluded-apps JSON")
            return
        }
        try {
            excludedAppsFile().writeText(canonical)
        } catch (e: Exception) {
            invoke.reject("failed to persist excluded apps: ${e.message}")
            return
        }
        if (SparkState.state.value == VpnState.CONNECTED) {
            runCatching { VpnController.applyExcludedApps(activity) }
                .onFailure { Log.w(TAG, "applyExcludedApps failed", it) }
        }
        invoke.resolve()
    }

    // ── routing mode ──────────────────────────────────────────────────────────────

    /** Read `<filesDir>/routing_mode.txt` (default "smart"; validated), resolving `{value: mode}`. */
    @Command
    fun getRoutingMode(invoke: Invoke) {
        val mode = loadRoutingMode()
        val ret = JSObject()
        ret.put("value", mode)
        invoke.resolve(ret)
    }

    /**
     * Persist the routing mode to `<filesDir>/routing_mode.txt` (rejecting anything but smart/full)
     * and, if the tunnel is up, push it live via `nativeSetRoutingMode`.
     */
    @Command
    fun setRoutingMode(invoke: Invoke) {
        val args = invoke.parseArgs(ModeArgs::class.java)
        val mode = args.mode.trim()
        if (mode != "smart" && mode != "full") {
            invoke.reject("invalid routing mode: \"${args.mode}\" (expected \"smart\" or \"full\")")
            return
        }
        try {
            routingModeFile().writeText(mode)
        } catch (e: Exception) {
            invoke.reject("failed to persist routing mode: ${e.message}")
            return
        }
        if (SparkState.state.value == VpnState.CONNECTED) {
            runCatching { SparkBridge.nativeSetRoutingMode(mode) }
                .onFailure { Log.w(TAG, "nativeSetRoutingMode failed", it) }
        }
        invoke.resolve()
    }

    // ── persistence helpers (mirror the desktop persist.rs schema) ────────────────

    private fun splitTunnelFile(): File = File(activity.filesDir, "split_tunnel.json")

    private fun routingModeFile(): File = File(activity.filesDir, "routing_mode.txt")

    private fun excludedAppsFile(): File = File(activity.filesDir, "excluded_apps.json")

    /** Read the persisted excluded-app package list (a JSON string array); [] if missing/invalid. */
    private fun loadExcludedApps(): String =
        runCatching { excludedAppsFile().readText() }.getOrNull()
            ?.let { canonicalizeExcludedApps(it) } ?: "[]"

    /** Validate + canonicalize to a JSON array of non-blank, **deduplicated** strings (insertion
     *  order preserved); null on parse error. Deduping keeps the persisted file stable and avoids
     *  redundant addDisallowedApplication() calls if the UI sends the same id more than once. */
    private fun canonicalizeExcludedApps(raw: String): String? = runCatching {
        val arr = org.json.JSONArray(raw)
        val seen = LinkedHashSet<String>()
        for (i in 0 until arr.length()) {
            val s = arr.optString(i).trim()
            if (s.isNotEmpty()) seen.add(s)
        }
        org.json.JSONArray(seen.toList()).toString()
    }.getOrNull()

    /**
     * Validate + canonicalize a split-tunnel JSON string to the `{enabled,domains,ips}` shape;
     * returns null on any parse/shape error. Shared by [loadSplitTunnel] (→ default on null) and
     * [setSplitTunnel] (→ reject on null), mirroring the desktop `persist.rs` so neither the on-disk
     * file nor the UI's `JSON.parse` (which assumes `domains`/`ips` are arrays) ever sees garbage.
     */
    private fun canonicalizeSplitTunnel(raw: String): String? = runCatching {
        val o = org.json.JSONObject(raw)
        val domains = o.optJSONArray("domains") ?: org.json.JSONArray()
        val ips = o.optJSONArray("ips") ?: org.json.JSONArray()
        org.json.JSONObject()
            .put("enabled", o.optBoolean("enabled", false))
            .put("domains", org.json.JSONArray((0 until domains.length()).map { domains.getString(it) }))
            .put("ips", org.json.JSONArray((0 until ips.length()).map { ips.getString(it) }))
            .toString()
    }.getOrNull()

    /** Read the persisted split-tunnel list, canonicalized; the disabled default if missing/invalid. */
    private fun loadSplitTunnel(): String =
        runCatching { splitTunnelFile().readText() }.getOrNull()
            ?.let { canonicalizeSplitTunnel(it) } ?: SPLIT_TUNNEL_DEFAULT

    /** Read the persisted routing mode, or "smart" if missing/unreadable/invalid. */
    private fun loadRoutingMode(): String {
        val m = runCatching { routingModeFile().readText().trim() }.getOrNull()
        return if (m == "smart" || m == "full") m else "smart"
    }

    // ── arg shapes ────────────────────────────────────────────────────────────────

    @InvokeArg
    internal class SelectServerArgs {
        var index: Int = -1
    }

    @InvokeArg
    internal class JsonArgs {
        lateinit var json: String
    }

    @InvokeArg
    internal class ModeArgs {
        lateinit var mode: String
    }

    companion object {
        private const val TAG = "SparkVpnPlugin"
        private const val SPLIT_TUNNEL_DEFAULT = "{\"enabled\":false,\"domains\":[],\"ips\":[]}"

        // Slightly longer than the service's own READY_TIMEOUT_MS (30s) so the service decides FAILED
        // (and stops the VPN) rather than us racing it and rejecting while it's still deciding.
        private const val READY_WAIT_MS = 35_000L
    }
}
