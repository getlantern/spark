package org.getlantern.spark.vpn

import android.app.Activity
import app.tauri.annotation.Command
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin
import org.getlantern.spark.SparkBridge

/**
 * Tauri plugin bridging the SvelteKit UI to the Android tunnel. Registered from Rust via
 * `api.register_android_plugin("org.getlantern.spark.vpn", "SparkVpnPlugin")`.
 *
 * P3.1 SCOPE: these @Command methods are minimal stubs that compile and let the app launch. The
 * read-only ones return safe defaults (or query [SparkBridge]); the mutating ones reject with
 * "not yet implemented". Full logic — consent gate, foreground service start/stop, live pushes —
 * is wired in P3.2.
 */
@TauriPlugin
class SparkVpnPlugin(private val activity: Activity) : Plugin(activity) {

    @Command
    fun connect(invoke: Invoke) {
        invoke.reject("connect: not yet implemented (P3.2)")
    }

    @Command
    fun disconnect(invoke: Invoke) {
        invoke.reject("disconnect: not yet implemented (P3.2)")
    }

    @Command
    fun status(invoke: Invoke) {
        // Neutral disconnected status until the service publishes real state (P3.2).
        val ret = JSObject()
        ret.put("state", "disconnected")
        ret.put("protocol", "AnyTLS")
        ret.put("failOpen", false)
        invoke.resolve(ret)
    }

    @Command
    fun servers(invoke: Invoke) {
        // The live pool as a JSON array; "[]" before any connect. Nullable only on a catastrophic
        // JNI string-allocation failure — treat null as "[]".
        val json = runCatching { SparkBridge.nativeServers() }.getOrNull() ?: "[]"
        val ret = JSObject()
        ret.put("servers", json)
        invoke.resolve(ret)
    }

    @Command
    fun selectServer(invoke: Invoke) {
        invoke.reject("selectServer: not yet implemented (P3.2)")
    }

    @Command
    fun getSplitTunnel(invoke: Invoke) {
        val ret = JSObject()
        ret.put("splitTunnel", "{\"enabled\":false,\"domains\":[],\"ips\":[]}")
        invoke.resolve(ret)
    }

    @Command
    fun setSplitTunnel(invoke: Invoke) {
        invoke.reject("setSplitTunnel: not yet implemented (P3.2)")
    }

    @Command
    fun getRoutingMode(invoke: Invoke) {
        val ret = JSObject()
        ret.put("routingMode", "smart")
        invoke.resolve(ret)
    }

    @Command
    fun setRoutingMode(invoke: Invoke) {
        invoke.reject("setRoutingMode: not yet implemented (P3.2)")
    }
}
