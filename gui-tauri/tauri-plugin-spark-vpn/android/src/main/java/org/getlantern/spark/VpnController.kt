package org.getlantern.spark

import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build

/** Connect/disconnect helpers shared by the Compose UI: VPN consent + start/stop the service. */
object VpnController {
    /** The consent Intent to launch (first run), or null if already granted — then call [start]. */
    fun consentIntent(ctx: Context): Intent? = VpnService.prepare(ctx)

    fun start(ctx: Context) {
        val intent = Intent(ctx, SparkVpnService::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) ctx.startForegroundService(intent)
        else ctx.startService(intent)
    }

    fun stop(ctx: Context) {
        // Deliver ACTION_STOP so the service stops ITSELF (stopForeground + stopSelf): the canonical,
        // reliable way to tear down a foreground service. stopService() does NOT reliably stop our
        // foreground specialUse service (verified: onDestroy never fires), so we don't use it. This is
        // only ever called from the toggle while connected, i.e. the service is already running, so it
        // doesn't trip Android 8+'s background-service-start restriction.
        ctx.startService(
            Intent(ctx, SparkVpnService::class.java).setAction(SparkVpnService.ACTION_STOP),
        )
    }

    /** Ask the running service to rebuild with the latest excluded-apps list (live, no reconnect). */
    fun applyExcludedApps(ctx: Context) {
        ctx.startService(
            Intent(ctx, SparkVpnService::class.java).setAction(SparkVpnService.ACTION_APPLY_APPS),
        )
    }
}
