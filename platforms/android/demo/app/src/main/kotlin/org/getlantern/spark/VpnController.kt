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
        ctx.startService(
            Intent(ctx, SparkVpnService::class.java).setAction(SparkVpnService.ACTION_STOP),
        )
    }
}
