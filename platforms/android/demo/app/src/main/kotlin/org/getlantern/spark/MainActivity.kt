package org.getlantern.spark

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.util.Log
import android.widget.Button
import android.widget.LinearLayout

/**
 * Minimal demo/test harness: a Connect button requests VPN consent then starts
 * [SparkVpnService]; Disconnect stops it. Also auto-connects on launch so the emulator gate can
 * drive it with a single `am start` (consent is pre-granted in the test via `appops`).
 */
class MainActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val layout = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        layout.addView(Button(this).apply {
            text = "Connect"
            setOnClickListener { connect() }
        })
        layout.addView(Button(this).apply {
            text = "Disconnect"
            setOnClickListener { disconnect() }
        })
        setContentView(layout)

        connect() // auto-connect for the test harness
    }

    private fun connect() {
        val consent = VpnService.prepare(this)
        if (consent != null) {
            startActivityForResult(consent, REQ_VPN)
        } else {
            startVpn()
        }
    }

    private fun disconnect() {
        startService(
            Intent(this, SparkVpnService::class.java).setAction(SparkVpnService.ACTION_STOP),
        )
    }

    private fun startVpn() {
        Log.i(TAG, "consent granted; starting SparkVpnService")
        // The service promotes itself to the foreground (startForeground) so the tunnel survives
        // backgrounding; on API 26+ a backgrounded app must launch it via startForegroundService.
        val intent = Intent(this, SparkVpnService::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(intent)
        } else {
            startService(intent)
        }
    }

    @Deprecated("startActivityForResult is fine for this minimal harness on minSdk 24")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQ_VPN && resultCode == RESULT_OK) startVpn()
    }

    companion object {
        private const val TAG = "SparkVpn"
        private const val REQ_VPN = 1
    }
}
