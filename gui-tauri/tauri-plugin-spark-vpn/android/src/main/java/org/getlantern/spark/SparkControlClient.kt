package org.getlantern.spark

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.Bundle
import android.os.Handler
import android.os.HandlerThread
import android.os.IBinder
import android.os.Message
import android.os.Messenger
import android.util.Log
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.withTimeoutOrNull
import org.getlantern.spark.control.ControlKey
import org.getlantern.spark.control.ControlMsg
import org.getlantern.spark.control.PendingRequests
import org.getlantern.spark.control.vpnStateFromWire

/**
 * Main-process client for the `:vpn` control Messenger. Binds to [SparkVpnService] (ACTION_CONTROL),
 * registers a reply channel, mirrors pushed state into the main-process [SparkState], and does
 * request/reply for servers/selectServer plus one-way sends for the live setters.
 *
 * Lifecycle: adopt-bind at plugin init (flags=0 → no-op if the tunnel isn't running, so it never
 * spawns an idle `:vpn`); auto-create bind on connect (the service is being started anyway);
 * unbind when a terminal-down state (DISCONNECTED/FAILED) is observed or the connection dies, so a
 * lingering binding never keeps a stopped `:vpn` alive.
 */
class SparkControlClient(private val context: Context) {
    private val incomingThread = HandlerThread("spark-control-client").apply { start() }
    private val incoming = Messenger(
        Handler(incomingThread.looper, Handler.Callback { msg -> handleReply(msg); true }),
    )

    private val serversPending = PendingRequests<String>()
    private val selectPending = PendingRequests<Boolean>()

    @Volatile private var service: Messenger? = null
    @Volatile private var bound = false

    private val conn = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, binder: IBinder?) {
            val svc = Messenger(binder)
            service = svc
            val m = Message.obtain(null, ControlMsg.REGISTER).apply { replyTo = incoming }
            runCatching { svc.send(m) }.onFailure { Log.w(TAG, "REGISTER send failed", it) }
        }

        override fun onServiceDisconnected(name: ComponentName?) = onLost()
        override fun onBindingDied(name: ComponentName?) = onLost()
    }

    private fun onLost() {
        service = null
        // Fail in-flight requests to their lenient defaults so callers don't hang.
        serversPending.failAll("[]")
        selectPending.failAll(false)
        unbind()
    }

    /** Adopt an already-running `:vpn` if present; no-op (and no process spawn) otherwise. */
    fun bindIfRunning() = bind(autoCreate = false)

    /** Ensure bound during a connect (the foreground service is being started concurrently). */
    fun bindForConnect() = bind(autoCreate = true)

    private fun bind(autoCreate: Boolean) {
        if (bound) return
        val intent = Intent(context, SparkVpnService::class.java).setAction(SparkVpnService.ACTION_CONTROL)
        val flags = if (autoCreate) Context.BIND_AUTO_CREATE else 0
        val ok = runCatching { context.bindService(intent, conn, flags) }.getOrDefault(false)
        if (ok) {
            bound = true
        } else {
            // bindService records the ServiceConnection even when it returns false (service not
            // running); release it so a later bind() starts clean.
            runCatching { context.unbindService(conn) }
        }
    }

    private fun unbind() {
        if (!bound) return
        bound = false
        // Politely deregister so the service stops pushing state to a Messenger we're about to drop.
        // Only reachable on an intentional unbind (service still bound); onLost() nulls `service`
        // first because the binding is already dead, so this send is correctly skipped there.
        service?.let { svc -> runCatching { svc.send(Message.obtain(null, ControlMsg.UNREGISTER)) } }
        service = null
        runCatching { context.unbindService(conn) }
    }

    private fun handleReply(msg: Message) {
        when (msg.what) {
            ControlMsg.STATE -> {
                val s = vpnStateFromWire(msg.arg1)
                SparkState.set(s)
                if (s == VpnState.DISCONNECTED || s == VpnState.FAILED) unbind()
            }
            ControlMsg.SERVERS_REPLY -> {
                val json = msg.data?.getString(ControlKey.JSON) ?: "[]"
                serversPending.resolve(msg.arg1, json)
            }
            ControlMsg.SELECT_SERVER_REPLY -> {
                val ok = msg.data?.getBoolean(ControlKey.OK, false) ?: false
                selectPending.resolve(msg.arg1, ok)
            }
        }
    }

    /** The live server pool as a JSON array string; "[]" if unbound or the request times out. */
    suspend fun getServers(): String {
        val svc = service ?: return "[]"
        val deferred = CompletableDeferred<String>()
        val id = serversPending.create(deferred)
        val m = Message.obtain(null, ControlMsg.GET_SERVERS, id, 0).apply { replyTo = incoming }
        if (runCatching { svc.send(m) }.isFailure) {
            serversPending.remove(id)
            return "[]"
        }
        return withTimeoutOrNull(REQUEST_TIMEOUT_MS) { deferred.await() }
            ?: run { serversPending.remove(id); "[]" }
    }

    /** Pin which pool member new flows dial; false if unbound or the request times out. */
    suspend fun selectServer(index: Int): Boolean {
        val svc = service ?: return false
        val deferred = CompletableDeferred<Boolean>()
        val id = selectPending.create(deferred)
        val m = Message.obtain(null, ControlMsg.SELECT_SERVER, id, 0).apply {
            replyTo = incoming
            data = Bundle().apply { putInt(ControlKey.INDEX, index) }
        }
        if (runCatching { svc.send(m) }.isFailure) {
            selectPending.remove(id)
            return false
        }
        return withTimeoutOrNull(REQUEST_TIMEOUT_MS) { deferred.await() }
            ?: run { selectPending.remove(id); false }
    }

    /** One-way live push of the split-tunnel bypass list (dropped if unbound; the persisted file
     *  still applies on the next start). */
    fun setSplitTunnel(json: String) {
        val svc = service ?: return
        val m = Message.obtain(null, ControlMsg.SET_SPLIT_TUNNEL).apply {
            data = Bundle().apply { putString(ControlKey.JSON, json) }
        }
        runCatching { svc.send(m) }
    }

    /** One-way live push of the routing mode (dropped if unbound; persisted file applies on start). */
    fun setRoutingMode(mode: String) {
        val svc = service ?: return
        val m = Message.obtain(null, ControlMsg.SET_ROUTING_MODE).apply {
            data = Bundle().apply { putString(ControlKey.MODE, mode) }
        }
        runCatching { svc.send(m) }
    }

    companion object {
        private const val TAG = "SparkControlClient"
        private const val REQUEST_TIMEOUT_MS = 5_000L
    }
}
