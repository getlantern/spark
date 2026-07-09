package org.getlantern.spark.control

import org.getlantern.spark.VpnState

/**
 * Wire contract for the `:vpn` control Messenger. Pure Kotlin (no Android types) so the encoding
 * and the [VpnState] mapping are host-unit-testable. `what` codes are split into a client→service
 * range and a service→client range so a stray cross-delivery can't be misread.
 */
object ControlMsg {
    // client -> service
    const val REGISTER = 1 // msg.replyTo = the client Messenger; service replies with current STATE
    const val UNREGISTER = 2
    const val GET_SERVERS = 3 // msg.arg1 = requestId
    const val SELECT_SERVER = 4 // msg.arg1 = requestId; data[INDEX] = Int
    const val SET_SPLIT_TUNNEL = 5 // data[JSON] = String (one-way, no reply)
    const val SET_ROUTING_MODE = 6 // data[MODE] = String (one-way, no reply)

    // service -> client
    const val STATE = 100 // msg.arg1 = VpnState wire ordinal
    const val SERVERS_REPLY = 101 // msg.arg1 = requestId; data[JSON] = String
    const val SELECT_SERVER_REPLY = 102 // msg.arg1 = requestId; data[OK] = Boolean
}

/** Keys for the [android.os.Bundle] payloads carried on control messages. */
object ControlKey {
    const val INDEX = "index"
    const val JSON = "json"
    const val MODE = "mode"
    const val OK = "ok"
}

/** Encode a [VpnState] for the wire as its enum ordinal. */
fun VpnState.toWire(): Int = ordinal

/**
 * Decode a wire ordinal back to a [VpnState]; any out-of-range value (a version skew or a corrupt
 * message) decodes to [VpnState.DISCONNECTED] rather than throwing. Uses `values()` (not `.entries`,
 * which needs Kotlin 1.9+; this module is on Kotlin 1.8.20).
 */
fun vpnStateFromWire(value: Int): VpnState =
    VpnState.values().getOrElse(value) { VpnState.DISCONNECTED }
