package org.getlantern.spark.control

import org.getlantern.spark.VpnState
import org.junit.Assert.assertEquals
import org.junit.Test

class ControlProtocolTest {
    @Test
    fun stateRoundTripsThroughWire() {
        for (s in VpnState.values()) {
            assertEquals(s, vpnStateFromWire(s.toWire()))
        }
    }

    @Test
    fun unknownWireValueDecodesToDisconnected() {
        assertEquals(VpnState.DISCONNECTED, vpnStateFromWire(999))
    }

    @Test
    fun negativeWireValueDecodesToDisconnected() {
        assertEquals(VpnState.DISCONNECTED, vpnStateFromWire(-1))
    }
}
