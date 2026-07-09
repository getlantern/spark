package org.getlantern.spark

import org.junit.Assert.assertEquals
import org.junit.Test

class SparkStateTest {
    @Test
    fun onChangeFiresWithEachNewValue() {
        val seen = mutableListOf<VpnState>()
        SparkState.onChange = { seen.add(it) }
        try {
            SparkState.set(VpnState.CONNECTING)
            SparkState.set(VpnState.CONNECTED)
        } finally {
            SparkState.onChange = null
            SparkState.set(VpnState.DISCONNECTED) // reset the global singleton for other tests
        }
        assertEquals(listOf(VpnState.CONNECTING, VpnState.CONNECTED), seen)
    }
}
