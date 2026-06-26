package org.getlantern.spark

import kotlinx.coroutines.flow.MutableStateFlow

enum class VpnState { DISCONNECTED, CONNECTING, CONNECTED, FAILED }

/** Process-global tunnel state. The service is the only writer; the UI observes it.
 *  (Activity + service + core share one process, so a plain singleton is correct here.) */
object SparkState {
    val state = MutableStateFlow(VpnState.DISCONNECTED)
}
