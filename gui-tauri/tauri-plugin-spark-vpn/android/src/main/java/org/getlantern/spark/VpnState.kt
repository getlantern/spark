package org.getlantern.spark

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

enum class VpnState { DISCONNECTED, CONNECTING, CONNECTED, FAILED }

/** Process-global tunnel state. The service is the only writer (via [set]); the UI observes [state].
 *  (Activity + service + core share one process, so a plain singleton is correct here.) */
object SparkState {
    private val _state = MutableStateFlow(VpnState.DISCONNECTED)
    val state: StateFlow<VpnState> = _state.asStateFlow()

    /** Publish a new tunnel state. Only [SparkVpnService] should call this. */
    fun set(value: VpnState) {
        _state.value = value
    }
}
