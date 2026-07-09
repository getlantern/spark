package org.getlantern.spark

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

enum class VpnState { DISCONNECTED, CONNECTING, CONNECTED, FAILED }

/** Process-global tunnel state. Each process holds its own singleton: in `:vpn` the service is the
 *  writer and wires [onChange] to its control broadcaster; in the UI process SparkControlClient is
 *  the writer, feeding it from pushed control messages (the plugin also sets CONNECTING optimistically
 *  at connect start). The UI observes [state]. */
object SparkState {
    private val _state = MutableStateFlow(VpnState.DISCONNECTED)
    val state: StateFlow<VpnState> = _state.asStateFlow()

    /** Invoked after every [set] if non-null. In `:vpn` the service wires this to broadcast state to
     *  the bound UI client; null (unused) in the UI process. @Volatile since set() is called from
     *  several threads. */
    @Volatile
    var onChange: ((VpnState) -> Unit)? = null

    /** Publish a new tunnel state (and notify [onChange]). */
    fun set(value: VpnState) {
        _state.value = value
        onChange?.invoke(value)
    }
}
