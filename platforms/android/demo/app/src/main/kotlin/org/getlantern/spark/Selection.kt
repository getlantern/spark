package org.getlantern.spark

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

/** UI-chosen server pin: null = auto (fastest), else the pinned pool index. Write only via [pin]. */
object Selection {
    private val _index = MutableStateFlow<Int?>(null)
    val index: StateFlow<Int?> = _index.asStateFlow()

    // Process-lived (not tied to a composition) so applying the native pin can't be cancelled by
    // the screen navigating away the instant after the tap.
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    /** Pin [idx] (null = auto): reflect it in [index] immediately, and apply the native pin off the
     *  main thread on the process-lived scope so a back-navigation can't cancel it before it lands. */
    fun pin(idx: Int?) {
        _index.value = idx
        scope.launch { SparkBridge.nativeSelectServer(idx ?: -1) }
    }
}
