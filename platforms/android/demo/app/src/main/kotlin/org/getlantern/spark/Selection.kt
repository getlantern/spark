package org.getlantern.spark

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch

/** UI-chosen server pin: null = auto (fastest), else the pinned pool index. UI-written. */
object Selection {
    val index = MutableStateFlow<Int?>(null)

    // Process-lived (not tied to a composition) so applying the native pin can't be cancelled by
    // the screen navigating away the instant after the tap.
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    /** Pin [idx] (null = auto): reflect it in [index] immediately, and apply the native pin off the
     *  main thread on the process-lived scope so a back-navigation can't cancel it before it lands. */
    fun pin(idx: Int?) {
        index.value = idx
        scope.launch { SparkBridge.nativeSelectServer(idx ?: -1) }
    }
}
