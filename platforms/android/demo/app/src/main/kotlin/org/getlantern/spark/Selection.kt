package org.getlantern.spark
import kotlinx.coroutines.flow.MutableStateFlow
/** UI-chosen server pin: null = auto (fastest), else the pinned pool index. UI-written. */
object Selection { val index = MutableStateFlow<Int?>(null) }
