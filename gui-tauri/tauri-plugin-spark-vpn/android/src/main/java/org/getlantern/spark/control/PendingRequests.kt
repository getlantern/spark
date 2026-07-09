package org.getlantern.spark.control

import kotlinx.coroutines.CompletableDeferred

/**
 * Correlates outbound control requests with their replies by a monotonic request id. `create` runs
 * on the caller's coroutine dispatcher while `resolve` runs on the incoming-Messenger handler
 * thread, so the map is guarded by a lock. Pure Kotlin (no Android types) → host-unit-testable.
 *
 * [T] is the reply payload type (String for the servers JSON, Boolean for the select-server ok),
 * so a client keeps one registry per reply type and each reply routes to the right one by `what`.
 */
class PendingRequests<T> {
    private val lock = Any()
    private var nextId = 1
    private val pending = HashMap<Int, CompletableDeferred<T>>()

    /** Register [deferred] under a fresh id and return that id to stamp on the outbound message. */
    fun create(deferred: CompletableDeferred<T>): Int = synchronized(lock) {
        val id = nextId++
        pending[id] = deferred
        id
    }

    /** Complete the deferred registered under [id] with [value]. Returns false if [id] is unknown
     *  (a late/duplicate reply) or was already completed. */
    fun resolve(id: Int, value: T): Boolean {
        val d = synchronized(lock) { pending.remove(id) } ?: return false
        return d.complete(value)
    }

    /** Drop the request under [id] without completing it (e.g. on the caller's own timeout). */
    fun remove(id: Int) {
        synchronized(lock) { pending.remove(id) }
    }

    /** Complete every in-flight request with [fallback] and clear the map (e.g. on disconnect). */
    fun failAll(fallback: T) {
        val snapshot = synchronized(lock) {
            val s = pending.values.toList()
            pending.clear()
            s
        }
        snapshot.forEach { it.complete(fallback) }
    }

    /** Count of in-flight requests (for tests/diagnostics). */
    val size: Int get() = synchronized(lock) { pending.size }
}
