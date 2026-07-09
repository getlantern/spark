package org.getlantern.spark.control

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class PendingRequestsTest {
    @Test
    fun createReturnsMonotonicIds() {
        val r = PendingRequests<String>()
        assertEquals(1, r.create(CompletableDeferred()))
        assertEquals(2, r.create(CompletableDeferred()))
    }

    @Test
    fun resolveCompletesTheMatchingDeferred() = runBlocking {
        val r = PendingRequests<String>()
        val d = CompletableDeferred<String>()
        val id = r.create(d)
        assertTrue(r.resolve(id, "hello"))
        assertEquals("hello", d.await())
        assertEquals(0, r.size)
    }

    @Test
    fun resolveUnknownIdIsNoop() {
        val r = PendingRequests<String>()
        assertFalse(r.resolve(999, "x"))
    }

    @Test
    fun resolveTwiceOnlyCompletesOnce() {
        val r = PendingRequests<String>()
        val id = r.create(CompletableDeferred())
        assertTrue(r.resolve(id, "a"))
        assertFalse(r.resolve(id, "b"))
    }

    @Test
    fun failAllCompletesEveryInFlightWithFallback() = runBlocking {
        val r = PendingRequests<String>()
        val d1 = CompletableDeferred<String>()
        val d2 = CompletableDeferred<String>()
        r.create(d1)
        r.create(d2)
        r.failAll("[]")
        assertEquals("[]", d1.await())
        assertEquals("[]", d2.await())
        assertEquals(0, r.size)
    }

    @Test
    fun removeDropsWithoutCompleting() {
        val r = PendingRequests<String>()
        val d = CompletableDeferred<String>()
        val id = r.create(d)
        r.remove(id)
        assertFalse(d.isCompleted)
        assertFalse(r.resolve(id, "x"))
    }
}
