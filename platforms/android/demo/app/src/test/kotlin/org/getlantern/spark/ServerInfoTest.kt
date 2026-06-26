package org.getlantern.spark

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ServerInfoTest {
    @Test fun parses_full_member() {
        val json = """[{"index":0,"name":"sfo","country":"United States","countryCode":"US",
            "city":"Phoenix","protocol":"hysteria2","latencyMs":502,"healthy":true,"isCurrent":true}]"""
        val s = parseServers(json).single()
        assertEquals(0, s.index); assertEquals("United States", s.country)
        assertEquals("US", s.countryCode); assertEquals("hysteria2", s.protocol)
        assertEquals(502L, s.latencyMs); assertTrue(s.healthy); assertTrue(s.isCurrent)
    }
    @Test fun handles_nulls_and_missing() {
        val s = parseServers("""[{"index":1,"healthy":false,"isCurrent":false}]""").single()
        assertEquals(1, s.index); assertEquals(null, s.country); assertEquals(null, s.latencyMs)
    }
    @Test fun null_and_empty_and_garbage_yield_empty_list() {
        assertEquals(emptyList<ServerInfo>(), parseServers(null))
        assertEquals(emptyList<ServerInfo>(), parseServers("[]"))
        assertEquals(emptyList<ServerInfo>(), parseServers("not json"))
    }
}
