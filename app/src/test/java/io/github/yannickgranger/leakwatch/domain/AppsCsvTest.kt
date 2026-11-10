package io.github.yannickgranger.leakwatch.domain

import io.github.yannickgranger.leakwatch.domain.Fixtures.flow
import org.junit.Assert.assertEquals
import org.junit.Test

class AppsCsvTest {
    @Test
    fun startsWithExactHeader() {
        assertEquals("label,packages,uid,flows,bytes_out,bytes_in,destinations,tracker_flows,suspicious_flows,suspicious_bytes_out,background_bytes_out,reasons,top_destinations,blocked_attempts", AppsCsv.render(emptyList()).lines().first())
    }

    @Test
    fun aggregatesPerUidSortedByBytesOut() {
        val csv = AppsCsv.render(
            listOf(
                flow(id = "1", uid = 10100, label = "Brave", bytesOut = 100, bytesIn = 10),
                flow(id = "2", uid = 10200, label = "Spy", packages = listOf("com.spy", "com.spy.sdk"), sni = "app-measurement.com", tracker = true, reasons = listOf("tracker"), bytesOut = 900, bytesIn = 5),
                flow(id = "3", uid = 10100, label = "Brave", sni = "neverssl.com", bytesOut = 50, bytesIn = 20),
            ),
        ).trim().lines()
        assertEquals(3, csv.size)
        assertEquals("Spy,com.spy|com.spy.sdk,10200,1,900,5,1,1,1,900,0,tracker,app-measurement.com,0", csv[1])
        assertEquals("Brave,com.brave.browser,10100,2,150,30,2,0,0,0,0,,example.com|neverssl.com,0", csv[2])
    }

    @Test
    fun topDestinationsAreFiveMostContacted() {
        val flows = mutableListOf<FlowRecord>()
        val counts = mapOf("a.com" to 7, "b.com" to 6, "c.com" to 5, "d.com" to 4, "e.com" to 3, "f.com" to 2)
        var n = 0
        for ((name, c) in counts) repeat(c) { flows += flow(id = "${n++}", sni = name) }
        val row = AppsCsv.render(flows).trim().lines()[1].split(",")
        assertEquals("6", row[6])
        assertEquals("a.com|b.com|c.com|d.com|e.com", row[12])
    }

    @Test
    fun fallsBackToHttpHostDnsNameThenIpAndQuotesCommas() {
        val csv = AppsCsv.render(
            listOf(
                flow(id = "1", label = "Maps, Navigation", sni = null, httpHost = "h.com", bytesOut = 3),
                flow(id = "2", label = "Maps, Navigation", sni = null, dnsName = "d.com", bytesOut = 2),
                flow(id = "3", label = "Maps, Navigation", sni = null, dst = "[2001:db8::1]:443", bytesOut = 1),
            ),
        ).trim().lines()
        assertEquals("\"Maps, Navigation\",com.brave.browser,10100,3,6,3000,3,0,0,0,0,,2001:db8::1|d.com|h.com,0", csv[1])
    }

    @Test
    fun summaryListsDestinationsWithTrackerFlag() {
        val apps = AppStats.summarize(listOf(flow(id = "1", sni = "doubleclick.net", tracker = true, bytesOut = 5), flow(id = "2", sni = "example.com", bytesOut = 9)))
        val a = apps.single()
        assertEquals(1, a.trackerFlows)
        assertEquals(listOf("example.com", "doubleclick.net"), a.destinations.map { it.name })
        assertEquals(true, a.destinations[1].tracker)
    }

    @Test
    fun sortsBySuspiciousBytesOutThenBytesOut() {
        val csv = AppsCsv.render(
            listOf(
                flow(id = "1", uid = 10100, label = "Heavy", bytesOut = 90_000, bytesIn = 900_000),
                flow(id = "2", uid = 10200, label = "Quiet", packages = listOf("com.quiet"), bytesOut = 10),
                flow(id = "3", uid = 10300, label = "Sneaky", packages = listOf("com.sneaky"), appState = "background", reasons = listOf("background"), bytesOut = 2_000, bytesIn = 0),
                flow(id = "4", uid = 10300, label = "Sneaky", packages = listOf("com.sneaky"), sni = "log.sneaky.io", appState = "screen_off", reasons = listOf("telemetry_name", "screen_off"), bytesOut = 3_000, bytesIn = 0),
                flow(id = "5", uid = 10300, label = "Sneaky", packages = listOf("com.sneaky"), sni = "log.sneaky.io", reasons = listOf("telemetry_name"), bytesOut = 500, bytesIn = 0),
            ),
        ).trim().lines()
        assertEquals(listOf("Sneaky", "Heavy", "Quiet"), csv.drop(1).map { it.substringBefore(',') })
        assertEquals("Sneaky,com.sneaky,10300,3,5500,0,2,0,3,5500,5000,telemetry_name|screen_off|background,log.sneaky.io|example.com,0", csv[1])
        assertEquals("Heavy,com.brave.browser,10100,1,90000,900000,1,0,0,0,0,,example.com,0", csv[2])
    }

    @Test
    fun destinationsCarryTheirReasons() {
        val a = AppStats.summarize(
            listOf(
                flow(id = "1", sni = "log.example.com", reasons = listOf("telemetry_name"), bytesOut = 5),
                flow(id = "2", sni = "log.example.com", reasons = listOf("tracker", "telemetry_name"), bytesOut = 5),
                flow(id = "3", sni = "example.com", bytesOut = 9),
            ),
        ).single()
        assertEquals(2, a.suspiciousFlows)
        assertEquals(10L, a.suspiciousBytesOut)
        assertEquals(listOf("tracker", "telemetry_name"), a.reasons)
        assertEquals(listOf("tracker", "telemetry_name"), a.destinations.first { it.name == "log.example.com" }.reasons)
        assertEquals(emptyList<String>(), a.destinations.first { it.name == "example.com" }.reasons)
    }

    @Test
    fun tunnelledFlowsCountAsTrafficButNeverAsSuspiciousOrBackground() {
        val csv = AppsCsv.render(
            listOf(
                flow(id = "1", uid = 10400, label = "FairEmail", packages = listOf("eu.faircode.email"), dst = "10.200.0.1:143", sni = null, appState = "background", reasons = listOf("background", "cleartext_data"), bytesOut = 4_000, bytesIn = 100, via = FlowRecord.VIA_WIREGUARD),
                flow(id = "2", uid = 10400, label = "FairEmail", packages = listOf("eu.faircode.email"), bytesOut = 50, bytesIn = 100),
            ),
        ).trim().lines()
        assertEquals("FairEmail,eu.faircode.email,10400,2,4050,200,2,0,0,0,0,,10.200.0.1|example.com,0", csv[1])
    }

    @Test
    fun blockedAttemptsCountBlockedDnsAnswersAndDomainBlockedFlows() {
        val blockedFlow = flow(id = "b1", uid = 10200, label = "Spy", packages = listOf("com.spy"), sni = "graph.facebook.com", bytesOut = 0, bytesIn = 0, reasons = listOf("tracker"))
            .copy(blocked = true, closeReason = "domain_blocked")
        val csv = AppsCsv.render(
            listOf(flow(id = "1", uid = 10200, label = "Spy", packages = listOf("com.spy"), bytesOut = 10, bytesIn = 10), blockedFlow),
            mapOf(10200 to 3, 99999 to 4),
        ).trim().lines()
        assertEquals(2, csv.size)
        assertEquals("Spy,com.spy,10200,2,10,10,2,0,0,0,0,,example.com|graph.facebook.com,4", csv[1])
    }
}
