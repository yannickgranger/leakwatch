package io.github.yannickgranger.leakwatch.domain

import org.junit.Assert.assertEquals
import org.junit.Test

class OffendersCsvTest {
    private fun f(uid: Int, label: String, state: String, out: Long, reasons: List<String>, sni: String = "a.example", tracker: Boolean = false) =
        Fixtures.flow(uid = uid, label = label, packages = listOf("p.$uid"), appState = state, bytesOut = out, reasons = reasons, sni = sni, tracker = tracker)

    private val days = mapOf(
        "2026-11-01" to listOf(f(1, "Old", "screen_off", 9_000, listOf("screen_off"))),
        "2026-11-02" to listOf(f(2, "Ads", "background", 2_000, listOf("tracker", "background"), "ads.example", true)),
        "2026-11-03" to listOf(
            f(2, "Ads", "screen_off", 3_000, listOf("tracker", "screen_off"), "ads.example", true),
            f(3, "Chat", "foreground", 50, emptyList()),
            f(4, "Night", "screen_off", 5_000, listOf("screen_off"), "n1.example"),
        ),
        "2026-11-04" to listOf(f(4, "Night", "screen_off", 1_500, listOf("screen_off", "bulk_upload"), "n2.example")),
        "2026-11-05" to listOf(f(5, "Leak", "foreground", 400, listOf("cleartext_data"))),
        "2026-11-06" to emptyList(),
        "2026-11-07" to listOf(f(5, "Leak", "background", 100, emptyList())),
        "2026-11-08" to listOf(f(6, "Fresh", "background", 7_000, listOf("background"))),
    )

    @Test
    fun headerIsExact() {
        assertEquals(
            "label,packages,uid,days_suspicious,suspicious_bytes_out_7d,screen_off_bytes_out_7d,background_bytes_out_7d,tracker_flows_7d,reasons,top_destinations,blocked,blocked_attempts_7d",
            OffendersCsv.HEADER,
        )
        assertEquals(OffendersCsv.HEADER, OffendersCsv.render(emptyList()).lines().first())
    }

    @Test
    fun keepsOnlyTheLastSevenDays() {
        assertEquals(listOf("2026-11-02", "2026-11-03", "2026-11-04", "2026-11-05", "2026-11-06", "2026-11-07", "2026-11-08"), OffendersCsv.lastDays(days.keys, 7))
        val rows = OffendersCsv.rank(days, emptySet())
        assertEquals(null, rows.firstOrNull { it.label == "Old" })
    }

    @Test
    fun ranksByDaysThenScreenOffThenSuspiciousBytes() {
        val rows = OffendersCsv.rank(days, setOf(4))
        assertEquals(listOf("Night", "Ads", "Fresh", "Leak"), rows.map { it.label })
        val night = rows[0]
        assertEquals(2, night.daysSuspicious)
        assertEquals(6_500, night.screenOffBytesOut7d)
        assertEquals(6_500, night.suspiciousBytesOut7d)
        assertEquals(listOf("screen_off", "bulk_upload"), night.reasons)
        assertEquals(true, night.blocked)
        val ads = rows[1]
        assertEquals(2, ads.daysSuspicious)
        assertEquals(3_000, ads.screenOffBytesOut7d)
        assertEquals(5_000, ads.backgroundBytesOut7d)
        assertEquals(2, ads.trackerFlows7d)
        assertEquals(listOf("tracker", "screen_off", "background"), ads.reasons)
        assertEquals(listOf("ads.example"), ads.topDestinations)
        assertEquals(false, ads.blocked)
        val leak = rows[3]
        assertEquals(1, leak.daysSuspicious)
        assertEquals(400, leak.suspiciousBytesOut7d)
        assertEquals(100, leak.backgroundBytesOut7d)
    }

    @Test
    fun appsWithoutSuspiciousFlowsAreNotOffenders() {
        assertEquals(null, OffendersCsv.rank(days, emptySet()).firstOrNull { it.label == "Chat" })
    }

    @Test
    fun rendersRowsAndParsesThemBack() {
        val rows = OffendersCsv.rank(days, setOf(4))
        val csv = OffendersCsv.render(rows)
        val lines = csv.trimEnd().lines()
        assertEquals(5, lines.size)
        assertEquals("Night,p.4,4,2,6500,6500,6500,0,screen_off|bulk_upload,n1.example|n2.example,true,0", lines[1])
        assertEquals(rows, OffendersCsv.parse(csv))
    }

    @Test
    fun quotesCellsWithCommas() {
        val rows = OffendersCsv.rank(mapOf("2026-11-08" to listOf(f(7, "A, B \"x\"", "background", 2_000, listOf("background")))), emptySet())
        val csv = OffendersCsv.render(rows)
        assertEquals("\"A, B \"\"x\"\"\"", csv.lines()[1].substringBefore(",p.7"))
        assertEquals(rows, OffendersCsv.parse(csv))
    }

    @Test
    fun tunnelledFlowsDoNotMakeAnOffender() {
        val sync = Fixtures.flow(
            uid = 7, label = "FairEmail", packages = listOf("eu.faircode.email"), dst = "10.200.0.1:143", sni = null,
            appState = AppState.SCREEN_OFF, bytesOut = 80_000, bytesIn = 10, reasons = listOf("background", "cleartext_data"),
            via = FlowRecord.VIA_WIREGUARD,
        )
        assertEquals(emptyList<OffenderRow>(), OffendersCsv.rank(mapOf("2026-11-08" to listOf(sync)), emptySet()))
        val leak = f(7, "FairEmail", AppState.BACKGROUND, 2_000, listOf("background"))
        val rows = OffendersCsv.rank(mapOf("2026-11-07" to listOf(sync), "2026-11-08" to listOf(sync, leak)), emptySet())
        assertEquals(1, rows.size)
        val row = rows[0]
        assertEquals(1, row.daysSuspicious)
        assertEquals(2_000, row.suspiciousBytesOut7d)
        assertEquals(0, row.screenOffBytesOut7d)
        assertEquals(2_000, row.backgroundBytesOut7d)
        assertEquals(listOf("background"), row.reasons)
    }

    @Test
    fun blockedAttemptsSumBlockedDnsAndDomainBlockedFlowsOverSevenDays() {
        val blockedFlow = f(4, "Night", AppState.SCREEN_OFF, 0, listOf("tracker")).copy(blocked = true, closeReason = "domain_blocked")
        val more = days + ("2026-11-08" to days.getValue("2026-11-08") + blockedFlow)
        val dns = mapOf("2026-11-01" to mapOf(4 to 50), "2026-11-04" to mapOf(4 to 2), "2026-11-08" to mapOf(4 to 1, 6 to 9))
        val rows = OffendersCsv.rank(more, emptySet(), dns)
        assertEquals(4, rows.single { it.uid == 4 }.blockedAttempts7d)
        assertEquals(9, rows.single { it.uid == 6 }.blockedAttempts7d)
        assertEquals(2, rows.single { it.uid == 4 }.daysSuspicious)
        assertEquals(rows, OffendersCsv.parse(OffendersCsv.render(rows)))
        assert(OffendersCsv.render(rows).lines().first { it.startsWith("Night,") }.endsWith(",false,4"))
    }
}
