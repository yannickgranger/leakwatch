package io.github.yannickgranger.leakwatch.domain

import java.time.ZoneId
import io.github.yannickgranger.leakwatch.port.ArchiveStore
import io.github.yannickgranger.leakwatch.port.Clock
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ArchiveDayChangeTest {
    private class Store : ArchiveStore {
        val files = sortedMapOf<String, StringBuilder>()
        override fun append(day: String, name: String, text: String) { files.getOrPut("$day/$name") { StringBuilder() }.append(text) }
        override fun write(day: String, name: String, text: String) { files["$day/$name"] = StringBuilder(text) }
        override fun read(day: String, name: String): String? = files["$day/$name"]?.toString()
        override fun days(): List<String> = files.keys.map { it.substringBefore('/') }.filter { it.isNotEmpty() }.distinct()
        override fun writeRoot(name: String, text: String) { files["/$name"] = StringBuilder(text) }
        override fun readRoot(name: String): String? = files["/$name"]?.toString()
    }

    private val paris = ZoneId.of("Europe/Paris")
    private var now = java.time.ZonedDateTime.of(2026, 11, 8, 23, 59, 50, 0, paris).toInstant().toEpochMilli()
    private val clock = object : Clock {
        override fun nowMillis() = now
        override fun zone(): ZoneId = paris
    }

    @Test
    fun midnightStartsANewDayFolderAndResetsCountersWithoutRestart() {
        val store = Store()
        val w = ArchiveWriter(store, clock)
        w.flow(Fixtures.flow(id = "a", bytesOut = 500, tsStart = now), null)
        assertEquals(1, w.today().size)
        now += 20_000
        w.flow(Fixtures.flow(id = "b", bytesOut = 700, tsStart = now), null)
        assertEquals(listOf("b"), w.today().map { it.id })
        w.flush(emptyList())
        assertEquals(listOf("2026-11-08", "2026-11-09"), store.days())
        assertTrue(store.read("2026-11-08", "flows.jsonl")!!.contains("\"id\":\"a\""))
        assertTrue(store.read("2026-11-09", "flows.jsonl")!!.contains("\"id\":\"b\""))
        assertEquals(2, store.read("2026-11-08", "apps.csv")!!.trim().lines().size)
        assertTrue(store.read("2026-11-08", "apps.csv")!!.contains(",500,"))
        assertTrue(store.read("2026-11-09", "apps.csv")!!.contains(",700,"))
    }

    @Test
    fun offendersReportReadsDayFoldersAndWritesRootCsv() {
        val store = Store()
        val w = ArchiveWriter(store, clock)
        w.flow(Fixtures.flow(id = "a", appState = "screen_off", bytesOut = 4_000, reasons = listOf("screen_off"), tsStart = now), null)
        w.flush(emptyList())
        val rows = OffendersReport(store).write(setOf(10100))
        assertEquals(1, rows.size)
        assertEquals(OffendersCsv.HEADER, store.readRoot("offenders.csv")!!.lines().first())
        assertEquals(rows, OffendersReport(store).read())
        assertEquals(true, rows[0].blocked)
    }
}
