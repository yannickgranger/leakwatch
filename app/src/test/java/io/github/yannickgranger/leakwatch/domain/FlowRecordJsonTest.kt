package io.github.yannickgranger.leakwatch.domain

import java.time.ZoneId
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class FlowRecordJsonTest {
    private val paris = ZoneId.of("Europe/Paris")

    @Test
    fun emitsExactlyTheArchiveKeysIncludingNulls() {
        val obj = Json.parseObject(Fixtures.flow().toJson(paris))
        assertEquals(FlowRecord.KEYS.toSet(), obj.keys)
        assertEquals(26, obj.size)
        assertEquals(
            setOf(
                "id", "ts_start", "ts_end", "uid", "packages", "label", "proto", "ip_version", "src", "dst", "dns_name", "sni",
                "http_host", "tracker", "bytes_out", "bytes_in", "packets_out", "packets_in", "blocked", "close_reason", "dump",
                "app_state", "last_used", "reasons", "suspicious", "via",
            ),
            obj.keys,
        )
        assertNull(obj["last_used"])
        assertEquals(emptyList<String>(), obj["reasons"])
        assertEquals(false, obj["suspicious"])
        assertTrue(obj.containsKey("http_host"))
        assertNull(obj["http_host"])
        assertNull(obj["dump"])
        assertEquals("direct", obj["via"])
    }

    @Test
    fun writesTunnelledFlowsAsViaWireguard() {
        val f = Fixtures.flow(dst = "10.200.0.1:22", sni = null).copy(via = "wireguard")
        val obj = Json.parseObject(f.toJson(paris))
        assertEquals("wireguard", obj["via"])
        assertEquals(f, FlowRecord.fromJson(f.toJson(paris)))
    }

    @Test
    fun writesIsoTimestampsWithOffsetAndTypedValues() {
        val obj = Json.parseObject(Fixtures.flow().toJson(paris))
        assertEquals("2025-11-08T12:06:40+01:00", obj["ts_start"])
        assertEquals(10100L, obj["uid"])
        assertEquals(listOf("com.brave.browser"), obj["packages"])
        assertEquals(false, obj["tracker"])
        assertEquals(4L, obj["ip_version"])
        assertEquals("tcp", obj["proto"])
        assertTrue(Fixtures.flow().toJson(paris).lines().size == 1)
    }

    @Test
    fun roundTripsThroughJson() {
        val f = Fixtures.flow(
            dst = "[2606:2800::1]:443", dump = "dumps/f1.txt", httpHost = "a.b", tracker = true,
            appState = "background", lastUsed = 1_762_590_000_000, reasons = listOf("tracker", "background"),
        )
        assertEquals(f, FlowRecord.fromJson(f.toJson(paris)))
    }

    @Test
    fun writesDetectionValues() {
        val f = Fixtures.flow(appState = "screen_off", lastUsed = 1_762_600_000_000, reasons = listOf("screen_off", "bulk_upload"))
        val obj = Json.parseObject(f.toJson(paris))
        assertEquals("screen_off", obj["app_state"])
        assertEquals("2025-11-08T12:06:40+01:00", obj["last_used"])
        assertEquals(listOf("screen_off", "bulk_upload"), obj["reasons"])
        assertEquals(true, obj["suspicious"])
    }

    @Test
    fun readsV1LinesWithDefaults() {
        val v1 = Fixtures.flow().toJson(paris).replace(Regex(",\"app_state\".*}$"), "}")
        val back = FlowRecord.fromJson(v1)
        assertEquals("unknown", back.appState)
        assertNull(back.lastUsed)
        assertEquals(emptyList<String>(), back.reasons)
    }

    @Test
    fun escapesSpecialCharacters() {
        val f = Fixtures.flow(label = "Quote \" back \\ tab\t new\nline é")
        val back = FlowRecord.fromJson(f.toJson(paris))
        assertEquals(f.label, back.label)
        assertTrue(!f.toJson(paris).contains("\n"))
    }

    @Test
    fun dnsRecordHasExactKeys() {
        val d = DnsRecord(1_762_600_000_000, 10100, "Brave", "example.com", "A", listOf("93.184.215.14"))
        val obj = Json.parseObject(d.toJson(paris))
        assertEquals(setOf("ts", "uid", "label", "name", "qtype", "answers", "blocked"), obj.keys)
        assertEquals(false, obj["blocked"])
        assertEquals(true, Json.parseObject(d.copy(blocked = true, answers = emptyList()).toJson(paris))["blocked"])
        assertEquals(listOf("93.184.215.14"), obj["answers"])
        assertEquals("2025-11-08T12:06:40+01:00", obj["ts"])
    }

    @Test
    fun isoTimeRoundTripsAndNamesLocalDay() {
        assertEquals(1_762_600_000_000, IsoTime.parse(IsoTime.format(1_762_600_000_000, paris)))
        assertEquals("2025-11-08", IsoTime.day(1_762_600_000_000, paris))
    }
}
