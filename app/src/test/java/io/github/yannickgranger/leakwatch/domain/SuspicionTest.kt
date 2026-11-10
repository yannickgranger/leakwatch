package io.github.yannickgranger.leakwatch.domain

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SuspicionTest {
    private fun reasons(
        tracker: Boolean = false,
        telemetryName: Boolean = false,
        appState: String = AppState.FOREGROUND,
        notUsedToday: Boolean = false,
        cleartext: Boolean = false,
        bytesOut: Long = 100,
        bytesIn: Long = 1000,
    ) = Suspicion.reasons(tracker, telemetryName, appState, notUsedToday, cleartext, bytesOut, bytesIn)

    @Test
    fun legitimateForegroundTrafficHasNoReason() {
        assertEquals(emptyList<String>(), reasons())
        assertEquals(emptyList<String>(), reasons(appState = AppState.UNKNOWN, bytesOut = 10_000))
    }

    @Test
    fun trackerAndTelemetryName() {
        assertEquals(listOf("tracker"), reasons(tracker = true))
        assertEquals(listOf("telemetry_name"), reasons(telemetryName = true))
    }

    @Test
    fun screenOffNeedsOneKilobyteOut() {
        assertEquals(emptyList<String>(), reasons(appState = AppState.SCREEN_OFF, bytesOut = 1023))
        assertEquals(listOf("screen_off"), reasons(appState = AppState.SCREEN_OFF, bytesOut = 1024))
    }

    @Test
    fun backgroundNeedsOneKilobyteOut() {
        assertEquals(emptyList<String>(), reasons(appState = AppState.BACKGROUND, bytesOut = 1023))
        assertEquals(listOf("background"), reasons(appState = AppState.BACKGROUND, bytesOut = 1024))
    }

    @Test
    fun notUsedTodayAndCleartext() {
        assertEquals(listOf("not_used_today"), reasons(notUsedToday = true))
        assertEquals(listOf("cleartext_data"), reasons(cleartext = true))
    }

    @Test
    fun bulkUploadNeedsFiftyKilobytesAndMoreOutThanIn() {
        assertEquals(emptyList<String>(), reasons(bytesOut = 51_199, bytesIn = 0))
        assertEquals(listOf("bulk_upload"), reasons(bytesOut = 51_200, bytesIn = 51_199))
        assertEquals(emptyList<String>(), reasons(bytesOut = 51_200, bytesIn = 51_200))
    }

    @Test
    fun reasonsComeInTheFixedOrder() {
        assertEquals(
            listOf("tracker", "telemetry_name", "background", "not_used_today", "cleartext_data", "bulk_upload"),
            reasons(true, true, AppState.BACKGROUND, true, true, 60_000, 10),
        )
        assertEquals(listOf("tracker", "screen_off", "bulk_upload"), reasons(tracker = true, appState = AppState.SCREEN_OFF, bytesOut = 60_000, bytesIn = 0))
        assertEquals(listOf("tracker", "cleartext_data", "bulk_upload"), Suspicion.ordered(listOf("bulk_upload", "cleartext_data", "tracker", "bulk_upload")))
    }

    @Test
    fun suspiciousMeansAtLeastOneReason() {
        assertFalse(Fixtures.flow().suspicious)
        assertTrue(Fixtures.flow(reasons = listOf("cleartext_data")).suspicious)
    }

    private fun inspect(text: String): Inspection {
        val i = PayloadInspector()
        i.offer(text.toByteArray(Charsets.ISO_8859_1))
        return i.finish()
    }

    @Test
    fun httpWithBodyOrQueryIsCleartextData() {
        assertTrue(inspect("POST /collect HTTP/1.0\r\nHost: h\r\nContent-Length: 47\r\n\r\nemail=leakwatch-probe@example.org&imei=000000").cleartext)
        assertTrue(inspect("GET /p?id=42 HTTP/1.1\r\nHost: h\r\n\r\n").cleartext)
        assertFalse(inspect("GET /index.html HTTP/1.1\r\nHost: h\r\n\r\n").cleartext)
    }

    @Test
    fun rawTcpPayloadIsCleartextAndTlsIsNot() {
        assertTrue(inspect("\u0001\u0002binary protocol hello").cleartext)
        val hello = TestNet.hex(javaClass.classLoader!!.getResourceAsStream("clienthello_sni.hex")!!.readBytes().decodeToString().trim())
        val i = PayloadInspector()
        i.offer(hello)
        assertFalse(i.finish().cleartext)
    }

    @Test
    fun tunnelledFlowsAreNeverSuspicious() {
        val all = Suspicion.reasons(
            tracker = true, telemetryName = true, appState = AppState.BACKGROUND, notUsedToday = true, cleartext = true,
            bytesOut = 200_000, bytesIn = 10, via = FlowRecord.VIA_WIREGUARD,
        )
        assertEquals(emptyList<String>(), all)
        val screenOff = Suspicion.reasons(
            tracker = false, telemetryName = false, appState = AppState.SCREEN_OFF, notUsedToday = false, cleartext = true,
            bytesOut = 200_000, bytesIn = 10, via = FlowRecord.VIA_WIREGUARD,
        )
        assertEquals(emptyList<String>(), screenOff)
        val record = Fixtures.flow(appState = AppState.BACKGROUND, bytesOut = 200_000, reasons = listOf("background", "cleartext_data"), via = FlowRecord.VIA_WIREGUARD)
        assertFalse(record.suspicious)
        assertEquals(emptyList<String>(), FlowRecord.fromJson(record.toJson(java.time.ZoneOffset.UTC)).reasons)
    }
}
