package io.github.yannickgranger.leakwatch.domain

object Fixtures {
    fun flow(
        id: String = "f1",
        uid: Int = 10100,
        label: String = "Brave",
        packages: List<String> = listOf("com.brave.browser"),
        dst: String = "93.184.215.14:443",
        dnsName: String? = null,
        sni: String? = "example.com",
        httpHost: String? = null,
        tracker: Boolean = false,
        bytesOut: Long = 100,
        bytesIn: Long = 1000,
        proto: String = "tcp",
        dump: String? = null,
        appState: String = AppState.FOREGROUND,
        lastUsed: Long? = null,
        reasons: List<String> = emptyList(),
        tsStart: Long = 1_762_600_000_000,
        via: String = FlowRecord.VIA_DIRECT,
    ) = FlowRecord(
        id = id, tsStart = tsStart, tsEnd = tsStart + 5_000, uid = uid, packages = packages, label = label,
        proto = proto, ipVersion = 4, src = "10.111.0.1:40000", dst = dst, dnsName = dnsName, sni = sni, httpHost = httpHost,
        tracker = tracker, bytesOut = bytesOut, bytesIn = bytesIn, packetsOut = 3, packetsIn = 4, blocked = false,
        closeReason = "fin", dump = dump, appState = appState, lastUsed = lastUsed, reasons = reasons, via = via,
    )
}
