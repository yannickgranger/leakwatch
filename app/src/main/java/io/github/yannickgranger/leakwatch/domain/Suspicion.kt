package io.github.yannickgranger.leakwatch.domain

object TelemetryNameMatcher {
    private val TOKENS = setOf(
        "log", "logs", "logging", "telemetry", "metrics", "analytics", "crash", "crashlytics", "stats", "tracking", "tracker",
        "beacon", "events", "collect", "measurement", "ads", "adservice",
    )
    private val SECOND_LEVEL = setOf(
        "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "ltd.uk", "plc.uk", "com.au", "net.au", "org.au", "co.nz", "co.jp", "ne.jp",
        "or.jp", "co.kr", "or.kr", "com.br", "com.cn", "com.tw", "com.hk", "co.in", "co.za", "com.mx", "com.ar", "com.tr", "com.sg",
        "co.id", "com.my", "co.il",
    )

    fun matches(host: String?): Boolean {
        if (host == null) return false
        val h = host.trim().trimEnd('.').lowercase()
        if (h.isEmpty() || h.contains(':') || h.all { it.isDigit() || it == '.' }) return false
        val labels = h.split('.')
        val keep = if (labels.size >= 3 && labels.takeLast(2).joinToString(".") in SECOND_LEVEL) 3 else 2
        if (labels.size <= keep) return false
        return labels.dropLast(keep).flatMap { it.split('-') }.any { it in TOKENS }
    }
}

object Suspicion {
    const val TRACKER = "tracker"
    const val TELEMETRY_NAME = "telemetry_name"
    const val SCREEN_OFF = "screen_off"
    const val BACKGROUND = "background"
    const val NOT_USED_TODAY = "not_used_today"
    const val CLEARTEXT_DATA = "cleartext_data"
    const val BULK_UPLOAD = "bulk_upload"
    val ORDER = listOf(TRACKER, TELEMETRY_NAME, SCREEN_OFF, BACKGROUND, NOT_USED_TODAY, CLEARTEXT_DATA, BULK_UPLOAD)
    const val ACTIVE_BYTES = 1024L
    const val BULK_BYTES = 50L * 1024

    fun reasons(
        tracker: Boolean,
        telemetryName: Boolean,
        appState: String,
        notUsedToday: Boolean,
        cleartext: Boolean,
        bytesOut: Long,
        bytesIn: Long,
        via: String = FlowRecord.VIA_DIRECT,
        system: Boolean = false,
    ): List<String> = if (via == FlowRecord.VIA_WIREGUARD) emptyList() else buildList {
        if (tracker) add(TRACKER)
        if (telemetryName) add(TELEMETRY_NAME)
        if (appState == AppState.SCREEN_OFF && bytesOut >= ACTIVE_BYTES) add(SCREEN_OFF)
        if (appState == AppState.BACKGROUND && bytesOut >= ACTIVE_BYTES) add(BACKGROUND)
        if (notUsedToday && !system) add(NOT_USED_TODAY)
        if (cleartext) add(CLEARTEXT_DATA)
        if (bytesOut >= BULK_BYTES && bytesOut > bytesIn) add(BULK_UPLOAD)
    }

    fun ordered(reasons: Iterable<String>): List<String> {
        val set = reasons.toSet()
        return ORDER.filter { it in set } + set.filter { it !in ORDER }.sorted()
    }
}
