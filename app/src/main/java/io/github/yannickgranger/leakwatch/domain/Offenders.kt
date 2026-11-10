package io.github.yannickgranger.leakwatch.domain

import io.github.yannickgranger.leakwatch.port.ArchiveStore

data class OffenderRow(
    val label: String,
    val packages: List<String>,
    val uid: Int,
    val daysSuspicious: Int,
    val suspiciousBytesOut7d: Long,
    val screenOffBytesOut7d: Long,
    val backgroundBytesOut7d: Long,
    val trackerFlows7d: Int,
    val reasons: List<String>,
    val topDestinations: List<String>,
    val blocked: Boolean,
    val blockedAttempts7d: Int = 0,
)

object OffendersCsv {
    const val HEADER = "label,packages,uid,days_suspicious,suspicious_bytes_out_7d,screen_off_bytes_out_7d,background_bytes_out_7d,tracker_flows_7d,reasons,top_destinations,blocked,blocked_attempts_7d"
    const val FILE = "offenders.csv"
    const val DAYS = 7
    private val DAY = Regex("^\\d{4}-\\d{2}-\\d{2}$")

    fun lastDays(days: Collection<String>, n: Int): List<String> = days.filter { DAY.matches(it) }.sorted().takeLast(n)

    fun rank(days: Map<String, List<FlowRecord>>, blocked: Set<Int>, blockedDns: Map<String, Map<Int, Int>> = emptyMap()): List<OffenderRow> {
        val window = lastDays(days.keys, DAYS)
        val byUid = LinkedHashMap<Int, MutableList<Pair<String, FlowRecord>>>()
        for (d in window) for (f in days[d].orEmpty()) byUid.getOrPut(f.uid) { ArrayList() } += d to f
        return byUid.mapNotNull { (uid, entries) ->
            val flows = entries.map { it.second }
            val suspicious = flows.filter { it.suspicious }
            if (suspicious.isEmpty()) return@mapNotNull null
            val latest = flows.last()
            val top = flows.groupBy { AppStats.destination(it) }.map { (name, fl) -> name to fl.size }
                .sortedWith(compareByDescending<Pair<String, Int>> { it.second }.thenBy { it.first }).take(5).map { it.first }
            OffenderRow(
                label = latest.label,
                packages = latest.packages,
                uid = uid,
                daysSuspicious = entries.filter { it.second.suspicious }.map { it.first }.distinct().size,
                suspiciousBytesOut7d = suspicious.sumOf { it.bytesOut },
                screenOffBytesOut7d = flows.filter { !it.tunnelled && it.appState == AppState.SCREEN_OFF }.sumOf { it.bytesOut },
                backgroundBytesOut7d = flows.filter { it.unattended }.sumOf { it.bytesOut },
                trackerFlows7d = flows.count { it.tracker },
                reasons = Suspicion.ordered(suspicious.flatMap { it.reasons }),
                topDestinations = top,
                blocked = uid in blocked,
                blockedAttempts7d = flows.count { it.domainBlocked } + window.sumOf { blockedDns[it]?.get(uid) ?: 0 },
            )
        }.sortedWith(
            compareByDescending<OffenderRow> { it.daysSuspicious }
                .thenByDescending { it.screenOffBytesOut7d }
                .thenByDescending { it.suspiciousBytesOut7d }
                .thenBy { it.label },
        )
    }

    private fun cell(s: String): String =
        if (s.any { it == ',' || it == '"' || it == '\n' || it == '\r' }) "\"" + s.replace("\"", "\"\"") + "\"" else s

    fun render(rows: List<OffenderRow>): String {
        val sb = StringBuilder(HEADER).append('\n')
        for (r in rows) {
            sb.append(
                listOf(
                    cell(r.label), cell(r.packages.joinToString("|")), r.uid.toString(), r.daysSuspicious.toString(),
                    r.suspiciousBytesOut7d.toString(), r.screenOffBytesOut7d.toString(), r.backgroundBytesOut7d.toString(),
                    r.trackerFlows7d.toString(), cell(r.reasons.joinToString("|")), cell(r.topDestinations.joinToString("|")), r.blocked.toString(), r.blockedAttempts7d.toString(),
                ).joinToString(","),
            ).append('\n')
        }
        return sb.toString()
    }

    private fun cells(line: String): List<String> {
        val out = ArrayList<String>()
        val sb = StringBuilder()
        var quoted = false
        var i = 0
        while (i < line.length) {
            val c = line[i]
            when {
                quoted && c == '"' && i + 1 < line.length && line[i + 1] == '"' -> {
                    sb.append('"')
                    i++
                }
                c == '"' -> quoted = !quoted
                c == ',' && !quoted -> {
                    out += sb.toString()
                    sb.setLength(0)
                }
                else -> sb.append(c)
            }
            i++
        }
        out += sb.toString()
        return out
    }

    private fun split(s: String): List<String> = if (s.isEmpty()) emptyList() else s.split('|')

    fun parse(text: String): List<OffenderRow> = text.lineSequence().drop(1).filter { it.isNotBlank() }.mapNotNull { line ->
        val c = cells(line)
        if (c.size != 12) return@mapNotNull null
        runCatching {
            OffenderRow(
                label = c[0], packages = split(c[1]), uid = c[2].toInt(), daysSuspicious = c[3].toInt(),
                suspiciousBytesOut7d = c[4].toLong(), screenOffBytesOut7d = c[5].toLong(), backgroundBytesOut7d = c[6].toLong(),
                trackerFlows7d = c[7].toInt(), reasons = split(c[8]), topDestinations = split(c[9]), blocked = c[10] == "true", blockedAttempts7d = c[11].toInt(),
            )
        }.getOrNull()
    }.toList()
}

class OffendersReport(private val store: ArchiveStore) {
    fun rows(blocked: Set<Int>): List<OffenderRow> {
        val days = OffendersCsv.lastDays(store.days(), OffendersCsv.DAYS)
        val flows = days.associateWith { d ->
            val text = runCatching { store.read(d, FLOWS) }.getOrNull().orEmpty()
            text.lineSequence().filter { it.isNotBlank() }.mapNotNull { runCatching { FlowRecord.fromJson(it) }.getOrNull() }.toList()
        }
        val dns = days.associateWith { d -> DnsRecord.blockedByUid(runCatching { store.read(d, DNS) }.getOrNull().orEmpty()) }
        return OffendersCsv.rank(flows, blocked, dns)
    }

    fun write(blocked: Set<Int>): List<OffenderRow> {
        val rows = rows(blocked)
        store.writeRoot(OffendersCsv.FILE, OffendersCsv.render(rows))
        return rows
    }

    fun read(): List<OffenderRow> = runCatching { store.readRoot(OffendersCsv.FILE) }.getOrNull()?.let { OffendersCsv.parse(it) }.orEmpty()

    private companion object {
        const val FLOWS = "flows.jsonl"
        const val DNS = "dns.jsonl"
    }
}
