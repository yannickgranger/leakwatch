package io.github.yannickgranger.leakwatch.domain

import io.github.yannickgranger.leakwatch.port.ArchiveStore
import io.github.yannickgranger.leakwatch.port.Clock

class ArchiveWriter(private val store: ArchiveStore, private val clock: Clock) {
    private val flowLines = LinkedHashMap<String, StringBuilder>()
    private val dnsLines = LinkedHashMap<String, StringBuilder>()
    private val dumps = mutableListOf<Triple<String, String, String>>()
    private var currentDay = day()
    private val todayFlows = mutableListOf<FlowRecord>()
    private var closingDay: Pair<String, List<FlowRecord>>? = null
    private val todayBlockedDns = HashMap<Int, Int>()
    private var closingBlockedDns: Map<Int, Int> = emptyMap()

    private fun day(): String = IsoTime.day(clock.nowMillis(), clock.zone())

    private fun rollDay(): String {
        val d = day()
        if (d != currentDay) {
            closingDay = currentDay to todayFlows.toList()
            closingBlockedDns = HashMap(todayBlockedDns)
            currentDay = d
            todayFlows.clear()
            todayBlockedDns.clear()
        }
        return d
    }

    @Synchronized
    fun flow(record: FlowRecord, dumpText: String?) {
        val d = rollDay()
        todayFlows += record
        flowLines.getOrPut(d) { StringBuilder() }.append(record.toJson(clock.zone())).append('\n')
        if (dumpText != null && record.dump != null) dumps += Triple(d, record.dump, dumpText)
    }

    @Synchronized
    fun dns(record: DnsRecord) {
        val d = rollDay()
        dnsLines.getOrPut(d) { StringBuilder() }.append(record.toJson(clock.zone())).append('\n')
        if (record.blocked) todayBlockedDns[record.uid] = (todayBlockedDns[record.uid] ?: 0) + 1
    }

    @Synchronized
    fun blockedDnsToday(): Map<Int, Int> {
        rollDay()
        return HashMap(todayBlockedDns)
    }

    @Synchronized
    fun today(): List<FlowRecord> {
        rollDay()
        return todayFlows.toList()
    }

    @Synchronized
    fun loadToday() {
        val d = rollDay()
        runCatching { store.read(d, DNS) }.getOrNull()?.let { text ->
            for ((uid, n) in DnsRecord.blockedByUid(text)) todayBlockedDns[uid] = (todayBlockedDns[uid] ?: 0) + n
        }
        val text = runCatching { store.read(d, FLOWS) }.getOrNull() ?: return
        for (line in text.lineSequence()) {
            if (line.isBlank()) continue
            runCatching { FlowRecord.fromJson(line) }.getOrNull()?.let { todayFlows += it }
        }
    }

    @Synchronized
    fun flush(open: List<FlowRecord>) {
        val d = rollDay()
        for ((day, name, text) in dumps) store.write(day, name, text)
        dumps.clear()
        for ((day, sb) in flowLines) store.append(day, FLOWS, sb.toString())
        flowLines.clear()
        for ((day, sb) in dnsLines) store.append(day, DNS, sb.toString())
        dnsLines.clear()
        closingDay?.let { (day, flows) -> if (flows.isNotEmpty()) store.write(day, APPS, AppsCsv.render(flows, closingBlockedDns)) }
        closingDay = null
        store.write(d, APPS, AppsCsv.render(todayFlows + open, todayBlockedDns))
    }

    private companion object {
        const val FLOWS = "flows.jsonl"
        const val DNS = "dns.jsonl"
        const val APPS = "apps.csv"
    }
}
