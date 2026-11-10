package io.github.yannickgranger.leakwatch.domain

import java.time.Instant
import java.time.OffsetDateTime
import java.time.ZoneId
import java.time.format.DateTimeFormatter

data class FlowRecord(
    val id: String,
    val tsStart: Long,
    val tsEnd: Long,
    val uid: Int,
    val packages: List<String>,
    val label: String,
    val proto: String,
    val ipVersion: Int,
    val src: String,
    val dst: String,
    val dnsName: String?,
    val sni: String?,
    val httpHost: String?,
    val tracker: Boolean,
    val bytesOut: Long,
    val bytesIn: Long,
    val packetsOut: Long,
    val packetsIn: Long,
    val blocked: Boolean,
    val closeReason: String,
    val dump: String?,
    val appState: String = AppState.UNKNOWN,
    val lastUsed: Long? = null,
    val reasons: List<String> = emptyList(),
    val via: String = "direct",
) {
    val tunnelled: Boolean get() = via == VIA_WIREGUARD
    val domainBlocked: Boolean get() = closeReason == DOMAIN_BLOCKED
    val suspicious: Boolean get() = !tunnelled && !domainBlocked && reasons.isNotEmpty()
    val unattended: Boolean get() = !tunnelled && (appState == AppState.BACKGROUND || appState == AppState.SCREEN_OFF)

    fun toJson(zone: ZoneId): String = Json.obj(
        "id" to id,
        "ts_start" to IsoTime.format(tsStart, zone),
        "ts_end" to IsoTime.format(tsEnd, zone),
        "uid" to uid,
        "packages" to packages,
        "label" to label,
        "proto" to proto,
        "ip_version" to ipVersion,
        "src" to src,
        "dst" to dst,
        "dns_name" to dnsName,
        "sni" to sni,
        "http_host" to httpHost,
        "tracker" to tracker,
        "bytes_out" to bytesOut,
        "bytes_in" to bytesIn,
        "packets_out" to packetsOut,
        "packets_in" to packetsIn,
        "blocked" to blocked,
        "close_reason" to closeReason,
        "dump" to dump,
        "app_state" to appState,
        "last_used" to lastUsed?.let { IsoTime.format(it, zone) },
        "reasons" to reasons,
        "suspicious" to suspicious,
        "via" to via,
    )

    companion object {
        const val VIA_DIRECT = "direct"
        const val VIA_WIREGUARD = "wireguard"
        const val DOMAIN_BLOCKED = "domain_blocked"
        val KEYS = listOf(
            "id", "ts_start", "ts_end", "uid", "packages", "label", "proto", "ip_version", "src", "dst",
            "dns_name", "sni", "http_host", "tracker", "bytes_out", "bytes_in", "packets_out", "packets_in",
            "blocked", "close_reason", "dump", "app_state", "last_used", "reasons", "suspicious", "via",
        )

        fun fromJson(line: String): FlowRecord {
            val o = Json.parseObject(line)
            fun s(k: String) = o[k] as String?
            fun l(k: String) = (o[k] as Number).toLong()
            return FlowRecord(
                id = s("id")!!,
                tsStart = IsoTime.parse(s("ts_start")!!),
                tsEnd = IsoTime.parse(s("ts_end")!!),
                uid = l("uid").toInt(),
                packages = (o["packages"] as List<*>).map { it as String },
                label = s("label")!!,
                proto = s("proto")!!,
                ipVersion = l("ip_version").toInt(),
                src = s("src")!!,
                dst = s("dst")!!,
                dnsName = s("dns_name"),
                sni = s("sni"),
                httpHost = s("http_host"),
                tracker = o["tracker"] as Boolean,
                bytesOut = l("bytes_out"),
                bytesIn = l("bytes_in"),
                packetsOut = l("packets_out"),
                packetsIn = l("packets_in"),
                blocked = o["blocked"] as Boolean,
                closeReason = s("close_reason")!!,
                dump = s("dump"),
                appState = s("app_state") ?: AppState.UNKNOWN,
                lastUsed = s("last_used")?.let { IsoTime.parse(it) },
                reasons = if (s("via") == VIA_WIREGUARD || s("close_reason") == DOMAIN_BLOCKED) emptyList() else (o["reasons"] as List<*>?)?.map { it as String } ?: emptyList(),
                via = s("via") ?: VIA_DIRECT,
            )
        }
    }
}

data class DnsRecord(val ts: Long, val uid: Int, val label: String, val name: String, val qtype: String, val answers: List<String>, val blocked: Boolean = false) {
    fun toJson(zone: ZoneId): String = Json.obj(
        "ts" to IsoTime.format(ts, zone),
        "uid" to uid,
        "label" to label,
        "name" to name,
        "qtype" to qtype,
        "answers" to answers,
        "blocked" to blocked,
    )

    companion object {
        fun blockedByUid(text: String): Map<Int, Int> {
            val out = HashMap<Int, Int>()
            for (line in text.lineSequence()) {
                if (line.isBlank()) continue
                val o = runCatching { Json.parseObject(line) }.getOrNull() ?: continue
                if (o["blocked"] != true) continue
                val uid = (o["uid"] as? Number)?.toInt() ?: continue
                out[uid] = (out[uid] ?: 0) + 1
            }
            return out
        }
    }
}

object Json {
    fun quote(s: String?): String {
        if (s == null) return "null"
        val sb = StringBuilder(s.length + 2).append('"')
        for (c in s) {
            when {
                c == '"' -> sb.append("\\\"")
                c == '\\' -> sb.append("\\\\")
                c == '\n' -> sb.append("\\n")
                c == '\r' -> sb.append("\\r")
                c == '\t' -> sb.append("\\t")
                c < ' ' || c == ' ' || c == ' ' -> sb.append(String.format("\\u%04x", c.code))
                else -> sb.append(c)
            }
        }
        return sb.append('"').toString()
    }

    fun value(v: Any?): String = when (v) {
        null -> "null"
        is String -> quote(v)
        is Boolean, is Int, is Long -> v.toString()
        is Number -> v.toString()
        is List<*> -> v.joinToString(",", "[", "]") { value(it) }
        else -> quote(v.toString())
    }

    fun obj(vararg pairs: Pair<String, Any?>): String = pairs.joinToString(",", "{", "}") { quote(it.first) + ":" + value(it.second) }

    fun parseObject(text: String): Map<String, Any?> {
        val p = Parser(text)
        val v = p.value()
        p.ws()
        require(p.i == text.length)
        @Suppress("UNCHECKED_CAST")
        return v as Map<String, Any?>
    }

    private class Parser(val s: String) {
        var i = 0

        fun ws() {
            while (i < s.length && s[i].isWhitespace()) i++
        }

        fun value(): Any? {
            ws()
            require(i < s.length)
            return when (s[i]) {
                '{' -> obj()
                '[' -> arr()
                '"' -> str()
                't' -> lit("true", true)
                'f' -> lit("false", false)
                'n' -> lit("null", null)
                else -> num()
            }
        }

        fun lit(word: String, v: Any?): Any? {
            require(s.startsWith(word, i))
            i += word.length
            return v
        }

        fun num(): Number {
            val start = i
            while (i < s.length && (s[i].isDigit() || s[i] in "+-.eE")) i++
            val t = s.substring(start, i)
            return t.toLongOrNull() ?: t.toDouble()
        }

        fun str(): String {
            i++
            val sb = StringBuilder()
            while (true) {
                require(i < s.length)
                val c = s[i++]
                when (c) {
                    '"' -> return sb.toString()
                    '\\' -> {
                        val e = s[i++]
                        when (e) {
                            'n' -> sb.append('\n')
                            'r' -> sb.append('\r')
                            't' -> sb.append('\t')
                            'b' -> sb.append('\b')
                            'f' -> sb.append('\u000c')
                            'u' -> {
                                sb.append(s.substring(i, i + 4).toInt(16).toChar())
                                i += 4
                            }
                            else -> sb.append(e)
                        }
                    }
                    else -> sb.append(c)
                }
            }
        }

        fun arr(): List<Any?> {
            i++
            val out = mutableListOf<Any?>()
            ws()
            if (s[i] == ']') {
                i++
                return out
            }
            while (true) {
                out += value()
                ws()
                val c = s[i++]
                if (c == ']') return out
                require(c == ',')
            }
        }

        fun obj(): Map<String, Any?> {
            i++
            val out = LinkedHashMap<String, Any?>()
            ws()
            if (s[i] == '}') {
                i++
                return out
            }
            while (true) {
                ws()
                val k = str()
                ws()
                require(s[i++] == ':')
                out[k] = value()
                ws()
                val c = s[i++]
                if (c == '}') return out
                require(c == ',')
            }
        }
    }
}

object IsoTime {
    private val FORMAT = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ssxxx")
    private val DAY = DateTimeFormatter.ofPattern("yyyy-MM-dd")

    fun format(ms: Long, zone: ZoneId): String = OffsetDateTime.ofInstant(Instant.ofEpochMilli(ms), zone).format(FORMAT)
    fun parse(text: String): Long = OffsetDateTime.parse(text).toInstant().toEpochMilli()
    fun day(ms: Long, zone: ZoneId): String = Instant.ofEpochMilli(ms).atZone(zone).format(DAY)
}

data class DestinationSummary(val name: String, val flows: Int, val bytesOut: Long, val bytesIn: Long, val tracker: Boolean, val reasons: List<String> = emptyList())

data class AppSummary(
    val uid: Int,
    val label: String,
    val packages: List<String>,
    val flows: Int,
    val bytesOut: Long,
    val bytesIn: Long,
    val trackerFlows: Int,
    val destinations: List<DestinationSummary>,
    val suspiciousFlows: Int = 0,
    val suspiciousBytesOut: Long = 0,
    val backgroundBytesOut: Long = 0,
    val reasons: List<String> = emptyList(),
    val blockedAttempts: Int = 0,
)

object AppStats {
    fun destination(flow: FlowRecord): String {
        flow.sni?.let { return it }
        flow.httpHost?.let { return it }
        flow.dnsName?.let { return it }
        val d = flow.dst
        return if (d.startsWith("[")) d.substring(1, d.indexOf(']')) else d.substringBeforeLast(':')
    }

    fun summarize(flows: List<FlowRecord>, blockedDns: Map<Int, Int> = emptyMap()): List<AppSummary> =
        flows.groupBy { it.uid }.map { (uid, list) ->
            val first = list.first()
            val dests = list.groupBy { destination(it) }.map { (name, fl) ->
                DestinationSummary(name, fl.size, fl.sumOf { it.bytesOut }, fl.sumOf { it.bytesIn }, fl.any { it.tracker }, Suspicion.ordered(fl.filter { it.suspicious }.flatMap { it.reasons }))
            }.sortedWith(compareByDescending<DestinationSummary> { it.bytesOut }.thenBy { it.name })
            val suspicious = list.filter { it.suspicious }
            AppSummary(
                uid = uid,
                label = first.label,
                packages = first.packages,
                flows = list.size,
                bytesOut = list.sumOf { it.bytesOut },
                bytesIn = list.sumOf { it.bytesIn },
                trackerFlows = list.count { it.tracker },
                destinations = dests,
                suspiciousFlows = suspicious.size,
                suspiciousBytesOut = suspicious.sumOf { it.bytesOut },
                backgroundBytesOut = list.filter { it.unattended }.sumOf { it.bytesOut },
                reasons = Suspicion.ordered(suspicious.flatMap { it.reasons }),
                blockedAttempts = list.count { it.domainBlocked } + (blockedDns[uid] ?: 0),
            )
        }.sortedWith(compareByDescending<AppSummary> { it.suspiciousBytesOut }.thenByDescending { it.bytesOut }.thenBy { it.label })
}

object AppsCsv {
    const val HEADER = "label,packages,uid,flows,bytes_out,bytes_in,destinations,tracker_flows,suspicious_flows,suspicious_bytes_out,background_bytes_out,reasons,top_destinations,blocked_attempts"

    private fun cell(s: String): String =
        if (s.any { it == ',' || it == '"' || it == '\n' || it == '\r' }) "\"" + s.replace("\"", "\"\"") + "\"" else s

    fun render(flows: List<FlowRecord>, blockedDns: Map<Int, Int> = emptyMap()): String {
        val sb = StringBuilder(HEADER).append('\n')
        for (a in AppStats.summarize(flows, blockedDns)) {
            val top = a.destinations.sortedWith(compareByDescending<DestinationSummary> { it.flows }.thenBy { it.name }).take(5).joinToString("|") { it.name }
            sb.append(
                listOf(
                    cell(a.label), cell(a.packages.joinToString("|")), a.uid.toString(), a.flows.toString(), a.bytesOut.toString(),
                    a.bytesIn.toString(), a.destinations.size.toString(), a.trackerFlows.toString(), a.suspiciousFlows.toString(),
                    a.suspiciousBytesOut.toString(), a.backgroundBytesOut.toString(), cell(a.reasons.joinToString("|")), cell(top), a.blockedAttempts.toString(),
                ).joinToString(","),
            ).append('\n')
        }
        return sb.toString()
    }
}
