package io.github.yannickgranger.leakwatch.domain

import java.net.InetAddress

class DnsMessage(val id: Int, val isResponse: Boolean, val name: String, val qtype: Int, val answers: List<String>)

object DnsCodec {
    private val TYPES = mapOf(
        1 to "A", 2 to "NS", 5 to "CNAME", 6 to "SOA", 12 to "PTR", 15 to "MX", 16 to "TXT",
        28 to "AAAA", 33 to "SRV", 64 to "SVCB", 65 to "HTTPS", 255 to "ANY",
    )

    private class Reader(val b: ByteArray, val base: Int, val end: Int) {
        fun u8(i: Int): Int {
            if (i < base || i >= end) throw IndexOutOfBoundsException()
            return b[i].toInt() and 0xff
        }

        fun u16(i: Int): Int = (u8(i) shl 8) or u8(i + 1)

        fun name(start: Int): Pair<String, Int> {
            val labels = mutableListOf<String>()
            var i = start
            var next = -1
            var jumps = 0
            while (true) {
                val len = u8(i)
                when {
                    len == 0 -> {
                        if (next < 0) next = i + 1
                        break
                    }
                    len and 0xc0 == 0xc0 -> {
                        if (++jumps > 16) throw IllegalStateException()
                        if (next < 0) next = i + 2
                        i = base + (((len and 0x3f) shl 8) or u8(i + 1))
                    }
                    len and 0xc0 != 0 -> throw IllegalStateException()
                    else -> {
                        val sb = StringBuilder()
                        for (k in 1..len) sb.append(u8(i + k).toChar())
                        labels += sb.toString()
                        i += len + 1
                    }
                }
            }
            return labels.joinToString(".").lowercase() to next
        }
    }

    fun parse(data: ByteArray, off: Int = 0, len: Int = data.size): DnsMessage? = try {
        val r = Reader(data, off, off + len)
        val id = r.u16(off)
        val flags = r.u16(off + 2)
        val qd = r.u16(off + 4)
        val an = r.u16(off + 6)
        if (qd < 1) {
            null
        } else {
            var p = off + 12
            val (name, after) = r.name(p)
            val qtype = r.u16(after)
            r.u16(after + 2)
            p = after + 4
            repeat(qd - 1) { p = r.name(p).second + 4 }
            val answers = mutableListOf<String>()
            repeat(an) {
                val (_, a) = r.name(p)
                val type = r.u16(a)
                val rdlen = r.u16(a + 8)
                val rd = a + 10
                r.u8(rd + rdlen - 1)
                if (type == 1 && rdlen == 4 || type == 28 && rdlen == 16) {
                    answers += Endpoint.host(InetAddress.getByAddress(data.copyOfRange(rd, rd + rdlen)))
                }
                p = rd + rdlen
            }
            DnsMessage(id, flags and 0x8000 != 0, name, qtype, answers)
        }
    } catch (e: RuntimeException) {
        null
    }

    fun query(id: Int, name: String, qtype: Int): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        out.write(byteArrayOf((id ushr 8).toByte(), id.toByte(), 1, 0, 0, 1, 0, 0, 0, 0, 0, 0))
        for (label in name.trimEnd('.').split('.')) {
            val b = label.toByteArray()
            out.write(b.size)
            out.write(b)
        }
        out.write(byteArrayOf(0, (qtype ushr 8).toByte(), qtype.toByte(), 0, 1))
        return out.toByteArray()
    }

    fun nxdomain(query: ByteArray, off: Int = 0, len: Int = query.size): ByteArray? = try {
        val r = Reader(query, off, off + len)
        val flags = r.u16(off + 2)
        if (flags and 0x8000 != 0 || r.u16(off + 4) < 1) {
            null
        } else {
            val end = r.name(off + 12).second + 4
            r.u8(end - 1)
            val out = query.copyOfRange(off, end)
            val reply = 0x8000 or (flags and 0x7900) or 0x0080 or 3
            out[2] = (reply ushr 8).toByte()
            out[3] = reply.toByte()
            out[4] = 0
            out[5] = 1
            for (i in 6 until 12) out[i] = 0
            out
        }
    } catch (e: RuntimeException) {
        null
    }

    fun typeName(qtype: Int): String = TYPES[qtype] ?: "TYPE$qtype"
}

class DnsNameMap(private val ttlMs: Long) {
    private val entries = HashMap<String, LinkedHashMap<String, Long>>()
    private var puts = 0

    fun put(ip: String, name: String, nowMs: Long) {
        val names = entries.getOrPut(ip) { LinkedHashMap() }
        names.remove(name)
        names[name] = nowMs
        if (names.size > MAX_NAMES) names.remove(names.keys.first())
        if (++puts % 1_000 == 0 && entries.size > 20_000) {
            entries.values.forEach { m -> m.entries.removeIf { nowMs - it.value > ttlMs } }
            entries.entries.removeIf { it.value.isEmpty() }
        }
    }

    fun get(ip: String, nowMs: Long): String? = all(ip, nowMs).lastOrNull()

    fun all(ip: String, nowMs: Long): List<String> =
        entries[ip]?.filter { nowMs - it.value <= ttlMs }?.keys?.toList().orEmpty()

    private companion object {
        const val MAX_NAMES = 8
    }
}
