package io.github.yannickgranger.leakwatch.domain

import java.util.Base64

sealed interface TlsParse {
    data object NotTls : TlsParse
    data object Incomplete : TlsParse
    data class Done(val sni: String?) : TlsParse
}

object TlsSni {
    private fun u8(b: ByteArray, i: Int) = b[i].toInt() and 0xff
    private fun u16(b: ByteArray, i: Int) = (u8(b, i) shl 8) or u8(b, i + 1)

    fun parse(data: ByteArray, len: Int = data.size): TlsParse {
        if (len < 1) return TlsParse.Incomplete
        if (u8(data, 0) != 0x16) return TlsParse.NotTls
        if (len >= 2 && u8(data, 1) != 3) return TlsParse.NotTls
        val hs = java.io.ByteArrayOutputStream()
        var p = 0
        var needed = -1
        while (needed < 0 || hs.size() < needed) {
            if (p + 5 > len) return TlsParse.Incomplete
            if (u8(data, p) != 0x16) return TlsParse.NotTls
            val rl = u16(data, p + 3)
            if (p + 5 + rl > len) return TlsParse.Incomplete
            hs.write(data, p + 5, rl)
            p += 5 + rl
            if (needed < 0 && hs.size() >= 4) {
                val h = hs.toByteArray()
                if (u8(h, 0) != 1) return TlsParse.NotTls
                needed = 4 + ((u8(h, 1) shl 16) or (u8(h, 2) shl 8) or u8(h, 3))
            }
        }
        return TlsParse.Done(sni(hs.toByteArray(), needed))
    }

    private fun sni(h: ByteArray, end: Int): String? = try {
        var i = 4 + 2 + 32
        i += 1 + u8(h, i)
        i += 2 + u16(h, i)
        i += 1 + u8(h, i)
        if (i + 2 > end) {
            null
        } else {
            val extEnd = minOf(end, i + 2 + u16(h, i))
            i += 2
            var found: String? = null
            while (i + 4 <= extEnd && found == null) {
                val type = u16(h, i)
                val l = u16(h, i + 2)
                if (type == 0) {
                    var j = i + 4 + 2
                    val listEnd = i + 4 + l
                    while (j + 3 <= listEnd && found == null) {
                        val nt = u8(h, j)
                        val nl = u16(h, j + 1)
                        if (nt == 0) found = String(h, j + 3, nl, Charsets.US_ASCII).lowercase()
                        j += 3 + nl
                    }
                }
                i += 4 + l
            }
            found
        }
    } catch (e: IndexOutOfBoundsException) {
        null
    }
}

sealed interface HttpParse {
    data object NotHttp : HttpParse
    data object Incomplete : HttpParse
    class Request(
        val method: String,
        val path: String,
        val version: String,
        val headers: List<Pair<String, String>>,
        val body: ByteArray,
        val complete: Boolean,
    ) : HttpParse {
        val carriesData: Boolean get() =
            body.isNotEmpty() || path.contains('?') ||
                headers.any { (k, v) -> (k.equals("content-length", ignoreCase = true) && (v.trim().toLongOrNull() ?: 0) > 0) || (k.equals("transfer-encoding", ignoreCase = true) && v.contains("chunked", ignoreCase = true)) }

        val host: String? get() {
            val raw = headers.firstOrNull { it.first.equals("host", ignoreCase = true) }?.second?.trim() ?: return null
            val h = when {
                raw.startsWith("[") -> raw.substringAfter("[").substringBefore("]")
                raw.count { it == ':' } == 1 -> raw.substringBefore(":")
                else -> raw
            }
            return h.lowercase().ifEmpty { null }
        }
    }
}

object HttpSniffer {
    const val MAX_BODY = 16 * 1024
    private val METHODS = listOf("GET", "POST", "PUT", "HEAD", "DELETE", "OPTIONS", "PATCH", "CONNECT", "TRACE")

    fun parse(data: ByteArray, len: Int = data.size, final: Boolean = false): HttpParse {
        val probe = String(data, 0, minOf(len, 8), Charsets.ISO_8859_1)
        val space = probe.indexOf(' ')
        if (space < 0) {
            return if (len < 8 && METHODS.any { it.startsWith(probe) }) HttpParse.Incomplete else HttpParse.NotHttp
        }
        if (probe.substring(0, space) !in METHODS) return HttpParse.NotHttp
        val text = String(data, 0, len, Charsets.ISO_8859_1)
        var headEnd = text.indexOf("\r\n\r\n")
        val bodyStart: Int
        if (headEnd < 0) {
            if (!final) return HttpParse.Incomplete
            headEnd = len
            bodyStart = len
        } else {
            bodyStart = headEnd + 4
        }
        val lines = text.substring(0, headEnd).split("\r\n")
        val parts = lines.first().split(' ')
        val headers = lines.drop(1).filter { it.contains(':') }.map { it.substringBefore(':').trim() to it.substringAfter(':').trim() }
        val available = len - bodyStart
        val cl = headers.firstOrNull { it.first.equals("content-length", ignoreCase = true) }?.second?.toLongOrNull()
        val chunked = headers.any { it.first.equals("transfer-encoding", ignoreCase = true) && it.second.contains("chunked", ignoreCase = true) }
        val (bodyLen, complete) = when {
            cl != null -> {
                val want = minOf(cl, MAX_BODY.toLong()).toInt()
                minOf(want, available) to (available >= want)
            }
            chunked -> {
                val n = minOf(available, MAX_BODY)
                n to (n >= MAX_BODY || text.substring(bodyStart).contains("0\r\n\r\n"))
            }
            else -> 0 to true
        }
        return HttpParse.Request(
            method = parts[0],
            path = parts.getOrElse(1) { "" },
            version = parts.getOrElse(2) { "" },
            headers = headers,
            body = data.copyOfRange(bodyStart, bodyStart + bodyLen),
            complete = complete && headEnd < len,
        )
    }

    fun dump(request: HttpParse.Request): String {
        val sb = StringBuilder()
        sb.append(request.method).append(' ').append(request.path).append(' ').append(request.version).append("\r\n")
        for ((k, v) in request.headers) sb.append(k).append(": ").append(v).append("\r\n")
        sb.append("\r\n")
        sb.append(request.body.decodeToString())
        return sb.toString()
    }
}

class Inspection(val sni: String?, val httpHost: String?, val dump: String?, val cleartext: Boolean = false)

class HostProbe(val host: String?)

object StartTls {
    private val COMMAND = Regex("^(?:[A-Za-z0-9._-]+ )?(?:STARTTLS|STLS)\\r?\\n", RegexOption.IGNORE_CASE)

    fun commandLength(b: ByteArray): Int? {
        val head = String(b, 0, minOf(b.size, 64), Charsets.ISO_8859_1)
        return COMMAND.find(head)?.value?.length
    }
}

class PayloadInspector {
    private val buffer = ByteQueue()
    private var result: Inspection? = null

    var done = false
        private set

    fun offer(data: ByteArray): Boolean {
        if (done) return true
        val room = MAX - buffer.size
        buffer.append(data, 0, minOf(room, data.size))
        val b = buffer.copy(0, buffer.size)
        val full = buffer.size >= MAX
        when (val tls = TlsSni.parse(b)) {
            is TlsParse.Done -> return settle(Inspection(tls.sni, null, null))
            TlsParse.Incomplete -> return if (full) settle(Inspection(null, null, null)) else false
            TlsParse.NotTls -> Unit
        }
        val command = StartTls.commandLength(b)
        if (command != null) {
            if (b.size == command) return if (full) settle(Inspection(null, null, null)) else false
            when (val tls = TlsSni.parse(b.copyOfRange(command, b.size))) {
                is TlsParse.Done -> return settle(Inspection(tls.sni, null, null))
                TlsParse.Incomplete -> return if (full) settle(Inspection(null, null, null)) else false
                TlsParse.NotTls -> Unit
            }
        }
        when (val http = HttpSniffer.parse(b)) {
            is HttpParse.Request -> return if (http.complete || full) settle(fromHttp(http)) else false
            HttpParse.Incomplete -> return if (full) settle(conclude(b)) else false
            HttpParse.NotHttp -> Unit
        }
        return if (buffer.size >= RAW) settle(raw(b)) else false
    }

    fun current(): Inspection {
        result?.let { return it }
        val b = buffer.copy(0, buffer.size)
        return if (b.isEmpty()) Inspection(null, null, null) else conclude(b)
    }

    fun host(): HostProbe? {
        result?.let { return HostProbe(it.sni ?: it.httpHost) }
        val b = buffer.copy(0, buffer.size)
        if (b.isEmpty()) return null
        when (val tls = TlsSni.parse(b)) {
            is TlsParse.Done -> return HostProbe(tls.sni)
            TlsParse.Incomplete -> return null
            TlsParse.NotTls -> Unit
        }
        return when (val http = HttpSniffer.parse(b)) {
            is HttpParse.Request -> HostProbe(http.host)
            HttpParse.Incomplete -> null
            HttpParse.NotHttp -> HostProbe(null)
        }
    }

    fun finish(): Inspection {
        result?.let { return it }
        val b = buffer.copy(0, buffer.size)
        settle(if (b.isEmpty()) Inspection(null, null, null) else conclude(b))
        return result!!
    }

    private fun conclude(b: ByteArray): Inspection {
        when (val tls = TlsSni.parse(b)) {
            is TlsParse.Done -> return Inspection(tls.sni, null, null)
            TlsParse.Incomplete -> return Inspection(null, null, null)
            TlsParse.NotTls -> Unit
        }
        val command = StartTls.commandLength(b)
        if (command != null) {
            if (b.size == command) return Inspection(null, null, null)
            when (val tls = TlsSni.parse(b.copyOfRange(command, b.size))) {
                is TlsParse.Done -> return Inspection(tls.sni, null, null)
                TlsParse.Incomplete -> return Inspection(null, null, null)
                TlsParse.NotTls -> Unit
            }
        }
        val http = HttpSniffer.parse(b, b.size, final = true)
        if (http is HttpParse.Request) return fromHttp(http)
        return raw(b)
    }

    private fun fromHttp(http: HttpParse.Request): Inspection = Inspection(null, http.host, HttpSniffer.dump(http), http.carriesData)

    private fun raw(b: ByteArray): Inspection =
        Inspection(null, null, Base64.getEncoder().encodeToString(b.copyOfRange(0, minOf(RAW, b.size))) + "\n", true)

    private fun settle(i: Inspection): Boolean {
        result = i
        done = true
        return true
    }

    private companion object {
        const val MAX = 16 * 1024
        const val RAW = 4096
    }
}
