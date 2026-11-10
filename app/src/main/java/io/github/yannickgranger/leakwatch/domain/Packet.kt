package io.github.yannickgranger.leakwatch.domain

import java.net.InetAddress

object Proto {
    const val ICMP = 1
    const val TCP = 6
    const val UDP = 17
    const val ICMPV6 = 58
}

object TcpFlags {
    const val FIN = 0x01
    const val SYN = 0x02
    const val RST = 0x04
    const val PSH = 0x08
    const val ACK = 0x10
}

class TcpHeader(val seq: Int, val ack: Int, val flags: Int, val window: Int, val mss: Int?) {
    fun has(flag: Int): Boolean = flags and flag != 0
}

class ParsedPacket(
    val ipVersion: Int,
    val protocol: Int,
    val src: InetAddress,
    val dst: InetAddress,
    val srcPort: Int,
    val dstPort: Int,
    val tcp: TcpHeader?,
    val payload: ByteArray,
)

object Checksum {
    fun sum(data: ByteArray, off: Int, len: Int, initial: Long = 0): Long {
        var sum = initial
        var i = off
        val end = off + len
        while (i + 1 < end) {
            sum += ((data[i].toInt() and 0xff) shl 8) or (data[i + 1].toInt() and 0xff)
            i += 2
        }
        if (i < end) sum += (data[i].toInt() and 0xff) shl 8
        return sum
    }

    fun fold(sum: Long): Int {
        var s = sum
        while (s shr 16 != 0L) s = (s and 0xffff) + (s shr 16)
        return s.toInt().inv() and 0xffff
    }

    fun ipv4Header(buf: ByteArray, off: Int, headerLen: Int): Int {
        val s = sum(buf, off, headerLen) - (((buf[off + 10].toInt() and 0xff) shl 8) or (buf[off + 11].toInt() and 0xff))
        return fold(s)
    }

    fun transport(src: ByteArray, dst: ByteArray, protocol: Int, segment: ByteArray, off: Int, len: Int): Int {
        var s = sum(src, 0, src.size) + sum(dst, 0, dst.size)
        s += protocol.toLong()
        s += len.toLong() and 0xffff
        if (src.size == 16) s += (len.toLong() ushr 16)
        return fold(sum(segment, off, len, s))
    }
}

object PacketCodec {
    val EMPTY = ByteArray(0)
    private const val TCP_HEADER = 20
    private const val UDP_HEADER = 8

    private fun u8(b: ByteArray, i: Int) = b[i].toInt() and 0xff
    private fun u16(b: ByteArray, i: Int) = (u8(b, i) shl 8) or u8(b, i + 1)
    private fun i32(b: ByteArray, i: Int) = (u8(b, i) shl 24) or (u8(b, i + 1) shl 16) or (u8(b, i + 2) shl 8) or u8(b, i + 3)

    private fun put16(b: ByteArray, i: Int, v: Int) {
        b[i] = (v ushr 8).toByte()
        b[i + 1] = v.toByte()
    }

    private fun put32(b: ByteArray, i: Int, v: Int) {
        b[i] = (v ushr 24).toByte()
        b[i + 1] = (v ushr 16).toByte()
        b[i + 2] = (v ushr 8).toByte()
        b[i + 3] = v.toByte()
    }

    fun parse(buf: ByteArray, len: Int): ParsedPacket? {
        if (len < 1) return null
        return when (u8(buf, 0) ushr 4) {
            4 -> parse4(buf, len)
            6 -> parse6(buf, len)
            else -> null
        }
    }

    private fun parse4(buf: ByteArray, len: Int): ParsedPacket? {
        if (len < 20) return null
        val ihl = (u8(buf, 0) and 0x0f) * 4
        if (ihl < 20 || ihl > len) return null
        val total = minOf(u16(buf, 2), len)
        if (total < ihl) return null
        val fragment = u16(buf, 6)
        if (fragment and 0x3fff != 0) return null
        val src = InetAddress.getByAddress(buf.copyOfRange(12, 16))
        val dst = InetAddress.getByAddress(buf.copyOfRange(16, 20))
        return transport(4, u8(buf, 9), src, dst, buf, ihl, total)
    }

    private fun parse6(buf: ByteArray, len: Int): ParsedPacket? {
        if (len < 40) return null
        val end = minOf(40 + u16(buf, 4), len)
        var next = u8(buf, 6)
        var off = 40
        while (next == 0 || next == 43 || next == 60) {
            if (off + 8 > end) return null
            val n = u8(buf, off)
            off += (u8(buf, off + 1) + 1) * 8
            next = n
        }
        if (next == 44 || off > end) return null
        val src = InetAddress.getByAddress(buf.copyOfRange(8, 24))
        val dst = InetAddress.getByAddress(buf.copyOfRange(24, 40))
        return transport(6, next, src, dst, buf, off, end)
    }

    private fun transport(version: Int, protocol: Int, src: InetAddress, dst: InetAddress, buf: ByteArray, off: Int, end: Int): ParsedPacket? =
        when (protocol) {
            Proto.TCP -> {
                if (end - off < TCP_HEADER) return null
                val dataOff = (u8(buf, off + 12) ushr 4) * 4
                if (dataOff < TCP_HEADER || off + dataOff > end) return null
                var mss: Int? = null
                var o = off + TCP_HEADER
                while (o < off + dataOff) {
                    val kind = u8(buf, o)
                    if (kind == 0) break
                    if (kind == 1) { o++; continue }
                    if (o + 1 >= off + dataOff) break
                    val l = u8(buf, o + 1)
                    if (l < 2) break
                    if (kind == 2 && l == 4 && o + 4 <= off + dataOff) mss = u16(buf, o + 2)
                    o += l
                }
                val header = TcpHeader(i32(buf, off + 4), i32(buf, off + 8), u8(buf, off + 13), u16(buf, off + 14), mss)
                ParsedPacket(version, protocol, src, dst, u16(buf, off), u16(buf, off + 2), header, buf.copyOfRange(off + dataOff, end))
            }
            Proto.UDP -> {
                if (end - off < UDP_HEADER) return null
                val udpLen = u16(buf, off + 4)
                val stop = if (udpLen in UDP_HEADER..(end - off)) off + udpLen else end
                ParsedPacket(version, protocol, src, dst, u16(buf, off), u16(buf, off + 2), null, buf.copyOfRange(off + UDP_HEADER, stop))
            }
            else -> ParsedPacket(version, protocol, src, dst, 0, 0, null, EMPTY)
        }

    private fun ipHeader(src: InetAddress, dst: InetAddress, protocol: Int, segmentLen: Int): ByteArray {
        val s = src.address
        val d = dst.address
        return if (s.size == 4) {
            val out = ByteArray(20 + segmentLen)
            out[0] = 0x45
            put16(out, 2, 20 + segmentLen)
            put16(out, 6, 0x4000)
            out[8] = 64
            out[9] = protocol.toByte()
            s.copyInto(out, 12)
            d.copyInto(out, 16)
            put16(out, 10, Checksum.ipv4Header(out, 0, 20))
            out
        } else {
            val out = ByteArray(40 + segmentLen)
            out[0] = 0x60
            put16(out, 4, segmentLen)
            out[6] = protocol.toByte()
            out[7] = 64
            s.copyInto(out, 8)
            d.copyInto(out, 24)
            out
        }
    }

    fun buildTcp(
        src: InetAddress, srcPort: Int, dst: InetAddress, dstPort: Int,
        seq: Int, ack: Int, flags: Int, window: Int,
        payload: ByteArray = EMPTY, off: Int = 0, len: Int = payload.size, mss: Int? = null,
    ): ByteArray {
        val hl = if (mss != null) TCP_HEADER + 4 else TCP_HEADER
        val out = ipHeader(src, dst, Proto.TCP, hl + len)
        val t = out.size - hl - len
        put16(out, t, srcPort)
        put16(out, t + 2, dstPort)
        put32(out, t + 4, seq)
        put32(out, t + 8, ack)
        out[t + 12] = ((hl / 4) shl 4).toByte()
        out[t + 13] = flags.toByte()
        put16(out, t + 14, window.coerceIn(0, 0xffff))
        if (mss != null) {
            out[t + 20] = 2
            out[t + 21] = 4
            put16(out, t + 22, mss)
        }
        payload.copyInto(out, t + hl, off, off + len)
        put16(out, t + 16, Checksum.transport(src.address, dst.address, Proto.TCP, out, t, hl + len))
        return out
    }

    fun buildUdp(
        src: InetAddress, srcPort: Int, dst: InetAddress, dstPort: Int,
        payload: ByteArray, off: Int = 0, len: Int = payload.size,
    ): ByteArray {
        val out = ipHeader(src, dst, Proto.UDP, UDP_HEADER + len)
        val u = out.size - UDP_HEADER - len
        put16(out, u, srcPort)
        put16(out, u + 2, dstPort)
        put16(out, u + 4, UDP_HEADER + len)
        payload.copyInto(out, u + UDP_HEADER, off, off + len)
        val c = Checksum.transport(src.address, dst.address, Proto.UDP, out, u, UDP_HEADER + len)
        put16(out, u + 6, if (c == 0) 0xffff else c)
        return out
    }
}

object Endpoint {
    fun host(ip: InetAddress): String {
        val a = ip.address
        if (a.size == 4) return a.joinToString(".") { (it.toInt() and 0xff).toString() }
        val groups = IntArray(8) { ((a[it * 2].toInt() and 0xff) shl 8) or (a[it * 2 + 1].toInt() and 0xff) }
        var bestStart = -1
        var bestLen = 0
        var i = 0
        while (i < 8) {
            if (groups[i] == 0) {
                var j = i
                while (j < 8 && groups[j] == 0) j++
                if (j - i > bestLen) { bestStart = i; bestLen = j - i }
                i = j
            } else {
                i++
            }
        }
        if (bestLen < 2) return groups.joinToString(":") { Integer.toHexString(it) }
        val left = (0 until bestStart).joinToString(":") { Integer.toHexString(groups[it]) }
        val right = (bestStart + bestLen until 8).joinToString(":") { Integer.toHexString(groups[it]) }
        return "$left::$right"
    }

    fun format(ip: InetAddress, port: Int): String =
        if (ip.address.size == 4) "${host(ip)}:$port" else "[${host(ip)}]:$port"
}

data class FlowKey(val protocol: Int, val src: InetAddress, val srcPort: Int, val dst: InetAddress, val dstPort: Int) {
    val ipVersion: Int get() = if (src.address.size == 4) 4 else 6
}
