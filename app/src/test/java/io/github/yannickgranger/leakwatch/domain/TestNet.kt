package io.github.yannickgranger.leakwatch.domain

import java.net.InetAddress

object TestNet {
    fun ip(s: String): InetAddress = InetAddress.getByName(s)

    fun onesSum(vararg parts: ByteArray): Int {
        var sum = 0L
        for (p in parts) {
            var i = 0
            while (i + 1 < p.size) {
                sum += ((p[i].toInt() and 0xff) shl 8) or (p[i + 1].toInt() and 0xff)
                i += 2
            }
            if (i < p.size) sum += (p[i].toInt() and 0xff) shl 8
        }
        while (sum shr 16 != 0L) sum = (sum and 0xffff) + (sum shr 16)
        return sum.toInt()
    }

    fun transportValid(packet: ByteArray): Boolean {
        val v = (packet[0].toInt() and 0xff) shr 4
        return if (v == 4) {
            val ihl = (packet[0].toInt() and 0x0f) * 4
            val total = ((packet[2].toInt() and 0xff) shl 8) or (packet[3].toInt() and 0xff)
            val proto = packet[9].toInt() and 0xff
            val seg = packet.copyOfRange(ihl, total)
            val pseudo = packet.copyOfRange(12, 20) + byteArrayOf(0, proto.toByte(), (seg.size shr 8).toByte(), seg.size.toByte())
            onesSum(packet.copyOfRange(0, ihl)) == 0xffff && onesSum(pseudo, seg) == 0xffff
        } else {
            val plen = ((packet[4].toInt() and 0xff) shl 8) or (packet[5].toInt() and 0xff)
            val proto = packet[6].toInt() and 0xff
            val seg = packet.copyOfRange(40, 40 + plen)
            val pseudo = packet.copyOfRange(8, 40) + byteArrayOf(0, 0, (seg.size shr 8).toByte(), seg.size.toByte(), 0, 0, 0, proto.toByte())
            onesSum(pseudo, seg) == 0xffff
        }
    }

    fun hex(s: String): ByteArray = s.replace(" ", "").chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}
