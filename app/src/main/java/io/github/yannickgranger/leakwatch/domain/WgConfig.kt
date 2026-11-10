package io.github.yannickgranger.leakwatch.domain

import java.io.ByteArrayInputStream
import java.net.Inet4Address
import java.net.InetAddress
import java.util.Base64
import java.util.zip.ZipInputStream

class Cidr(val address: InetAddress, val prefix: Int) {
    private val bytes = address.address

    val isDefault: Boolean get() = prefix == 0

    val isV4: Boolean get() = address is Inet4Address

    fun contains(ip: InetAddress): Boolean {
        val other = ip.address
        if (other.size != bytes.size) return false
        var bits = prefix
        var i = 0
        while (bits > 0) {
            val mask = if (bits >= 8) 0xff else (0xff shl (8 - bits)) and 0xff
            if ((other[i].toInt() and mask) != (bytes[i].toInt() and mask)) return false
            bits -= 8
            i++
        }
        return true
    }

    override fun equals(other: Any?): Boolean = other is Cidr && other.prefix == prefix && other.bytes.contentEquals(bytes)

    override fun hashCode(): Int = bytes.contentHashCode() * 31 + prefix

    override fun toString(): String = "${address.hostAddress}/$prefix"

    companion object {
        private val LITERAL = Regex("^[0-9a-fA-F:.]+$")

        fun literal(text: String): InetAddress? {
            val t = text.trim().removePrefix("[").removeSuffix("]")
            if (t.isEmpty() || !LITERAL.matches(t) || (!t.contains(':') && t.count { it == '.' } != 3)) return null
            return runCatching { InetAddress.getByName(t) }.getOrNull()
        }

        fun parse(text: String): Cidr = requireNotNull(parseOrNull(text)) { "bad address" }

        fun parseOrNull(text: String): Cidr? {
            val t = text.trim()
            val addr = literal(t.substringBefore('/')) ?: return null
            val max = addr.address.size * 8
            val prefix = if (t.contains('/')) t.substringAfter('/').trim().toIntOrNull() ?: return null else max
            if (prefix !in 0..max) return null
            return Cidr(addr, prefix)
        }
    }
}

class WgConfig(
    val name: String?,
    val privateKey: ByteArray,
    val addresses: List<Cidr>,
    val dns: List<String>,
    val mtu: Int?,
    val peerPublicKey: ByteArray,
    val presharedKey: ByteArray?,
    val endpointHost: String,
    val endpointPort: Int,
    val allowedIps: List<Cidr>,
    val keepalive: Int,
) {
    override fun toString(): String =
        "WgConfig(name=$name, addresses=$addresses, dns=$dns, mtu=$mtu, endpoint=$endpointHost:$endpointPort, allowedIps=$allowedIps, keepalive=$keepalive)"
}

sealed interface WgParse {
    data class Ok(val config: WgConfig) : WgParse
    data class Refused(val message: String) : WgParse
}

object WgConfigParser {
    const val FULL_TUNNEL = "This config sends all traffic through WireGuard; LeakWatch only carries a split tunnel, so import a config whose AllowedIPs lists your own networks only."
    const val NOT_A_CONFIG = "This file is not a WireGuard config with an interface, a peer, keys, an endpoint and allowed addresses."

    private fun key(text: String?): ByteArray? {
        val t = text?.trim() ?: return null
        val b = runCatching { Base64.getDecoder().decode(t) }.getOrNull() ?: return null
        return b.takeIf { it.size == 32 }
    }

    private fun list(text: String?): List<String> = text?.split(',')?.map { it.trim() }?.filter { it.isNotEmpty() } ?: emptyList()

    fun parse(text: String, name: String? = null): WgParse {
        val iface = HashMap<String, String>()
        val peers = ArrayList<HashMap<String, String>>()
        var section: MutableMap<String, String>? = null
        for (raw in text.lines()) {
            val line = raw.substringBefore('#').trim()
            if (line.isEmpty()) continue
            if (line.startsWith("[") && line.endsWith("]")) {
                section = when (line.substring(1, line.length - 1).trim().lowercase()) {
                    "interface" -> iface
                    "peer" -> HashMap<String, String>().also { peers += it }
                    else -> null
                }
                continue
            }
            val s = section ?: continue
            if (!line.contains('=')) continue
            val k = line.substringBefore('=').trim().lowercase()
            val v = line.substringAfter('=').trim()
            s[k] = if (s.containsKey(k) && (k == "address" || k == "allowedips" || k == "dns")) s[k] + "," + v else v
        }
        val peer = peers.firstOrNull() ?: return WgParse.Refused(NOT_A_CONFIG)
        val privateKey = key(iface["privatekey"]) ?: return WgParse.Refused(NOT_A_CONFIG)
        val publicKey = key(peer["publickey"]) ?: return WgParse.Refused(NOT_A_CONFIG)
        val psk = peer["presharedkey"]?.let { key(it) ?: return WgParse.Refused(NOT_A_CONFIG) }
        val addresses = list(iface["address"]).map { Cidr.parseOrNull(it) ?: return WgParse.Refused(NOT_A_CONFIG) }
        val allowed = list(peer["allowedips"]).map { Cidr.parseOrNull(it) ?: return WgParse.Refused(NOT_A_CONFIG) }
        if (addresses.isEmpty() || allowed.isEmpty()) return WgParse.Refused(NOT_A_CONFIG)
        if (allowed.any { it.isDefault }) return WgParse.Refused(FULL_TUNNEL)
        val endpoint = peer["endpoint"]?.trim().orEmpty()
        val host: String
        val portText: String
        if (endpoint.startsWith("[")) {
            host = endpoint.substringAfter('[').substringBefore(']')
            portText = endpoint.substringAfter("]:", "")
        } else {
            host = endpoint.substringBeforeLast(':', "")
            portText = endpoint.substringAfterLast(':', "")
        }
        val port = portText.toIntOrNull()
        if (host.isEmpty() || port == null || port !in 1..65535) return WgParse.Refused(NOT_A_CONFIG)
        val mtu = iface["mtu"]?.let { it.toIntOrNull()?.takeIf { m -> m in 576..9000 } ?: return WgParse.Refused(NOT_A_CONFIG) }
        val keepalive = peer["persistentkeepalive"]?.let { if (it.equals("off", true)) 0 else it.toIntOrNull()?.takeIf { k -> k in 0..65535 } ?: return WgParse.Refused(NOT_A_CONFIG) } ?: 0
        return WgParse.Ok(WgConfig(name, privateKey, addresses, list(iface["dns"]), mtu, publicKey, psk, host, port, allowed, keepalive))
    }

    private fun tunnelName(path: String): String = path.substringAfterLast('/').substringAfterLast('\\').let {
        if (it.endsWith(".conf", true)) it.dropLast(5) else it
    }

    fun tunnels(fileName: String, bytes: ByteArray): List<Pair<String, String>> {
        val zip = fileName.endsWith(".zip", true) || (bytes.size >= 4 && bytes[0] == 'P'.code.toByte() && bytes[1] == 'K'.code.toByte() && bytes[2].toInt() == 3 && bytes[3].toInt() == 4)
        if (!zip) return listOf(tunnelName(fileName) to bytes.toString(Charsets.UTF_8))
        val out = ArrayList<Pair<String, String>>()
        ZipInputStream(ByteArrayInputStream(bytes)).use { z ->
            while (true) {
                val e = z.nextEntry ?: break
                if (!e.isDirectory && e.name.endsWith(".conf", true)) {
                    out += tunnelName(e.name) to z.readBytes().toString(Charsets.UTF_8)
                }
            }
        }
        return out
    }
}

class TunnelRouting(val allowed: List<Cidr>, val addresses: List<Cidr>, val mtu: Int) {
    private val local4: InetAddress? = addresses.firstOrNull { it.isV4 }?.address
    private val local6: InetAddress? = addresses.firstOrNull { !it.isV4 }?.address
    private val nat = object : LinkedHashMap<String, InetAddress>(256, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, InetAddress>?): Boolean = size > NAT_LIMIT
    }

    private class View(val version: Int, val protocol: Int, val l4: Int, val end: Int, val whole: Boolean) {
        val srcOff get() = if (version == 4) 12 else 8
        val dstOff get() = if (version == 4) 16 else 24
        val addrLen get() = if (version == 4) 4 else 16
    }

    private fun u8(b: ByteArray, i: Int) = b[i].toInt() and 0xff
    private fun u16(b: ByteArray, i: Int) = (u8(b, i) shl 8) or u8(b, i + 1)

    private fun put16(b: ByteArray, i: Int, v: Int) {
        b[i] = (v ushr 8).toByte()
        b[i + 1] = v.toByte()
    }

    private fun view(b: ByteArray, len: Int): View? {
        if (len < 1) return null
        return when (u8(b, 0) ushr 4) {
            4 -> {
                if (len < 20) return null
                val ihl = (u8(b, 0) and 0x0f) * 4
                val total = minOf(u16(b, 2), len)
                if (ihl < 20 || total < ihl) return null
                View(4, u8(b, 9), ihl, total, u16(b, 6) and 0x3fff == 0)
            }
            6 -> {
                if (len < 40) return null
                View(6, u8(b, 6), 40, minOf(40 + u16(b, 4), len), true)
            }
            else -> null
        }
    }

    private fun address(b: ByteArray, off: Int, n: Int): InetAddress = InetAddress.getByAddress(b.copyOfRange(off, off + n))

    private fun ports(b: ByteArray, v: View): Pair<Int, Int> =
        if ((v.protocol == Proto.TCP || v.protocol == Proto.UDP) && v.whole && v.end >= v.l4 + 4) u16(b, v.l4) to u16(b, v.l4 + 2) else 0 to 0

    private fun key(protocol: Int, remote: InetAddress, remotePort: Int, localPort: Int) = "$protocol|${remote.hostAddress}|$remotePort|$localPort"

    fun routes(dst: InetAddress): Boolean = allowed.any { it.contains(dst) }

    fun outbound(packet: ByteArray, len: Int): ByteArray? {
        val v = view(packet, len) ?: return null
        val dst = address(packet, v.dstOff, v.addrLen)
        if (!routes(dst)) return null
        val local = (if (v.version == 4) local4 else local6) ?: return null
        val out = packet.copyOf(v.end)
        val src = address(out, v.srcOff, v.addrLen)
        val (srcPort, dstPort) = ports(out, v)
        if (src != local) {
            nat[key(v.protocol, dst, dstPort, srcPort)] = src
            local.address.copyInto(out, v.srcOff)
        }
        if (v.protocol == Proto.TCP && v.whole) clampMss(out, v)
        fix(out, v)
        return out
    }

    fun inbound(packet: ByteArray): ByteArray? {
        val v = view(packet, packet.size) ?: return null
        val src = address(packet, v.srcOff, v.addrLen)
        if (!routes(src)) return null
        val local = (if (v.version == 4) local4 else local6) ?: return null
        if (address(packet, v.dstOff, v.addrLen) != local) return null
        val out = packet.copyOf(v.end)
        val (srcPort, dstPort) = ports(out, v)
        val original = nat[key(v.protocol, src, srcPort, dstPort)] ?: return out
        original.address.copyInto(out, v.dstOff)
        fix(out, v)
        return out
    }

    private fun clampMss(b: ByteArray, v: View) {
        val t = v.l4
        if (v.end < t + 20 || u8(b, t + 13) and TcpFlags.SYN == 0) return
        val limit = mtu - (if (v.version == 4) 40 else 60)
        val hl = (u8(b, t + 12) ushr 4) * 4
        var i = t + 20
        val end = minOf(t + hl, v.end)
        while (i < end) {
            val kind = u8(b, i)
            if (kind == 0) return
            if (kind == 1) {
                i++
                continue
            }
            if (i + 1 >= end) return
            val l = u8(b, i + 1)
            if (l < 2) return
            if (kind == 2 && l == 4 && i + 3 < end && u16(b, i + 2) > limit) put16(b, i + 2, limit)
            i += l
        }
    }

    private fun fix(b: ByteArray, v: View) {
        if (v.version == 4) {
            put16(b, 10, 0)
            put16(b, 10, Checksum.fold(Checksum.sum(b, 0, v.l4)))
        }
        if (!v.whole) return
        val src = b.copyOfRange(v.srcOff, v.srcOff + v.addrLen)
        val dst = b.copyOfRange(v.dstOff, v.dstOff + v.addrLen)
        val len = v.end - v.l4
        val at = when (v.protocol) {
            Proto.TCP -> 16
            Proto.UDP -> 6
            Proto.ICMPV6 -> 2
            else -> return
        }
        if (len < at + 2) return
        if (v.protocol == Proto.UDP && v.version == 4 && u16(b, v.l4 + 6) == 0) return
        put16(b, v.l4 + at, 0)
        val c = Checksum.transport(src, dst, v.protocol, b, v.l4, len)
        put16(b, v.l4 + at, if (c == 0 && v.protocol == Proto.UDP) 0xffff else c)
    }

    private companion object {
        const val NAT_LIMIT = 8192
    }
}
