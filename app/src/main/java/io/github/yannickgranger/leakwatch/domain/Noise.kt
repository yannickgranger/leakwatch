package io.github.yannickgranger.leakwatch.domain

import java.util.Random
import io.github.yannickgranger.leakwatch.port.Aead

object WgMessage {
    const val INITIATION = 1
    const val RESPONSE = 2
    const val COOKIE = 3
    const val DATA = 4
    const val INITIATION_SIZE = 148
    const val RESPONSE_SIZE = 92
    const val COOKIE_SIZE = 64
    const val DATA_HEADER = 16
    const val TAG = 16

    fun le32(b: ByteArray, o: Int): Int =
        (b[o].toInt() and 0xff) or ((b[o + 1].toInt() and 0xff) shl 8) or ((b[o + 2].toInt() and 0xff) shl 16) or ((b[o + 3].toInt() and 0xff) shl 24)

    fun le64(b: ByteArray, o: Int): Long {
        var v = 0L
        for (i in 7 downTo 0) v = (v shl 8) or (b[o + i].toLong() and 0xff)
        return v
    }

    fun put32(b: ByteArray, o: Int, v: Int) {
        for (i in 0 until 4) b[o + i] = (v ushr (8 * i)).toByte()
    }

    fun put64(b: ByteArray, o: Int, v: Long) {
        for (i in 0 until 8) b[o + i] = (v ushr (8 * i)).toByte()
    }

    fun type(b: ByteArray): Int = if (b.size < 4 || b[1].toInt() != 0 || b[2].toInt() != 0 || b[3].toInt() != 0) -1 else b[0].toInt() and 0xff
}

class WgSession(val localIndex: Int, val remoteIndex: Int, private val sendKey: ByteArray, private val recvKey: ByteArray, val createdMs: Long) {
    private var sendCounter = 0L
    private val replay = ReplayWindow()

    val exhausted: Boolean get() = sendCounter >= ReplayWindow.REJECT_AFTER_MESSAGES

    fun seal(aead: Aead, packet: ByteArray): ByteArray {
        val counter = sendCounter++
        val padded = packet.copyOf((packet.size + 15) / 16 * 16)
        val sealed = aead.seal(sendKey, WgPrimitives.nonce(counter), padded, EMPTY)
        val out = ByteArray(WgMessage.DATA_HEADER + sealed.size)
        out[0] = WgMessage.DATA.toByte()
        WgMessage.put32(out, 4, remoteIndex)
        WgMessage.put64(out, 8, counter)
        sealed.copyInto(out, WgMessage.DATA_HEADER)
        return out
    }

    fun open(aead: Aead, message: ByteArray): ByteArray? {
        if (message.size < WgMessage.DATA_HEADER + WgMessage.TAG || WgMessage.type(message) != WgMessage.DATA) return null
        if (WgMessage.le32(message, 4) != localIndex) return null
        val counter = WgMessage.le64(message, 8)
        if (!replay.check(counter)) return null
        val plain = aead.open(recvKey, WgPrimitives.nonce(counter), message.copyOfRange(WgMessage.DATA_HEADER, message.size), EMPTY) ?: return null
        if (!replay.accept(counter)) return null
        if (plain.isEmpty()) return plain
        val length = when ((plain[0].toInt() and 0xff) ushr 4) {
            4 -> if (plain.size >= 20) ((plain[2].toInt() and 0xff) shl 8) or (plain[3].toInt() and 0xff) else return ByteArray(0)
            6 -> if (plain.size >= 40) 40 + (((plain[4].toInt() and 0xff) shl 8) or (plain[5].toInt() and 0xff)) else return ByteArray(0)
            else -> return ByteArray(0)
        }
        if (length > plain.size || length < 20) return ByteArray(0)
        return plain.copyOf(length)
    }

    private companion object {
        val EMPTY = ByteArray(0)
    }
}

class NoiseInitiator(private val staticPrivate: ByteArray, val peerPublic: ByteArray, private val psk: ByteArray?, private val aead: Aead) {
    private val staticPublic = X25519.publicKey(staticPrivate)
    private val staticShared = X25519.scalarMult(staticPrivate, peerPublic)
    private val mac1Key = WgPrimitives.hash(WgPrimitives.LABEL_MAC1, peerPublic)
    private val mac1KeyLocal = WgPrimitives.hash(WgPrimitives.LABEL_MAC1, staticPublic)
    private val cookieKey = WgPrimitives.hash(WgPrimitives.LABEL_COOKIE, peerPublic)
    private var pending: Pending? = null

    private class Pending(val index: Int, val ephemeral: ByteArray, val chain: ByteArray, val hash: ByteArray, val mac1: ByteArray)

    val pendingIndex: Int? get() = pending?.index

    fun initiation(localIndex: Int, ephemeralPrivate: ByteArray, timestamp: ByteArray, cookie: ByteArray?): ByteArray {
        val ePub = X25519.publicKey(ephemeralPrivate)
        var c = WgPrimitives.hash(WgPrimitives.CONSTRUCTION)
        var h = WgPrimitives.hash(c, WgPrimitives.IDENTIFIER)
        h = WgPrimitives.hash(h, peerPublic)
        c = WgPrimitives.kdf(1, c, ePub)[0]
        h = WgPrimitives.hash(h, ePub)
        var k = WgPrimitives.kdf(2, c, X25519.scalarMult(ephemeralPrivate, peerPublic))
        c = k[0]
        val encStatic = aead.seal(k[1], WgPrimitives.nonce(0), staticPublic, h)
        h = WgPrimitives.hash(h, encStatic)
        k = WgPrimitives.kdf(2, c, staticShared)
        c = k[0]
        val encTs = aead.seal(k[1], WgPrimitives.nonce(0), timestamp, h)
        h = WgPrimitives.hash(h, encTs)
        val msg = ByteArray(WgMessage.INITIATION_SIZE)
        msg[0] = WgMessage.INITIATION.toByte()
        WgMessage.put32(msg, 4, localIndex)
        ePub.copyInto(msg, 8)
        encStatic.copyInto(msg, 40)
        encTs.copyInto(msg, 88)
        val mac1 = WgPrimitives.mac(mac1Key, msg.copyOfRange(0, 116))
        mac1.copyInto(msg, 116)
        if (cookie != null) WgPrimitives.mac(cookie, msg.copyOfRange(0, 132)).copyInto(msg, 132)
        pending = Pending(localIndex, ephemeralPrivate, c, h, mac1)
        return msg
    }

    fun response(message: ByteArray, nowMs: Long): WgSession? {
        val p = pending ?: return null
        if (message.size != WgMessage.RESPONSE_SIZE || WgMessage.type(message) != WgMessage.RESPONSE) return null
        if (WgMessage.le32(message, 8) != p.index) return null
        if (!WgPrimitives.mac(mac1KeyLocal, message.copyOfRange(0, 60)).contentEquals(message.copyOfRange(60, 76))) return null
        val remoteIndex = WgMessage.le32(message, 4)
        val ePub = message.copyOfRange(12, 44)
        var c = WgPrimitives.kdf(1, p.chain, ePub)[0]
        var h = WgPrimitives.hash(p.hash, ePub)
        c = WgPrimitives.kdf(1, c, X25519.scalarMult(p.ephemeral, ePub))[0]
        c = WgPrimitives.kdf(1, c, X25519.scalarMult(staticPrivate, ePub))[0]
        val t = WgPrimitives.kdf(3, c, psk ?: ByteArray(32))
        c = t[0]
        h = WgPrimitives.hash(h, t[1])
        aead.open(t[2], WgPrimitives.nonce(0), message.copyOfRange(44, 60), h) ?: return null
        val keys = WgPrimitives.kdf(2, c, ByteArray(0))
        pending = null
        return WgSession(p.index, remoteIndex, keys[0], keys[1], nowMs)
    }

    fun cookie(message: ByteArray): ByteArray? {
        val p = pending ?: return null
        if (message.size != WgMessage.COOKIE_SIZE || WgMessage.type(message) != WgMessage.COOKIE) return null
        if (WgMessage.le32(message, 4) != p.index) return null
        return WgPrimitives.xopen(aead, cookieKey, message.copyOfRange(8, 32), message.copyOfRange(32, 64), p.mac1)
    }
}

class WgPeerSettings(val privateKey: ByteArray, val peerPublic: ByteArray, val presharedKey: ByteArray?, val keepaliveSec: Int) {
    override fun toString(): String = "WgPeerSettings(keepaliveSec=$keepaliveSec)"
}

class WgInbound(val toTun: List<ByteArray>, val toNet: List<ByteArray>)

class WgPeer(private val settings: WgPeerSettings, private val aead: Aead, private val random: Random) {
    private val initiator = NoiseInitiator(settings.privateKey, settings.peerPublic, settings.presharedKey, aead)
    private var current: WgSession? = null
    private var previous: WgSession? = null
    private var initiating = false
    private var firstAttemptMs = 0L
    private var nextRetryMs = 0L
    private var lastTimestampMs = Long.MIN_VALUE
    private var cookie: ByteArray? = null
    private var cookieMs = 0L
    private var lastSentMs = 0L
    private val queue = ArrayDeque<ByteArray>()

    @Volatile
    var lastHandshakeMs: Long? = null
        private set

    val connected: Boolean get() = current != null

    private fun usable(nowMs: Long): WgSession? {
        val s = current ?: return null
        if (nowMs - s.createdMs >= REJECT_AFTER_MS || s.exhausted) {
            previous = s
            current = null
            return null
        }
        return s
    }

    private fun initiate(nowMs: Long): ByteArray {
        if (!initiating) firstAttemptMs = nowMs
        initiating = true
        nextRetryMs = nowMs + REKEY_TIMEOUT_MS + random.nextInt(JITTER_MS + 1)
        val ts = if (nowMs > lastTimestampMs) nowMs else lastTimestampMs + 1
        lastTimestampMs = ts
        val c = cookie?.takeIf { nowMs - cookieMs < COOKIE_LIFE_MS }
        var index = random.nextInt()
        while (index == current?.localIndex || index == previous?.localIndex) index = random.nextInt()
        return initiator.initiation(index, X25519.newPrivate(random), WgPrimitives.tai64n(ts), c)
    }

    private fun seal(s: WgSession, packet: ByteArray, nowMs: Long): ByteArray {
        lastSentMs = nowMs
        return s.seal(aead, packet)
    }

    fun send(packet: ByteArray, nowMs: Long): List<ByteArray> {
        val out = ArrayList<ByteArray>(2)
        val s = usable(nowMs)
        if (s != null) {
            out += seal(s, packet, nowMs)
            if (nowMs - s.createdMs >= REKEY_AFTER_MS && (!initiating || nowMs >= nextRetryMs)) out += initiate(nowMs)
            return out
        }
        if (queue.size >= QUEUE_LIMIT) queue.removeFirst()
        queue.addLast(packet)
        if (!initiating || nowMs >= nextRetryMs) out += initiate(nowMs)
        return out
    }

    fun receive(datagram: ByteArray, nowMs: Long): WgInbound {
        when (WgMessage.type(datagram)) {
            WgMessage.RESPONSE -> {
                val s = initiator.response(datagram, nowMs) ?: return NOTHING
                previous = current
                current = s
                initiating = false
                lastHandshakeMs = nowMs
                val out = ArrayList<ByteArray>()
                while (queue.isNotEmpty()) out += seal(s, queue.removeFirst(), nowMs)
                if (out.isEmpty()) out += seal(s, ByteArray(0), nowMs)
                return WgInbound(emptyList(), out)
            }
            WgMessage.COOKIE -> {
                initiator.cookie(datagram)?.let {
                    cookie = it
                    cookieMs = nowMs
                }
                return NOTHING
            }
            WgMessage.DATA -> {
                if (datagram.size < WgMessage.DATA_HEADER) return NOTHING
                val index = WgMessage.le32(datagram, 4)
                val s = listOfNotNull(current, previous).firstOrNull { it.localIndex == index } ?: return NOTHING
                if (nowMs - s.createdMs >= REJECT_AFTER_MS) return NOTHING
                val plain = s.open(aead, datagram) ?: return NOTHING
                return if (plain.isEmpty()) NOTHING else WgInbound(listOf(plain), emptyList())
            }
            else -> return NOTHING
        }
    }

    fun tick(nowMs: Long): List<ByteArray> {
        val out = ArrayList<ByteArray>(1)
        val s = usable(nowMs)
        val wanted = queue.isNotEmpty() || settings.keepaliveSec > 0
        if (initiating && nowMs - firstAttemptMs >= REKEY_ATTEMPT_MS && settings.keepaliveSec <= 0) {
            initiating = false
            queue.clear()
        }
        if (s == null) {
            if (wanted && (!initiating || nowMs >= nextRetryMs)) out += initiate(nowMs)
            return out
        }
        if (initiating && nowMs >= nextRetryMs) out += initiate(nowMs)
        if (settings.keepaliveSec > 0 && nowMs - lastSentMs >= settings.keepaliveSec * 1000L) {
            out += seal(s, ByteArray(0), nowMs)
            if (nowMs - s.createdMs >= REKEY_AFTER_MS && !initiating) out += initiate(nowMs)
        }
        return out
    }

    companion object {
        const val REKEY_AFTER_MS = 120_000L
        const val REJECT_AFTER_MS = 180_000L
        const val REKEY_TIMEOUT_MS = 5_000L
        const val REKEY_ATTEMPT_MS = 90_000L
        const val JITTER_MS = 333
        const val COOKIE_LIFE_MS = 120_000L
        const val QUEUE_LIMIT = 256
        private val NOTHING = WgInbound(emptyList(), emptyList())
    }
}

class WgLink(val routing: TunnelRouting, val peer: WgPeer, val endpoint: java.net.InetSocketAddress)
