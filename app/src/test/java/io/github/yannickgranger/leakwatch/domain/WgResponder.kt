package io.github.yannickgranger.leakwatch.domain

import java.nio.ByteBuffer
import java.nio.ByteOrder
import io.github.yannickgranger.leakwatch.port.Aead

class WgResponder(private val staticPrivate: ByteArray, private val psk: ByteArray, private val aead: Aead) {
    val staticPublic: ByteArray = X25519.publicKey(staticPrivate)
    var initiatorStatic: ByteArray? = null
    var timestamp: ByteArray? = null
    var session: WgSession? = null
    private var chain = ByteArray(0)
    private var hash = ByteArray(0)
    private var initiatorEphemeral = ByteArray(0)
    private var initiatorIndex = 0

    private fun le32(b: ByteArray, off: Int) = ByteBuffer.wrap(b, off, 4).order(ByteOrder.LITTLE_ENDIAN).int

    fun mac1Valid(msg: ByteArray): Boolean {
        val off = msg.size - 32
        val key = WgPrimitives.hash(WgPrimitives.LABEL_MAC1, staticPublic)
        return WgPrimitives.mac(key, msg.copyOfRange(0, off)).contentEquals(msg.copyOfRange(off, off + 16))
    }

    fun mac2Valid(msg: ByteArray, cookie: ByteArray): Boolean {
        val off = msg.size - 16
        return WgPrimitives.mac(cookie, msg.copyOfRange(0, off)).contentEquals(msg.copyOfRange(off, msg.size))
    }

    fun consumeInitiation(msg: ByteArray): Boolean {
        if (msg.size != 148 || msg[0].toInt() != 1 || !mac1Valid(msg)) return false
        initiatorIndex = le32(msg, 4)
        initiatorEphemeral = msg.copyOfRange(8, 40)
        var c = WgPrimitives.hash(WgPrimitives.CONSTRUCTION)
        var h = WgPrimitives.hash(c, WgPrimitives.IDENTIFIER)
        h = WgPrimitives.hash(h, staticPublic)
        c = WgPrimitives.kdf(1, c, initiatorEphemeral)[0]
        h = WgPrimitives.hash(h, initiatorEphemeral)
        var k = WgPrimitives.kdf(2, c, X25519.scalarMult(staticPrivate, initiatorEphemeral)).also { c = it[0] }[1]
        val encStatic = msg.copyOfRange(40, 88)
        val s = aead.open(k, WgPrimitives.nonce(0), encStatic, h) ?: return false
        h = WgPrimitives.hash(h, encStatic)
        k = WgPrimitives.kdf(2, c, X25519.scalarMult(staticPrivate, s)).also { c = it[0] }[1]
        val encTs = msg.copyOfRange(88, 116)
        val ts = aead.open(k, WgPrimitives.nonce(0), encTs, h) ?: return false
        h = WgPrimitives.hash(h, encTs)
        initiatorStatic = s
        timestamp = ts
        chain = c
        hash = h
        return true
    }

    fun response(localIndex: Int, ephemeralPrivate: ByteArray, nowMs: Long): ByteArray {
        val ePub = X25519.publicKey(ephemeralPrivate)
        var c = WgPrimitives.kdf(1, chain, ePub)[0]
        var h = WgPrimitives.hash(hash, ePub)
        c = WgPrimitives.kdf(1, c, X25519.scalarMult(ephemeralPrivate, initiatorEphemeral))[0]
        c = WgPrimitives.kdf(1, c, X25519.scalarMult(ephemeralPrivate, initiatorStatic!!))[0]
        val t = WgPrimitives.kdf(3, c, psk)
        c = t[0]
        h = WgPrimitives.hash(h, t[1])
        val empty = aead.seal(t[2], WgPrimitives.nonce(0), ByteArray(0), h)
        val msg = ByteBuffer.allocate(92).order(ByteOrder.LITTLE_ENDIAN)
        msg.put(2).put(0).put(0).put(0).putInt(localIndex).putInt(initiatorIndex).put(ePub).put(empty)
        val body = msg.array().copyOfRange(0, 60)
        val mac1 = WgPrimitives.mac(WgPrimitives.hash(WgPrimitives.LABEL_MAC1, initiatorStatic!!), body)
        msg.put(mac1)
        val keys = WgPrimitives.kdf(2, c, ByteArray(0))
        session = WgSession(localIndex, initiatorIndex, keys[1], keys[0], nowMs)
        return msg.array()
    }

    fun cookieReply(initiation: ByteArray, cookie: ByteArray, nonce: ByteArray): ByteArray {
        val mac1 = initiation.copyOfRange(116, 132)
        val key = WgPrimitives.hash(WgPrimitives.LABEL_COOKIE, staticPublic)
        val enc = WgPrimitives.xseal(aead, key, nonce, cookie, mac1)
        val msg = ByteBuffer.allocate(64).order(ByteOrder.LITTLE_ENDIAN)
        msg.put(3).put(0).put(0).put(0).putInt(le32(initiation, 4)).put(nonce).put(enc)
        return msg.array()
    }
}
