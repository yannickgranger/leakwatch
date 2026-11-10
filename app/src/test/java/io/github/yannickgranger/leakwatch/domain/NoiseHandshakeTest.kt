package io.github.yannickgranger.leakwatch.domain

import java.util.Base64
import java.util.Random
import io.github.yannickgranger.leakwatch.adapter.JcaAead
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class NoiseHandshakeTest {
    private val aead = JcaAead()
    private fun b64(s: String): ByteArray = Base64.getDecoder().decode(s)
    private val initiatorPriv = b64(WgVectors.PRIV_1)
    private val responderPriv = b64(WgVectors.PRIV_2)
    private val psk = b64(WgVectors.PSK)
    private val t0 = 1_762_600_000_000L

    private fun ipPacket(payload: String): ByteArray =
        PacketCodec.buildUdp(TestNet.ip("10.200.0.2"), 5000, TestNet.ip("10.200.0.1"), 7, payload.toByteArray())

    @Test
    fun fixedInitiationVectorComputedFromWgKeys() {
        val i = NoiseInitiator(initiatorPriv, b64(WgVectors.PUB_2), null, aead)
        val msg = i.initiation(0x01020304, ByteArray(32) { 0x11 }, TestNet.hex(WgVectors.INITIATION_TAI64N), null)
        assertArrayEquals(TestNet.hex(WgVectors.INITIATION), msg)
    }

    @Test
    fun initiatorCompletesHandshakeWithResponderAndTransportsBothWays() {
        val r = WgResponder(responderPriv, psk, aead)
        val i = NoiseInitiator(initiatorPriv, r.staticPublic, psk, aead)
        val init = i.initiation(77, X25519.newPrivate(Random(1)), WgPrimitives.tai64n(t0), null)
        assertTrue(r.consumeInitiation(init))
        assertArrayEquals(X25519.publicKey(initiatorPriv), r.initiatorStatic)
        assertArrayEquals(WgPrimitives.tai64n(t0), r.timestamp)
        val resp = r.response(99, X25519.newPrivate(Random(2)), t0)
        val s = i.response(resp, t0)
        assertNotNull(s)
        assertEquals(77, s!!.localIndex)
        assertEquals(99, s.remoteIndex)
        val out = s.seal(aead, ipPacket("hello"))
        assertArrayEquals(ipPacket("hello"), r.session!!.open(aead, out))
        val back = r.session!!.seal(aead, ipPacket("world"))
        assertArrayEquals(ipPacket("world"), s.open(aead, back))
        assertNull(s.open(aead, back))
    }

    @Test
    fun transportMessagesArePaddedAndCounted() {
        val r = WgResponder(responderPriv, psk, aead)
        val i = NoiseInitiator(initiatorPriv, r.staticPublic, psk, aead)
        assertTrue(r.consumeInitiation(i.initiation(1, X25519.newPrivate(Random(3)), WgPrimitives.tai64n(t0), null)))
        val s = i.response(r.response(2, X25519.newPrivate(Random(4)), t0), t0)!!
        val m1 = s.seal(aead, ipPacket("abc"))
        val m2 = s.seal(aead, ByteArray(0))
        assertEquals(4, m1[0].toInt())
        assertEquals(0, (m1.size - 16 - 16) % 16)
        assertEquals(32, m2.size)
        assertEquals(1L, java.nio.ByteBuffer.wrap(m2, 8, 8).order(java.nio.ByteOrder.LITTLE_ENDIAN).long)
        assertArrayEquals(ipPacket("abc"), r.session!!.open(aead, m1))
        assertArrayEquals(ByteArray(0), r.session!!.open(aead, m2))
    }

    @Test
    fun wrongPresharedKeyIsRejected() {
        val r = WgResponder(responderPriv, ByteArray(32) { 9 }, aead)
        val i = NoiseInitiator(initiatorPriv, r.staticPublic, psk, aead)
        assertTrue(r.consumeInitiation(i.initiation(1, X25519.newPrivate(Random(5)), WgPrimitives.tai64n(t0), null)))
        assertNull(i.response(r.response(2, X25519.newPrivate(Random(6)), t0), t0))
    }

    @Test
    fun responseForAnotherIndexIsIgnored() {
        val r = WgResponder(responderPriv, psk, aead)
        val i = NoiseInitiator(initiatorPriv, r.staticPublic, psk, aead)
        assertTrue(r.consumeInitiation(i.initiation(1, X25519.newPrivate(Random(5)), WgPrimitives.tai64n(t0), null)))
        val resp = r.response(2, X25519.newPrivate(Random(6)), t0)
        resp[8] = 42
        assertNull(i.response(resp, t0))
    }

    @Test
    fun cookieReplyIsAcceptedAndMac2Recomputed() {
        val r = WgResponder(responderPriv, psk, aead)
        val i = NoiseInitiator(initiatorPriv, r.staticPublic, psk, aead)
        val first = i.initiation(5, X25519.newPrivate(Random(7)), WgPrimitives.tai64n(t0), null)
        assertArrayEquals(ByteArray(16), first.copyOfRange(132, 148))
        val cookie = ByteArray(16) { (it * 3).toByte() }
        val reply = r.cookieReply(first, cookie, ByteArray(24) { (it + 1).toByte() })
        assertArrayEquals(cookie, i.cookie(reply))
        val second = i.initiation(6, X25519.newPrivate(Random(8)), WgPrimitives.tai64n(t0 + 1000), cookie)
        assertTrue(r.mac1Valid(second))
        assertTrue(r.mac2Valid(second, cookie))
        reply[40] = (reply[40].toInt() xor 1).toByte()
        assertNull(i.cookie(reply))
    }

    @Test
    fun hchacha20MatchesXChaChaDraftVector() {
        val key = ByteArray(32) { it.toByte() }
        val nonce = TestNet.hex("000000090000004a0000000031415927")
        assertArrayEquals(TestNet.hex("82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc"), WgPrimitives.hchacha20(key, nonce))
    }

    @Test
    fun tai64nIsLabelledBigEndianSeconds() {
        val ts = WgPrimitives.tai64n(1_000_123L)
        assertEquals(12, ts.size)
        assertEquals(0x400000000000000aL + 1000L, java.nio.ByteBuffer.wrap(ts, 0, 8).long)
        assertEquals(123_000_000, java.nio.ByteBuffer.wrap(ts, 8, 4).int)
    }

    @Test
    fun peerQueuesUntilHandshakeThenFlushesAndDecrypts() {
        val r = WgResponder(responderPriv, psk, aead)
        val peer = WgPeer(WgPeerSettings(initiatorPriv, r.staticPublic, psk, 25), aead, Random(11))
        val out = peer.send(ipPacket("queued"), t0)
        assertEquals(1, out.size)
        assertTrue(r.consumeInitiation(out[0]))
        assertTrue(peer.send(ipPacket("queued2"), t0 + 10).isEmpty())
        val resp = r.response(500, X25519.newPrivate(Random(12)), t0 + 20)
        val res = peer.receive(resp, t0 + 20)
        assertEquals(2, res.toNet.size)
        assertArrayEquals(ipPacket("queued"), r.session!!.open(aead, res.toNet[0]))
        assertArrayEquals(ipPacket("queued2"), r.session!!.open(aead, res.toNet[1]))
        val inbound = peer.receive(r.session!!.seal(aead, ipPacket("reply")), t0 + 30)
        assertEquals(1, inbound.toTun.size)
        assertArrayEquals(ipPacket("reply"), inbound.toTun[0])
        assertEquals(t0 + 20, peer.lastHandshakeMs)
    }

    @Test
    fun peerSendsKeepaliveAfterHandshakeWithoutData() {
        val r = WgResponder(responderPriv, psk, aead)
        val peer = WgPeer(WgPeerSettings(initiatorPriv, r.staticPublic, psk, 25), aead, Random(13))
        val init = peer.tick(t0)
        assertEquals(1, init.size)
        assertTrue(r.consumeInitiation(init[0]))
        val res = peer.receive(r.response(9, X25519.newPrivate(Random(14)), t0), t0)
        assertEquals(1, res.toNet.size)
        assertArrayEquals(ByteArray(0), r.session!!.open(aead, res.toNet[0]))
        assertTrue(peer.tick(t0 + 24_000).isEmpty())
        val ka = peer.tick(t0 + 25_000)
        assertEquals(1, ka.size)
        assertArrayEquals(ByteArray(0), r.session!!.open(aead, ka[0]))
    }

    @Test
    fun peerRetriesHandshakeEveryFiveSecondsWithJitter() {
        val peer = WgPeer(WgPeerSettings(initiatorPriv, X25519.publicKey(responderPriv), psk, 25), aead, Random(15))
        assertEquals(1, peer.tick(t0).size)
        assertTrue(peer.tick(t0 + 4_999).isEmpty())
        val retry = (t0 + 5_000..t0 + 5_400 step 10).firstOrNull { peer.tick(it).isNotEmpty() }
        assertNotNull(retry)
    }

    @Test
    fun peerRekeysAfterTwoMinutesAndDropsSessionAfterThree() {
        val r = WgResponder(responderPriv, psk, aead)
        val peer = WgPeer(WgPeerSettings(initiatorPriv, r.staticPublic, psk, 0), aead, Random(16))
        assertTrue(r.consumeInitiation(peer.send(ipPacket("x"), t0)[0]))
        peer.receive(r.response(9, X25519.newPrivate(Random(17)), t0), t0)
        assertTrue(peer.tick(t0 + 60_000).isEmpty())
        val sent = peer.send(ipPacket("y"), t0 + 120_000)
        assertEquals(2, sent.size)
        assertEquals(4, sent[0][0].toInt())
        assertEquals(1, sent[1][0].toInt())
        val late = peer.send(ipPacket("z"), t0 + 181_000)
        assertFalse(late.any { it[0].toInt() == 4 })
    }

    @Test
    fun cookieReplyMakesNextInitiationCarryMac2() {
        val r = WgResponder(responderPriv, psk, aead)
        val peer = WgPeer(WgPeerSettings(initiatorPriv, r.staticPublic, psk, 25), aead, Random(18))
        val first = peer.tick(t0)[0]
        val cookie = ByteArray(16) { 7 }
        assertTrue(peer.receive(r.cookieReply(first, cookie, ByteArray(24) { 2 }), t0 + 5).toNet.isEmpty())
        val second = (t0 + 5_000..t0 + 5_400 step 10).firstNotNullOf { peer.tick(it).firstOrNull() }
        assertTrue(r.mac2Valid(second, cookie))
    }
}
