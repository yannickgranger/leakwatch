package io.github.yannickgranger.leakwatch.domain

import io.github.yannickgranger.leakwatch.domain.TestNet.ip
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class TcpSessionTest {
    private val key = FlowKey(Proto.TCP, ip("10.111.0.1"), 40000, ip("1.2.3.4"), 80)
    private val clientIsn = 100
    private val serverIsn = 5000

    private fun parse(b: ByteArray): ParsedPacket {
        assertTrue(TestNet.transportValid(b))
        return PacketCodec.parse(b, b.size)!!
    }

    private fun seg(seq: Int, ack: Int, flags: Int, window: Int = 65535) = TcpHeader(seq, ack, flags, window, null)

    private fun established(window: Int = 65535, k: FlowKey = key): TcpSession {
        val s = TcpSession(k, clientIsn, serverIsn, window, 1460, 0)
        s.connected(0)
        s.onClientSegment(seg(clientIsn + 1, serverIsn + 1, TcpFlags.ACK, window), PacketCodec.EMPTY, 0)
        return s
    }

    private fun drain(s: TcpSession): ByteArray {
        var out = ByteArray(0)
        s.drainUpstream { b, o, l -> out += b.copyOfRange(o, o + l); l }
        return out
    }

    @Test
    fun handshakeAnswersSynAckOnceUpstreamConnects() {
        val s = TcpSession(key, clientIsn, serverIsn, 65535, 1460, 0)
        assertEquals(TcpSession.State.CONNECTING, s.state)
        val synAck = parse(s.connected(0).single())
        val t = synAck.tcp!!
        assertEquals(ip("1.2.3.4"), synAck.src)
        assertEquals(ip("10.111.0.1"), synAck.dst)
        assertEquals(80, synAck.srcPort)
        assertEquals(40000, synAck.dstPort)
        assertEquals(serverIsn, t.seq)
        assertEquals(clientIsn + 1, t.ack)
        assertTrue(t.has(TcpFlags.SYN) && t.has(TcpFlags.ACK))
        assertEquals(1400, t.mss)
        s.onClientSegment(seg(clientIsn + 1, serverIsn + 1, TcpFlags.ACK), PacketCodec.EMPTY, 1)
        assertEquals(TcpSession.State.ESTABLISHED, s.state)
    }

    @Test
    fun ipv6AdvertisesMss1380() {
        val k6 = FlowKey(Proto.TCP, ip("fd00:111::1"), 40000, ip("2001:db8::1"), 443)
        val s = TcpSession(k6, clientIsn, serverIsn, 65535, 1440, 0)
        assertEquals(1380, parse(s.connected(0).single()).tcp!!.mss)
    }

    @Test
    fun clientDataIsAcknowledgedAndQueuedUpstream() {
        val s = established()
        val data = "GET / HTTP/1.1\r\n\r\n".toByteArray()
        val r = s.onClientSegment(seg(clientIsn + 1, serverIsn + 1, TcpFlags.ACK or TcpFlags.PSH), data, 2)
        assertArrayEquals(data, r.accepted)
        val ack = parse(r.toClient.single()).tcp!!
        assertEquals(clientIsn + 1 + data.size, ack.ack)
        assertEquals(data.size, s.upstreamPending)
        assertArrayEquals(data, drain(s))
        assertEquals(0, s.upstreamPending)
        assertEquals(data.size.toLong(), s.bytesOut)
    }

    @Test
    fun retransmittedClientDataIsNotCountedTwice() {
        val s = established()
        val data = ByteArray(100) { 1 }
        s.onClientSegment(seg(clientIsn + 1, serverIsn + 1, TcpFlags.ACK), data, 2)
        val r = s.onClientSegment(seg(clientIsn + 1, serverIsn + 1, TcpFlags.ACK), data, 3)
        assertEquals(0, r.accepted.size)
        assertEquals(clientIsn + 101, parse(r.toClient.single()).tcp!!.ack)
        assertEquals(100L, s.bytesOut)
        assertEquals(100, s.upstreamPending)
    }

    @Test
    fun upstreamDataIsSegmentedByMssAndClientWindow() {
        val s = established(window = 3000)
        val data = ByteArray(5000) { (it % 251).toByte() }
        assertTrue(s.upstreamReadBudget() >= 5000)
        val sent = s.onUpstreamData(data, 0, data.size, 5).map { parse(it) }
        assertEquals(listOf(1400, 1400, 200), sent.map { it.payload.size })
        assertEquals(serverIsn + 1, sent[0].tcp!!.seq)
        assertEquals(serverIsn + 1 + 2800, sent[2].tcp!!.seq)
        val more = s.onClientSegment(seg(clientIsn + 1, serverIsn + 1 + 3000, TcpFlags.ACK, 3000), PacketCodec.EMPTY, 6).toClient.map { parse(it) }
        assertEquals(listOf(1400, 600), more.map { it.payload.size })
        val all = (sent + more).fold(ByteArray(0)) { acc, p -> acc + p.payload }
        assertArrayEquals(data, all)
        assertEquals(5000L, s.bytesIn)
    }

    @Test
    fun zeroWindowStopsSendingUntilWindowOpens() {
        val s = established(window = 0)
        assertEquals(0, s.onUpstreamData(ByteArray(10), 0, 10, 1).size)
        val r = s.onClientSegment(seg(clientIsn + 1, serverIsn + 1, TcpFlags.ACK, 1000), PacketCodec.EMPTY, 2)
        assertEquals(10, parse(r.toClient.single()).payload.size)
    }

    @Test
    fun finFromClientThenUpstreamCloses() {
        val s = established()
        val r = s.onClientSegment(seg(clientIsn + 1, serverIsn + 1, TcpFlags.ACK or TcpFlags.FIN), PacketCodec.EMPTY, 2)
        assertEquals(clientIsn + 2, parse(r.toClient.single()).tcp!!.ack)
        assertTrue(s.needsUpstreamShutdown())
        s.upstreamShutdownDone()
        assertFalse(s.needsUpstreamShutdown())
        val fin = parse(s.onUpstreamEof(3).single()).tcp!!
        assertTrue(fin.has(TcpFlags.FIN))
        assertEquals(serverIsn + 1, fin.seq)
        assertFalse(s.isClosed)
        s.onClientSegment(seg(clientIsn + 2, serverIsn + 2, TcpFlags.ACK), PacketCodec.EMPTY, 4)
        assertTrue(s.isClosed)
        assertEquals("fin", s.closeReason)
    }

    @Test
    fun finFromUpstreamWaitsForPendingDataThenClientFinCloses() {
        val s = established(window = 1000)
        val out = s.onUpstreamData(ByteArray(1500), 0, 1500, 1) + s.onUpstreamEof(1)
        assertEquals(1, out.size)
        val rest = s.onClientSegment(seg(clientIsn + 1, serverIsn + 1 + 1000, TcpFlags.ACK, 1000), PacketCodec.EMPTY, 2).toClient.map { parse(it) }
        assertEquals(500, rest[0].payload.size)
        assertTrue(rest.last().tcp!!.has(TcpFlags.FIN))
        val last = s.onClientSegment(seg(clientIsn + 1, serverIsn + 1 + 1501, TcpFlags.ACK or TcpFlags.FIN), PacketCodec.EMPTY, 3)
        assertEquals(clientIsn + 2, parse(last.toClient.single()).tcp!!.ack)
        assertTrue(s.isClosed)
    }

    @Test
    fun rstFromClientClosesAndUpstreamErrorResetsClient() {
        val a = established()
        assertEquals(0, a.onClientSegment(seg(clientIsn + 1, 0, TcpFlags.RST), PacketCodec.EMPTY, 1).toClient.size)
        assertTrue(a.isClosed)
        assertEquals("rst_client", a.closeReason)
        val b = established()
        val rst = parse(b.abort("rst_upstream")).tcp!!
        assertTrue(rst.has(TcpFlags.RST))
        assertEquals(serverIsn + 1, rst.seq)
        assertTrue(b.isClosed)
        assertEquals("rst_upstream", b.closeReason)
    }

    @Test
    fun refusedConnectAnswersRst() {
        val s = TcpSession(key, clientIsn, serverIsn, 65535, 1460, 0)
        val rst = parse(s.refuse("connect_failed")).tcp!!
        assertTrue(rst.has(TcpFlags.RST) && rst.has(TcpFlags.ACK))
        assertEquals(clientIsn + 1, rst.ack)
        assertEquals("connect_failed", s.closeReason)
    }

    @Test
    fun unacknowledgedDataIsRetransmittedOnTimer() {
        val s = established()
        s.onUpstreamData(ByteArray(100) { 9 }, 0, 100, 0)
        assertEquals(0, s.onTimer(100).size)
        val re = parse(s.onTimer(5_000).single())
        assertEquals(serverIsn + 1, re.tcp!!.seq)
        assertEquals(100, re.payload.size)
        assertEquals(100L, s.bytesIn)
    }

    @Test
    fun advertisedWindowShrinksWithQueuedUpstreamData() {
        val s = established()
        val r = s.onClientSegment(seg(clientIsn + 1, serverIsn + 1, TcpFlags.ACK), ByteArray(1000), 1)
        val w = parse(r.toClient.single()).tcp!!.window
        assertEquals(65535 - 1000, w)
    }
}
