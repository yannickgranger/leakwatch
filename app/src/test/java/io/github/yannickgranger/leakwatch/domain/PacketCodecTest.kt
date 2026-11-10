package io.github.yannickgranger.leakwatch.domain

import io.github.yannickgranger.leakwatch.domain.TestNet.hex
import io.github.yannickgranger.leakwatch.domain.TestNet.ip
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class PacketCodecTest {
    @Test
    fun ipv4HeaderChecksumMatchesKnownVector() {
        val header = hex("45000073000040004011 0000 c0a80001c0a800c7")
        assertEquals(0xb861, Checksum.ipv4Header(header, 0, 20))
    }

    @Test
    fun ipv4TcpRoundTripWithMssOption() {
        val payload = "hello".toByteArray()
        val pkt = PacketCodec.buildTcp(ip("10.111.0.1"), 40000, ip("93.184.215.14"), 443, 1000, 2000, TcpFlags.SYN or TcpFlags.ACK, 65535, payload, mss = 1400)
        assertTrue(TestNet.transportValid(pkt))
        val p = PacketCodec.parse(pkt, pkt.size)!!
        assertEquals(4, p.ipVersion)
        assertEquals(Proto.TCP, p.protocol)
        assertEquals(ip("10.111.0.1"), p.src)
        assertEquals(ip("93.184.215.14"), p.dst)
        assertEquals(40000, p.srcPort)
        assertEquals(443, p.dstPort)
        val t = p.tcp!!
        assertEquals(1000, t.seq)
        assertEquals(2000, t.ack)
        assertTrue(t.has(TcpFlags.SYN) && t.has(TcpFlags.ACK))
        assertEquals(65535, t.window)
        assertEquals(1400, t.mss)
        assertArrayEquals(payload, p.payload)
    }

    @Test
    fun ipv6TcpRoundTripWithPseudoHeaderChecksum() {
        val payload = ByteArray(1380) { it.toByte() }
        val pkt = PacketCodec.buildTcp(ip("fd00:111::1"), 50000, ip("2606:2800:21f:cb07:6820:80da:af6b:8b2c"), 443, -5, 7, TcpFlags.ACK or TcpFlags.PSH, 4000, payload)
        assertEquals(40 + 20 + 1380, pkt.size)
        assertTrue(TestNet.transportValid(pkt))
        val p = PacketCodec.parse(pkt, pkt.size)!!
        assertEquals(6, p.ipVersion)
        assertEquals(-5, p.tcp!!.seq)
        assertNull(p.tcp!!.mss)
        assertArrayEquals(payload, p.payload)
    }

    @Test
    fun ipv4UdpRoundTrip() {
        val payload = byteArrayOf(1, 2, 3)
        val pkt = PacketCodec.buildUdp(ip("10.111.0.2"), 53, ip("10.111.0.1"), 33333, payload)
        assertTrue(TestNet.transportValid(pkt))
        val p = PacketCodec.parse(pkt, pkt.size)!!
        assertEquals(Proto.UDP, p.protocol)
        assertEquals(53, p.srcPort)
        assertEquals(33333, p.dstPort)
        assertNull(p.tcp)
        assertArrayEquals(payload, p.payload)
    }

    @Test
    fun ipv6UdpRoundTrip() {
        val payload = ByteArray(301) { (it * 7).toByte() }
        val pkt = PacketCodec.buildUdp(ip("fd00:111::1"), 5353, ip("2001:4860:4860::8888"), 443, payload)
        assertTrue(TestNet.transportValid(pkt))
        val p = PacketCodec.parse(pkt, pkt.size)!!
        assertEquals(6, p.ipVersion)
        assertEquals(443, p.dstPort)
        assertArrayEquals(payload, p.payload)
    }

    @Test
    fun parsesForeignIcmpAndRejectsGarbage() {
        val icmp = hex("4500001c00004000400100000a6f0001080808080800f7ff00000000")
        val p = PacketCodec.parse(icmp, icmp.size)!!
        assertEquals(Proto.ICMP, p.protocol)
        assertNull(PacketCodec.parse(byteArrayOf(0x45, 0), 2))
        assertNull(PacketCodec.parse(byteArrayOf(0x10, 0, 0, 0), 4))
    }

    @Test
    fun formatsEndpoints() {
        assertEquals("1.2.3.4:80", Endpoint.format(ip("1.2.3.4"), 80))
        assertEquals("[2001:db8::1]:443", Endpoint.format(ip("2001:db8::1"), 443))
        assertEquals("2001:db8::1", Endpoint.host(ip("2001:db8::1")))
    }
}
