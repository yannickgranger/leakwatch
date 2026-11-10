package io.github.yannickgranger.leakwatch.domain

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class TunnelRoutingTest {
    private val ip = TestNet::ip
    private val routing = TunnelRouting(listOf(Cidr.parse("10.200.0.0/24"), Cidr.parse("fd00:200::/64")), listOf(Cidr.parse("10.200.0.3/32"), Cidr.parse("fd00:200::3/128")), 1420)

    @Test
    fun cidrMatchesOnPrefix() {
        val c = Cidr.parse("10.200.0.0/24")
        assertTrue(c.contains(ip("10.200.0.1")))
        assertTrue(c.contains(ip("10.200.0.255")))
        assertFalse(c.contains(ip("10.200.1.1")))
        assertFalse(c.contains(ip("fd00:200::1")))
        assertTrue(Cidr.parse("10.200.0.3/17").contains(ip("10.200.127.1")))
        assertTrue(Cidr.parse("fd00:200::/64").contains(ip("fd00:200::abcd")))
        assertEquals("10.200.0.0/24", c.toString())
        assertTrue(Cidr.parse("0.0.0.0/0").isDefault)
        assertTrue(Cidr.parse("::/0").isDefault)
    }

    @Test
    fun matchesAllowedIpsOnly() {
        assertTrue(routing.routes(ip("10.200.0.1")))
        assertTrue(routing.routes(ip("fd00:200::1")))
        assertFalse(routing.routes(ip("93.184.215.14")))
        assertFalse(routing.routes(ip("10.111.0.2")))
    }

    @Test
    fun rewritesSourceToTunnelAddressAndBackWithValidChecksums() {
        val out = PacketCodec.buildTcp(ip("10.111.0.1"), 40000, ip("10.200.0.1"), 22, 1000, 0, TcpFlags.SYN, 65535, mss = 1460)
        val sent = routing.outbound(out, out.size)!!
        val ps = PacketCodec.parse(sent, sent.size)!!
        assertEquals(ip("10.200.0.3"), ps.src)
        assertEquals(ip("10.200.0.1"), ps.dst)
        assertTrue(TestNet.transportValid(sent))
        assertEquals(1380, ps.tcp!!.mss)
        val reply = PacketCodec.buildTcp(ip("10.200.0.1"), 22, ip("10.200.0.3"), 40000, 5000, 1001, TcpFlags.SYN or TcpFlags.ACK, 65535, mss = 1380)
        val back = routing.inbound(reply)!!
        val pb = PacketCodec.parse(back, back.size)!!
        assertEquals(ip("10.111.0.1"), pb.dst)
        assertEquals(ip("10.200.0.1"), pb.src)
        assertTrue(TestNet.transportValid(back))
    }

    @Test
    fun udpAndIpv6AreRewrittenToo() {
        val out = PacketCodec.buildUdp(ip("fd00:111::1"), 5353, ip("fd00:200::1"), 53, "q".toByteArray())
        val sent = routing.outbound(out, out.size)!!
        assertEquals(ip("fd00:200::3"), PacketCodec.parse(sent, sent.size)!!.src)
        assertTrue(TestNet.transportValid(sent))
        val reply = PacketCodec.buildUdp(ip("fd00:200::1"), 53, ip("fd00:200::3"), 5353, "a".toByteArray())
        val back = routing.inbound(reply)!!
        assertEquals(ip("fd00:111::1"), PacketCodec.parse(back, back.size)!!.dst)
        assertTrue(TestNet.transportValid(back))
    }

    @Test
    fun sourceAlreadyOnTunnelAddressIsKept() {
        val out = PacketCodec.buildUdp(ip("10.200.0.3"), 6000, ip("10.200.0.1"), 7, "x".toByteArray())
        val sent = routing.outbound(out, out.size)!!
        assertEquals(ip("10.200.0.3"), PacketCodec.parse(sent, sent.size)!!.src)
        val back = routing.inbound(PacketCodec.buildUdp(ip("10.200.0.1"), 7, ip("10.200.0.3"), 6000, "y".toByteArray()))!!
        assertEquals(ip("10.200.0.3"), PacketCodec.parse(back, back.size)!!.dst)
    }

    @Test
    fun notRoutedOrForeignPacketsAreRefused() {
        val out = PacketCodec.buildUdp(ip("10.111.0.1"), 6000, ip("1.1.1.1"), 53, "x".toByteArray())
        assertNull(routing.outbound(out, out.size))
        assertNull(routing.inbound(PacketCodec.buildUdp(ip("10.200.0.1"), 7, ip("10.200.0.9"), 6000, "y".toByteArray())))
        assertNull(routing.inbound(PacketCodec.buildUdp(ip("8.8.8.8"), 7, ip("10.200.0.3"), 6000, "y".toByteArray())))
    }

    @Test
    fun mssClampFollowsTunnelMtuForIpv6() {
        val out = PacketCodec.buildTcp(ip("fd00:111::1"), 40000, ip("fd00:200::1"), 22, 1, 0, TcpFlags.SYN, 65535, mss = 1440)
        val sent = routing.outbound(out, out.size)!!
        assertEquals(1360, PacketCodec.parse(sent, sent.size)!!.tcp!!.mss)
        assertTrue(TestNet.transportValid(sent))
    }
}
