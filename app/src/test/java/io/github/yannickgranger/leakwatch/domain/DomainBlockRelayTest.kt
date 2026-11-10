package io.github.yannickgranger.leakwatch.domain

import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class DomainBlockRelayTest {
    private val rig = EngineRig(listOf("example.com"))

    @After
    fun close() = rig.close()

    private fun handshake(srcPort: Int): Int {
        rig.tcp(1000, 0, TcpFlags.SYN, srcPort = srcPort)
        val synAck = rig.tun.next()!!
        assertTrue(synAck.tcp!!.has(TcpFlags.SYN) && synAck.tcp!!.has(TcpFlags.ACK))
        val sAck = synAck.tcp!!.seq + 1
        rig.tcp(1001, sAck, TcpFlags.ACK, srcPort = srcPort)
        return sAck
    }

    @Test
    fun blockedSniGetsRstAndDomainBlockedRecord() {
        val sAck = handshake(47000)
        rig.tcp(1001, sAck, TcpFlags.ACK or TcpFlags.PSH, rig.clientHello(), srcPort = 47000)
        var rst = false
        val deadline = System.currentTimeMillis() + 3000
        while (!rst && System.currentTimeMillis() < deadline) {
            val p = rig.tun.next(200) ?: continue
            assertEquals(0, p.payload.size)
            rst = p.tcp!!.has(TcpFlags.RST)
        }
        assertTrue(rst)
        Thread.sleep(300)
        rig.stop()
        val f = rig.flows().single { it.src.endsWith(":47000") }
        assertEquals("example.com", f.sni)
        assertTrue(f.blocked)
        assertEquals("domain_blocked", f.closeReason)
        assertEquals(0L, f.bytesIn)
        assertFalse(f.suspicious)
        assertEquals(emptyList<String>(), f.reasons)
    }

    @Test
    fun sameSniForAnAllowedPackagePassesAndEchoes() {
        rig.domains.put(DomainRule("com.test.app10123", "example.com", RuleAction.ALLOW))
        val sAck = handshake(47001)
        val hello = rig.clientHello()
        rig.tcp(1001, sAck, TcpFlags.ACK or TcpFlags.PSH, hello, srcPort = 47001)
        val back = java.io.ByteArrayOutputStream()
        val deadline = System.currentTimeMillis() + 5000
        while (back.size() < hello.size && System.currentTimeMillis() < deadline) {
            val p = rig.tun.next(200) ?: continue
            assertFalse(p.tcp!!.has(TcpFlags.RST))
            back.write(p.payload)
        }
        assertArrayEquals(hello, back.toByteArray())
        rig.stop()
        val f = rig.flows().single { it.src.endsWith(":47001") }
        assertEquals("example.com", f.sni)
        assertFalse(f.blocked)
        assertEquals(hello.size.toLong(), f.bytesIn)
    }

    @Test
    fun blockedHttpHostGetsRst() {
        rig.domains.put(DomainRule(DomainRule.ALL, "plain.blocked.test", RuleAction.BLOCK))
        val sAck = handshake(47002)
        rig.tcp(1001, sAck, TcpFlags.ACK or TcpFlags.PSH, "GET / HTTP/1.1\r\nHost: plain.blocked.test\r\n\r\n".toByteArray(), srcPort = 47002)
        var rst = false
        val deadline = System.currentTimeMillis() + 3000
        while (!rst && System.currentTimeMillis() < deadline) {
            val p = rig.tun.next(200) ?: continue
            assertEquals(0, p.payload.size)
            rst = p.tcp!!.has(TcpFlags.RST)
        }
        assertTrue(rst)
        rig.stop()
        val f = rig.flows().single { it.src.endsWith(":47002") }
        assertEquals("domain_blocked", f.closeReason)
        assertTrue(f.blocked)
    }

    @Test
    fun synToAnAddressNamedByABlockedNameIsRefusedBeforeConnecting() {
        rig.send(PacketCodec.buildUdp(rig.client, 44010, rig.dnsVirtual, 53, DnsCodec.query(5, "loop.test", 1)))
        assertEquals(listOf("127.0.0.1"), DnsCodec.parse(rig.tun.next()!!.payload)!!.answers)
        rig.domains.put(DomainRule("com.test.app10123", "loop.test", RuleAction.BLOCK))
        rig.tcp(3000, 0, TcpFlags.SYN, srcPort = 47003)
        val rst = rig.tun.next()!!
        assertTrue(rst.tcp!!.has(TcpFlags.RST))
        Thread.sleep(300)
        assertEquals(0, rig.accepts.get())
        rig.stop()
        val f = rig.flows().single { it.src.endsWith(":47003") }
        assertEquals("loop.test", f.dnsName)
        assertEquals("domain_blocked", f.closeReason)
        assertTrue(f.blocked)
        assertFalse(f.suspicious)
    }
}
