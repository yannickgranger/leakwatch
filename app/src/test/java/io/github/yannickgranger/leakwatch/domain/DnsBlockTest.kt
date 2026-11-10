package io.github.yannickgranger.leakwatch.domain

import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class DnsBlockTest {
    private val rig = EngineRig(listOf("*.blocked.test"))

    @After
    fun close() = rig.close()

    private fun u16(b: ByteArray, i: Int) = ((b[i].toInt() and 0xff) shl 8) or (b[i + 1].toInt() and 0xff)

    @Test
    fun nxdomainEchoesIdAndQuestion() {
        val q = DnsCodec.query(4242, "ads.blocked.test", 28)
        val r = DnsCodec.nxdomain(q)!!
        val m = DnsCodec.parse(r)!!
        assertEquals(4242, m.id)
        assertTrue(m.isResponse)
        assertEquals("ads.blocked.test", m.name)
        assertEquals(28, m.qtype)
        assertEquals(emptyList<String>(), m.answers)
        assertEquals(3, u16(r, 2) and 0x000f)
        assertEquals(0x0080, u16(r, 2) and 0x0080)
        assertEquals(0x0100, u16(r, 2) and 0x0100)
        assertEquals(1, u16(r, 4))
        assertEquals(0, u16(r, 6))
        assertArrayEquals(q.copyOfRange(12, q.size), r.copyOfRange(12, r.size))
    }

    @Test
    fun blockedNameGetsLocalNxdomainAndNoUpstreamQuery() {
        rig.send(PacketCodec.buildUdp(rig.client, 44000, rig.dnsVirtual, 53, DnsCodec.query(91, "x.blocked.test", 1)))
        val reply = rig.tun.next()!!
        assertEquals(rig.dnsVirtual, reply.src)
        assertEquals(53, reply.srcPort)
        assertEquals(44000, reply.dstPort)
        val m = DnsCodec.parse(reply.payload)!!
        assertEquals(91, m.id)
        assertEquals("x.blocked.test", m.name)
        assertEquals(3, u16(reply.payload, 2) and 0x000f)
        Thread.sleep(300)
        assertEquals(0, rig.upstreamQueries.get())
        rig.send(PacketCodec.buildUdp(rig.client, 44001, rig.dnsVirtual, 53, DnsCodec.query(92, "fine.test", 1)))
        assertEquals(listOf("127.0.0.1"), DnsCodec.parse(rig.tun.next()!!.payload)!!.answers)
        rig.stop()
        assertEquals(1, rig.upstreamQueries.get())
        val d = rig.dns()
        assertEquals(true, d.single { it["name"] == "x.blocked.test" }["blocked"])
        assertEquals(emptyList<Any?>(), d.single { it["name"] == "x.blocked.test" }["answers"])
        assertEquals(false, d.single { it["name"] == "fine.test" }["blocked"])
        assertTrue(rig.flows().none { it.suspicious && it.dnsName == "x.blocked.test" })
    }

    @Test
    fun packageAllowLetsTheQueryThrough() {
        rig.domains.put(DomainRule("com.test.app10123", "x.blocked.test", RuleAction.ALLOW))
        rig.send(PacketCodec.buildUdp(rig.client, 44002, rig.dnsVirtual, 53, DnsCodec.query(93, "x.blocked.test", 1)))
        assertEquals(listOf("127.0.0.1"), DnsCodec.parse(rig.tun.next()!!.payload)!!.answers)
        rig.stop()
        assertEquals(false, rig.dns().single()["blocked"])
    }
}
