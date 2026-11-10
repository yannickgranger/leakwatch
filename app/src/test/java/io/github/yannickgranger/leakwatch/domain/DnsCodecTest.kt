package io.github.yannickgranger.leakwatch.domain

import io.github.yannickgranger.leakwatch.domain.TestNet.hex
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class DnsCodecTest {
    private val cnameAndA = hex(
        "1234 8180 0001 0002 0000 0000" +
            "03777777 076578616d706c65 03636f6d 00 0001 0001" +
            "c00c 0005 0001 00000e10 0006 0363646e c010" +
            "c00c 0001 0001 00000e10 0004 5db8d70e",
    )

    @Test
    fun buildsAndParsesQuery() {
        val q = DnsCodec.query(0x4242, "example.com", 28)
        val m = DnsCodec.parse(q)!!
        assertEquals(0x4242, m.id)
        assertFalse(m.isResponse)
        assertEquals("example.com", m.name)
        assertEquals(28, m.qtype)
        assertTrue(m.answers.isEmpty())
    }

    @Test
    fun parsesResponseWithCompressionAndCname() {
        val m = DnsCodec.parse(cnameAndA)!!
        assertEquals(0x1234, m.id)
        assertTrue(m.isResponse)
        assertEquals("www.example.com", m.name)
        assertEquals(1, m.qtype)
        assertEquals(listOf("93.184.215.14"), m.answers)
    }

    @Test
    fun parsesAaaaAnswer() {
        val r = hex(
            "0001 8180 0001 0001 0000 0000" +
                "076578616d706c65 03636f6d 00 001c 0001" +
                "c00c 001c 0001 0000003c 0010 26062800021f cb07 682080daaf6b8b2c",
        )
        val m = DnsCodec.parse(r)!!
        assertEquals("AAAA", DnsCodec.typeName(m.qtype))
        assertEquals(listOf("2606:2800:21f:cb07:6820:80da:af6b:8b2c"), m.answers)
    }

    @Test
    fun namesQueryTypes() {
        assertEquals("A", DnsCodec.typeName(1))
        assertEquals("HTTPS", DnsCodec.typeName(65))
        assertEquals("TYPE999", DnsCodec.typeName(999))
    }

    @Test
    fun rejectsMalformedMessages() {
        assertNull(DnsCodec.parse(byteArrayOf(1, 2, 3)))
        assertNull(DnsCodec.parse(cnameAndA.copyOfRange(0, 20)))
        val loop = hex("0001 0100 0001 0000 0000 0000 c00c 0001 0001")
        assertNull(DnsCodec.parse(loop))
    }

    @Test
    fun nameMapExpiresAfterTtl() {
        val map = DnsNameMap(3_600_000)
        map.put("93.184.215.14", "example.com", 0)
        assertEquals("example.com", map.get("93.184.215.14", 3_599_999))
        assertNull(map.get("93.184.215.14", 3_600_001))
    }
}
