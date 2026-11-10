package io.github.yannickgranger.leakwatch.domain

import org.junit.Assert.assertEquals
import org.junit.Test

class TlsSniTest {
    private fun resource(name: String): ByteArray =
        TestNet.hex(javaClass.classLoader!!.getResourceAsStream(name)!!.readBytes().decodeToString().trim())

    @Test
    fun extractsSniFromRealClientHello() {
        assertEquals(TlsParse.Done("example.com"), TlsSni.parse(resource("clienthello_sni.hex")))
    }

    @Test
    fun clientHelloWithoutSniGivesNull() {
        assertEquals(TlsParse.Done(null), TlsSni.parse(resource("clienthello_nosni.hex")))
    }

    @Test
    fun truncatedHelloIsIncomplete() {
        val b = resource("clienthello_sni.hex")
        assertEquals(TlsParse.Incomplete, TlsSni.parse(b, 200))
        assertEquals(TlsParse.Incomplete, TlsSni.parse(b, 3))
    }

    @Test
    fun otherBytesAreNotTls() {
        assertEquals(TlsParse.NotTls, TlsSni.parse("GET / HTTP/1.1\r\n".toByteArray()))
        assertEquals(TlsParse.NotTls, TlsSni.parse(byteArrayOf(0x17, 3, 3, 0, 5, 1, 2, 3, 4, 5)))
    }
}
