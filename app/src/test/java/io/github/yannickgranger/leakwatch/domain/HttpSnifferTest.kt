package io.github.yannickgranger.leakwatch.domain

import java.util.Base64
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class HttpSnifferTest {
    @Test
    fun parsesGetRequest() {
        val raw = "GET /online?x=1 HTTP/1.1\r\nHost: neverssl.com\r\nUser-Agent: Test\r\nAccept: text/html\r\n\r\n".toByteArray()
        val r = HttpSniffer.parse(raw) as HttpParse.Request
        assertEquals("GET", r.method)
        assertEquals("/online?x=1", r.path)
        assertEquals("neverssl.com", r.host)
        assertEquals(listOf("Host" to "neverssl.com", "User-Agent" to "Test", "Accept" to "text/html"), r.headers)
        assertTrue(r.complete)
    }

    @Test
    fun capturesPostBodyByContentLength() {
        val head = "POST /collect HTTP/1.1\r\nHost: tracker.example:8080\r\nContent-Length: 11\r\n\r\n"
        val partial = HttpSniffer.parse((head + "id=4").toByteArray()) as HttpParse.Request
        assertTrue(!partial.complete)
        val r = HttpSniffer.parse((head + "id=42&gps=1").toByteArray()) as HttpParse.Request
        assertTrue(r.complete)
        assertEquals("tracker.example", r.host)
        assertEquals("id=42&gps=1", r.body.decodeToString())
        val dump = HttpSniffer.dump(r)
        assertTrue(dump.contains("POST /collect HTTP/1.1"))
        assertTrue(dump.contains("Content-Length: 11"))
        assertTrue(dump.endsWith("id=42&gps=1"))
    }

    @Test
    fun incompleteHeadersAndNonHttp() {
        assertEquals(HttpParse.Incomplete, HttpSniffer.parse("GET / HTTP/1.1\r\nHost: a".toByteArray()))
        assertEquals(HttpParse.Incomplete, HttpSniffer.parse("GE".toByteArray()))
        assertEquals(HttpParse.NotHttp, HttpSniffer.parse("SSH-2.0-OpenSSH\r\n".toByteArray()))
        assertEquals(HttpParse.NotHttp, HttpSniffer.parse(byteArrayOf(0x16, 3, 1)))
    }

    @Test
    fun inspectorDumpsHttpRequest() {
        val i = PayloadInspector()
        assertTrue(!i.offer("GET / HTTP/1.1\r\nHo".toByteArray()))
        assertTrue(i.offer("st: neverssl.com\r\n\r\n".toByteArray()))
        val r = i.finish()
        assertEquals("neverssl.com", r.httpHost)
        assertNull(r.sni)
        assertTrue(r.dump!!.startsWith("GET / HTTP/1.1"))
    }

    @Test
    fun inspectorBase64DumpsFirst4kOfUnknownPayload() {
        val i = PayloadInspector()
        val data = ByteArray(5000) { (it * 31).toByte() }
        assertTrue(i.offer(data))
        val r = i.finish()
        assertNull(r.httpHost)
        assertEquals(Base64.getEncoder().encodeToString(data.copyOfRange(0, 4096)), r.dump!!.trim())
    }

    @Test
    fun inspectorExtractsSniWithoutDump() {
        val hello = TestNet.hex(javaClass.classLoader!!.getResourceAsStream("clienthello_sni.hex")!!.readBytes().decodeToString().trim())
        val i = PayloadInspector()
        assertTrue(!i.offer(hello.copyOfRange(0, 700)))
        assertTrue(i.offer(hello.copyOfRange(700, hello.size)))
        val r = i.finish()
        assertEquals("example.com", r.sni)
        assertNull(r.dump)
    }

    @Test
    fun inspectorFinishesPartialPayloadOnClose() {
        val i = PayloadInspector()
        i.offer(byteArrayOf(1, 2, 3))
        val r = i.finish()
        assertEquals(Base64.getEncoder().encodeToString(byteArrayOf(1, 2, 3)), r.dump!!.trim())
    }
}
