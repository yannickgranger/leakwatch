package io.github.yannickgranger.leakwatch.domain

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class StartTlsTest {
    private val hello = TestNet.hex(javaClass.classLoader!!.getResourceAsStream("clienthello_sni.hex")!!.readBytes().decodeToString().trim())

    private fun inspect(vararg parts: ByteArray): Inspection {
        val i = PayloadInspector()
        parts.forEach { i.offer(it) }
        return i.finish()
    }

    @Test
    fun imapTaggedStartTlsThenHelloIsTls() {
        val r = inspect("a1 STARTTLS\r\n".toByteArray(), hello)
        assertFalse(r.cleartext)
        assertEquals("example.com", r.sni)
        assertNull(r.dump)
    }

    @Test
    fun smtpStartTlsWithoutTagIsTls() {
        val r = inspect("STARTTLS\r\n".toByteArray() + hello)
        assertFalse(r.cleartext)
        assertEquals("example.com", r.sni)
    }

    @Test
    fun pop3StlsIsTlsAndCaseDoesNotMatter() {
        assertFalse(inspect("stls\r\n".toByteArray(), hello).cleartext)
        assertFalse(inspect("A0001 starttls\n".toByteArray(), hello).cleartext)
    }

    @Test
    fun commandSeenBeforeTheHelloArrivesIsNotCleartext() {
        assertFalse(inspect("a1 STARTTLS\r\n".toByteArray()).cleartext)
        val i = PayloadInspector()
        i.offer("a1 STARTTLS\r\n".toByteArray())
        assertFalse(i.current().cleartext)
        i.offer(hello)
        assertEquals("example.com", i.finish().sni)
    }

    @Test
    fun otherMailCommandsStayCleartext() {
        assertTrue(inspect("a1 LOGIN user secret\r\n".toByteArray()).cleartext)
        assertTrue(inspect("STARTTLS\r\nEHLO plain\r\n".toByteArray()).cleartext)
    }
}
