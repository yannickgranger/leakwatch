package io.github.yannickgranger.leakwatch.domain

import org.junit.Assert.assertArrayEquals
import org.junit.Test

class Blake2sTest {
    private fun h(s: String) = TestNet.hex(s)
    private val key = ByteArray(32) { it.toByte() }

    @Test
    fun rfc7693AbcVector() {
        assertArrayEquals(h("508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982"), Blake2s.hash("abc".toByteArray()))
    }

    @Test
    fun keyedEmptyInput() {
        assertArrayEquals(h("48a8997da407876b3d79c0d92325ad3b89cbb754d86ab71aee047ad345fd2c49"), Blake2s.hash(ByteArray(0), key = key))
    }

    @Test
    fun keyedOneByte() {
        assertArrayEquals(h("40d15fee7c328830166ac3f918650f807e7e01e177258cdc0a39b11f598066f1"), Blake2s.hash(byteArrayOf(0), key = key))
    }

    @Test
    fun keyedExactlyOneBlock() {
        assertArrayEquals(h("8975b0577fd35566d750b362b0897a26c399136df07bababbde6203ff2954ed4"), Blake2s.hash(ByteArray(64) { it.toByte() }, key = key))
    }

    @Test
    fun keyedSeveralBlocks() {
        assertArrayEquals(h("3fb735061abc519dfe979e54c1ee5bfad0a9d858b3315bad34bde999efd724dd"), Blake2s.hash(ByteArray(255) { it.toByte() }, key = key))
    }

    @Test
    fun shortOutputWithShortKey() {
        assertArrayEquals(h("da5b50d8f2073c6d2bc49dc3f556bde3"), Blake2s.hash("abc".toByteArray(), 16, ByteArray(32) { 'k'.code.toByte() }))
    }
}
