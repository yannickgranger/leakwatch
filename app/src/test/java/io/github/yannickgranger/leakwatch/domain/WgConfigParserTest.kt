package io.github.yannickgranger.leakwatch.domain

import java.io.ByteArrayOutputStream
import java.util.Base64
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class WgConfigParserTest {
    private val sample = """
        [Interface]
        PrivateKey = ${WgVectors.PRIV_1}
        Address = 10.200.0.3/32
        DNS = 10.200.0.1
        MTU = 1380

        [Peer]
        PublicKey = ${WgVectors.PUB_2}
        PresharedKey = ${WgVectors.PSK}
        Endpoint = 203.0.113.10:51820
        AllowedIPs = 10.200.0.0/24
        PersistentKeepalive = 25
    """.trimIndent()

    private fun ok(text: String, name: String? = null): WgConfig {
        val r = WgConfigParser.parse(text, name)
        assertTrue(r.toString(), r is WgParse.Ok)
        return (r as WgParse.Ok).config
    }

    private fun zip(vararg entries: Pair<String, String>): ByteArray {
        val bytes = ByteArrayOutputStream()
        ZipOutputStream(bytes).use { z ->
            for ((n, t) in entries) {
                z.putNextEntry(ZipEntry(n))
                z.write(t.toByteArray())
                z.closeEntry()
            }
        }
        return bytes.toByteArray()
    }

    @Test
    fun parsesTheSampleConf() {
        val c = ok(sample, "home")
        assertEquals("home", c.name)
        assertArrayEquals(Base64.getDecoder().decode(WgVectors.PRIV_1), c.privateKey)
        assertEquals(listOf(Cidr.parse("10.200.0.3/32")), c.addresses)
        assertEquals(listOf("10.200.0.1"), c.dns)
        assertEquals(1380, c.mtu)
        assertArrayEquals(Base64.getDecoder().decode(WgVectors.PUB_2), c.peerPublicKey)
        assertArrayEquals(Base64.getDecoder().decode(WgVectors.PSK), c.presharedKey)
        assertEquals("203.0.113.10", c.endpointHost)
        assertEquals(51820, c.endpointPort)
        assertEquals(listOf(Cidr.parse("10.200.0.0/24")), c.allowedIps)
        assertEquals(25, c.keepalive)
    }

    @Test
    fun acceptsCommentsCaseAndListsWithoutOptionalKeys() {
        val c = ok(
            """
            # exported
            [interface]
            privatekey=${WgVectors.PRIV_1}
            address = 10.200.0.3/24, fd00:200::3/64

            [Peer]
            PublicKey = ${WgVectors.PUB_2}
            AllowedIPs = 10.200.0.0/24,fd00:200::/64
            Endpoint = [2001:db8::1]:51820
            """.trimIndent(),
        )
        assertEquals(2, c.addresses.size)
        assertEquals(2, c.allowedIps.size)
        assertNull(c.presharedKey)
        assertNull(c.mtu)
        assertEquals(0, c.keepalive)
        assertEquals("2001:db8::1", c.endpointHost)
    }

    @Test
    fun refusesFullTunnelWithOnePlainSentence() {
        for (all in listOf("0.0.0.0/0", "::/0", "10.200.0.0/24, 0.0.0.0/0")) {
            val r = WgConfigParser.parse(sample.replace("AllowedIPs = 10.200.0.0/24", "AllowedIPs = $all"))
            assertTrue(all, r is WgParse.Refused)
            assertEquals(WgConfigParser.FULL_TUNNEL, (r as WgParse.Refused).message)
        }
        assertEquals(1, WgConfigParser.FULL_TUNNEL.count { it == '.' })
    }

    @Test
    fun refusesMissingKeysOrEndpoint() {
        assertTrue(WgConfigParser.parse(sample.lines().filterNot { it.startsWith("PrivateKey") }.joinToString("\n")) is WgParse.Refused)
        assertTrue(WgConfigParser.parse(sample.lines().filterNot { it.startsWith("Endpoint") }.joinToString("\n")) is WgParse.Refused)
        assertTrue(WgConfigParser.parse(sample.replace(WgVectors.PUB_2, "short")) is WgParse.Refused)
        assertTrue(WgConfigParser.parse("not a config") is WgParse.Refused)
    }

    @Test
    fun readsZipWithTwoTunnels() {
        val other = sample.replace("10.200.0.3/32", "10.88.0.5/32")
        val tunnels = WgConfigParser.tunnels("wireguard-export.zip", zip("home.conf" to sample, "office.conf" to other, "readme.txt" to "x"))
        assertEquals(listOf("home", "office"), tunnels.map { it.first })
        assertEquals(listOf(Cidr.parse("10.88.0.5/32")), ok(tunnels[1].second, tunnels[1].first).addresses)
    }

    @Test
    fun readsSingleConf() {
        val tunnels = WgConfigParser.tunnels("home.conf", sample.toByteArray())
        assertEquals(listOf("home"), tunnels.map { it.first })
    }

    @Test
    fun privateAndPresharedKeysAbsentFromToString() {
        val text = ok(sample, "home").toString()
        assertFalse(text.contains(WgVectors.PRIV_1))
        assertFalse(text.contains(WgVectors.PSK))
        assertFalse(text.contains(WgVectors.PRIV_1.substring(0, 8)))
        assertTrue(text.contains("10.200.0.0/24"))
    }
}
