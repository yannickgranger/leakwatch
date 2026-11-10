package io.github.yannickgranger.leakwatch.domain

import java.util.Base64
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test

class X25519Test {
    private fun h(s: String) = TestNet.hex(s)
    private fun b64(s: String): ByteArray = Base64.getDecoder().decode(s)

    @Test
    fun rfc7748FirstScalarMultVector() {
        val out = X25519.scalarMult(
            h("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"),
            h("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"),
        )
        assertArrayEquals(h("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"), out)
    }

    @Test
    fun rfc7748SecondScalarMultVectorIgnoresHighBitOfU() {
        val out = X25519.scalarMult(
            h("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d"),
            h("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493"),
        )
        assertArrayEquals(h("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"), out)
    }

    @Test
    fun rfc7748IteratedOnceAndThousandTimes() {
        var k = X25519.BASE.copyOf()
        var u = X25519.BASE.copyOf()
        for (i in 1..1000) {
            val r = X25519.scalarMult(k, u)
            u = k
            k = r
            if (i == 1) assertArrayEquals(h("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079"), k)
        }
        assertArrayEquals(h("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51"), k)
    }

    @Test
    fun rfc7748DiffieHellman() {
        val a = h("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        val b = h("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
        val aPub = X25519.publicKey(a)
        val bPub = X25519.publicKey(b)
        assertArrayEquals(h("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"), aPub)
        assertArrayEquals(h("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"), bPub)
        val shared = h("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
        assertArrayEquals(shared, X25519.scalarMult(a, bPub))
        assertArrayEquals(shared, X25519.scalarMult(b, aPub))
    }

    @Test
    fun publicKeysMatchWgPubkey() {
        assertEquals("FFRh+MowS1v6HjANRbTDG5BoVn1cAvH+K8A2Yfcv0go=", Base64.getEncoder().encodeToString(X25519.publicKey(b64(WgVectors.PRIV_1))))
        assertEquals("2YNHXsG6sz6gqNci04cVzYweDEWCXtqdSB3cbfoDZR0=", Base64.getEncoder().encodeToString(X25519.publicKey(b64(WgVectors.PRIV_2))))
    }

    @Test
    fun newPrivateIsClamped() {
        val k = X25519.newPrivate(java.util.Random(7))
        assertEquals(0, k[0].toInt() and 7)
        assertEquals(0x40, k[31].toInt() and 0xc0)
    }
}
