package io.github.yannickgranger.leakwatch.domain

import java.util.Random
import io.github.yannickgranger.leakwatch.port.Aead

object X25519 {
    val BASE: ByteArray = ByteArray(32).also { it[0] = 9 }
    private val A24 = longArrayOf(0xDB41, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)

    private fun gf() = LongArray(16)

    private fun carry(o: LongArray) {
        for (i in 0 until 16) {
            o[i] += 1L shl 16
            val c = o[i] shr 16
            if (i < 15) o[i + 1] += c - 1 else o[0] += 38 * (c - 1)
            o[i] -= c shl 16
        }
    }

    private fun select(p: LongArray, q: LongArray, b: Int) {
        val c = (b - 1).toLong().inv()
        for (i in 0 until 16) {
            val t = c and (p[i] xor q[i])
            p[i] = p[i] xor t
            q[i] = q[i] xor t
        }
    }

    private fun pack(n: LongArray): ByteArray {
        val m = gf()
        val t = n.copyOf()
        carry(t)
        carry(t)
        carry(t)
        for (j in 0 until 2) {
            m[0] = t[0] - 0xffed
            for (i in 1 until 15) {
                m[i] = t[i] - 0xffff - ((m[i - 1] shr 16) and 1)
                m[i - 1] = m[i - 1] and 0xffff
            }
            m[15] = t[15] - 0x7fff - ((m[14] shr 16) and 1)
            val b = ((m[15] shr 16) and 1).toInt()
            m[14] = m[14] and 0xffff
            select(t, m, 1 - b)
        }
        val o = ByteArray(32)
        for (i in 0 until 16) {
            o[2 * i] = (t[i] and 0xff).toByte()
            o[2 * i + 1] = (t[i] shr 8).toByte()
        }
        return o
    }

    private fun unpack(n: ByteArray): LongArray {
        val o = gf()
        for (i in 0 until 16) o[i] = (n[2 * i].toLong() and 0xff) + ((n[2 * i + 1].toLong() and 0xff) shl 8)
        o[15] = o[15] and 0x7fff
        return o
    }

    private fun add(o: LongArray, a: LongArray, b: LongArray) {
        for (i in 0 until 16) o[i] = a[i] + b[i]
    }

    private fun sub(o: LongArray, a: LongArray, b: LongArray) {
        for (i in 0 until 16) o[i] = a[i] - b[i]
    }

    private fun mul(o: LongArray, a: LongArray, b: LongArray) {
        val t = LongArray(31)
        for (i in 0 until 16) for (j in 0 until 16) t[i + j] += a[i] * b[j]
        for (i in 0 until 15) t[i] += 38 * t[i + 16]
        for (i in 0 until 16) o[i] = t[i]
        carry(o)
        carry(o)
    }

    private fun square(o: LongArray, a: LongArray) = mul(o, a, a)

    private fun invert(i: LongArray): LongArray {
        val c = i.copyOf()
        for (a in 253 downTo 0) {
            square(c, c)
            if (a != 2 && a != 4) mul(c, c, i)
        }
        return c
    }

    fun scalarMult(scalar: ByteArray, u: ByteArray): ByteArray {
        require(scalar.size == 32 && u.size == 32)
        val z = scalar.copyOf()
        z[31] = ((z[31].toInt() and 127) or 64).toByte()
        z[0] = (z[0].toInt() and 248).toByte()
        val x = unpack(u)
        val a = gf()
        val b = x.copyOf()
        val c = gf()
        val d = gf()
        val e = gf()
        val f = gf()
        a[0] = 1
        d[0] = 1
        for (i in 254 downTo 0) {
            val r = ((z[i ushr 3].toInt() and 0xff) ushr (i and 7)) and 1
            select(a, b, r)
            select(c, d, r)
            add(e, a, c)
            sub(a, a, c)
            add(c, b, d)
            sub(b, b, d)
            square(d, e)
            square(f, a)
            mul(a, c, a)
            mul(c, b, e)
            add(e, a, c)
            sub(a, a, c)
            square(b, a)
            sub(c, d, f)
            mul(a, c, A24)
            add(a, a, d)
            mul(c, c, a)
            mul(a, d, f)
            mul(d, b, x)
            square(b, e)
            select(a, b, r)
            select(c, d, r)
        }
        val inv = invert(c)
        mul(a, a, inv)
        return pack(a)
    }

    fun publicKey(privateKey: ByteArray): ByteArray = scalarMult(privateKey, BASE)

    fun newPrivate(random: Random): ByteArray {
        val k = ByteArray(32)
        random.nextBytes(k)
        k[0] = (k[0].toInt() and 248).toByte()
        k[31] = ((k[31].toInt() and 127) or 64).toByte()
        return k
    }
}

object Blake2s {
    private val IV = intArrayOf(
        0x6A09E667, 0xBB67AE85.toInt(), 0x3C6EF372, 0xA54FF53A.toInt(),
        0x510E527F, 0x9B05688C.toInt(), 0x1F83D9AB, 0x5BE0CD19,
    )
    private val SIGMA = arrayOf(
        intArrayOf(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15),
        intArrayOf(14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3),
        intArrayOf(11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4),
        intArrayOf(7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8),
        intArrayOf(9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13),
        intArrayOf(2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9),
        intArrayOf(12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11),
        intArrayOf(13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10),
        intArrayOf(6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5),
        intArrayOf(10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0),
    )

    private fun g(v: IntArray, a: Int, b: Int, c: Int, d: Int, x: Int, y: Int) {
        v[a] += v[b] + x
        v[d] = Integer.rotateRight(v[d] xor v[a], 16)
        v[c] += v[d]
        v[b] = Integer.rotateRight(v[b] xor v[c], 12)
        v[a] += v[b] + y
        v[d] = Integer.rotateRight(v[d] xor v[a], 8)
        v[c] += v[d]
        v[b] = Integer.rotateRight(v[b] xor v[c], 7)
    }

    private fun compress(h: IntArray, block: ByteArray, off: Int, counter: Long, last: Boolean) {
        val m = IntArray(16) { i ->
            val j = off + 4 * i
            (block[j].toInt() and 0xff) or ((block[j + 1].toInt() and 0xff) shl 8) or
                ((block[j + 2].toInt() and 0xff) shl 16) or ((block[j + 3].toInt() and 0xff) shl 24)
        }
        val v = IntArray(16)
        h.copyInto(v, 0)
        IV.copyInto(v, 8)
        v[12] = v[12] xor counter.toInt()
        v[13] = v[13] xor (counter ushr 32).toInt()
        if (last) v[14] = v[14].inv()
        for (s in SIGMA) {
            g(v, 0, 4, 8, 12, m[s[0]], m[s[1]])
            g(v, 1, 5, 9, 13, m[s[2]], m[s[3]])
            g(v, 2, 6, 10, 14, m[s[4]], m[s[5]])
            g(v, 3, 7, 11, 15, m[s[6]], m[s[7]])
            g(v, 0, 5, 10, 15, m[s[8]], m[s[9]])
            g(v, 1, 6, 11, 12, m[s[10]], m[s[11]])
            g(v, 2, 7, 8, 13, m[s[12]], m[s[13]])
            g(v, 3, 4, 9, 14, m[s[14]], m[s[15]])
        }
        for (i in 0 until 8) h[i] = h[i] xor v[i] xor v[i + 8]
    }

    fun hash(data: ByteArray, outLen: Int = 32, key: ByteArray = ByteArray(0)): ByteArray {
        require(outLen in 1..32 && key.size <= 32)
        val h = IV.copyOf()
        h[0] = h[0] xor 0x01010000 xor (key.size shl 8) xor outLen
        val input = if (key.isEmpty()) data else key.copyOf(64) + data
        if (input.isEmpty()) {
            compress(h, ByteArray(64), 0, 0, true)
        } else {
            val blocks = (input.size + 63) / 64
            for (i in 0 until blocks) {
                val last = i == blocks - 1
                val counter = if (last) input.size.toLong() else (i + 1) * 64L
                if (last && input.size % 64 != 0) {
                    compress(h, input.copyOfRange(i * 64, input.size).copyOf(64), 0, counter, true)
                } else {
                    compress(h, input, i * 64, counter, last)
                }
            }
        }
        val out = ByteArray(32)
        for (i in 0 until 8) for (j in 0 until 4) out[4 * i + j] = (h[i] ushr (8 * j)).toByte()
        return out.copyOf(outLen)
    }
}

object WgPrimitives {
    val CONSTRUCTION = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s".toByteArray()
    val IDENTIFIER = "WireGuard v1 zx2c4 Jason@zx2c4.com".toByteArray()
    val LABEL_MAC1 = "mac1----".toByteArray()
    val LABEL_COOKIE = "cookie--".toByteArray()
    private const val TAI64_LABEL = 0x400000000000000aL

    fun hash(vararg parts: ByteArray): ByteArray {
        var size = 0
        for (p in parts) size += p.size
        val all = ByteArray(size)
        var o = 0
        for (p in parts) {
            p.copyInto(all, o)
            o += p.size
        }
        return Blake2s.hash(all)
    }

    fun hmac(key: ByteArray, data: ByteArray): ByteArray {
        val k = if (key.size > 64) Blake2s.hash(key).copyOf(64) else key.copyOf(64)
        val inner = ByteArray(64) { (k[it].toInt() xor 0x36).toByte() }
        val outer = ByteArray(64) { (k[it].toInt() xor 0x5c).toByte() }
        return Blake2s.hash(outer + Blake2s.hash(inner + data))
    }

    fun mac(key: ByteArray, data: ByteArray): ByteArray = Blake2s.hash(data, 16, key)

    fun kdf(n: Int, key: ByteArray, input: ByteArray): List<ByteArray> {
        val t0 = hmac(key, input)
        val out = ArrayList<ByteArray>(n)
        var prev = ByteArray(0)
        for (i in 1..n) {
            prev = hmac(t0, prev + byteArrayOf(i.toByte()))
            out += prev
        }
        return out
    }

    fun nonce(counter: Long): ByteArray {
        val n = ByteArray(12)
        for (i in 0 until 8) n[4 + i] = (counter ushr (8 * i)).toByte()
        return n
    }

    fun tai64n(epochMs: Long): ByteArray {
        val secs = Math.floorDiv(epochMs, 1000L) + TAI64_LABEL
        val nanos = (Math.floorMod(epochMs, 1000L) * 1_000_000L).toInt()
        val out = ByteArray(12)
        for (i in 0 until 8) out[i] = (secs ushr (56 - 8 * i)).toByte()
        for (i in 0 until 4) out[8 + i] = (nanos ushr (24 - 8 * i)).toByte()
        return out
    }

    private fun le(b: ByteArray, o: Int) =
        (b[o].toInt() and 0xff) or ((b[o + 1].toInt() and 0xff) shl 8) or ((b[o + 2].toInt() and 0xff) shl 16) or ((b[o + 3].toInt() and 0xff) shl 24)

    private fun quarter(x: IntArray, a: Int, b: Int, c: Int, d: Int) {
        x[a] += x[b]
        x[d] = Integer.rotateLeft(x[d] xor x[a], 16)
        x[c] += x[d]
        x[b] = Integer.rotateLeft(x[b] xor x[c], 12)
        x[a] += x[b]
        x[d] = Integer.rotateLeft(x[d] xor x[a], 8)
        x[c] += x[d]
        x[b] = Integer.rotateLeft(x[b] xor x[c], 7)
    }

    fun hchacha20(key: ByteArray, nonce: ByteArray): ByteArray {
        require(key.size == 32 && nonce.size == 16)
        val x = IntArray(16)
        x[0] = 0x61707865
        x[1] = 0x3320646e
        x[2] = 0x79622d32
        x[3] = 0x6b206574
        for (i in 0 until 8) x[4 + i] = le(key, 4 * i)
        for (i in 0 until 4) x[12 + i] = le(nonce, 4 * i)
        repeat(10) {
            quarter(x, 0, 4, 8, 12)
            quarter(x, 1, 5, 9, 13)
            quarter(x, 2, 6, 10, 14)
            quarter(x, 3, 7, 11, 15)
            quarter(x, 0, 5, 10, 15)
            quarter(x, 1, 6, 11, 12)
            quarter(x, 2, 7, 8, 13)
            quarter(x, 3, 4, 9, 14)
        }
        val out = ByteArray(32)
        val words = intArrayOf(x[0], x[1], x[2], x[3], x[12], x[13], x[14], x[15])
        for (i in 0 until 8) for (j in 0 until 4) out[4 * i + j] = (words[i] ushr (8 * j)).toByte()
        return out
    }

    private fun xnonce(nonce: ByteArray): ByteArray = ByteArray(4) + nonce.copyOfRange(16, 24)

    fun xseal(aead: Aead, key: ByteArray, nonce: ByteArray, plaintext: ByteArray, aad: ByteArray): ByteArray =
        aead.seal(hchacha20(key, nonce.copyOfRange(0, 16)), xnonce(nonce), plaintext, aad)

    fun xopen(aead: Aead, key: ByteArray, nonce: ByteArray, ciphertext: ByteArray, aad: ByteArray): ByteArray? =
        aead.open(hchacha20(key, nonce.copyOfRange(0, 16)), xnonce(nonce), ciphertext, aad)
}

class ReplayWindow {
    private val bits = LongArray((SIZE / 64).toInt())
    private var greatest = -1L

    private fun index(c: Long) = (c % SIZE).toInt()
    private fun isSet(c: Long): Boolean = bits[index(c) ushr 6] and (1L shl (index(c) and 63)) != 0L

    private fun set(c: Long) {
        bits[index(c) ushr 6] = bits[index(c) ushr 6] or (1L shl (index(c) and 63))
    }

    private fun clear(c: Long) {
        bits[index(c) ushr 6] = bits[index(c) ushr 6] and (1L shl (index(c) and 63)).inv()
    }

    fun check(counter: Long): Boolean {
        if (counter < 0 || counter >= REJECT_AFTER_MESSAGES) return false
        if (counter > greatest) return true
        if (greatest - counter >= SIZE) return false
        return !isSet(counter)
    }

    fun accept(counter: Long): Boolean {
        if (!check(counter)) return false
        if (counter > greatest) {
            if (counter - greatest >= SIZE) {
                bits.fill(0)
            } else {
                var c = greatest + 1
                while (c <= counter) clear(c++)
            }
            greatest = counter
        }
        set(counter)
        return true
    }

    companion object {
        const val SIZE = 2048L
        const val REJECT_AFTER_MESSAGES = Long.MAX_VALUE - 8192
    }
}
