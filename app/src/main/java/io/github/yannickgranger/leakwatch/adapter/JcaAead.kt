package io.github.yannickgranger.leakwatch.adapter

import java.security.GeneralSecurityException
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import io.github.yannickgranger.leakwatch.port.Aead

class JcaAead : Aead {
    private val algorithm: String = listOf("ChaCha20-Poly1305", "ChaCha20/Poly1305/NoPadding").first {
        runCatching { Cipher.getInstance(it) }.isSuccess
    }

    private fun cipher(mode: Int, key: ByteArray, nonce: ByteArray, aad: ByteArray): Cipher {
        val c = Cipher.getInstance(algorithm)
        c.init(mode, SecretKeySpec(key, "ChaCha20"), IvParameterSpec(nonce))
        if (aad.isNotEmpty()) c.updateAAD(aad)
        return c
    }

    override fun seal(key: ByteArray, nonce: ByteArray, plaintext: ByteArray, aad: ByteArray): ByteArray =
        cipher(Cipher.ENCRYPT_MODE, key, nonce, aad).doFinal(plaintext)

    override fun open(key: ByteArray, nonce: ByteArray, ciphertext: ByteArray, aad: ByteArray): ByteArray? = try {
        cipher(Cipher.DECRYPT_MODE, key, nonce, aad).doFinal(ciphertext)
    } catch (e: GeneralSecurityException) {
        null
    }
}
