package io.github.yannickgranger.leakwatch.adapter

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import io.github.yannickgranger.leakwatch.port.WgConfigStore

class KeystoreWgConfigStore(context: Context) : WgConfigStore {
    private val file = File(context.noBackupFilesDir, "wireguard-link.bin")

    private fun keyStore(): KeyStore = KeyStore.getInstance(PROVIDER).apply { load(null) }

    private fun key(create: Boolean): SecretKey? {
        (keyStore().getKey(ALIAS, null) as? SecretKey)?.let { return it }
        if (!create) return null
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, PROVIDER)
        generator.init(
            KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build(),
        )
        return generator.generateKey()
    }

    @Synchronized
    override fun load(): String? {
        if (!file.isFile) return null
        return runCatching {
            val bytes = file.readBytes()
            val ivLen = bytes[0].toInt()
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, key(false) ?: return null, GCMParameterSpec(128, bytes, 1, ivLen))
            cipher.doFinal(bytes, 1 + ivLen, bytes.size - 1 - ivLen).toString(Charsets.UTF_8)
        }.getOrNull()
    }

    @Synchronized
    override fun save(text: String) {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, key(true))
        val iv = cipher.iv
        val sealed = cipher.doFinal(text.toByteArray(Charsets.UTF_8))
        val tmp = File(file.parentFile, file.name + ".tmp")
        tmp.writeBytes(byteArrayOf(iv.size.toByte()) + iv + sealed)
        if (!tmp.renameTo(file)) {
            file.writeBytes(tmp.readBytes())
            tmp.delete()
        }
    }

    @Synchronized
    override fun clear() {
        file.delete()
        runCatching { keyStore().deleteEntry(ALIAS) }
    }

    private companion object {
        const val PROVIDER = "AndroidKeyStore"
        const val ALIAS = "leakwatch-wireguard-link"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
    }
}
