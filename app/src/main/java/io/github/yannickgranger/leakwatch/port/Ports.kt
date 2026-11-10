package io.github.yannickgranger.leakwatch.port

import java.net.InetSocketAddress
import java.nio.channels.DatagramChannel
import java.nio.channels.SocketChannel
import java.time.ZoneId

fun interface PacketSink {
    fun write(packet: ByteArray)
}

fun interface PacketSource {
    fun read(buffer: ByteArray): Int
}

interface SocketFactory {
    fun tcp(): SocketChannel
    fun udp(): DatagramChannel
}

fun interface OwnerResolver {
    fun ownerUid(protocol: Int, local: InetSocketAddress, remote: InetSocketAddress): Int
}

interface AppDirectory {
    fun packagesForUid(uid: Int): List<String>
    fun label(packageName: String): String
    fun isSystem(packageName: String): Boolean = false
}

interface ArchiveStore {
    fun append(day: String, name: String, text: String)
    fun write(day: String, name: String, text: String)
    fun read(day: String, name: String): String?
    fun days(): List<String>
    fun writeRoot(name: String, text: String)
    fun readRoot(name: String): String?
}

interface BlockStore {
    fun load(): Set<Int>
    fun save(uids: Set<Int>)
}

interface DomainRuleStore {
    fun load(): String?
    fun save(text: String)
}

interface Clock {
    fun nowMillis(): Long
    fun zone(): ZoneId
}

enum class UsageEventKind { RESUMED, PAUSED, SCREEN_ON, SCREEN_OFF }

data class UsageEvent(val ts: Long, val packageName: String?, val kind: UsageEventKind)

interface UsageSource {
    fun hasAccess(): Boolean
    fun events(fromMs: Long, toMs: Long): List<UsageEvent>
}

interface Aead {
    fun seal(key: ByteArray, nonce: ByteArray, plaintext: ByteArray, aad: ByteArray): ByteArray
    fun open(key: ByteArray, nonce: ByteArray, ciphertext: ByteArray, aad: ByteArray): ByteArray?
}

interface WgConfigStore {
    fun load(): String?
    fun save(text: String)
    fun clear()
}
