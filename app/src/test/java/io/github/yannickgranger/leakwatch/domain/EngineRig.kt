package io.github.yannickgranger.leakwatch.domain

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.nio.channels.DatagramChannel
import java.nio.channels.SocketChannel
import java.time.ZoneId
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import io.github.yannickgranger.leakwatch.port.AppDirectory
import io.github.yannickgranger.leakwatch.port.ArchiveStore
import io.github.yannickgranger.leakwatch.port.BlockStore
import io.github.yannickgranger.leakwatch.port.Clock
import io.github.yannickgranger.leakwatch.port.DomainRuleStore
import io.github.yannickgranger.leakwatch.port.PacketSink
import io.github.yannickgranger.leakwatch.port.PacketSource
import io.github.yannickgranger.leakwatch.port.SocketFactory
import org.junit.Assert.assertTrue

class MemoryTun : PacketSource, PacketSink {
    val toEngine = LinkedBlockingQueue<ByteArray>()
    val fromEngine = LinkedBlockingQueue<ByteArray>()
    override fun read(buffer: ByteArray): Int {
        val p = toEngine.poll() ?: return 0
        p.copyInto(buffer)
        return p.size
    }
    override fun write(packet: ByteArray) {
        assertTrue(TestNet.transportValid(packet))
        fromEngine.put(packet)
    }
    fun next(timeoutMs: Long = 3000): ParsedPacket? = fromEngine.poll(timeoutMs, TimeUnit.MILLISECONDS)?.let { PacketCodec.parse(it, it.size) }
}

class MemoryArchive : ArchiveStore {
    val files = mutableMapOf<String, StringBuilder>()
    @Synchronized override fun append(day: String, name: String, text: String) { files.getOrPut("$day/$name") { StringBuilder() }.append(text) }
    @Synchronized override fun write(day: String, name: String, text: String) { files["$day/$name"] = StringBuilder(text) }
    @Synchronized override fun read(day: String, name: String): String? = files["$day/$name"]?.toString()
    @Synchronized override fun days(): List<String> = files.keys.map { it.substringBefore('/') }.filter { it.isNotEmpty() }.distinct().sorted()
    @Synchronized override fun writeRoot(name: String, text: String) { files["/$name"] = StringBuilder(text) }
    @Synchronized override fun readRoot(name: String): String? = files["/$name"]?.toString()
    @Synchronized fun lines(name: String): List<String> = files.filterKeys { it.endsWith("/$name") }.values.flatMap { it.toString().lines() }.filter { it.isNotBlank() }
}

class MemoryRuleStore(var text: String? = null) : DomainRuleStore {
    override fun load(): String? = text
    override fun save(text: String) {
        this.text = text
    }
}

class EngineRig(defaults: List<String>) : AutoCloseable {
    val client: InetAddress = TestNet.ip("10.111.0.1")
    val dnsVirtual: InetAddress = TestNet.ip("10.111.0.2")
    val loopback: InetAddress = InetAddress.getLoopbackAddress()
    val tun = MemoryTun()
    val archive = MemoryArchive()
    val accepts = AtomicInteger()
    val upstreamQueries = AtomicInteger()
    @Volatile var uid = 10123
    val echoServer = ServerSocket(0, 50, loopback)
    private val resolver = DatagramSocket(0, loopback)
    val domains = DomainPolicy(MemoryRuleStore(), defaults.map { DomainRule(DomainRule.ALL, it, RuleAction.BLOCK) })
    private val engine: RelayEngine
    private val thread: Thread

    init {
        Thread {
            while (!echoServer.isClosed) {
                val s = runCatching { echoServer.accept() }.getOrNull() ?: break
                accepts.incrementAndGet()
                Thread { s.use { it.getInputStream().copyTo(it.getOutputStream()) } }.start()
            }
        }.start()
        Thread {
            val buf = ByteArray(2048)
            while (!resolver.isClosed) {
                val p = DatagramPacket(buf, buf.size)
                runCatching {
                    resolver.receive(p)
                    upstreamQueries.incrementAndGet()
                    val q = p.data.copyOf(p.length)
                    q[2] = 0x81.toByte(); q[3] = 0x80.toByte(); q[7] = 1
                    val answer = TestNet.hex("c00c 0001 0001 0000003c 0004 7f000001")
                    resolver.send(DatagramPacket(q + answer, q.size + answer.size, p.socketAddress))
                }
            }
        }.start()
        val sockets = object : SocketFactory {
            override fun tcp(): SocketChannel = SocketChannel.open()
            override fun udp(): DatagramChannel = DatagramChannel.open()
        }
        val apps = object : AppDirectory {
            override fun packagesForUid(uid: Int) = listOf("com.test.app$uid")
            override fun label(packageName: String) = "Test $packageName"
        }
        val store = object : BlockStore {
            override fun load(): Set<Int> = emptySet()
            override fun save(uids: Set<Int>) {}
        }
        val clock = object : Clock {
            override fun nowMillis() = System.currentTimeMillis()
            override fun zone(): ZoneId = ZoneId.systemDefault()
        }
        engine = RelayEngine(
            tun, tun, sockets, Attribution({ _, _, _ -> uid }, apps), BlockPolicy(store),
            TrackerMatcher(listOf("tracker.test")), ArchiveWriter(archive, clock), clock,
            EngineConfig(dnsVirtual, InetSocketAddress(loopback, resolver.localPort)),
            domains = domains,
        )
        thread = Thread { engine.run() }.apply { start() }
    }

    fun stop() {
        if (thread.isAlive) {
            engine.stop()
            thread.join(5000)
        }
    }

    override fun close() {
        stop()
        echoServer.close()
        resolver.close()
    }

    fun flows(): List<FlowRecord> = archive.lines("flows.jsonl").map { FlowRecord.fromJson(it) }

    fun dns(): List<Map<String, Any?>> = archive.lines("dns.jsonl").map { Json.parseObject(it) }

    fun send(p: ByteArray) = tun.toEngine.put(p)

    fun tcp(seq: Int, ack: Int, flags: Int, data: ByteArray = PacketCodec.EMPTY, srcPort: Int = 41000, dst: InetAddress = loopback, port: Int = echoServer.localPort) =
        send(PacketCodec.buildTcp(client, srcPort, dst, port, seq, ack, flags, 65535, data, 0, data.size, if (flags and TcpFlags.SYN != 0) 1460 else null))

    fun clientHello(): ByteArray =
        TestNet.hex(javaClass.classLoader!!.getResourceAsStream("clienthello_sni.hex")!!.readBytes().decodeToString().trim())
}
