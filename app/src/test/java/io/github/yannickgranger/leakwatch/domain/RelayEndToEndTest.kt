package io.github.yannickgranger.leakwatch.domain

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.nio.channels.DatagramChannel
import java.nio.channels.SocketChannel
import java.time.ZoneId
import java.util.concurrent.atomic.AtomicInteger
import kotlin.random.Random
import io.github.yannickgranger.leakwatch.domain.TestNet.ip
import io.github.yannickgranger.leakwatch.port.AppDirectory
import io.github.yannickgranger.leakwatch.port.BlockStore
import io.github.yannickgranger.leakwatch.port.Clock
import io.github.yannickgranger.leakwatch.port.SocketFactory
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class RelayEndToEndTest {
    private val client = ip("10.111.0.1")
    private val dnsVirtual = ip("10.111.0.2")
    private val loopback = InetAddress.getLoopbackAddress()
    private val tun = MemoryTun()
    private val archive = MemoryArchive()
    private val blockedUids = mutableSetOf<Int>()
    @Volatile private var uid = 10123
    private val accepts = AtomicInteger()
    private lateinit var echoServer: ServerSocket
    private lateinit var udpEcho: DatagramSocket
    private lateinit var resolver: DatagramSocket
    private lateinit var engine: RelayEngine
    private lateinit var policy: BlockPolicy
    private lateinit var thread: Thread
    private lateinit var wgServer: DatagramSocket
    private val wgAead = io.github.yannickgranger.leakwatch.adapter.JcaAead()
    private val wgServerPrivate = X25519.newPrivate(java.util.Random(21))
    private val wgClientPrivate = X25519.newPrivate(java.util.Random(22))
    private val wgHub = ip("10.200.0.1")
    private val wgPhone = ip("10.200.0.3")
    private val banner = "SSH-2.0-test\r\n".toByteArray()

    private fun startWgServer() {
        wgServer = DatagramSocket(0, loopback)
        val responder = WgResponder(wgServerPrivate, ByteArray(32), wgAead)
        Thread {
            val buf = ByteArray(4096)
            var serverSeq = 5000
            while (!wgServer.isClosed) {
                val p = DatagramPacket(buf, buf.size)
                runCatching {
                    wgServer.receive(p)
                    val msg = p.data.copyOf(p.length)
                    fun reply(inner: ByteArray) {
                        val sealed = responder.session!!.seal(wgAead, inner)
                        wgServer.send(DatagramPacket(sealed, sealed.size, p.socketAddress))
                    }
                    when (msg[0].toInt()) {
                        1 -> if (responder.consumeInitiation(msg)) {
                            val r = responder.response(77, X25519.newPrivate(java.util.Random(23)), System.currentTimeMillis())
                            wgServer.send(DatagramPacket(r, r.size, p.socketAddress))
                        }
                        4 -> {
                            val inner = responder.session!!.open(wgAead, msg) ?: return@runCatching
                            if (inner.isEmpty()) return@runCatching
                            val q = PacketCodec.parse(inner, inner.size) ?: return@runCatching
                            assertEquals(wgPhone, q.src)
                            val t = q.tcp ?: return@runCatching
                            if (t.has(TcpFlags.SYN)) {
                                reply(PacketCodec.buildTcp(wgHub, 22, wgPhone, q.srcPort, serverSeq, t.seq + 1, TcpFlags.SYN or TcpFlags.ACK, 65535, mss = 1380))
                                serverSeq++
                                reply(PacketCodec.buildTcp(wgHub, 22, wgPhone, q.srcPort, serverSeq, t.seq + 1, TcpFlags.ACK or TcpFlags.PSH, 65535, banner))
                                serverSeq += banner.size
                            } else if (t.has(TcpFlags.FIN)) {
                                reply(PacketCodec.buildTcp(wgHub, 22, wgPhone, q.srcPort, serverSeq, t.seq + q.payload.size + 1, TcpFlags.FIN or TcpFlags.ACK, 65535))
                            }
                        }
                    }
                }
            }
        }.start()
    }

    @Before
    fun start() {
        echoServer = ServerSocket(0, 50, loopback)
        Thread {
            while (!echoServer.isClosed) {
                val s = runCatching { echoServer.accept() }.getOrNull() ?: break
                accepts.incrementAndGet()
                Thread { s.use { it.getInputStream().copyTo(it.getOutputStream()) } }.start()
            }
        }.start()
        udpEcho = DatagramSocket(0, loopback)
        Thread {
            val buf = ByteArray(2048)
            while (!udpEcho.isClosed) {
                val p = DatagramPacket(buf, buf.size)
                runCatching { udpEcho.receive(p); udpEcho.send(DatagramPacket(p.data, p.length, p.socketAddress)) }
            }
        }.start()
        resolver = DatagramSocket(0, loopback)
        Thread {
            val buf = ByteArray(2048)
            while (!resolver.isClosed) {
                val p = DatagramPacket(buf, buf.size)
                runCatching {
                    resolver.receive(p)
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
            override fun load(): Set<Int> = blockedUids
            override fun save(uids: Set<Int>) {}
        }
        val clock = object : Clock {
            override fun nowMillis() = System.currentTimeMillis()
            override fun zone(): ZoneId = ZoneId.systemDefault()
        }
        policy = BlockPolicy(store)
        startWgServer()
        val link = WgLink(
            TunnelRouting(listOf(Cidr.parse("10.200.0.0/24")), listOf(Cidr.parse("10.200.0.3/32")), 1420),
            WgPeer(WgPeerSettings(wgClientPrivate, X25519.publicKey(wgServerPrivate), null, 0), wgAead, java.util.Random(24)),
            InetSocketAddress(loopback, wgServer.localPort),
        )
        engine = RelayEngine(
            tun, tun, sockets, Attribution({ _, _, _ -> uid }, apps), policy,
            TrackerMatcher(listOf("tracker.test")), ArchiveWriter(archive, clock), clock,
            EngineConfig(dnsVirtual, InetSocketAddress(loopback, resolver.localPort)),
            tunnel = link,
        )
        thread = Thread { engine.run() }.apply { start() }
    }

    @After
    fun close() {
        stopEngine()
        echoServer.close()
        udpEcho.close()
        resolver.close()
        wgServer.close()
    }

    @Test
    fun tunnelledFlowBypassesRelayAndIsArchivedViaWireguard() {
        tcp(22, 700, 0, TcpFlags.SYN, dst = wgHub, srcPort = 42000)
        val synAck = tun.next(5000)!!
        assertEquals(wgHub, synAck.src)
        assertEquals(client, synAck.dst)
        assertTrue(synAck.tcp!!.has(TcpFlags.SYN) && synAck.tcp!!.has(TcpFlags.ACK))
        assertEquals(701, synAck.tcp!!.ack)
        val data = tun.next(5000)!!
        assertArrayEquals(banner, data.payload)
        tcp(22, 701, data.tcp!!.seq + banner.size, TcpFlags.ACK, dst = wgHub, srcPort = 42000)
        tcp(22, 701, data.tcp!!.seq + banner.size, TcpFlags.FIN or TcpFlags.ACK, dst = wgHub, srcPort = 42000)
        val fin = tun.next(5000)!!
        assertTrue(fin.tcp!!.has(TcpFlags.FIN))
        tcp(22, 702, fin.tcp!!.seq + 1, TcpFlags.ACK, dst = wgHub, srcPort = 42000)
        Thread.sleep(300)
        stopEngine()
        val f = flows().single { it.dst == "10.200.0.1:22" }
        assertEquals("wireguard", f.via)
        assertEquals(banner.size.toLong(), f.bytesIn)
        assertEquals(0L, f.bytesOut)
        assertEquals("fin", f.closeReason)
        assertEquals(false, f.tracker)
        assertEquals(10123, f.uid)
        assertEquals(0, accepts.get())
        assertTrue(flows().filter { it.dst != "10.200.0.1:22" }.all { it.via == "direct" })
    }

    private fun stopEngine() {
        if (thread.isAlive) {
            engine.stop()
            thread.join(5000)
        }
    }

    private fun flows(): List<FlowRecord> = archive.lines("flows.jsonl").map { FlowRecord.fromJson(it) }

    private fun send(p: ByteArray) = tun.toEngine.put(p)

    private fun tcp(port: Int, seq: Int, ack: Int, flags: Int, data: ByteArray = PacketCodec.EMPTY, off: Int = 0, len: Int = data.size, srcPort: Int = 41000, dst: InetAddress = loopback) =
        send(PacketCodec.buildTcp(client, srcPort, dst, port, seq, ack, flags, 65535, data, off, len, if (flags and TcpFlags.SYN != 0) 1460 else null))

    @Test
    fun relaysHundredKilobytesThroughTcpEchoAndArchivesFlow() {
        val port = echoServer.localPort
        val isn = 1000
        tcp(port, isn, 0, TcpFlags.SYN)
        val synAck = tun.next()!!
        assertTrue(synAck.tcp!!.has(TcpFlags.SYN) && synAck.tcp!!.has(TcpFlags.ACK))
        assertEquals(isn + 1, synAck.tcp!!.ack)
        var rcvNxt = synAck.tcp!!.seq + 1
        tcp(port, isn + 1, rcvNxt, TcpFlags.ACK)

        val total = 102_400
        val data = Random(7).nextBytes(total)
        val received = java.io.ByteArrayOutputStream()
        var acked = 0
        var sent = 0
        var window = synAck.tcp!!.window
        var lastProgress = System.currentTimeMillis()
        val deadline = System.currentTimeMillis() + 30_000
        while (received.size() < total && System.currentTimeMillis() < deadline) {
            while (sent < total && sent - acked < window) {
                val n = minOf(1400, total - sent, window - (sent - acked))
                tcp(port, isn + 1 + sent, rcvNxt, TcpFlags.ACK or TcpFlags.PSH, data, sent, n)
                sent += n
            }
            val p = tun.next(100)
            if (p == null) {
                if (System.currentTimeMillis() - lastProgress > 500) { sent = acked; lastProgress = System.currentTimeMillis() }
                continue
            }
            val t = p.tcp!!
            val a = t.ack - (isn + 1)
            if (a > acked) { acked = a; lastProgress = System.currentTimeMillis() }
            window = t.window
            if (p.payload.isNotEmpty()) {
                if (t.seq == rcvNxt) { received.write(p.payload); rcvNxt += p.payload.size; lastProgress = System.currentTimeMillis() }
                tcp(port, isn + 1 + sent, rcvNxt, TcpFlags.ACK)
            }
        }
        assertArrayEquals(data, received.toByteArray())

        tcp(port, isn + 1 + total, rcvNxt, TcpFlags.ACK or TcpFlags.FIN)
        var finSeen = false
        val finDeadline = System.currentTimeMillis() + 5000
        while (!finSeen && System.currentTimeMillis() < finDeadline) {
            val p = tun.next(200) ?: continue
            if (p.tcp!!.has(TcpFlags.FIN)) {
                finSeen = true
                tcp(port, isn + 2 + total, p.tcp!!.seq + 1, TcpFlags.ACK)
            }
        }
        assertTrue(finSeen)
        Thread.sleep(300)
        stopEngine()
        val f = flows().single { it.proto == "tcp" && it.dst.endsWith(":$port") }
        assertEquals(102_400L, f.bytesOut)
        assertEquals(102_400L, f.bytesIn)
        assertEquals("fin", f.closeReason)
        assertEquals(10123, f.uid)
        assertEquals(listOf("com.test.app10123"), f.packages)
        assertEquals(false, f.blocked)
        assertEquals("10.111.0.1:41000", f.src)
    }

    @Test
    fun relaysUdpBothWays() {
        val port = udpEcho.localPort
        send(PacketCodec.buildUdp(client, 42000, loopback, port, "ping".toByteArray()))
        val back = tun.next()!!
        assertEquals(Proto.UDP, back.protocol)
        assertEquals(loopback, back.src)
        assertEquals(port, back.srcPort)
        assertEquals(42000, back.dstPort)
        assertEquals("ping", back.payload.decodeToString())
        stopEngine()
        val f = flows().single { it.proto == "udp" && it.dst.endsWith(":$port") }
        assertEquals(4L, f.bytesOut)
        assertEquals(4L, f.bytesIn)
        assertEquals("capture_stopped", f.closeReason)
    }

    @Test
    fun blockedUidGetsRstAndNoServerConnection() {
        policy.block(10666)
        uid = 10666
        tcp(echoServer.localPort, 500, 0, TcpFlags.SYN)
        val rst = tun.next()!!
        assertTrue(rst.tcp!!.has(TcpFlags.RST))
        assertEquals(501, rst.tcp!!.ack)
        Thread.sleep(300)
        assertEquals(0, accepts.get())
        stopEngine()
        val f = flows().single { it.proto == "tcp" }
        assertTrue(f.blocked)
        assertEquals(10666, f.uid)
    }

    @Test
    fun quicIsDroppedAndRecorded() {
        send(PacketCodec.buildUdp(client, 43000, loopback, 443, ByteArray(1200)))
        assertEquals(null, tun.next(300))
        stopEngine()
        val f = flows().single { it.dst.endsWith(":443") }
        assertEquals("quic_dropped", f.closeReason)
        assertEquals(1200L, f.bytesOut)
    }

    @Test
    fun dnsIsForwardedRecordedAndNamesLaterFlows() {
        send(PacketCodec.buildUdp(client, 44000, dnsVirtual, 53, DnsCodec.query(77, "echo.tracker.test", 1)))
        val reply = tun.next()!!
        assertEquals(dnsVirtual, reply.src)
        assertEquals(53, reply.srcPort)
        assertEquals(44000, reply.dstPort)
        val m = DnsCodec.parse(reply.payload)!!
        assertEquals(77, m.id)
        assertEquals(listOf("127.0.0.1"), m.answers)

        tcp(echoServer.localPort, 9000, 0, TcpFlags.SYN, srcPort = 45000)
        val synAck = tun.next()!!
        tcp(echoServer.localPort, 9001, synAck.tcp!!.seq + 1, TcpFlags.ACK, srcPort = 45000)
        tcp(echoServer.localPort, 9001, synAck.tcp!!.seq + 1, TcpFlags.RST, srcPort = 45000)
        Thread.sleep(300)
        stopEngine()
        val d = archive.lines("dns.jsonl").map { Json.parseObject(it) }.single()
        assertEquals("echo.tracker.test", d["name"])
        assertEquals("A", d["qtype"])
        assertEquals(listOf("127.0.0.1"), d["answers"])
        assertEquals(10123L, d["uid"])
        val f = flows().single { it.src.endsWith(":45000") }
        assertEquals("echo.tracker.test", f.dnsName)
        assertTrue(f.tracker)
        assertEquals("rst_client", f.closeReason)
    }

    @Test
    fun tcpToVirtualDnsAddressIsReset() {
        tcp(853, 100, 0, TcpFlags.SYN, dst = dnsVirtual)
        val rst = tun.next()!!
        assertTrue(rst.tcp!!.has(TcpFlags.RST))
        assertNotNull(rst)
    }

    @Test
    fun httpRequestIsSniffedAndDumped() {
        val port = echoServer.localPort
        tcp(port, 1, 0, TcpFlags.SYN, srcPort = 46000)
        val synAck = tun.next()!!
        val sAck = synAck.tcp!!.seq + 1
        tcp(port, 2, sAck, TcpFlags.ACK, srcPort = 46000)
        val req = "GET /x HTTP/1.1\r\nHost: plain.test\r\n\r\n".toByteArray()
        tcp(port, 2, sAck, TcpFlags.ACK or TcpFlags.PSH, req, srcPort = 46000)
        Thread.sleep(500)
        stopEngine()
        val f = flows().single { it.src.endsWith(":46000") }
        assertEquals("plain.test", f.httpHost)
        assertEquals("dumps/${f.id}.txt", f.dump)
        val dump = archive.files.entries.single { it.key.endsWith("/dumps/${f.id}.txt") }.value.toString()
        assertTrue(dump.startsWith("GET /x HTTP/1.1"))
    }
}
