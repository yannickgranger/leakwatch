package io.github.yannickgranger.leakwatch.domain

import java.io.ByteArrayOutputStream
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.DatagramChannel
import java.nio.channels.SelectionKey
import java.nio.channels.Selector
import java.security.SecureRandom
import java.util.Base64
import java.util.concurrent.TimeUnit
import io.github.yannickgranger.leakwatch.adapter.JcaAead
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test

class WireGuardPeerIT {
    private val podman = "/usr/bin/podman"
    private val image = "docker.io/library/alpine:3.22"
    private val random = SecureRandom()
    private val name = "leakwatch-wg-it-${System.nanoTime()}"
    private val serverPrivate = Base64.getDecoder().decode(WgVectors.PRIV_2)
    private val clientPrivate = Base64.getDecoder().decode(WgVectors.PRIV_1)
    private val psk = Base64.getDecoder().decode(WgVectors.PSK)
    private var port = 0

    private fun b64(b: ByteArray) = Base64.getEncoder().encodeToString(b)

    private fun run(vararg args: String, timeoutSec: Long = 120): String {
        val p = ProcessBuilder(podman, *args).redirectErrorStream(true).start()
        val out = p.inputStream.bufferedReader().readText()
        p.waitFor(timeoutSec, TimeUnit.SECONDS)
        return out
    }

    @Before
    fun startServer() {
        assumeTrue("set -Dwg.it=1 to run against a real WireGuard peer in Podman", System.getProperty("wg.it") == "1")
        port = DatagramSocket(0).use { it.localPort }
        val script = "apk add -q wireguard-go wireguard-tools socat >/dev/null && " +
            "echo \"\$SK\" > /k && echo \"\$PSK\" > /p && wireguard-go wg0 && " +
            "wg set wg0 private-key /k listen-port 51820 peer \"\$PK\" preshared-key /p allowed-ips 10.200.0.2/32 && " +
            "ip addr add 10.200.0.1/24 dev wg0 && ip link set wg0 up && echo READY && " +
            "exec socat TCP-LISTEN:7,bind=10.200.0.1,fork,reuseaddr EXEC:cat"
        val id = run(
            "run", "-d", "--rm", "--name", name, "--cap-add", "NET_ADMIN", "--device", "/dev/net/tun",
            "--security-opt", "label=disable", "-p", "127.0.0.1:$port:51820/udp",
            "-e", "SK=${b64(serverPrivate)}", "-e", "PK=${b64(X25519.publicKey(clientPrivate))}", "-e", "PSK=${b64(psk)}",
            image, "sh", "-c", script,
        )
        println("container ${id.trim()} on udp 127.0.0.1:$port")
        val deadline = System.currentTimeMillis() + 180_000
        while (System.currentTimeMillis() < deadline) {
            if (run("logs", name).contains("READY")) return
            Thread.sleep(500)
        }
        throw AssertionError("WireGuard container not ready: " + run("logs", name))
    }

    @After
    fun stopServer() {
        if (port != 0) run("rm", "-f", name)
    }

    @Test
    fun echoesTwentyKilobytesThroughARealWireGuardPeer() {
        val aead = JcaAead()
        val peer = WgPeer(WgPeerSettings(clientPrivate, X25519.publicKey(serverPrivate), psk, 0), aead, random)
        val routing = TunnelRouting(listOf(Cidr.parse("10.200.0.0/24")), listOf(Cidr.parse("10.200.0.2/32")), 1420)
        val tun = TestNet.ip("10.111.0.1")
        val server = TestNet.ip("10.200.0.1")
        val channel = DatagramChannel.open()
        channel.configureBlocking(false)
        channel.connect(InetSocketAddress("127.0.0.1", port))
        val selector = Selector.open()
        channel.register(selector, SelectionKey.OP_READ)
        val buffer = ByteBuffer.allocate(65535)

        fun toNet(datagrams: List<ByteArray>) {
            for (d in datagrams) channel.write(ByteBuffer.wrap(d))
        }

        fun sendIp(packet: ByteArray) {
            val routed = routing.outbound(packet, packet.size)!!
            assertTrue(TestNet.transportValid(routed))
            toNet(peer.send(routed, System.currentTimeMillis()))
        }

        val data = ByteArray(20 * 1024).also { random.nextBytes(it) }
        val received = ByteArrayOutputStream()
        val iss = 1000
        var sndUna = iss + 1
        var sndNxt = iss + 1
        var rcvNxt = 0
        var established = false
        var lastProgress = System.currentTimeMillis()
        var lastSyn = 0L
        val localPort = 40000 + random.nextInt(20000)
        val deadline = System.currentTimeMillis() + 90_000

        while (received.size() < data.size && System.currentTimeMillis() < deadline) {
            val now = System.currentTimeMillis()
            if (!established && now - lastSyn >= 1000) {
                lastSyn = now
                sendIp(PacketCodec.buildTcp(tun, localPort, server, 7, iss, 0, TcpFlags.SYN, 65535, mss = 1460))
            }
            if (established) {
                if (now - lastProgress >= 1000) {
                    sndNxt = sndUna
                    lastProgress = now
                }
                while (sndNxt - (iss + 1) < data.size && sndNxt - sndUna < 8000) {
                    val off = sndNxt - (iss + 1)
                    val n = minOf(1000, data.size - off)
                    sendIp(PacketCodec.buildTcp(tun, localPort, server, 7, sndNxt, rcvNxt, TcpFlags.ACK or TcpFlags.PSH, 65535, data, off, n))
                    sndNxt += n
                }
            }
            toNet(peer.tick(now))
            if (selector.select(50) > 0) {
                selector.selectedKeys().clear()
                while (true) {
                    buffer.clear()
                    if (channel.read(buffer) <= 0) break
                    val result = peer.receive(buffer.array().copyOf(buffer.position()), System.currentTimeMillis())
                    toNet(result.toNet)
                    for (inner in result.toTun) {
                        val back = routing.inbound(inner) ?: continue
                        assertTrue(TestNet.transportValid(back))
                        val p = PacketCodec.parse(back, back.size) ?: continue
                        assertEquals(tun, p.dst)
                        val t = p.tcp ?: continue
                        if (t.has(TcpFlags.SYN) && t.has(TcpFlags.ACK) && !established) {
                            established = true
                            rcvNxt = t.seq + 1
                            lastProgress = System.currentTimeMillis()
                            sendIp(PacketCodec.buildTcp(tun, localPort, server, 7, sndNxt, rcvNxt, TcpFlags.ACK, 65535))
                            continue
                        }
                        if (t.has(TcpFlags.ACK) && t.ack - sndUna > 0 && t.ack - sndNxt <= 0) {
                            sndUna = t.ack
                            lastProgress = System.currentTimeMillis()
                        }
                        if (p.payload.isNotEmpty()) {
                            if (t.seq == rcvNxt) {
                                received.write(p.payload)
                                rcvNxt += p.payload.size
                            }
                            sendIp(PacketCodec.buildTcp(tun, localPort, server, 7, sndNxt, rcvNxt, TcpFlags.ACK, 65535))
                        }
                    }
                }
            }
        }
        sendIp(PacketCodec.buildTcp(tun, localPort, server, 7, sndNxt, rcvNxt, TcpFlags.RST or TcpFlags.ACK, 0))
        selector.close()
        channel.close()

        assertNotNull("handshake completed", peer.lastHandshakeMs)
        assertEquals(data.size, received.size())
        assertArrayEquals(data, received.toByteArray())
        val show = run("exec", name, "wg", "show", "wg0", "latest-handshakes")
        println("wg show wg0 latest-handshakes: $show")
        val line = show.lines().first { it.startsWith(b64(X25519.publicKey(clientPrivate))) }
        assertTrue(line, line.substringAfter('\t').trim().toLong() > 0)
        println("echoed ${received.size()} bytes intact through the tunnel")
    }
}
