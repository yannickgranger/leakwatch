package io.github.yannickgranger.leakwatch.domain

import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.DatagramChannel
import java.nio.channels.SelectionKey
import java.nio.channels.Selector
import java.nio.channels.SocketChannel
import java.security.SecureRandom
import io.github.yannickgranger.leakwatch.port.Clock
import io.github.yannickgranger.leakwatch.port.PacketSink
import io.github.yannickgranger.leakwatch.port.PacketSource
import io.github.yannickgranger.leakwatch.port.SocketFactory

class EngineConfig(
    val dnsVirtual: InetAddress,
    val upstreamDns: InetSocketAddress,
    val connectTimeoutMs: Long = 10_000,
    val tcpIdleMs: Long = 600_000,
    val udpIdleMs: Long = 60_000,
    val flushMs: Long = 30_000,
    val statsMs: Long = 2_000,
)

class RelayEngine(
    private val source: PacketSource,
    private val sink: PacketSink,
    private val sockets: SocketFactory,
    private val attribution: Attribution,
    private val blocks: BlockPolicy,
    private val trackers: TrackerMatcher,
    private val archive: ArchiveWriter,
    private val clock: Clock,
    private val config: EngineConfig,
    private val stats: (List<AppSummary>) -> Unit = {},
    private val appStates: AppStateClassifier? = null,
    private val tunnel: WgLink? = null,
    private val domains: DomainPolicy? = null,
) {
    @Volatile
    private var running = true
    private val selector: Selector = Selector.open()
    private val tcpFlows = HashMap<FlowKey, TcpFlow>()
    private val udpFlows = HashMap<FlowKey, UdpFlow>()
    private val names = DnsNameMap(3_600_000)
    private val packet = ByteArray(65535)
    private val readBuffer: ByteBuffer = ByteBuffer.allocate(65535)
    private val random = SecureRandom()
    private var counter = 0L
    private val sessionStart = clock.nowMillis()
    private val settling = ArrayList<Settling>()
    private val wgFlows = HashMap<FlowKey, WgFlow>()
    private var wgChannel: DatagramChannel? = null
    private var wgLastInboundMs = 0L
    private var wgLastOpenMs = 0L

    private class Settling(val flow: Flow, val reason: String, val endMs: Long)

    private enum class UdpKind { NORMAL, DNS, QUIC, BLOCKED }

    private abstract inner class Flow(val key: FlowKey, val identity: AppIdentity, val startMs: Long) {
        val id = "$sessionStart-${counter++}"
        var dnsName: String? = names.get(Endpoint.host(key.dst), startMs)
        abstract fun record(reason: String, nowMs: Long): FlowRecord
        open fun dumpText(): String? = null
        private var usageInfo: UsageInfo? = null

        fun usage(): UsageInfo {
            usageInfo?.let { return it }
            val c = appStates ?: return UsageInfo.UNKNOWN
            val info = c.classify(identity.uid, identity.packages, startMs)
            if (settled()) usageInfo = info
            return info
        }

        fun settled(): Boolean {
            val c = appStates ?: return true
            return c.knownUntil() >= startMs + SETTLE_MS
        }

        fun base(reason: String, nowMs: Long, sni: String?, httpHost: String?, bytesOut: Long, bytesIn: Long, packetsOut: Long, packetsIn: Long, blocked: Boolean, dump: String?, cleartext: Boolean = false, via: String = FlowRecord.VIA_DIRECT): FlowRecord {
            val direct = via == FlowRecord.VIA_DIRECT
            val tracker = direct && (trackers.matches(sni) || trackers.matches(httpHost) || trackers.matches(dnsName))
            val telemetry = direct && (TelemetryNameMatcher.matches(sni) || TelemetryNameMatcher.matches(httpHost) || TelemetryNameMatcher.matches(dnsName))
            val u = usage()
            return FlowRecord(
                id = id,
                tsStart = startMs,
                tsEnd = nowMs,
                uid = identity.uid,
                packages = identity.packages,
                label = identity.label,
                proto = if (key.protocol == Proto.TCP) "tcp" else "udp",
                ipVersion = key.ipVersion,
                src = Endpoint.format(key.src, key.srcPort),
                dst = Endpoint.format(key.dst, key.dstPort),
                dnsName = dnsName,
                sni = sni,
                httpHost = httpHost,
                tracker = tracker,
                bytesOut = bytesOut,
                bytesIn = bytesIn,
                packetsOut = packetsOut,
                packetsIn = packetsIn,
                blocked = blocked,
                closeReason = reason,
                dump = dump,
                appState = u.appState,
                lastUsed = u.lastUsed,
                reasons = if (reason == FlowRecord.DOMAIN_BLOCKED) emptyList() else Suspicion.reasons(tracker, telemetry, u.appState, u.notUsedToday, cleartext, bytesOut, bytesIn, via, identity.system),
                via = via,
            )
        }
    }

    private inner class TcpFlow(key: FlowKey, identity: AppIdentity, val session: TcpSession, startMs: Long, var blocked: Boolean) : Flow(key, identity, startMs) {
        var channel: SocketChannel? = null
        var selectionKey: SelectionKey? = null
        val inspector = PayloadInspector()
        var sawData = false
        val connectDeadline = startMs + config.connectTimeoutMs
        var hostChecked = false

        fun inspection(): Inspection? = if (sawData) inspector.current() else null

        override fun dumpText(): String? = inspection()?.dump

        override fun record(reason: String, nowMs: Long): FlowRecord {
            val i = inspection()
            return base(
                reason, nowMs, i?.sni, i?.httpHost, session.bytesOut, session.bytesIn, session.packetsOut, session.packetsIn, blocked,
                if (i?.dump != null) "dumps/$id.txt" else null, i?.cleartext ?: false,
            )
        }
    }

    private inner class UdpFlow(key: FlowKey, identity: AppIdentity, startMs: Long, val kind: UdpKind) : Flow(key, identity, startMs) {
        var channel: DatagramChannel? = null
        var bytesOut = 0L
        var bytesIn = 0L
        var packetsOut = 0L
        var packetsIn = 0L
        var lastActivityMs = startMs
        val pendingDns = HashMap<Int, Pair<String, Int>>()

        override fun record(reason: String, nowMs: Long): FlowRecord {
            val r = when (kind) {
                UdpKind.QUIC -> "quic_dropped"
                UdpKind.BLOCKED -> "blocked"
                else -> reason
            }
            return base(r, nowMs, null, null, bytesOut, bytesIn, packetsOut, packetsIn, kind == UdpKind.BLOCKED, null)
        }
    }

    private inner class WgFlow(key: FlowKey, identity: AppIdentity, startMs: Long, val blocked: Boolean) : Flow(key, identity, startMs) {
        var bytesOut = 0L
        var bytesIn = 0L
        var packetsOut = 0L
        var packetsIn = 0L
        var lastActivityMs = startMs
        var outEnd: Int? = null
        var inEnd: Int? = null
        var finOut = false
        var finIn = false
        val inspector = PayloadInspector()
        var sawData = false

        fun inspection(): Inspection? = if (sawData) inspector.finish() else null

        override fun dumpText(): String? = inspection()?.dump

        override fun record(reason: String, nowMs: Long): FlowRecord {
            val i = inspection()
            return base(
                reason, nowMs, i?.sni, i?.httpHost, bytesOut, bytesIn, packetsOut, packetsIn, blocked,
                if (i?.dump != null) "dumps/$id.txt" else null, i?.cleartext ?: false, FlowRecord.VIA_WIREGUARD,
            )
        }
    }

    fun stop() {
        running = false
        selector.wakeup()
    }

    fun run() {
        var lastFlush = clock.nowMillis()
        var lastStats = 0L
        var lastTimers = 0L
        var lastTunActivity = 0L
        safely { openTunnel(clock.nowMillis()) }
        try {
            while (running) {
                var got = 0
                while (got < 512) {
                    val n = source.read(packet)
                    if (n < 0) {
                        running = false
                        break
                    }
                    if (n == 0) break
                    got++
                    safely { onTunPacket(n) }
                }
                if (!running) break
                var now = clock.nowMillis()
                if (got > 0) lastTunActivity = now
                val ready = if (got > 0) selector.selectNow() else selector.select(if (now - lastTunActivity < 200) 1 else 10)
                if (ready > 0) {
                    val it = selector.selectedKeys().iterator()
                    while (it.hasNext()) {
                        val k = it.next()
                        it.remove()
                        safely { onReady(k) }
                    }
                }
                now = clock.nowMillis()
                safely { refreshUsage(now) }
                if (now - lastTimers >= 100) {
                    lastTimers = now
                    safely { timers(now) }
                }
                if (now - lastFlush >= config.flushMs) {
                    lastFlush = now
                    safely { archive.flush(openRecords(now)) }
                }
                if (now - lastStats >= config.statsMs) {
                    lastStats = now
                    safely { stats(AppStats.summarize(archive.today() + openRecords(now), archive.blockedDnsToday())) }
                }
            }
        } finally {
            shutdown()
        }
    }

    private inline fun safely(block: () -> Unit) {
        try {
            block()
        } catch (e: IOException) {
            Unit
        } catch (e: RuntimeException) {
            Unit
        }
    }

    private fun openRecords(now: Long): List<FlowRecord> =
        tcpFlows.values.map { it.record("open", now) } + udpFlows.values.map { it.record("open", now) } + wgFlows.values.map { it.record("open", now) } +
            settling.map { it.flow.record(it.reason, it.endMs) }

    private fun refreshUsage(now: Long) {
        val c = appStates ?: return
        if (c.refresh(now) || settling.isNotEmpty()) drainSettled(false)
    }

    private fun drainSettled(all: Boolean) {
        val it = settling.iterator()
        while (it.hasNext()) {
            val s = it.next()
            if (all || s.flow.settled()) {
                it.remove()
                archive.flow(s.flow.record(s.reason, s.endMs), s.flow.dumpText())
            }
        }
    }

    private fun archiveClosed(flow: Flow, reason: String, now: Long) {
        if (flow.settled()) archive.flow(flow.record(reason, now), flow.dumpText()) else settling += Settling(flow, reason, now)
    }

    private fun shutdown() {
        val now = clock.nowMillis()
        for (f in tcpFlows.values.toList()) closeTcp(f, "capture_stopped", now)
        for (f in udpFlows.values.toList()) closeUdp(f, "capture_stopped", now)
        for (f in wgFlows.values.toList()) closeWg(f, "capture_stopped", now)
        runCatching { wgChannel?.close() }
        safely { appStates?.refresh(now) }
        safely { drainSettled(true) }
        safely { archive.flush(emptyList()) }
        safely { stats(AppStats.summarize(archive.today(), archive.blockedDnsToday())) }
        safely { selector.close() }
    }

    private fun write(p: ByteArray) {
        try {
            sink.write(p)
        } catch (e: IOException) {
            Unit
        }
    }

    private fun writeAll(ps: List<ByteArray>) {
        for (p in ps) write(p)
    }

    private fun onTunPacket(len: Int) {
        if (tunnel != null) {
            val routed = tunnel.routing.outbound(packet, len)
            if (routed != null) {
                onTunnelOut(PacketCodec.parse(packet, len), routed)
                return
            }
        }
        val p = PacketCodec.parse(packet, len) ?: return
        when (p.protocol) {
            Proto.TCP -> onTcp(p)
            Proto.UDP -> onUdp(p)
            else -> Unit
        }
    }

    private fun resetFor(p: ParsedPacket) {
        val t = p.tcp ?: return
        if (t.has(TcpFlags.RST)) return
        val reply = if (t.has(TcpFlags.ACK)) {
            PacketCodec.buildTcp(p.dst, p.dstPort, p.src, p.srcPort, t.ack, 0, TcpFlags.RST, 0)
        } else {
            val consumed = p.payload.size + (if (t.has(TcpFlags.SYN)) 1 else 0) + (if (t.has(TcpFlags.FIN)) 1 else 0)
            PacketCodec.buildTcp(p.dst, p.dstPort, p.src, p.srcPort, 0, t.seq + consumed, TcpFlags.RST or TcpFlags.ACK, 0)
        }
        write(reply)
    }

    private fun onTcp(p: ParsedPacket) {
        val t = p.tcp ?: return
        val key = FlowKey(Proto.TCP, p.src, p.srcPort, p.dst, p.dstPort)
        val now = clock.nowMillis()
        val existing = tcpFlows[key]
        if (existing != null) {
            val r = existing.session.onClientSegment(t, p.payload, now)
            writeAll(r.toClient)
            if (r.accepted.isNotEmpty() && !existing.inspector.done) {
                existing.sawData = true
                existing.inspector.offer(r.accepted)
            }
            if (domainBlockedByHost(existing)) {
                existing.blocked = true
                write(existing.session.abort(FlowRecord.DOMAIN_BLOCKED))
                closeTcp(existing, FlowRecord.DOMAIN_BLOCKED, now)
                return
            }
            afterChange(existing, now)
            return
        }
        if (!t.has(TcpFlags.SYN) || t.has(TcpFlags.ACK) || p.dst == config.dnsVirtual) {
            resetFor(p)
            return
        }
        val identity = attribution.identify(Proto.TCP, InetSocketAddress(p.src, p.srcPort), InetSocketAddress(p.dst, p.dstPort))
        val verdict = blocks.verdict(identity.uid, Proto.TCP)
        val session = TcpSession(key, t.seq, random.nextInt(), t.window, t.mss, now)
        val flow = TcpFlow(key, identity, session, now, verdict != Verdict.ALLOW)
        if (verdict != Verdict.ALLOW) {
            write(session.refuse("blocked"))
            finishTcp(flow, "blocked", now)
            return
        }
        if (domainBlockedByAddress(p.dst, identity, now)) {
            flow.blocked = true
            write(session.refuse(FlowRecord.DOMAIN_BLOCKED))
            finishTcp(flow, FlowRecord.DOMAIN_BLOCKED, now)
            return
        }
        tcpFlows[key] = flow
        try {
            val ch = sockets.tcp()
            flow.channel = ch
            ch.configureBlocking(false)
            if (ch.connect(InetSocketAddress(p.dst, p.dstPort))) {
                writeAll(session.connected(now))
                flow.selectionKey = ch.register(selector, SelectionKey.OP_READ, flow)
            } else {
                flow.selectionKey = ch.register(selector, SelectionKey.OP_CONNECT, flow)
            }
        } catch (e: IOException) {
            write(session.refuse("connect_failed"))
            closeTcp(flow, "connect_failed", now)
        } catch (e: RuntimeException) {
            write(session.refuse("connect_failed"))
            closeTcp(flow, "connect_failed", now)
        }
    }

    private fun domainBlockedByHost(flow: TcpFlow): Boolean {
        val policy = domains ?: return false
        if (flow.hostChecked || !flow.sawData) return false
        val probe = flow.inspector.host() ?: return false
        flow.hostChecked = true
        return probe.host != null && policy.isBlocked(probe.host, flow.identity.packages)
    }

    private fun domainBlockedByAddress(dst: InetAddress, identity: AppIdentity, now: Long): Boolean {
        val policy = domains ?: return false
        val known = names.all(Endpoint.host(dst), now)
        return known.isNotEmpty() && known.all { policy.isBlocked(it, identity.packages) }
    }

    private fun afterChange(flow: TcpFlow, now: Long) {
        val s = flow.session
        if (s.isClosed) {
            closeTcp(flow, s.closeReason ?: "closed", now)
            return
        }
        val ch = flow.channel ?: return
        if (!ch.isConnected) return
        try {
            writeAll(s.drainUpstream { b, o, l -> ch.write(ByteBuffer.wrap(b, o, l)) })
            if (s.needsUpstreamShutdown()) {
                ch.shutdownOutput()
                s.upstreamShutdownDone()
            }
        } catch (e: IOException) {
            write(s.abort("rst_upstream"))
            closeTcp(flow, "rst_upstream", now)
            return
        }
        if (s.isClosed) {
            closeTcp(flow, s.closeReason ?: "closed", now)
            return
        }
        var ops = 0
        if (s.upstreamReadBudget() > 0) ops = ops or SelectionKey.OP_READ
        if (s.upstreamPending > 0) ops = ops or SelectionKey.OP_WRITE
        flow.selectionKey?.takeIf { it.isValid }?.interestOps(ops)
    }

    private fun onReady(k: SelectionKey) {
        if (!k.isValid) return
        val now = clock.nowMillis()
        when (val flow = k.attachment()) {
            is TcpFlow -> onTcpReady(flow, k, now)
            is UdpFlow -> onUdpReady(flow, now)
            is WgLink -> onTunnelReady(now)
        }
    }

    private fun onTcpReady(flow: TcpFlow, k: SelectionKey, now: Long) {
        val ch = flow.channel ?: return
        val s = flow.session
        try {
            if (k.isConnectable) {
                if (ch.finishConnect()) {
                    writeAll(s.connected(now))
                    k.interestOps(SelectionKey.OP_READ)
                }
                return
            }
            if (k.isReadable) {
                val budget = s.upstreamReadBudget()
                if (budget > 0) {
                    readBuffer.clear()
                    readBuffer.limit(minOf(budget, readBuffer.capacity()))
                    val n = ch.read(readBuffer)
                    if (n < 0) {
                        writeAll(s.onUpstreamEof(now))
                    } else if (n > 0) {
                        writeAll(s.onUpstreamData(readBuffer.array(), 0, n, now))
                    }
                }
            }
        } catch (e: IOException) {
            if (s.state == TcpSession.State.CONNECTING) {
                write(s.refuse("connect_failed"))
                closeTcp(flow, "connect_failed", now)
            } else {
                write(s.abort("rst_upstream"))
                closeTcp(flow, "rst_upstream", now)
            }
            return
        }
        afterChange(flow, now)
    }

    private fun closeTcp(flow: TcpFlow, reason: String, now: Long) {
        tcpFlows.remove(flow.key)
        flow.selectionKey?.cancel()
        runCatching { flow.channel?.close() }
        finishTcp(flow, reason, now)
    }

    private fun finishTcp(flow: TcpFlow, reason: String, now: Long) {
        archiveClosed(flow, reason, now)
    }

    private fun onUdp(p: ParsedPacket) {
        val key = FlowKey(Proto.UDP, p.src, p.srcPort, p.dst, p.dstPort)
        val now = clock.nowMillis()
        var flow = udpFlows[key]
        if (flow == null) {
            if (p.dst == config.dnsVirtual && p.dstPort != 53) return
            val identity = attribution.identify(Proto.UDP, InetSocketAddress(p.src, p.srcPort), InetSocketAddress(p.dst, p.dstPort))
            val kind = when {
                blocks.verdict(identity.uid, Proto.UDP) != Verdict.ALLOW -> UdpKind.BLOCKED
                p.dst == config.dnsVirtual -> UdpKind.DNS
                p.dstPort == 443 -> UdpKind.QUIC
                else -> UdpKind.NORMAL
            }
            flow = UdpFlow(key, identity, now, kind)
            udpFlows[key] = flow
            if (kind == UdpKind.NORMAL || kind == UdpKind.DNS) {
                try {
                    val ch = sockets.udp()
                    flow.channel = ch
                    ch.configureBlocking(false)
                    ch.connect(if (kind == UdpKind.DNS) config.upstreamDns else InetSocketAddress(p.dst, p.dstPort))
                    ch.register(selector, SelectionKey.OP_READ, flow)
                } catch (e: IOException) {
                    runCatching { flow.channel?.close() }
                    flow.channel = null
                }
            }
        }
        flow.packetsOut++
        flow.bytesOut += p.payload.size
        flow.lastActivityMs = now
        if (flow.kind == UdpKind.DNS) {
            val q = DnsCodec.parse(p.payload)?.takeIf { !it.isResponse }
            if (q != null) {
                if (flow.dnsName == null) flow.dnsName = q.name
                if (domains?.isBlocked(q.name, flow.identity.packages) == true) {
                    val answer = DnsCodec.nxdomain(p.payload)
                    if (answer != null) {
                        write(PacketCodec.buildUdp(config.dnsVirtual, 53, flow.key.src, flow.key.srcPort, answer))
                        flow.bytesIn += answer.size
                        flow.packetsIn++
                        archive.dns(DnsRecord(now, flow.identity.uid, flow.identity.label, q.name, DnsCodec.typeName(q.qtype), emptyList(), true))
                        return
                    }
                }
                flow.pendingDns[q.id] = q.name to q.qtype
            }
        }
        val ch = flow.channel ?: return
        try {
            ch.write(ByteBuffer.wrap(p.payload))
        } catch (e: IOException) {
            Unit
        }
    }

    private fun onUdpReady(flow: UdpFlow, now: Long) {
        val ch = flow.channel ?: return
        while (true) {
            readBuffer.clear()
            val n = try {
                ch.read(readBuffer)
            } catch (e: IOException) {
                -1
            }
            if (n <= 0) return
            val data = readBuffer.array().copyOf(n)
            flow.bytesIn += n
            flow.packetsIn++
            flow.lastActivityMs = now
            if (flow.kind == UdpKind.DNS) {
                DnsCodec.parse(data)?.takeIf { it.isResponse }?.let { m ->
                    val q = flow.pendingDns.remove(m.id)
                    val name = q?.first ?: m.name
                    val type = q?.second ?: m.qtype
                    for (ip in m.answers) names.put(ip, name, now)
                    archive.dns(DnsRecord(now, flow.identity.uid, flow.identity.label, name, DnsCodec.typeName(type), m.answers))
                }
                write(PacketCodec.buildUdp(config.dnsVirtual, 53, flow.key.src, flow.key.srcPort, data))
            } else {
                write(PacketCodec.buildUdp(flow.key.dst, flow.key.dstPort, flow.key.src, flow.key.srcPort, data))
            }
        }
    }

    private fun closeUdp(flow: UdpFlow, reason: String, now: Long) {
        udpFlows.remove(flow.key)
        runCatching { flow.channel?.close() }
        archiveClosed(flow, reason, now)
    }

    private fun timers(now: Long) {
        for (f in tcpFlows.values.toList()) {
            val s = f.session
            when {
                s.state == TcpSession.State.CONNECTING && now >= f.connectDeadline -> {
                    write(s.refuse("connect_failed"))
                    closeTcp(f, "connect_failed", now)
                }
                now - s.lastActivityMs >= config.tcpIdleMs -> {
                    write(s.abort("idle"))
                    closeTcp(f, "idle", now)
                }
                else -> {
                    writeAll(s.onTimer(now))
                    if (s.isClosed) closeTcp(f, s.closeReason ?: "closed", now)
                }
            }
        }
        for (f in udpFlows.values.toList()) {
            if (now - f.lastActivityMs >= config.udpIdleMs) closeUdp(f, "idle", now)
        }
        for (f in wgFlows.values.toList()) {
            val idle = if (f.key.protocol == Proto.TCP) config.tcpIdleMs else config.udpIdleMs
            if (now - f.lastActivityMs >= idle) closeWg(f, "idle", now)
        }
        tunnel?.let { sendTunnel(it.peer.tick(now), now) }
    }

    private fun openTunnel(now: Long) {
        val link = tunnel ?: return
        runCatching { wgChannel?.close() }
        wgChannel = null
        wgLastOpenMs = now
        val ch = sockets.udp()
        try {
            ch.configureBlocking(false)
            ch.connect(link.endpoint)
            ch.register(selector, SelectionKey.OP_READ, link)
            wgChannel = ch
        } catch (e: IOException) {
            runCatching { ch.close() }
        }
    }

    private fun sendTunnel(datagrams: List<ByteArray>, now: Long) {
        if (datagrams.isEmpty()) return
        val stale = now - wgLastInboundMs >= WG_STALE_MS && now - wgLastOpenMs >= WG_REOPEN_MS
        if (wgChannel == null || stale) safely { openTunnel(now) }
        val ch = wgChannel ?: return
        try {
            for (d in datagrams) ch.write(ByteBuffer.wrap(d))
        } catch (e: IOException) {
            safely { openTunnel(now) }
        }
    }

    private fun wgKey(p: ParsedPacket) = FlowKey(p.protocol, p.src, p.srcPort, p.dst, p.dstPort)

    private fun onTunnelOut(p: ParsedPacket?, routed: ByteArray) {
        val link = tunnel ?: return
        val now = clock.nowMillis()
        if (p != null && (p.protocol == Proto.TCP || p.protocol == Proto.UDP)) {
            val key = wgKey(p)
            var flow = wgFlows[key]
            val t = p.tcp
            if (flow == null) {
                val opening = t == null || t.has(TcpFlags.SYN) || p.payload.isNotEmpty()
                if (opening) {
                    val identity = attribution.identify(p.protocol, InetSocketAddress(p.src, p.srcPort), InetSocketAddress(p.dst, p.dstPort))
                    val blocked = blocks.verdict(identity.uid, p.protocol) != Verdict.ALLOW
                    flow = WgFlow(key, identity, now, blocked)
                    if (blocked) {
                        if (t != null) resetFor(p)
                        flow.packetsOut++
                        archiveClosed(flow, "blocked", now)
                        return
                    }
                    wgFlows[key] = flow
                }
            }
            if (flow != null) {
                flow.packetsOut++
                flow.lastActivityMs = now
                if (t == null) {
                    flow.bytesOut += p.payload.size
                } else {
                    val fresh = freshTail(flow.outEnd, t.seq, p.payload)
                    if (t.has(TcpFlags.SYN)) flow.outEnd = t.seq + 1
                    if (p.payload.isNotEmpty()) flow.outEnd = maxSeq(flow.outEnd, t.seq + p.payload.size)
                    if (fresh.isNotEmpty()) {
                        flow.bytesOut += fresh.size
                        if (!flow.inspector.done) {
                            flow.sawData = true
                            flow.inspector.offer(fresh)
                        }
                    }
                    if (t.has(TcpFlags.FIN)) flow.finOut = true
                }
            }
            sendTunnel(link.peer.send(routed, now), now)
            if (flow != null && t != null && (t.has(TcpFlags.RST) || (flow.finOut && flow.finIn))) closeWg(flow, if (t.has(TcpFlags.RST)) "rst_client" else "fin", now)
            return
        }
        sendTunnel(link.peer.send(routed, now), now)
    }

    private fun maxSeq(a: Int?, b: Int): Int = if (a == null || b - a > 0) b else a

    private fun freshTail(end: Int?, seq: Int, payload: ByteArray): ByteArray {
        if (payload.isEmpty()) return payload
        if (end == null) return payload
        val skip = end - seq
        if (skip <= 0) return payload
        if (skip >= payload.size) return PacketCodec.EMPTY
        return payload.copyOfRange(skip, payload.size)
    }

    private fun onTunnelReady(now: Long) {
        val link = tunnel ?: return
        val ch = wgChannel ?: return
        while (true) {
            readBuffer.clear()
            val n = try {
                ch.read(readBuffer)
            } catch (e: IOException) {
                -1
            }
            if (n <= 0) return
            wgLastInboundMs = now
            val result = link.peer.receive(readBuffer.array().copyOf(n), now)
            sendTunnel(result.toNet, now)
            for (inner in result.toTun) {
                val back = link.routing.inbound(inner) ?: continue
                onTunnelIn(back, now)
                write(back)
            }
        }
    }

    private fun onTunnelIn(back: ByteArray, now: Long) {
        val p = PacketCodec.parse(back, back.size) ?: return
        if (p.protocol != Proto.TCP && p.protocol != Proto.UDP) return
        val flow = wgFlows[FlowKey(p.protocol, p.dst, p.dstPort, p.src, p.srcPort)] ?: return
        flow.packetsIn++
        flow.lastActivityMs = now
        val t = p.tcp
        if (t == null) {
            flow.bytesIn += p.payload.size
            return
        }
        val fresh = freshTail(flow.inEnd, t.seq, p.payload)
        if (t.has(TcpFlags.SYN)) flow.inEnd = t.seq + 1
        if (p.payload.isNotEmpty()) flow.inEnd = maxSeq(flow.inEnd, t.seq + p.payload.size)
        flow.bytesIn += fresh.size
        if (t.has(TcpFlags.FIN)) flow.finIn = true
        if (t.has(TcpFlags.RST)) closeWg(flow, "rst_upstream", now)
    }

    private fun closeWg(flow: WgFlow, reason: String, now: Long) {
        if (wgFlows.remove(flow.key) == null) return
        archiveClosed(flow, reason, now)
    }

    private companion object {
        const val SETTLE_MS = 2_000L
        const val WG_STALE_MS = 150_000L
        const val WG_REOPEN_MS = 60_000L
    }
}
