package io.github.yannickgranger.leakwatch.domain

class TcpSession(
    val key: FlowKey,
    clientIsn: Int,
    serverIsn: Int,
    clientWindow: Int,
    clientMss: Int?,
    nowMs: Long,
) {
    enum class State { CONNECTING, SYN_ACK_SENT, ESTABLISHED, CLOSED }

    class Result(val toClient: List<ByteArray>, val accepted: ByteArray)

    var state: State = State.CONNECTING
        private set
    var closeReason: String? = null
        private set
    var bytesOut = 0L
        private set
    var bytesIn = 0L
        private set
    var packetsOut = 1L
        private set
    var packetsIn = 0L
        private set
    var lastActivityMs = nowMs
        private set
    private val ourMss = if (key.ipVersion == 4) 1400 else 1380
    private val sendMss = minOf(ourMss, clientMss ?: 536)
    private val synIsn = serverIsn
    private var rcvNxt = clientIsn + 1
    private var sndBase = serverIsn + 1
    private var sent = 0
    private var clientWnd = clientWindow
    private val toUpstream = ByteQueue()
    private val outbound = ByteQueue()
    private var upstreamEof = false
    private var finSent = false
    private var finAcked = false
    private var clientFin = false
    private var shutdownDone = false
    private var lastSendMs = nowMs
    private var rto = INITIAL_RTO
    private var lastAdvertised = UPSTREAM_CAP

    val isClosed: Boolean get() = state == State.CLOSED
    val upstreamPending: Int get() = toUpstream.size

    private fun free(): Int = (UPSTREAM_CAP - toUpstream.size).coerceAtLeast(0)

    private fun packet(seq: Int, flags: Int, payload: ByteArray = PacketCodec.EMPTY, mss: Int? = null): ByteArray {
        packetsIn++
        val w = free()
        lastAdvertised = w
        return PacketCodec.buildTcp(key.dst, key.dstPort, key.src, key.srcPort, seq, rcvNxt, flags, w, payload, mss = mss)
    }

    private fun synAck(): ByteArray = packet(synIsn, TcpFlags.SYN or TcpFlags.ACK, mss = ourMss)

    fun connected(nowMs: Long): List<ByteArray> {
        if (state != State.CONNECTING) return emptyList()
        state = State.SYN_ACK_SENT
        lastSendMs = nowMs
        lastActivityMs = nowMs
        return listOf(synAck())
    }

    fun refuse(reason: String): ByteArray {
        state = State.CLOSED
        closeReason = reason
        packetsIn++
        return PacketCodec.buildTcp(key.dst, key.dstPort, key.src, key.srcPort, 0, rcvNxt, TcpFlags.RST or TcpFlags.ACK, 0)
    }

    fun onClientSegment(tcp: TcpHeader, payload: ByteArray, nowMs: Long): Result {
        packetsOut++
        lastActivityMs = nowMs
        if (state == State.CLOSED) return Result(emptyList(), PacketCodec.EMPTY)
        if (tcp.has(TcpFlags.RST)) {
            close("rst_client")
            return Result(emptyList(), PacketCodec.EMPTY)
        }
        if (tcp.has(TcpFlags.SYN)) {
            return Result(if (state == State.SYN_ACK_SENT) listOf(synAck()) else emptyList(), PacketCodec.EMPTY)
        }
        if (state == State.CONNECTING || !tcp.has(TcpFlags.ACK)) return Result(emptyList(), PacketCodec.EMPTY)
        if (state == State.SYN_ACK_SENT) {
            if (tcp.ack != synIsn + 1) return Result(emptyList(), PacketCodec.EMPTY)
            state = State.ESTABLISHED
        }
        onAck(tcp.ack, tcp.window, nowMs)
        var needAck = false
        var accepted = PacketCodec.EMPTY
        if (payload.isNotEmpty()) {
            needAck = true
            val already = rcvNxt - tcp.seq
            if (already >= 0 && already < payload.size) {
                val n = minOf(payload.size - already, free())
                if (n > 0) {
                    accepted = payload.copyOfRange(already, already + n)
                    toUpstream.append(accepted)
                    rcvNxt += n
                    bytesOut += n
                }
            }
        }
        if (tcp.has(TcpFlags.FIN)) {
            needAck = true
            if (!clientFin && tcp.seq + payload.size == rcvNxt) {
                clientFin = true
                rcvNxt += 1
            }
        }
        val out = pump(nowMs)
        if (needAck && out.isEmpty()) out += packet(sndBase + sent + if (finSent) 1 else 0, TcpFlags.ACK)
        if (clientFin && finAcked) close("fin")
        return Result(out, accepted)
    }

    private fun onAck(ack: Int, window: Int, nowMs: Long) {
        val acked = ack - sndBase
        if (acked in 1..sent) {
            outbound.drop(acked)
            sndBase += acked
            sent -= acked
            lastSendMs = nowMs
            rto = INITIAL_RTO
        } else if (finSent && sent == 0 && acked == 1) {
            if (!finAcked) {
                finAcked = true
                lastSendMs = nowMs
            }
        } else if (finSent && acked == sent + 1 && sent > 0) {
            outbound.drop(sent)
            sndBase += sent
            sent = 0
            finAcked = true
        }
        if (acked >= 0 && acked <= sent + 1) clientWnd = window
    }

    private fun pump(nowMs: Long): MutableList<ByteArray> {
        val out = mutableListOf<ByteArray>()
        if (state != State.ESTABLISHED) return out
        val idleBefore = sent == 0 && !(finSent && !finAcked)
        while (sent < outbound.size) {
            val avail = clientWnd - sent
            if (avail <= 0) break
            val n = minOf(sendMss, outbound.size - sent, avail)
            out += packet(sndBase + sent, TcpFlags.ACK or TcpFlags.PSH, outbound.copy(sent, n))
            sent += n
            bytesIn += n
        }
        if (upstreamEof && !finSent && sent == outbound.size) {
            out += packet(sndBase + sent, TcpFlags.FIN or TcpFlags.ACK)
            finSent = true
        }
        if (out.isNotEmpty() && idleBefore) lastSendMs = nowMs
        return out
    }

    fun drainUpstream(writer: (ByteArray, Int, Int) -> Int): List<ByteArray> {
        while (toUpstream.size > 0) {
            val n = writer(toUpstream.array, toUpstream.start, toUpstream.size)
            if (n <= 0) break
            toUpstream.drop(n)
        }
        if (state == State.ESTABLISHED && lastAdvertised < UPSTREAM_CAP / 2 && free() - lastAdvertised >= 2 * ourMss) {
            return listOf(packet(sndBase + sent + if (finSent) 1 else 0, TcpFlags.ACK))
        }
        return emptyList()
    }

    fun upstreamReadBudget(): Int = if (upstreamEof || state == State.CLOSED) 0 else (OUTBOUND_CAP - outbound.size).coerceAtLeast(0)

    fun onUpstreamData(data: ByteArray, off: Int, len: Int, nowMs: Long): List<ByteArray> {
        lastActivityMs = nowMs
        outbound.append(data, off, len)
        return pump(nowMs)
    }

    fun onUpstreamEof(nowMs: Long): List<ByteArray> {
        lastActivityMs = nowMs
        upstreamEof = true
        val out = pump(nowMs)
        if (clientFin && finAcked) close("fin")
        return out
    }

    fun abort(reason: String): ByteArray {
        val seq = if (state == State.CONNECTING) 0 else sndBase + sent
        close(reason)
        packetsIn++
        return PacketCodec.buildTcp(key.dst, key.dstPort, key.src, key.srcPort, seq, rcvNxt, TcpFlags.RST or TcpFlags.ACK, 0)
    }

    fun onTimer(nowMs: Long): List<ByteArray> {
        if (nowMs - lastSendMs < rto) return emptyList()
        val out = mutableListOf<ByteArray>()
        when {
            state == State.SYN_ACK_SENT -> out += synAck()
            state != State.ESTABLISHED -> return out
            sent > 0 -> {
                var o = 0
                while (o < sent && out.size < RETRANSMIT_SEGMENTS) {
                    val n = minOf(sendMss, sent - o)
                    out += packet(sndBase + o, TcpFlags.ACK or TcpFlags.PSH, outbound.copy(o, n))
                    o += n
                }
                if (o == sent && finSent && !finAcked) out += packet(sndBase + sent, TcpFlags.FIN or TcpFlags.ACK)
            }
            finSent && !finAcked -> out += packet(sndBase, TcpFlags.FIN or TcpFlags.ACK)
            else -> return out
        }
        lastSendMs = nowMs
        rto = minOf(rto * 2, MAX_RTO)
        return out
    }

    fun needsUpstreamShutdown(): Boolean = clientFin && !shutdownDone && toUpstream.size == 0

    fun upstreamShutdownDone() {
        shutdownDone = true
    }

    private fun close(reason: String) {
        if (state != State.CLOSED) {
            state = State.CLOSED
            closeReason = reason
        }
    }

    private companion object {
        const val UPSTREAM_CAP = 65535
        const val OUTBOUND_CAP = 256 * 1024
        const val INITIAL_RTO = 1000L
        const val MAX_RTO = 8000L
        const val RETRANSMIT_SEGMENTS = 4
    }
}
