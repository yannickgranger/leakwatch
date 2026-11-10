package io.github.yannickgranger.leakwatch.entry

import android.content.Context
import java.net.InetAddress
import java.net.InetSocketAddress
import java.security.SecureRandom
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import io.github.yannickgranger.leakwatch.adapter.JcaAead
import io.github.yannickgranger.leakwatch.adapter.KeystoreWgConfigStore
import io.github.yannickgranger.leakwatch.domain.Cidr
import io.github.yannickgranger.leakwatch.domain.TunnelRouting
import io.github.yannickgranger.leakwatch.domain.WgConfig
import io.github.yannickgranger.leakwatch.domain.WgConfigParser
import io.github.yannickgranger.leakwatch.domain.WgLink
import io.github.yannickgranger.leakwatch.domain.WgParse
import io.github.yannickgranger.leakwatch.domain.WgPeer
import io.github.yannickgranger.leakwatch.domain.WgPeerSettings

data class LinkSummary(val name: String, val addresses: String, val endpoint: String, val allowedIps: String)

object WireGuardLink {
    private val summaryState = MutableStateFlow<LinkSummary?>(null)
    private val handshakeState = MutableStateFlow<Long?>(null)
    val summary: StateFlow<LinkSummary?> = summaryState
    val lastHandshake: StateFlow<Long?> = handshakeState
    private val choicesState = MutableStateFlow<List<Pair<String, String>>>(emptyList())
    private val messageState = MutableStateFlow<String?>(null)
    val choices: StateFlow<List<Pair<String, String>>> = choicesState
    val message: StateFlow<String?> = messageState

    fun offerChoices(tunnels: List<Pair<String, String>>) {
        choicesState.value = tunnels
    }

    fun setMessage(text: String?) {
        messageState.value = text
    }

    private fun store(context: Context) = KeystoreWgConfigStore(context.applicationContext)

    private fun summarize(c: WgConfig) = LinkSummary(
        c.name ?: "WireGuard",
        c.addresses.joinToString(", "),
        "${c.endpointHost}:${c.endpointPort}",
        c.allowedIps.joinToString(", "),
    )

    fun config(context: Context): WgConfig? {
        val text = store(context).load() ?: return null
        val name = text.lineSequence().firstOrNull { it.startsWith(NAME_PREFIX) }?.removePrefix(NAME_PREFIX)?.trim()
        return (WgConfigParser.parse(text, name) as? WgParse.Ok)?.config
    }

    fun refresh(context: Context) {
        summaryState.value = config(context)?.let(::summarize)
    }

    fun import(context: Context, name: String, text: String): String? =
        when (val r = WgConfigParser.parse(text, name)) {
            is WgParse.Refused -> r.message
            is WgParse.Ok -> {
                store(context).save("$NAME_PREFIX$name\n$text")
                summaryState.value = summarize(r.config)
                null
            }
        }

    fun remove(context: Context) {
        store(context).clear()
        messageState.value = null
        summaryState.value = null
        handshakeState.value = null
    }

    fun publishHandshake(ms: Long?) {
        handshakeState.value = ms
    }

    fun link(config: WgConfig): WgLink? {
        val address = Cidr.literal(config.endpointHost) ?: runCatching { InetAddress.getByName(config.endpointHost) }.getOrNull() ?: return null
        val peer = WgPeer(WgPeerSettings(config.privateKey, config.peerPublicKey, config.presharedKey, config.keepalive), JcaAead(), SecureRandom())
        return WgLink(TunnelRouting(config.allowedIps, config.addresses, config.mtu ?: DEFAULT_MTU), peer, InetSocketAddress(address, config.endpointPort))
    }

    private const val NAME_PREFIX = "# leakwatch-name: "
    private const val DEFAULT_MTU = 1420
}
