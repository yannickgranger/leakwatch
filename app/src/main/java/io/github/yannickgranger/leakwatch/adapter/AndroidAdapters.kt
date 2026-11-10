package io.github.yannickgranger.leakwatch.adapter

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.VpnService
import java.io.File
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.nio.channels.DatagramChannel
import java.nio.channels.SocketChannel
import java.time.ZoneId
import io.github.yannickgranger.leakwatch.port.AppDirectory
import io.github.yannickgranger.leakwatch.port.ArchiveStore
import io.github.yannickgranger.leakwatch.port.BlockStore
import io.github.yannickgranger.leakwatch.port.Clock
import io.github.yannickgranger.leakwatch.port.DomainRuleStore
import io.github.yannickgranger.leakwatch.port.OwnerResolver
import io.github.yannickgranger.leakwatch.port.SocketFactory

class ProtectedSocketFactory(private val vpn: VpnService) : SocketFactory {
    override fun tcp(): SocketChannel {
        val ch = SocketChannel.open()
        if (!vpn.protect(ch.socket())) {
            ch.close()
            throw IOException("protect failed")
        }
        return ch
    }

    override fun udp(): DatagramChannel {
        val ch = DatagramChannel.open()
        if (!vpn.protect(ch.socket())) {
            ch.close()
            throw IOException("protect failed")
        }
        return ch
    }
}

class ConnectivityOwnerResolver(private val cm: ConnectivityManager) : OwnerResolver {
    override fun ownerUid(protocol: Int, local: InetSocketAddress, remote: InetSocketAddress): Int = try {
        cm.getConnectionOwnerUid(protocol, local, remote)
    } catch (e: SecurityException) {
        -1
    } catch (e: IllegalArgumentException) {
        -1
    }
}

class PackageAppDirectory(private val pm: PackageManager) : AppDirectory {
    override fun packagesForUid(uid: Int): List<String> = pm.getPackagesForUid(uid)?.toList() ?: emptyList()

    override fun label(packageName: String): String =
        pm.getApplicationLabel(pm.getApplicationInfo(packageName, 0)).toString()

    override fun isSystem(packageName: String): Boolean = try {
        val flags = pm.getApplicationInfo(packageName, 0).flags
        flags and (ApplicationInfo.FLAG_SYSTEM or ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0
    } catch (e: PackageManager.NameNotFoundException) {
        false
    }
}

class FileArchiveStore(private val root: File) : ArchiveStore {
    private fun file(day: String, name: String): File = File(File(root, day), name).also { it.parentFile?.mkdirs() }

    override fun append(day: String, name: String, text: String) {
        file(day, name).appendText(text)
    }

    override fun write(day: String, name: String, text: String) {
        val f = file(day, name)
        val tmp = File(f.parentFile, f.name + ".tmp")
        tmp.writeText(text)
        if (!tmp.renameTo(f)) {
            f.writeText(text)
            tmp.delete()
        }
    }

    override fun read(day: String, name: String): String? {
        val f = File(File(root, day), name)
        return if (f.isFile) f.readText() else null
    }

    override fun days(): List<String> =
        root.listFiles()?.filter { it.isDirectory && DAY.matches(it.name) }?.map { it.name }?.sorted() ?: emptyList()

    override fun writeRoot(name: String, text: String) {
        root.mkdirs()
        val f = File(root, name)
        val tmp = File(root, "$name.tmp")
        tmp.writeText(text)
        if (!tmp.renameTo(f)) {
            f.writeText(text)
            tmp.delete()
        }
    }

    override fun readRoot(name: String): String? {
        val f = File(root, name)
        return if (f.isFile) f.readText() else null
    }

    private companion object {
        val DAY = Regex("^\\d{4}-\\d{2}-\\d{2}$")
    }
}

class PrefsBlockStore(context: Context) : BlockStore {
    private val prefs = context.getSharedPreferences("blocks", Context.MODE_PRIVATE)

    override fun load(): Set<Int> = prefs.getStringSet(KEY, emptySet()).orEmpty().mapNotNull { it.toIntOrNull() }.toSet()

    override fun save(uids: Set<Int>) {
        prefs.edit().putStringSet(KEY, uids.map { it.toString() }.toSet()).apply()
    }

    private companion object {
        const val KEY = "uids"
    }
}

class FileDomainRuleStore(private val file: File) : DomainRuleStore {
    override fun load(): String? = if (file.isFile) file.readText() else null

    override fun save(text: String) {
        file.parentFile?.mkdirs()
        val tmp = File(file.parentFile, file.name + ".tmp")
        tmp.writeText(text)
        if (!tmp.renameTo(file)) {
            file.writeText(text)
            tmp.delete()
        }
    }
}

object WallClock : Clock {
    override fun nowMillis(): Long = System.currentTimeMillis()
    override fun zone(): ZoneId = ZoneId.systemDefault()
}

object UnderlyingDns {
    private val FALLBACK: InetAddress = InetAddress.getByAddress(byteArrayOf(9, 9, 9, 9))

    @Suppress("DEPRECATION")
    fun resolver(cm: ConnectivityManager): InetAddress {
        val nets = buildList {
            cm.activeNetwork?.let { add(it) }
            addAll(cm.allNetworks)
        }.distinct()
        val usable = nets.mapNotNull { n ->
            val caps = cm.getNetworkCapabilities(n) ?: return@mapNotNull null
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) return@mapNotNull null
            if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) return@mapNotNull null
            val lp = cm.getLinkProperties(n) ?: return@mapNotNull null
            Triple(caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED), lp.dnsServers, n)
        }
        val chosen = usable.firstOrNull { it.first && it.second.isNotEmpty() } ?: usable.firstOrNull { it.second.isNotEmpty() }
        return chosen?.second?.firstOrNull() ?: FALLBACK
    }
}
