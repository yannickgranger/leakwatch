package io.github.yannickgranger.leakwatch.domain

import java.net.InetSocketAddress
import java.util.concurrent.ConcurrentHashMap
import io.github.yannickgranger.leakwatch.port.AppDirectory
import io.github.yannickgranger.leakwatch.port.OwnerResolver

data class AppIdentity(val uid: Int, val packages: List<String>, val label: String, val system: Boolean = false)

class Attribution(private val owner: OwnerResolver, private val apps: AppDirectory) {
    private val cache = ConcurrentHashMap<Int, AppIdentity>()

    fun identify(protocol: Int, local: InetSocketAddress, remote: InetSocketAddress): AppIdentity {
        val uid = try {
            owner.ownerUid(protocol, local, remote)
        } catch (e: RuntimeException) {
            -1
        }
        return forUid(uid)
    }

    fun forUid(uid: Int): AppIdentity = cache.getOrPut(uid) {
        when {
            uid < 0 -> AppIdentity(-1, emptyList(), "unknown")
            uid < 10000 -> AppIdentity(uid, safePackages(uid), "android-system:$uid", true)
            else -> {
                val pkgs = safePackages(uid)
                val label = pkgs.firstOrNull()?.let { p -> runCatching { apps.label(p) }.getOrNull() ?: p } ?: "uid:$uid"
                AppIdentity(uid, pkgs, label, pkgs.any { p -> runCatching { apps.isSystem(p) }.getOrDefault(false) })
            }
        }
    }

    private fun safePackages(uid: Int): List<String> = runCatching { apps.packagesForUid(uid) }.getOrDefault(emptyList())
}
