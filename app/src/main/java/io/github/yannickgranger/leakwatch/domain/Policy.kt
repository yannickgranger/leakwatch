package io.github.yannickgranger.leakwatch.domain

import io.github.yannickgranger.leakwatch.port.BlockStore

class TrackerMatcher(suffixes: Iterable<String>) {
    private val set: Set<String> = suffixes.map { normalize(it) }.filter { it.isNotEmpty() }.toHashSet()

    val size: Int get() = set.size

    fun matches(host: String?): Boolean {
        if (host == null) return false
        var h = normalize(host)
        while (h.isNotEmpty()) {
            if (h in set) return true
            val dot = h.indexOf('.')
            if (dot < 0) return false
            h = h.substring(dot + 1)
        }
        return false
    }

    companion object {
        private fun normalize(s: String) = s.trim().trimEnd('.').lowercase()

        fun parse(text: String): TrackerMatcher =
            TrackerMatcher(text.lineSequence().map { it.trim() }.filter { it.isNotEmpty() && !it.startsWith("#") }.toList())
    }
}

enum class Verdict { ALLOW, RESET, DROP }

class BlockPolicy(private val store: BlockStore) {
    @Volatile
    private var uids: Set<Int> = store.load().toSet()

    fun blocked(): Set<Int> = uids
    fun isBlocked(uid: Int): Boolean = uid in uids

    @Synchronized
    fun block(uid: Int) {
        uids = uids + uid
        store.save(uids)
    }

    @Synchronized
    fun unblock(uid: Int) {
        uids = uids - uid
        store.save(uids)
    }

    fun verdict(uid: Int, protocol: Int): Verdict = when {
        uid !in uids -> Verdict.ALLOW
        protocol == Proto.TCP -> Verdict.RESET
        else -> Verdict.DROP
    }
}
