package io.github.yannickgranger.leakwatch.domain

import java.time.Instant
import io.github.yannickgranger.leakwatch.port.Clock
import io.github.yannickgranger.leakwatch.port.UsageEvent
import io.github.yannickgranger.leakwatch.port.UsageEventKind
import io.github.yannickgranger.leakwatch.port.UsageSource

object AppState {
    const val FOREGROUND = "foreground"
    const val BACKGROUND = "background"
    const val SCREEN_OFF = "screen_off"
    const val UNKNOWN = "unknown"
}

data class UsageInfo(val appState: String, val lastUsed: Long?, val notUsedToday: Boolean) {
    companion object {
        val UNKNOWN = UsageInfo(AppState.UNKNOWN, null, false)
    }
}

class AppStateClassifier(private val source: UsageSource, private val clock: Clock, private val refreshMs: Long = 2_000) {
    private val events = ArrayList<UsageEvent>()
    private var access = false
    private var known = Long.MIN_VALUE
    private var lastRefresh = Long.MIN_VALUE

    @Synchronized
    fun refresh(now: Long): Boolean {
        if (lastRefresh != Long.MIN_VALUE && now - lastRefresh < refreshMs) return false
        lastRefresh = now
        access = runCatching { source.hasAccess() }.getOrDefault(false)
        if (!access) {
            events.clear()
            known = now
            return true
        }
        val keepFrom = now - HISTORY_MS
        val from = if (known == Long.MIN_VALUE || known < keepFrom) keepFrom else maxOf(keepFrom, known - OVERLAP_MS)
        val fresh = runCatching { source.events(from, now) }.getOrNull() ?: return true
        events.removeAll { it.ts >= from || it.ts < keepFrom }
        events.addAll(fresh.filter { it.ts in from until now })
        events.sortBy { it.ts }
        known = now
        return true
    }

    @Synchronized
    fun knownUntil(): Long = known

    @Synchronized
    fun hasAccess(): Boolean = access

    @Synchronized
    fun classify(uid: Int, packages: List<String>, atMs: Long): UsageInfo {
        if (!access) return UsageInfo.UNKNOWN
        var foreground: String? = null
        var screenOn = true
        var lastForeground: Long? = null
        for (e in events) {
            if (e.ts > atMs) break
            when (e.kind) {
                UsageEventKind.RESUMED -> {
                    foreground = e.packageName
                    if (e.packageName in packages) lastForeground = e.ts
                }
                UsageEventKind.PAUSED -> {
                    if (e.packageName == foreground) foreground = null
                    if (e.packageName in packages) lastForeground = e.ts
                }
                UsageEventKind.SCREEN_ON -> screenOn = true
                UsageEventKind.SCREEN_OFF -> screenOn = false
            }
        }
        val inFront = foreground != null && foreground in packages
        if (inFront) lastForeground = atMs
        val lastUsed = lastForeground?.takeIf { it >= atMs - LOOKBACK_MS }
        if (uid < FIRST_APP_UID) return UsageInfo(AppState.UNKNOWN, lastUsed, false)
        val state = when {
            !screenOn -> AppState.SCREEN_OFF
            inFront || (lastUsed != null && atMs - lastUsed < GRACE_MS) -> AppState.FOREGROUND
            else -> AppState.BACKGROUND
        }
        val midnight = Instant.ofEpochMilli(atMs).atZone(clock.zone()).toLocalDate().atStartOfDay(clock.zone()).toInstant().toEpochMilli()
        return UsageInfo(state, lastUsed, lastUsed == null || lastUsed < midnight)
    }

    companion object {
        const val FIRST_APP_UID = 10_000
        const val GRACE_MS = 5_000L
        const val LOOKBACK_MS = 24 * 3_600_000L
        const val HISTORY_MS = 26 * 3_600_000L
        const val OVERLAP_MS = 10_000L
    }
}
