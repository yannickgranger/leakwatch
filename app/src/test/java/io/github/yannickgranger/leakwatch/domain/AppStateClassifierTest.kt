package io.github.yannickgranger.leakwatch.domain

import java.time.ZoneId
import io.github.yannickgranger.leakwatch.port.Clock
import io.github.yannickgranger.leakwatch.port.UsageEvent
import io.github.yannickgranger.leakwatch.port.UsageEventKind
import io.github.yannickgranger.leakwatch.port.UsageEventKind.PAUSED
import io.github.yannickgranger.leakwatch.port.UsageEventKind.RESUMED
import io.github.yannickgranger.leakwatch.port.UsageEventKind.SCREEN_OFF
import io.github.yannickgranger.leakwatch.port.UsageEventKind.SCREEN_ON
import io.github.yannickgranger.leakwatch.port.UsageSource
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class AppStateClassifierTest {
    private val paris = ZoneId.of("Europe/Paris")
    private val noon = 1_762_599_600_000L
    private val brave = listOf("com.brave.browser")

    private class FakeUsage(var access: Boolean = true) : UsageSource {
        val events = mutableListOf<UsageEvent>()
        var calls = 0
        override fun hasAccess(): Boolean = access
        override fun events(fromMs: Long, toMs: Long): List<UsageEvent> {
            calls++
            return events.filter { it.ts in fromMs until toMs }.sortedBy { it.ts }
        }
        fun add(ts: Long, pkg: String?, kind: UsageEventKind) {
            events += UsageEvent(ts, pkg, kind)
        }
    }

    private class FixedClock(val zone: ZoneId) : Clock {
        var now = 0L
        override fun nowMillis(): Long = now
        override fun zone(): ZoneId = zone
    }

    private fun classifier(usage: FakeUsage, now: Long): AppStateClassifier {
        val clock = FixedClock(paris).also { it.now = now }
        return AppStateClassifier(usage, clock).also { it.refresh(now) }
    }

    @Test
    fun foregroundWhileTheAppIsResumed() {
        val u = FakeUsage()
        u.add(noon - 60_000, "com.brave.browser", RESUMED)
        val info = classifier(u, noon).classify(10100, brave, noon - 1_000)
        assertEquals(AppState.FOREGROUND, info.appState)
        assertEquals(noon - 1_000, info.lastUsed)
        assertFalse(info.notUsedToday)
    }

    @Test
    fun foregroundWithinFiveSecondsAfterLeaving() {
        val u = FakeUsage()
        u.add(noon - 60_000, "com.brave.browser", RESUMED)
        u.add(noon - 20_000, "com.brave.browser", PAUSED)
        u.add(noon - 20_000, "com.other", RESUMED)
        val c = classifier(u, noon)
        assertEquals(AppState.FOREGROUND, c.classify(10100, brave, noon - 15_001).appState)
        val later = c.classify(10100, brave, noon - 15_000)
        assertEquals(AppState.BACKGROUND, later.appState)
        assertEquals(noon - 20_000, later.lastUsed)
    }

    @Test
    fun backgroundWhenAnotherAppIsInFront() {
        val u = FakeUsage()
        u.add(noon - 3_600_000, "com.brave.browser", RESUMED)
        u.add(noon - 3_000_000, "com.brave.browser", PAUSED)
        u.add(noon - 3_000_000, "com.other", RESUMED)
        val info = classifier(u, noon).classify(10100, brave, noon - 1_000)
        assertEquals(AppState.BACKGROUND, info.appState)
        assertEquals(noon - 3_000_000, info.lastUsed)
        assertFalse(info.notUsedToday)
    }

    @Test
    fun screenOffWinsOverForeground() {
        val u = FakeUsage()
        u.add(noon - 60_000, "com.brave.browser", RESUMED)
        u.add(noon - 30_000, null, SCREEN_OFF)
        val c = classifier(u, noon)
        assertEquals(AppState.SCREEN_OFF, c.classify(10100, brave, noon - 1_000).appState)
        assertEquals(AppState.FOREGROUND, c.classify(10100, brave, noon - 40_000).appState)
    }

    @Test
    fun screenOnAgainEndsScreenOff() {
        val u = FakeUsage()
        u.add(noon - 30_000, null, SCREEN_OFF)
        u.add(noon - 10_000, null, SCREEN_ON)
        val c = classifier(u, noon)
        assertEquals(AppState.SCREEN_OFF, c.classify(10100, brave, noon - 20_000).appState)
        assertEquals(AppState.BACKGROUND, c.classify(10100, brave, noon - 1_000).appState)
    }

    @Test
    fun screenCountsAsOnWhenNoScreenEventIsKnown() {
        val u = FakeUsage()
        u.add(noon - 2_000, "com.brave.browser", RESUMED)
        assertEquals(AppState.FOREGROUND, classifier(u, noon).classify(10100, brave, noon - 1_000).appState)
    }

    @Test
    fun unknownWithoutUsageAccess() {
        val u = FakeUsage(access = false)
        u.add(noon - 60_000, "com.brave.browser", RESUMED)
        val info = classifier(u, noon).classify(10100, brave, noon - 1_000)
        assertEquals(AppState.UNKNOWN, info.appState)
        assertNull(info.lastUsed)
        assertFalse(info.notUsedToday)
    }

    @Test
    fun unknownBelowFirstApplicationUid() {
        val u = FakeUsage()
        val info = classifier(u, noon).classify(1000, listOf("android"), noon - 1_000)
        assertEquals(AppState.UNKNOWN, info.appState)
        assertFalse(info.notUsedToday)
    }

    @Test
    fun notUsedTodayWhenLastForegroundIsBeforeMidnight() {
        val u = FakeUsage()
        u.add(noon - 20 * 3_600_000L, "com.brave.browser", RESUMED)
        u.add(noon - 19 * 3_600_000L, "com.brave.browser", PAUSED)
        val info = classifier(u, noon).classify(10100, brave, noon - 1_000)
        assertEquals(AppState.BACKGROUND, info.appState)
        assertEquals(noon - 19 * 3_600_000L, info.lastUsed)
        assertTrue(info.notUsedToday)
        val never = classifier(FakeUsage(), noon).classify(10100, brave, noon - 1_000)
        assertNull(never.lastUsed)
        assertTrue(never.notUsedToday)
    }

    @Test
    fun lastUsedLooksBackTwentyFourHoursOnly() {
        val u = FakeUsage()
        u.add(noon - 30 * 3_600_000L, "com.brave.browser", RESUMED)
        u.add(noon - 29 * 3_600_000L, "com.brave.browser", PAUSED)
        assertNull(classifier(u, noon).classify(10100, brave, noon - 1_000).lastUsed)
    }

    @Test
    fun refreshesAtMostEveryTwoSecondsAndClassifiesWithEventsLearnedLater() {
        val u = FakeUsage()
        val c = classifier(u, noon)
        assertEquals(1, u.calls)
        u.add(noon + 500, "com.brave.browser", RESUMED)
        assertFalse(c.refresh(noon + 1_999))
        assertEquals(1, u.calls)
        assertEquals(AppState.BACKGROUND, c.classify(10100, brave, noon + 1_000).appState)
        assertTrue(c.refresh(noon + 2_000))
        assertEquals(2, u.calls)
        assertEquals(noon + 2_000, c.knownUntil())
        assertEquals(AppState.FOREGROUND, c.classify(10100, brave, noon + 1_000).appState)
    }
}
