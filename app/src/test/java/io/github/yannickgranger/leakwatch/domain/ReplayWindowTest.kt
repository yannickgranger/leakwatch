package io.github.yannickgranger.leakwatch.domain

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ReplayWindowTest {
    @Test
    fun acceptsFreshCountersInOrder() {
        val w = ReplayWindow()
        for (c in 0L..100L) assertTrue(w.accept(c))
    }

    @Test
    fun rejectsReplay() {
        val w = ReplayWindow()
        assertTrue(w.accept(5))
        assertFalse(w.accept(5))
    }

    @Test
    fun acceptsOutOfOrderInsideWindowOnce() {
        val w = ReplayWindow()
        assertTrue(w.accept(10))
        assertTrue(w.accept(3))
        assertFalse(w.accept(3))
        assertTrue(w.accept(9))
    }

    @Test
    fun rejectsTooOldAfterWindowSlides() {
        val w = ReplayWindow()
        assertTrue(w.accept(0))
        assertTrue(w.accept(ReplayWindow.SIZE + 10))
        assertFalse(w.accept(5))
        assertTrue(w.accept(ReplayWindow.SIZE + 9))
        assertTrue(w.accept(11))
    }

    @Test
    fun bigJumpClearsOldBits() {
        val w = ReplayWindow()
        assertTrue(w.accept(1))
        assertTrue(w.accept(3 * ReplayWindow.SIZE + 1))
        assertTrue(w.accept(3 * ReplayWindow.SIZE))
        assertFalse(w.accept(3 * ReplayWindow.SIZE + 1))
    }

    @Test
    fun checkDoesNotMark() {
        val w = ReplayWindow()
        assertTrue(w.check(7))
        assertTrue(w.check(7))
        assertTrue(w.accept(7))
        assertFalse(w.check(7))
    }

    @Test
    fun rejectsCountersBeyondLimit() {
        val w = ReplayWindow()
        assertFalse(w.accept(ReplayWindow.REJECT_AFTER_MESSAGES))
        assertFalse(w.accept(-1))
    }
}
