package io.github.yannickgranger.leakwatch.domain

import io.github.yannickgranger.leakwatch.port.BlockStore
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class BlockPolicyTest {
    private class MemoryStore(var saved: Set<Int> = emptySet()) : BlockStore {
        override fun load(): Set<Int> = saved
        override fun save(uids: Set<Int>) { saved = uids }
    }

    @Test
    fun unblockedUidIsAllowed() {
        val p = BlockPolicy(MemoryStore())
        assertEquals(Verdict.ALLOW, p.verdict(10100, Proto.TCP))
        assertEquals(Verdict.ALLOW, p.verdict(10100, Proto.UDP))
    }

    @Test
    fun blockedUidGetsTcpResetAndUdpDrop() {
        val p = BlockPolicy(MemoryStore())
        p.block(10100)
        assertTrue(p.isBlocked(10100))
        assertEquals(Verdict.RESET, p.verdict(10100, Proto.TCP))
        assertEquals(Verdict.DROP, p.verdict(10100, Proto.UDP))
        assertEquals(Verdict.ALLOW, p.verdict(10101, Proto.TCP))
    }

    @Test
    fun blockSetIsPersistedAndReloaded() {
        val store = MemoryStore()
        BlockPolicy(store).apply { block(10100); block(10200); unblock(10100) }
        assertEquals(setOf(10200), store.saved)
        val reloaded = BlockPolicy(store)
        assertTrue(reloaded.isBlocked(10200))
        assertFalse(reloaded.isBlocked(10100))
    }

    @Test
    fun unblockRestoresTraffic() {
        val p = BlockPolicy(MemoryStore(setOf(10300)))
        assertEquals(Verdict.RESET, p.verdict(10300, Proto.TCP))
        p.unblock(10300)
        assertEquals(Verdict.ALLOW, p.verdict(10300, Proto.TCP))
        assertEquals(emptySet<Int>(), p.blocked())
    }
}
